//! daemonseed-gui — Slint client.
//!
//! Round 2 made the shell **interactive** over a RAM-only per-circle [`state`]
//! layer (click-to-switch rail; each circle keeps its own draft + scroll). Round 3
//! wired the **public Lobby room to real networking** (the [`net`] actor). Round 4
//! adds **circle plumbing**: Join-a-circle and New-circle flows that *materialize*
//! a circle into the rail at runtime, each carrying the net contract (phrase →
//! `derive_cot_key` → `CotKey` + a rendezvous slot). Round 5 **wires those circles
//! to the network**: materialize fires `NetCommand::JoinCircle{circle_id, phrase}`
//! and the composer Send on a materialized circle fires `SendCircle{circle_id}` —
//! real sealed circle chat over the relay (mirroring the Lobby path), routed back
//! into the right circle by `circle_id`. The binary seeds **Lobby-only**
//! (empty-state for circles; the Lobby stays pinned + real).
//!
//! Two run modes. **Windowed** (the `desktop` feature) opens a real winit window,
//! software-rendered (no GL) — the felt-test surface. **Offscreen** renders the
//! shell to a PNG; the only mode a headless *terminal* can verify.
//!
//! Offscreen verification flags: `--switch <n>` drives the real switch callback;
//! `--scroll <px>` sets the viewport-y sign; `--show-join` / `--show-new` open the
//! circle overlays before rendering; `--materialize <phrase>` drives the real
//! materialize path so the PNG shows a materialized circle selected in the rail;
//! `--self-check` runs a live materialize + draft-retention round-trip through the
//! real callbacks and prints `SELF-CHECK PASS` (panics → non-zero exit);
//! `--show-shares` / `--show-publish` render the Shares-tab browse tree / the Publish
//! overlay (with a fixture share set, no relay).

mod desktop_integration;
mod net;
mod profile;
mod share_browser;
mod state;

slint::include_modules!();

use daemonseed_core::bootstrap::BootstrapAnchor;
use daemonseed_core::first_start::{
    BackupVerified, FirstStart, FirstStartError, Sealed, TypeBackChallenge,
};
use daemonseed_core::handle::display_name::OsRng;
use daemonseed_core::passphrase::strength::{estimate, estimate_circle};
use daemonseed_core::profile::config::ArgonParams;
use daemonseed_core::profile::persist::{
    load_for_unlock, session_materials_from_unlock, write_first_start,
};
use daemonseed_core::profile::resolve::{ResolveArgs, ResolvedProfileRoot, resolve};
use daemonseed_core::storage::seeds;
use net::{NetCommand, NetEvent, NetHandle};
use profile::Profile;
use share_browser::{FetchTarget, ManifestRow, NodeKind, ShareBrowser};
use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType, Rgb565Pixel};
use slint::platform::{Platform, PlatformError, WindowAdapter};
use slint::{ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel};
use state::{CircleState, GuiState, Msg};
use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

/// The Lobby is rail index 0 — the only circle wired to the real public room. A
/// materialized circle (index ≥1) routes its Send to the Round-5 `SendCircle` seam.
const LOBBY: usize = 0;

/// Default relay (the alpha1 fra1 VPS). Overridable via env so a tester can point
/// at their own relay without a rebuild. Mirrors the TUI's connect target.
fn relay_target() -> (String, String) {
    let id =
        std::env::var("DAEMONSEED_RELAY_ID").unwrap_or_else(|_| "fra1#06177b08dc06".to_owned());
    let addr = std::env::var("DAEMONSEED_RELAY_ADDR").unwrap_or_else(|_| "167.86.91.98".to_owned());
    let addr = if addr.contains(':') {
        addr
    } else {
        format!("{addr}:443")
    };
    (id, addr)
}

/// Bring up the process-wide CryptoProvider + oxicrypt module the cli/tui/server
/// share. Needed before any `Connect` AND before any `derive_cot_key`
/// (materialization), so the offscreen + self-check paths init it too. Returns
/// `Ok(())` or a human-readable reason.
fn init_crypto() -> Result<(), String> {
    use daemonseed_server::kats::CNSA_2_0_KATS;
    use daemonseed_server::tls::install_provider;
    use oxicrypt_module::{AlgorithmProfile, initialize_with_profile};
    initialize_with_profile(CNSA_2_0_KATS, AlgorithmProfile::Cnsa2)
        .map_err(|e| format!("crypto module init failed: {e}"))?;
    install_provider().map_err(|e| format!("TLS provider install failed: {e}"))?;
    Ok(())
}

thread_local! {
    static CLOCK: Cell<Duration> = const { Cell::new(Duration::ZERO) };
}

/// Software-renderer platform with a real, app-advanced monotonic clock (not the
/// `ZERO` stub) so declarative animations can progress.
struct GuiPlatform {
    window: Rc<MinimalSoftwareWindow>,
}
impl Platform for GuiPlatform {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
        Ok(self.window.clone())
    }
    fn duration_since_start(&self) -> Duration {
        CLOCK.with(|c| c.get())
    }
}

const W: u32 = 1100;
const H: u32 = 680;

/// Released build version shown in-app (auth-screen readout, issue #59 surface).
/// Stamped at release from the git tag — like `lama.yaml` `version` and the README
/// Status line — NOT Cargo's tag-driven `0.1.0`.
const APP_VERSION: &str = "v0.29.2";

/// Run `f` on the next event-loop tick instead of synchronously. Used to move
/// `.focus()` calls OUT of key-event handlers: focusing an element while Slint is
/// mid key-processing is re-entrant and corrupts routing for the NEXT key (caraka
/// hit "the third Ctrl shortcut in a row fails" — each prior shortcut had focused a
/// field synchronously from inside the key handler). A 0ms single-shot defers it to
/// after the current event completes. No-op in offscreen mode (no event loop), which
/// is fine — the offscreen paths don't depend on focus.
fn defer<F: FnOnce() + 'static>(f: F) {
    slint::Timer::single_shot(Duration::from_millis(0), f);
}

/// The first-start wizard's cross-callback state: the `FirstStart` type-state
/// machine threaded between UI steps. `Sealed` after `initialize` (the mnemonic is
/// shown + confirmed), `Verified` after a matching round-trip (ready to finalize).
/// Held in a `RefCell` because each wizard button is a separate callback. `Empty`
/// is the resting / consumed state.
enum Wizard {
    Empty,
    Sealed(FirstStart<Sealed>),
    Verified(FirstStart<BackupVerified>),
}

impl Wizard {
    /// Take the `Sealed` state out, leaving `Empty`. Returns `None` if not Sealed.
    fn take_sealed(&mut self) -> Option<FirstStart<Sealed>> {
        match std::mem::replace(self, Wizard::Empty) {
            Wizard::Sealed(s) => Some(s),
            other => {
                *self = other;
                None
            }
        }
    }

    /// Take the `Verified` state out, leaving `Empty`. Returns `None` otherwise.
    fn take_verified(&mut self) -> Option<FirstStart<BackupVerified>> {
        match std::mem::replace(self, Wizard::Empty) {
            Wizard::Verified(v) => Some(v),
            other => {
                *self = other;
                None
            }
        }
    }
}

/// Human-readable prompt for a C34 type-back challenge: the 1-based word positions
/// the user must re-enter (e.g. "Type words #4, #12 and #22 of your recovery
/// phrase."). Positions come from the challenge in ascending order.
fn typeback_prompt(challenge: &TypeBackChallenge) -> String {
    let nums: Vec<String> = challenge
        .positions()
        .iter()
        .map(|p| format!("#{}", p + 1))
        .collect();
    match nums.as_slice() {
        [] => "Type the requested words of your recovery phrase.".to_owned(),
        [a] => format!("Type word {a} of your recovery phrase."),
        [rest @ .., last] => format!(
            "Type words {} and {last} of your recovery phrase.",
            rest.join(", ")
        ),
    }
}

/// PRE-check a C34 type-back answer set against the held mnemonic + challenge,
/// case-insensitively, WITHOUT consuming anything. `verify_type_back` consumes the
/// `Sealed` state by value, so (as with the old round-trip) it is only ever invoked
/// when it will succeed — a typo must not destroy the enrollment.
fn type_back_precheck(challenge: &TypeBackChallenge, mnemonic: &str, answers: &[String]) -> bool {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    let positions = challenge.positions();
    positions.len() == answers.len()
        && positions.iter().zip(answers).all(|(p, a)| {
            words
                .get(*p)
                .is_some_and(|w| w.eq_ignore_ascii_case(a.trim()))
        })
}

/// Convert a circle's `Vec<Msg>` into a Slint `ModelRc<MsgData>`.
fn messages_model(messages: &[Msg]) -> ModelRc<MsgData> {
    let rows: Vec<MsgData> = messages
        .iter()
        .map(|m| MsgData {
            who: SharedString::from(m.who.as_str()),
            text: SharedString::from(m.text.as_str()),
            mine: m.mine,
        })
        .collect();
    ModelRc::from(Rc::new(VecModel::from(rows)))
}

/// The SINGLE path that pushes a circle's state into the UI props.
///
/// ORDER MATTERS (ISC-39): set `messages` FIRST so the Flickable's content
/// height is current, then name/sub/draft/active, and write `scroll-y` LAST — so a
/// restored negative scroll is clamped against the new content height, not stale.
fn apply_view(ui: &AppWindow, c: &CircleState, active: i32) {
    ui.set_messages(messages_model(&c.messages));
    ui.set_header_name(SharedString::from(c.name.as_str()));
    ui.set_header_sub(SharedString::from(c.header_sub.as_str()));
    ui.set_draft(SharedString::from(c.draft.as_str()));
    ui.set_active(active);
    ui.set_scroll_y(c.scroll_y);
}

/// Rebuild the rail model from the current circle metas and refresh the
/// empty-state flag. Called once at startup and again after every materialize (a
/// circle was ADDED, so the `for`-over-model must be rebuilt).
fn rebuild_rail(ui: &AppWindow, st: &GuiState) {
    let circles: Vec<CircleData> = st
        .metas()
        .iter()
        .map(|c| CircleData {
            name: SharedString::from(c.name.as_str()),
            sub: SharedString::from(c.sub.as_str()),
            initial: SharedString::from(c.initial.as_str()),
            pinned: c.pinned,
            unread: c.unread,
        })
        .collect();
    ui.set_circles(ModelRc::from(Rc::new(VecModel::from(circles))));
    ui.set_only_lobby(st.only_lobby());
}

/// Materialize a circle from `phrase`, rebuild the rail, switch to it, and
/// autofocus the composer. Returns `false` if derivation failed (rare — a crypto
/// backend error). Shared by the submit-join / submit-new callbacks and the
/// `--materialize` offscreen flag.
fn materialize_and_select(
    ui: &AppWindow,
    state: &Rc<RefCell<GuiState>>,
    net: &Rc<RefCell<NetHandle>>,
    phrase: &str,
) -> bool {
    let join = {
        let mut st = state.borrow_mut();
        match st.materialize_from_phrase(phrase) {
            Ok(idx) => {
                // Capture the current circle's live edits before activating the new one.
                let live_draft = ui.get_draft().to_string();
                let live_scroll = ui.get_scroll_y();
                st.switch_to(idx, live_draft, live_scroll);
                let active = st.active();
                rebuild_rail(ui, &st);
                apply_view(ui, st.current(), active as i32);
                // Round 6 write-through: record the circle in the unlocked profile
                // so it silently re-joins next launch. A no-op without a profile; a
                // disk failure is surfaced quietly — the circle still works this
                // session (no-history property means nothing is lost but the rejoin).
                if let Err(e) = st.persist_circle(idx) {
                    ui.set_connection_status(SharedString::from(format!(
                        "circle active · saved in memory only ({e})"
                    )));
                }
                // The JoinCircle inputs come from the STORED net contract (the
                // keystone is the source of truth), not the passed-through arg.
                st.current()
                    .net
                    .as_ref()
                    .map(|n| (n.circle_id, n.phrase.clone()))
            }
            Err(_) => None,
        }
    };
    match join {
        Some((circle_id, phrase)) => {
            // Autofocus the composer so the user can type immediately (caraka note),
            // deferred off any key-triggered call path (re-entrant focus footgun).
            let w = ui.as_weak();
            defer(move || {
                if let Some(ui) = w.upgrade() {
                    ui.invoke_focus_composer();
                }
            });
            // Round 5: subscribe the actor to this circle. Fire-and-forget; if the
            // session isn't Connected yet the actor emits a (drained, non-fatal)
            // CircleError — the create-before-connect edge, flagged in the ISA.
            let _ = net
                .borrow()
                .send(NetCommand::JoinCircle { circle_id, phrase });
            true
        }
        None => false,
    }
}

/// Build the shell, own the RAM-only state, and wire ALL interactive callbacks
/// (rail switch, composer send, and the round-4 circle-plumbing surfaces).
/// Returns the window AND the shared state so the caller can wire real networking
/// and drive the offscreen verification flags.
type BuiltUi = (
    AppWindow,
    Rc<RefCell<GuiState>>,
    Rc<RefCell<NetHandle>>,
    Rc<RefCell<ShareBrowser>>,
);

fn build_ui() -> BuiltUi {
    let ui = AppWindow::new().expect("create AppWindow");
    ui.set_app_version(SharedString::from(APP_VERSION));
    // Round-4 seed: Lobby only (empty-state for circles; Lobby pinned + real).
    let state = Rc::new(RefCell::new(GuiState::lobby_only()));
    // The net actor is built HERE (round 5) so the circle-plumbing callbacks can
    // reach it (materialize → JoinCircle; circle Send → SendCircle). `NetHandle::new`
    // is crypto-independent — only Connect needs crypto — so it never fails on
    // crypto; the Connect + drain timer are started later by `start_net`.
    let net = Rc::new(RefCell::new(
        NetHandle::new().expect("build daemonseed-gui net actor"),
    ));

    // The public-share browse-tree model (Shares tab). Slint-free; the net drain
    // folds `SharesSnapshot`/`FetchManifest` into it and `apply_share_rows` pushes the
    // flattened rows to the UI. Held here so the callbacks + the drain/poll timer all
    // share the one instance.
    let browser = Rc::new(RefCell::new(ShareBrowser::new()));

    // Rail model + empty-state flag.
    rebuild_rail(&ui, &state.borrow());
    ui.set_active_tab(0);

    // Interactive rail: capture live edits into the active circle, switch, then
    // autofocus the composer so the user can start typing immediately.
    ui.on_switch_circle({
        let weak = ui.as_weak();
        let state = state.clone();
        move |target| {
            let ui = weak.unwrap();
            // Switching dismisses any open overlay (mutual exclusivity — never stack).
            ui.set_new_open(false);
            ui.set_join_open(false);
            ui.set_palette_open(false);
            ui.set_publish_open(false);
            let live_draft = ui.get_draft().to_string();
            let live_scroll = ui.get_scroll_y();
            let mut refresh_public_shares = false;
            {
                let mut st = state.borrow_mut();
                st.switch_to(target as usize, live_draft, live_scroll);
                let active = st.active();
                // #64: switch_to cleared the focused room's unread; reflect it.
                rebuild_rail(&ui, &st);
                apply_view(&ui, st.current(), active as i32);
                // Tidiness: keep the shares view coherent with the room. If already
                // on a shares tab, show the one that matches the destination — a
                // circle's "Circle shares" (tab 2) or the Lobby's public "Shares"
                // (tab 1) — so public shares never look available inside a circle
                // (or vice versa). Chat (tab 0) is left alone.
                let tab = ui.get_active_tab();
                if tab == 1 || tab == 2 {
                    if st.current().net.is_some() {
                        ui.set_active_tab(2);
                    } else {
                        ui.set_active_tab(1);
                        refresh_public_shares = true;
                    }
                }
            }
            // Deferred: focusing during a (possibly key-triggered, e.g. Ctrl+L) callback
            // is re-entrant and breaks the next key's routing. The public-shares
            // refresh is deferred for the same reason (its handler re-borrows state).
            let w = ui.as_weak();
            defer(move || {
                if let Some(ui) = w.upgrade() {
                    if refresh_public_shares {
                        ui.invoke_shares_tab_opened();
                    }
                    ui.invoke_focus_composer();
                }
            });
        }
    });

    // Open the Join overlay (from the rail empty-state or the palette). Reset the
    // phrase + strength so the overlay opens clean.
    ui.on_open_join({
        let weak = ui.as_weak();
        move || {
            let ui = weak.unwrap();
            // Mutual exclusivity — close the other surfaces so overlays never stack.
            ui.set_new_open(false);
            ui.set_palette_open(false);
            ui.set_publish_open(false);
            ui.set_join_phrase(SharedString::from(""));
            ui.set_join_phrase_strong(false);
            ui.set_join_open(true);
            // Deferred focus (see `defer`): focusing during a key-triggered (Ctrl+J)
            // callback is re-entrant and breaks the next key's routing.
            let w = ui.as_weak();
            defer(move || {
                if let Some(ui) = w.upgrade() {
                    ui.invoke_focus_join_input();
                }
            });
        }
    });

    // Open the New-circle overlay: pre-generate a strong (132-bit) diceware phrase
    // — one-tap, the ≥128-bit bar at zero friction (brief #2).
    ui.on_open_new({
        let weak = ui.as_weak();
        move || {
            let ui = weak.unwrap();
            // Mutual exclusivity — close the other surfaces so overlays never stack.
            ui.set_join_open(false);
            ui.set_palette_open(false);
            ui.set_publish_open(false);
            let phrase = state::generate_circle_phrase().unwrap_or_default();
            ui.set_new_phrase(SharedString::from(phrase.as_str()));
            // Generated ⇒ strong; reset the copied confirmation for a fresh open.
            ui.set_new_phrase_strong(true);
            ui.set_new_copied(false);
            ui.set_new_open(true);
        }
    });

    // Re-roll: regenerate a fresh phrase in place.
    ui.on_reroll_new({
        let weak = ui.as_weak();
        move || {
            let ui = weak.unwrap();
            let phrase = state::generate_circle_phrase().unwrap_or_default();
            ui.set_new_phrase(SharedString::from(phrase.as_str()));
            ui.set_new_phrase_strong(true);
            ui.set_new_copied(false);
        }
    });

    // Live (hidden) strength when the user EDITS the generated phrase → drives the
    // "Looks strong" pill and the submit gate (same estimator as join; D3).
    ui.on_new_phrase_edited({
        let weak = ui.as_weak();
        move |text| {
            let ui = weak.unwrap();
            ui.set_new_phrase_strong(estimate_circle(text.as_str()).is_circle_green());
        }
    });

    // Live (hidden) strength on each keystroke → drives the quiet "Looks strong"
    // pill. Reuses the SAME estimator the join gate uses (D3 — one shared
    // estimator, numbers HIDDEN).
    ui.on_join_phrase_edited({
        let weak = ui.as_weak();
        move |text| {
            let ui = weak.unwrap();
            let strong = estimate_circle(text.as_str()).is_circle_green();
            ui.set_join_phrase_strong(strong);
        }
    });

    // Right-click "paste" into the Join phrase field (#63). Reads the system
    // clipboard (the reusable plumbing for any future right-click paste), fills the
    // field, refreshes the strength cue with the SAME estimator typing uses, and
    // refocuses so the user can keep editing.
    ui.on_paste_into_join({
        let weak = ui.as_weak();
        move || {
            let ui = weak.unwrap();
            if let Some(text) = read_clipboard_text() {
                let text = text.trim();
                if !text.is_empty() {
                    ui.set_join_phrase(SharedString::from(text));
                    ui.set_join_phrase_strong(estimate_circle(text).is_circle_green());
                    ui.invoke_focus_join_input();
                }
            }
        }
    });

    // Submit Join: GATE on the ≥128-bit circle floor (ISC-C9, precautionary
    // default — block a weak phrase rather than warn). A weak phrase is KEPT in the
    // field so the user can strengthen it in place (the overlay stays open and the
    // calm recovery line is showing). A green phrase materializes + selects.
    ui.on_submit_join({
        let weak = ui.as_weak();
        let state = state.clone();
        let net = net.clone();
        move |text| {
            let ui = weak.unwrap();
            let phrase = text.to_string();
            if !estimate_circle(&phrase).is_circle_green() {
                ui.set_join_phrase_strong(false);
                return; // blocked — keep the overlay + phrase for strengthening
            }
            if materialize_and_select(&ui, &state, &net, &phrase) {
                ui.set_join_open(false);
                ui.set_join_phrase(SharedString::from(""));
                ui.set_join_phrase_strong(false);
            }
        }
    });

    // Submit New: the phrase is generator-strong by construction (132 bits), so no
    // gate — just guard against an empty phrase (a CSPRNG-failure fallback) and
    // materialize founderless.
    ui.on_submit_new({
        let weak = ui.as_weak();
        let state = state.clone();
        let net = net.clone();
        move |text| {
            let ui = weak.unwrap();
            let phrase = text.to_string();
            // The generated default is strong; but the phrase is now EDITABLE, so
            // gate on the same ≥128-bit floor as join — an edited-weak phrase is
            // blocked (the pill is hidden + the recovery line shows), kept for fixing.
            if !estimate_circle(&phrase).is_circle_green() {
                ui.set_new_phrase_strong(false);
                return;
            }
            if materialize_and_select(&ui, &state, &net, &phrase) {
                ui.set_new_open(false);
            }
        }
    });

    // Composer Send / Enter. The Lobby (no circle id) publishes a real sealed
    // public-room message; a materialized circle publishes a real sealed circle
    // message (Round 5 — replaces the round-4 local-echo stub). Both are
    // fire-and-forget; the local echo arrives back as a drained NetEvent
    // (`Message` / `CircleMessage`), so there is ONE render path and no double-add.
    ui.on_send_message({
        let weak = ui.as_weak();
        let state = state.clone();
        let net = net.clone();
        move |text| {
            let text = text.to_string();
            if text.is_empty() {
                return;
            }
            let ui = weak.unwrap();
            match state.borrow().active_circle_id() {
                None => {
                    let _ = net.borrow().send(NetCommand::SendRoom { text });
                }
                Some(circle_id) => {
                    let _ = net
                        .borrow()
                        .send(NetCommand::SendCircle { circle_id, text });
                }
            }
            // Clear the composer + persist the cleared draft into the active circle.
            ui.set_draft(SharedString::from(""));
            let mut st = state.borrow_mut();
            let active = st.active();
            st.set_draft(active, String::new());
        }
    });

    // Initial view = the seed's active circle (the Lobby).
    {
        let st = state.borrow();
        let active = st.active();
        apply_view(&ui, st.current(), active as i32);
    }

    // ── Shares tab: browse-tree callbacks (commit 1) ──
    // Refresh re-lists the relay catalog (Rust reconciles by share_id so open folders
    // survive); opening the tab fires the same refresh. Toggling a row expands or
    // collapses it — a share's first expand lazily fetches its manifest preview.
    ui.on_refresh_shares({
        let net = net.clone();
        move || {
            let _ = net.borrow().send(NetCommand::RefreshShares);
        }
    });
    ui.on_shares_tab_opened({
        let net = net.clone();
        move || {
            let _ = net.borrow().send(NetCommand::RefreshShares);
        }
    });
    ui.on_toggle_share_node({
        let weak = ui.as_weak();
        let net = net.clone();
        let browser = browser.clone();
        move |id| {
            let ui = weak.unwrap();
            let outcome = browser.borrow_mut().toggle(id as u64);
            if let Some(req) = outcome.needs_fetch {
                let _ = net.borrow().send(NetCommand::FetchShare {
                    share_id: req.share_id,
                    name: req.name,
                });
            }
            apply_share_rows(&ui, &browser.borrow());
        }
    });
    // Right-click a node -> resolve its download target -> native folder picker
    // (off-thread) -> ConfirmFetch to the chosen dir (commit 2).
    ui.on_download_node({
        let net = net.clone();
        let browser = browser.clone();
        move |id| {
            let target = browser.borrow().fetch_target(id as u64);
            if let Some(target) = target {
                pick_dir_and_fetch(&net, target);
            }
        }
    });

    // ── Publish (commit 3): the Publish overlay (manage-your-shares surface) ──
    // Open: close the other surfaces (mutual exclusivity), reset the optional name,
    // and refresh the live-shares list so it reflects anything already serving.
    ui.on_open_publish({
        let weak = ui.as_weak();
        let state = state.clone();
        move || {
            let ui = weak.unwrap();
            ui.set_join_open(false);
            ui.set_new_open(false);
            ui.set_palette_open(false);
            ui.set_publish_name(SharedString::from(""));
            ui.set_publish_status(SharedString::from(""));
            apply_my_shares(&ui, &state.borrow());
            ui.set_publish_open(true);
        }
    });
    // Publish: open the native folder picker off-thread; on a chosen folder, publish it
    // under `name` (blank → the folder's basename), self-asserting the unlocked handle
    // so our own share comes back tagged "you". The overlay closes immediately; the
    // outcome arrives as a `PublishStarted` / `PublishError` event.
    ui.on_submit_publish({
        let weak = ui.as_weak();
        let state = state.clone();
        let net = net.clone();
        move |name| {
            let ui = weak.unwrap();
            let sharer_handle = state.borrow().display_handle().unwrap_or_default();
            // Keep the overlay OPEN so the outcome lands somewhere visible: the picker
            // opens over it, then PublishStarted populates "Your live shares" (or
            // PublishError shows the reason). Closing it on submit made a successful
            // publish look like nothing happened.
            ui.set_publish_status(SharedString::from("Opening folder picker…"));
            pick_dir_and_publish(&net, name.to_string(), sharer_handle);
        }
    });
    // First-run desktop integration: register / decline the .desktop + icon. install()
    // is a few small file writes + best-effort cache refresh (synchronous); on success
    // the prompt shows a ✓ then closes after a beat. See desktop_integration.rs.
    ui.on_desktop_integrate({
        let weak = ui.as_weak();
        move || {
            let ui = weak.unwrap();
            match desktop_integration::install() {
                Ok(msg) => {
                    ui.set_desktop_prompt_status(SharedString::from(format!("{msg} ✓")));
                    let w2 = ui.as_weak();
                    slint::Timer::single_shot(Duration::from_millis(1400), move || {
                        if let Some(ui) = w2.upgrade() {
                            ui.set_desktop_prompt_open(false);
                        }
                    });
                }
                Err(e) => {
                    ui.set_desktop_prompt_status(SharedString::from(format!("Couldn't add: {e}")));
                }
            }
        }
    });
    ui.on_desktop_dismiss({
        let weak = ui.as_weak();
        move |remember| {
            let ui = weak.unwrap();
            if remember {
                desktop_integration::mark_declined();
            }
            ui.set_desktop_prompt_open(false);
        }
    });
    // Unpublish a share published this session (owner-scoped, ISC-A-S1). The relay
    // confirms with `PublishStopped`, which drops it from the list + (on next poll) the
    // tree.
    ui.on_unpublish_share({
        let net = net.clone();
        let state = state.clone();
        move |share_id| {
            let id = share_id.to_string();
            // Explicit user Unpublish = "forget this share", so drop its persisted
            // root (M16) — a later reconnect must NOT auto-republish it. PublishStopped
            // drops it from the session list. Forgetting is keyed on the root path.
            let root = state.borrow().share_root(&id);
            if let Some(root) = root {
                let _ = state.borrow_mut().unpersist_published(&root);
            }
            let _ = net
                .borrow()
                .send(NetCommand::UnpublishShare { share_id: id });
        }
    });

    // Action registry: one list, two surfaces (this palette + the rail empty-state
    // mouse-home). New circle / Join a circle now drive the real overlays.
    let actions = vec![
        ActionData {
            label: "Go to Lobby".into(),
            shortcut: "Ctrl+L".into(),
        },
        ActionData {
            label: "New circle".into(),
            shortcut: "Ctrl+N".into(),
        },
        ActionData {
            label: "Join a circle".into(),
            shortcut: "Ctrl+J".into(),
        },
        ActionData {
            // Opens the Shares tab + refreshes the catalog (no keybinding yet).
            label: "Fetch a share".into(),
            shortcut: "".into(),
        },
        ActionData {
            // Opens the About overlay (#59 — version / license / repo readout).
            label: "About daemonseed".into(),
            shortcut: "".into(),
        },
    ];
    ui.set_actions(ModelRc::from(Rc::new(VecModel::from(actions))));

    (ui, state, net, browser)
}

/// Flatten the [`ShareBrowser`] tree into the Slint `[ShareRow]` model and push it to
/// the Shares tab. Called after every refresh / expand / manifest-load.
fn apply_share_rows(ui: &AppWindow, browser: &ShareBrowser) {
    let rows: Vec<ShareRow> = browser
        .rows()
        .into_iter()
        .map(|r| ShareRow {
            id: r.id as i32,
            depth: r.depth as i32,
            label: SharedString::from(r.label),
            size: SharedString::from(r.size),
            kind: match r.kind {
                NodeKind::Share => 0,
                NodeKind::Folder => 1,
                NodeKind::File => 2,
            },
            expandable: r.expandable,
            expanded: r.expanded,
            mine: r.mine,
            loading: r.loading,
        })
        .collect();
    ui.set_share_rows(ModelRc::from(Rc::new(VecModel::from(rows))));
}

/// The publish-status line for a `PublishStarted` event. An auto-republish on
/// connect (`restored`, the M16 restore path) reads as "Restored N share(s) from
/// last session" so it is not mistaken for a fresh user-driven publish; a fresh
/// publish whose write-through persistence failed is surfaced inline. `restored_count`
/// is the number of shares served after this event (the running restore total, which
/// reaches N on the last restored share of a connect).
fn publish_status_line(
    restored: bool,
    name: &str,
    file_count: usize,
    restored_count: usize,
    persist_err: Option<&str>,
) -> String {
    if restored {
        let noun = if restored_count == 1 {
            "share"
        } else {
            "shares"
        };
        format!("Restored {restored_count} {noun} from last session")
    } else if let Some(e) = persist_err {
        format!("Published \u{201c}{name}\u{201d} · served this session only ({e})")
    } else {
        format!("Published \u{201c}{name}\u{201d} · {file_count} file(s)")
    }
}

/// Push the session's published shares (`GuiState::my_shares`) to the Publish overlay's
/// "Your live shares" list. Called whenever that set changes (`PublishStarted` /
/// `PublishStopped`) and when the overlay opens.
fn apply_my_shares(ui: &AppWindow, state: &GuiState) {
    let rows: Vec<MyShareRow> = state
        .my_shares()
        .iter()
        .map(|s| MyShareRow {
            id: SharedString::from(s.id.as_str()),
            name: SharedString::from(s.name.as_str()),
            files: s.files as i32,
        })
        .collect();
    ui.set_my_shares(ModelRc::from(Rc::new(VecModel::from(rows))));
}

/// Handle to the app's long-lived multi-thread runtime (built once at windowed
/// startup, ~`new_multi_thread()` below). The Shares folder pickers run their
/// xdg-portal dialogs on THIS runtime rather than a throwaway per-pick
/// `new_current_thread` runtime: a fresh runtime dropped the instant `block_on`
/// returns abruptly cancels ashpd/zbus connection-cleanup tasks mid-flight, leaking
/// D-Bus connections until a later portal pick hangs (#33). A persistent runtime
/// drives each pick's cleanup to completion. `None` only in offscreen/headless runs,
/// where the pickers aren't reached (publish uses the `DAEMONSEED_PUBLISH_DIR` hatch).
static PICKER_RT: std::sync::OnceLock<tokio::runtime::Handle> = std::sync::OnceLock::new();

/// Open the native folder picker OFF the UI thread and, if a folder is chosen, fire
/// `ConfirmFetch` to it (commit 2). The xdg portal is async over D-Bus; the dialog
/// runs as a task on the app's persistent runtime (`PICKER_RT`), and the destination
/// is dispatched through a cloned `Send` command sender (the `Rc<NetHandle>` can't
/// cross threads). The UI thread never blocks — chat + the download meter stay live
/// while the dialog is open. A cancelled pick, or a system with no portal service,
/// simply does nothing. `flat_dest: true` writes the selection under the chosen dir
/// directly (a single file as its basename; a folder with its ancestors dropped).
fn pick_dir_and_fetch(net: &Rc<RefCell<NetHandle>>, target: FetchTarget) {
    let sender = net.borrow().command_sender();
    let title = format!("Download \u{201c}{}\u{201d} to…", target.name);
    let Some(rt) = PICKER_RT.get() else {
        return;
    };
    rt.spawn(async move {
        let mut dialog = rfd::AsyncFileDialog::new().set_title(title);
        // Default the destination to the OS Downloads folder, not $HOME.
        if let Some(downloads) = dirs::download_dir() {
            dialog = dialog.set_directory(downloads);
        }
        let chosen = dialog
            .pick_folder()
            .await
            .map(|handle| handle.path().to_path_buf());
        if let Some(dir) = chosen {
            let _ = sender.send(NetCommand::ConfirmFetch {
                share_id: target.share_id,
                name: target.name,
                fetched_root: dir,
                selected: target.selected,
                flat_dest: true,
            });
        }
    });
}

/// Open the native folder picker OFF the UI thread and, on a chosen folder, publish it
/// (commit 3) under `name` — or the folder's own basename when `name` is blank. Mirrors
/// [`pick_dir_and_fetch`]: a dedicated thread drives the async xdg portal and dispatches
/// `PublishShare` through the cloned `Send` command sender, so the UI never blocks. A
/// cancelled pick (or a system with no portal) simply does nothing.
fn pick_dir_and_publish(net: &Rc<RefCell<NetHandle>>, name: String, sharer_handle: String) {
    let sender = net.borrow().command_sender();
    // Headless-test escape hatch (private-phase, review before public): this VM's xdg
    // portal picker drops selection clicks and returns the default dir, so set
    // DAEMONSEED_PUBLISH_DIR=<path> to publish that folder directly and exercise the
    // publish→serve→fetch pipeline without the portal. Ignored unless it names a dir.
    if let Ok(dir) = std::env::var("DAEMONSEED_PUBLISH_DIR") {
        let dir = std::path::PathBuf::from(dir.trim());
        if dir.is_dir() {
            let name = if name.trim().is_empty() {
                dir.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "share".to_string())
            } else {
                name
            };
            let _ = sender.send(NetCommand::PublishShare {
                root: dir,
                name,
                sharer_handle,
            });
            return;
        }
    }
    let Some(rt) = PICKER_RT.get() else {
        return;
    };
    rt.spawn(async move {
        let chosen = rfd::AsyncFileDialog::new()
            .set_title("Choose a folder to share…")
            .pick_folder()
            .await
            .map(|handle| handle.path().to_path_buf());
        if let Some(dir) = chosen {
            let name = if name.trim().is_empty() {
                dir.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "share".to_string())
            } else {
                name
            };
            let _ = sender.send(NetCommand::PublishShare {
                root: dir,
                name,
                sharer_handle,
            });
        }
    });
}

/// Re-focus the active auth field after a FAILED attempt (wrong/weak passphrase,
/// mismatch, …) so the user can retry by just typing — essential on hosts where the
/// WM drops pointer clicks (this VM's software-render path), where clicking back into
/// the field to recover focus may never register. Deferred: focusing synchronously
/// from inside the submit callback re-enters the property graph and panics. No-op in
/// offscreen mode (`defer` doesn't fire without an event loop).
fn refocus_auth(ui: &AppWindow) {
    let w = ui.as_weak();
    defer(move || {
        if let Some(ui) = w.upgrade() {
            ui.invoke_focus_auth();
        }
    });
}

/// #39: dispatch keyboard focus to the field appropriate for the CURRENT screen, used
/// when the window regains activation (app-switch) so typing/Enter survive without a
/// click. Always invoked from inside a `defer()` (off the winit event handler), so the
/// `invoke_focus_*` calls here are synchronous — same safe pattern as `refocus_auth`'s
/// deferred body. Desktop-only (the winit hook that calls it is desktop-gated).
#[cfg(feature = "desktop")]
fn refocus_active_field(ui: &AppWindow) {
    match ui.get_screen().as_str() {
        "first-start" | "unlock" => ui.invoke_focus_auth(),
        "main" => {
            if ui.get_join_open() {
                ui.invoke_focus_join_input();
            } else if ui.get_active_tab() == 0 {
                ui.invoke_focus_composer();
            }
            // other tabs / overlays carry no text field that needs keyboard focus
        }
        _ => {}
    }
}

/// Where the last window size is remembered — `<profile-root>/window-size`, a
/// one-line `WIDTHxHEIGHT` (physical px). It lives in the resolved profile root
/// (so a `--portable` / `--config` instance keeps its own size in its own
/// directory, not the shared XDG one), but it is a plain file outside the
/// profile/redb store: a non-secret UI convenience, independent of identity.
#[cfg(feature = "desktop")]
fn window_size_path(profile_root: &std::path::Path) -> std::path::PathBuf {
    profile_root.join("window-size")
}

/// Last saved window size, or None if absent/unparseable/out-of-sane-range. The clamp
/// (≥ the 720x480 min, ≤ 8K) drops an absurd value saved on another monitor so we fall
/// back to the default rather than restore something unusable.
#[cfg(feature = "desktop")]
fn load_window_size(profile_root: &std::path::Path) -> Option<(u32, u32)> {
    let s = std::fs::read_to_string(window_size_path(profile_root)).ok()?;
    let (w, h) = s.trim().split_once('x')?;
    let (w, h) = (w.parse::<u32>().ok()?, h.parse::<u32>().ok()?);
    ((720..=7680).contains(&w) && (480..=4320).contains(&h)).then_some((w, h))
}

/// Persist the window size (best-effort; a missing profile dir is created).
#[cfg(feature = "desktop")]
fn save_window_size(profile_root: &std::path::Path, w: u32, h: u32) {
    let p = window_size_path(profile_root);
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(p, format!("{w}x{h}"));
}

/// Everything the running app must keep alive for its whole lifetime. **If this
/// (or the `Timer` / `NetHandle` inside it) drops, the event drain and the net
/// thread silently die while the build still passes** — so it is held until
/// `ui.run()` returns (windowed) or the offscreen render completes.
struct LiveNet {
    _net: Rc<RefCell<NetHandle>>,
    _timer: Timer,
}

/// Start the [`NetEvent`] drain timer (round 6: this no longer connects — the
/// `Connect` is deferred to [`connect_now`], fired only once an identity is
/// unlocked, so the actor never connects under an ephemeral handle while the auth
/// gate is up). The ~33ms repeated, CAPPED non-blocking loop drains events onto the
/// UI thread for the app's whole life. Returns the [`LiveNet`] owner the caller MUST
/// keep alive (dropping it silently kills the drain + net thread).
fn start_drain(
    ui: &AppWindow,
    state: Rc<RefCell<GuiState>>,
    net: Rc<RefCell<NetHandle>>,
    browser: Rc<RefCell<ShareBrowser>>,
) -> LiveNet {
    let timer = Timer::default();
    {
        let weak = ui.as_weak();
        let state = state.clone();
        let net = net.clone();
        let browser = browser.clone();
        // Comparative-real-time poll counter (caraka 2026-06-16): the share catalog
        // has no relay push (`ListPublicShares` is unary), so liveness = re-list on a
        // cadence. ~90 × 33ms ≈ 3s.
        let mut poll_tick: u32 = 0;
        timer.start(TimerMode::Repeated, Duration::from_millis(33), move || {
            let Some(ui) = weak.upgrade() else { return };
            let mut n = 0u32;
            loop {
                let evt = match net.borrow_mut().try_recv() {
                    Ok(Some(evt)) => evt,
                    Ok(None) => break,
                    Err(()) => {
                        ui.set_connection_status(SharedString::from("offline"));
                        ui.set_connected(false);
                        break;
                    }
                };
                apply_net_event(&ui, &state, &browser, evt);
                n += 1;
                if n > 256 {
                    break;
                }
            }
            // Auto-poll the catalog only while the Shares tab is open AND connected —
            // off-tab / offline is silent (no chatter, no battery cost). The reconcile
            // in `set_shares` keeps the user's open folders across each refresh.
            poll_tick = poll_tick.wrapping_add(1);
            if poll_tick >= 90 {
                poll_tick = 0;
                if ui.get_active_tab() == 1 && ui.get_connected() {
                    let _ = net.borrow().send(NetCommand::RefreshShares);
                }
            }
        });
    }

    LiveNet {
        _net: net,
        _timer: timer,
    }
}

/// Read the system clipboard as text, or `None` if it is unavailable or empty.
/// The reusable clipboard-read plumbing behind right-click paste (#63); a fresh
/// `Clipboard` per call is fine for reads (the X11 ownership caveat only applies
/// to writes).
fn read_clipboard_text() -> Option<String> {
    let text = arboard::Clipboard::new().ok()?.get_text().ok()?;
    if text.is_empty() { None } else { Some(text) }
}

/// Fire the real `Connect` against the running net actor: auto-joins the default
/// public room, presents under the unlocked profile's stable handle (round 6), and
/// silently re-joins its persisted circles once the session is live. Called once an
/// identity is in hand — from the auth-success callbacks (first-start finish /
/// unlock) or, on the offscreen `main` path, directly at startup. On a crypto-init
/// failure the shell still renders; the Lobby just stays offline.
///
/// Auto-republish invariant: every production connection routes through here, and
/// this is the only place `republish_roots` is sourced (`persisted_published()`).
/// There is no mid-session `Reconnect` path today; if one is ever added it MUST go
/// through `connect_now` (or send `NetCommand::Connect` carrying
/// `persisted_published()` as `republish_roots`) — a bare reconnect that omits it
/// silently breaks restore-on-reconnect.
fn connect_now(
    ui: &AppWindow,
    state: &Rc<RefCell<GuiState>>,
    net: &Rc<RefCell<NetHandle>>,
    crypto: &Result<(), String>,
) {
    match crypto {
        Ok(()) => {
            let (server_id, address) = relay_target();
            let (display_handle, rejoin_circles, republish_roots) = {
                let st = state.borrow();
                (
                    st.display_handle(),
                    st.persisted_rejoins(),
                    st.persisted_published()
                        .into_iter()
                        .map(|(root, name)| (PathBuf::from(root), name))
                        .collect::<Vec<_>>(),
                )
            };
            let _ = net.borrow().send(NetCommand::Connect {
                server_id,
                address,
                display_handle,
                rejoin_circles,
                republish_roots,
            });
        }
        Err(reason) => {
            ui.set_connection_status(SharedString::from(format!("offline · {reason}")));
            ui.set_connected(false);
        }
    }
}

/// Apply one [`NetEvent`] to the UI + the Lobby's RAM state + the share browse tree.
fn apply_net_event(
    ui: &AppWindow,
    state: &Rc<RefCell<GuiState>>,
    browser: &Rc<RefCell<ShareBrowser>>,
    evt: NetEvent,
) {
    match evt {
        NetEvent::Connected { server_handle } => {
            ui.set_connection_status(SharedString::from(format!("connected · {server_handle}")));
            ui.set_connected(true);
        }
        NetEvent::RoomJoined { room } => {
            ui.set_connection_status(SharedString::from(format!("connected · {room}")));
            ui.set_connected(true);
        }
        NetEvent::ConnectFailed { reason } | NetEvent::Error { reason } => {
            ui.set_connection_status(SharedString::from(format!("offline · {reason}")));
            ui.set_connected(false);
        }
        // #72: a live connection dropped. The actor already cleared its stale
        // session and (when a connect plan exists, #71) armed auto-reconnect, so
        // the UI just reflects offline + "reconnecting"; no UI-side reconnect is
        // issued (that would double-dial and bypass the actor's backoff).
        NetEvent::Disconnected { reason } => {
            ui.set_connection_status(SharedString::from(format!("reconnecting · {reason}")));
            ui.set_connected(false);
        }
        NetEvent::Message { who, text, mine } => {
            // Always fold the message into the Lobby's RAM state; refresh the
            // visible transcript only when the Lobby is the active circle.
            let mut st = state.borrow_mut();
            let raised = st.push_message(LOBBY, who, text, mine);
            let active = st.active();
            if active == LOBBY {
                apply_view(ui, st.current(), active as i32);
            } else if raised {
                // #64: the Lobby got a message while unfocused — show its dot.
                rebuild_rail(ui, &st);
            }
        }
        NetEvent::CircleJoined {
            circle_id,
            asset_addr,
        } => {
            // The circle is already in the rail (materialized locally) and its
            // subscription is now live with a known relay rendezvous. Upgrade its
            // pre-join `#<hex>` placeholder to the stable relay-derived adj-noun label
            // and fill the net contract's rendezvous slot (ISC-C62), then refresh the
            // rail (and the header if it is the active circle).
            let mut st = state.borrow_mut();
            if let Some(idx) = st.set_circle_rendezvous(circle_id, asset_addr) {
                rebuild_rail(ui, &st);
                if st.active() == idx {
                    apply_view(ui, st.current(), idx as i32);
                }
            }
        }
        NetEvent::CircleMessage {
            circle_id,
            who,
            text,
            mine,
        } => {
            // Route by the GUI-assigned circle_id → rail index. Always fold into
            // that circle's RAM state; refresh the transcript only when it's active.
            let mut st = state.borrow_mut();
            if let Some(idx) = st.index_of_circle_id(circle_id) {
                let raised = st.push_message(idx, who, text, mine);
                let active = st.active();
                if active == idx {
                    apply_view(ui, st.current(), active as i32);
                } else if raised {
                    // #64: a circle got a message while unfocused — show its dot.
                    rebuild_rail(ui, &st);
                }
            }
        }
        NetEvent::CircleError { circle_id, reason } => {
            // Non-fatal (the connection may still be up). Surface on the status
            // line for felt-test diagnostics; no per-circle status surface yet.
            let _ = circle_id;
            ui.set_connection_status(SharedString::from(format!("circle: {reason}")));
        }
        // ── Shares: browse tree (commit 1) ──
        // SharesSnapshot + FetchManifest drive the Shares-tab tree. Publish events and
        // fetch progress/complete stay stubbed — publish is commit 3 (overlay), the
        // download progress meter is commit 2. The fields stay bound (not `..`) so the
        // data path is a compile-checked contract for those commits to consume.
        NetEvent::SharesSnapshot { shares } => {
            // commit 3: tag our own shares "you" by matching the relay's self-asserted
            // sharer_handle against our unlocked display handle (`None` on the ephemeral
            // path → nothing tagged, the empty-handle guard in `set_shares`).
            let my_handle = state.borrow().display_handle();
            {
                let mut b = browser.borrow_mut();
                b.set_shares(
                    shares.iter().map(|s| {
                        (
                            s.share_id.as_str(),
                            s.name.as_str(),
                            s.sharer_handle.as_str(),
                        )
                    }),
                    my_handle.as_deref(),
                );
            }
            apply_share_rows(ui, &browser.borrow());
            ui.set_share_status(SharedString::from("")); // clear any prior error
        }
        NetEvent::SharesError { message } => {
            ui.set_share_status(SharedString::from(message));
        }
        NetEvent::FetchManifest {
            share_id,
            name,
            entries,
        } => {
            let _ = name; // the tree already holds the share's name from the listing
            {
                // The manifest's order is the share's canonical file order — the index
                // commit 2's `ConfirmFetch { selected }` will key on.
                let rows: Vec<ManifestRow> = entries
                    .iter()
                    .enumerate()
                    .map(|(index, e)| ManifestRow {
                        rel_path: e.rel_path.clone(),
                        size: e.size,
                        index,
                    })
                    .collect();
                browser.borrow_mut().load_manifest(&share_id, &rows);
            }
            apply_share_rows(ui, &browser.borrow());
        }
        // Publish (commit 3): keep the session's live-shares list in sync + surface a
        // quiet status line. The own share also appears in the browse tree tagged "you"
        // on the next ~3s catalog poll (the relay re-list folds it in via `set_shares`).
        NetEvent::PublishStarted {
            share_id,
            name,
            file_count,
            root,
            restored,
        } => {
            // M16 write-through: remember this root so it auto-republishes next launch
            // (idempotent). A persistence failure is non-fatal — the share still serves
            // this session; surface it quietly like the circle write-through does.
            let persist_err = {
                let mut st = state.borrow_mut();
                st.add_my_share(share_id, name.clone(), file_count, root.clone());
                st.persist_published(&root).err()
            };
            apply_my_shares(ui, &state.borrow());
            // An auto-republish on connect reads as "Restored N shares…" rather than a
            // per-share "Published …" so it is not mistaken for a fresh publish.
            let restored_count = state.borrow().my_shares().len();
            let msg = publish_status_line(
                restored,
                &name,
                file_count,
                restored_count,
                persist_err.as_deref(),
            );
            ui.set_publish_status(SharedString::from(msg.clone()));
            ui.set_share_status(SharedString::from(msg.clone()));
            // Felt-test 2026-06-21: a restore must be visible from the Chat landing
            // view, not Shares-tab-only (share-status). Tab-independent banner shows
            // "Restored N shares…" wherever the user lands, then auto-dismisses after a
            // brief read (effortless motif: comes and goes on startup). 6s sits in the
            // GNOME toast / Material Snackbar-LONG range for a short informational line.
            // The ✕ still allows an early manual dismiss.
            if restored {
                ui.set_connect_notice(SharedString::from(msg));
                let ui_weak = ui.as_weak();
                slint::Timer::single_shot(Duration::from_secs(6), move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_connect_notice(SharedString::from(""));
                    }
                });
            }
        }
        // PublishStopped fires on user unpublish, session end, AND relay reap — so it
        // only drops the session list; it must NOT forget the persisted root (that
        // would defeat auto-republish on a reconnect). Forgetting is done on the
        // explicit user Unpublish action (`on_unpublish_share`).
        NetEvent::PublishStopped { share_id } => {
            state.borrow_mut().remove_my_share(&share_id);
            apply_my_shares(ui, &state.borrow());
        }
        NetEvent::PublishError { message } => {
            let msg = format!("Publish failed: {message}");
            ui.set_publish_status(SharedString::from(msg.clone()));
            ui.set_share_status(SharedString::from(msg));
        }
        // Download meter (commit 2): a simple label + fraction bar in the rail footer.
        NetEvent::FetchProgress {
            total_chunks,
            chunks_received,
            bytes_received,
        } => {
            let _ = bytes_received;
            let pct = match total_chunks {
                Some(total) if total > 0 => chunks_received as f32 / total as f32,
                _ => 0.0,
            };
            ui.set_download_progress(pct);
            ui.set_download_label(SharedString::from(format!(
                "Downloading… {}%",
                (pct * 100.0) as u32
            )));
        }
        NetEvent::FetchComplete {
            share_id,
            files_written,
            bytes_written,
        } => {
            let _ = (share_id, bytes_written);
            ui.set_download_progress(1.0);
            let msg = format!(
                "Downloaded {files_written} file{}",
                if files_written == 1 { "" } else { "s" }
            );
            ui.set_download_label(SharedString::from(msg.clone()));
            // The completed-download banner is informational — auto-dismiss it
            // after a generous read so it doesn't linger (the user often steps
            // away mid-download). Guard on the label being unchanged so a newer
            // download's banner isn't wiped by this stale timer (#55). Failed
            // downloads (FetchError) are left up deliberately — don't hide a
            // failure on a timer.
            let ui_weak = ui.as_weak();
            slint::Timer::single_shot(Duration::from_secs(30), move || {
                if let Some(ui) = ui_weak.upgrade()
                    && ui.get_download_label().as_str() == msg
                {
                    ui.set_download_label(SharedString::from(""));
                    ui.set_download_progress(0.0);
                }
            });
        }
        // FetchError covers a failed download AND a failed preview (the variant carries
        // no share_id to disambiguate). Surface it on the meter as the unified fetch
        // status; SharesError (catalog refresh) stays on the tree's status line.
        NetEvent::FetchError { message } => {
            ui.set_download_progress(0.0);
            ui.set_download_label(SharedString::from(format!("Download failed: {message}")));
        }
        // Test-only probe (net.rs in-process oracle); never produced in a running
        // binary, so it carries no UI effect.
        #[cfg(test)]
        NetEvent::ConnectedProbe { .. } => {}
    }
}

/// Render the shell offscreen to a PNG (headless-verifiable).
fn render_png(window: &Rc<MinimalSoftwareWindow>, path: &str) {
    let mut buf = vec![Rgb565Pixel(0); (W * H) as usize];
    let mut drawn = false;
    for _ in 0..3 {
        CLOCK.with(|c| c.set(c.get() + Duration::from_millis(16)));
        slint::platform::update_timers_and_animations();
        window.draw_if_needed(|r| {
            r.render(&mut buf, W as usize);
            drawn = true;
        });
    }
    assert!(drawn, "renderer never drew a frame");

    let mut img = image::RgbImage::new(W, H);
    for (i, px) in buf.iter().enumerate() {
        let x = i as u32 % W;
        let y = i as u32 / W;
        let v = px.0;
        let r = (((v >> 11) & 0x1f) as u32 * 255 + 15) / 31;
        let g = (((v >> 5) & 0x3f) as u32 * 255 + 31) / 63;
        let b = ((v & 0x1f) as u32 * 255 + 15) / 31;
        img.put_pixel(x, y, image::Rgb([r as u8, g as u8, b as u8]));
    }
    img.save(path)
        .unwrap_or_else(|e| panic!("save {path}: {e}"));
    println!("daemonseed-gui: wrote {path} ({W}x{H}, software renderer)");
}

/// Live materialize + draft-retention round-trip through the REAL callbacks
/// (asserts at the UI-property level). Proves a circle materializes from a phrase
/// AND its draft survives a switch end-to-end. Panics on failure (→ non-zero exit).
fn self_check(ui: &AppWindow, state: &Rc<RefCell<GuiState>>, net: &Rc<RefCell<NetHandle>>) {
    const SENTINEL: &str = "SENTINEL-DRAFT";
    // A genuinely-strong phrase (12 distinct BIP-39 words) so the join gate is moot.
    const PHRASE: &str =
        "abandon ability able about above absent absorb abstract absurd abuse access accident";

    assert!(
        materialize_and_select(ui, state, net, PHRASE),
        "materialize failed in self-check"
    );
    let circle = ui.get_active();
    assert_eq!(circle, 1, "materialized circle should be active at index 1");

    // Type into the circle, switch to the Lobby and back; the draft must survive.
    ui.set_draft(SENTINEL.into());
    ui.invoke_switch_circle(LOBBY as i32);
    ui.invoke_switch_circle(circle);

    let got = ui.get_draft();
    assert_eq!(
        got.as_str(),
        SENTINEL,
        "draft not retained across materialized-circle switch: got {got:?}"
    );
    println!("SELF-CHECK PASS");
}

/// Enter the main shell from an authenticated state: refresh the rail (it may now
/// hold restored circles), drop the auth gate, connect under the identity, and
/// autofocus the composer.
///
/// The whole body is DEFERRED off the triggering callback. The auth-success paths
/// fire from a field's `accepted` (Enter) or a button `clicked` handler that lives
/// INSIDE the `if screen == …` / `if fs-step == …` subtree. Flipping `screen` to
/// "main" tears that subtree down — including the element whose event we are still
/// inside — which re-enters the partial_renderer and panics with "RefCell already
/// borrowed" (partial_renderer.rs:818), the same footgun as toggling an `if` during
/// a text edit. A 0ms single-shot runs the teardown after the event fully unwinds.
fn enter_main(
    ui: &AppWindow,
    state: &Rc<RefCell<GuiState>>,
    net: &Rc<RefCell<NetHandle>>,
    crypto: &Result<(), String>,
) {
    let ui_weak = ui.as_weak();
    let state = state.clone();
    let net = net.clone();
    let crypto = crypto.clone();
    defer(move || {
        let Some(ui) = ui_weak.upgrade() else { return };
        rebuild_rail(&ui, &state.borrow());
        ui.set_screen(SharedString::from("main"));
        connect_now(&ui, &state, &net, &crypto);
        let w = ui.as_weak();
        defer(move || {
            if let Some(ui) = w.upgrade() {
                ui.invoke_focus_composer();
            }
        });
    });
}

/// Change the first-start wizard step, DEFERRED off the triggering callback. A step
/// change swaps which `if fs-step == N` subtree is mounted; doing that synchronously
/// from inside a field/button handler in the OUTGOING subtree re-enters the
/// partial_renderer (see [`enter_main`]). The 0ms single-shot defers it safely.
fn defer_set_fs_step(ui: &AppWindow, step: i32) {
    let w = ui.as_weak();
    defer(move || {
        if let Some(ui) = w.upgrade() {
            ui.set_fs_step(step);
            // Focus the new step's entry field on arrival. focus-auth reads the
            // just-set fs-step and is a no-op for the read-only mnemonic step and
            // in offscreen mode. Already inside a defer, so reading the freshly-set
            // property is safe (no synchronous property-graph re-entry).
            ui.invoke_focus_auth();
        }
    });
}

/// Wire the round-6 auth callbacks: the first-start wizard (passphrase → mnemonic →
/// round-trip confirm → name) and the daily-login Unlock. The `FirstStart` machine
/// lives in `wizard`; the profile root to write / read lives in `profile_root`. On
/// success each path adopts the profile and enters the shell via [`enter_main`].
fn wire_auth(
    ui: &AppWindow,
    state: &Rc<RefCell<GuiState>>,
    net: &Rc<RefCell<NetHandle>>,
    crypto: Result<(), String>,
    wizard: Rc<RefCell<Wizard>>,
    challenge: Rc<RefCell<Option<TypeBackChallenge>>>,
    profile_root: Rc<RefCell<PathBuf>>,
) {
    // Live (hidden) passphrase strength against the session floor (ISC-C12).
    ui.on_fs_passphrase_edited({
        let weak = ui.as_weak();
        move |text| {
            let ui = weak.unwrap();
            ui.set_fs_passphrase_strong(estimate(text.as_str()).is_session_green());
        }
    });

    // Step 0 → 1: FirstStart::initialize gates strength + generates the mnemonic.
    ui.on_fs_passphrase_next({
        let weak = ui.as_weak();
        let wizard = wizard.clone();
        move || {
            let ui = weak.unwrap();
            let pass = ui.get_fs_passphrase().to_string();
            // Confirm the re-entry matches BEFORE sealing — there is no recovery flow
            // yet, so an unnoticed typo here would lock this identity out permanently.
            let confirm = ui.get_fs_passphrase_confirm().to_string();
            if pass != confirm {
                ui.set_auth_error(SharedString::from(
                    "Those don't match — type the same passphrase in both boxes.",
                ));
                refocus_auth(&ui);
                return;
            }
            match FirstStart::new().initialize(pass.as_str(), ArgonParams::default()) {
                Ok(sealed) => {
                    ui.set_fs_mnemonic(SharedString::from(sealed.display_phrase()));
                    *wizard.borrow_mut() = Wizard::Sealed(sealed);
                    ui.set_auth_error(SharedString::from(""));
                    defer_set_fs_step(&ui, 1);
                }
                Err(FirstStartError::PassphraseTooWeak { .. }) => {
                    ui.set_auth_error(SharedString::from(
                        "That passphrase is too easy to guess — add a few more words.",
                    ));
                    refocus_auth(&ui);
                }
                Err(e) => {
                    ui.set_auth_error(SharedString::from(format!("Couldn't create identity: {e}")));
                    refocus_auth(&ui);
                }
            }
        }
    });

    // Step 1 → 2: "I've saved it" — issue a fresh C34 type-back challenge from the
    // sealed mnemonic (3 words by position), then advance + focus the field.
    ui.on_fs_saved_next({
        let weak = ui.as_weak();
        let wizard = wizard.clone();
        let challenge = challenge.clone();
        move || {
            let ui = weak.unwrap();
            ui.set_auth_error(SharedString::from(""));
            ui.set_fs_confirm_1(SharedString::from(""));
            ui.set_fs_confirm_2(SharedString::from(""));
            ui.set_fs_confirm_3(SharedString::from(""));
            if let Wizard::Sealed(s) = &*wizard.borrow() {
                let ch = s.issue_type_back_challenge(&mut OsRng);
                ui.set_fs_typeback_prompt(SharedString::from(typeback_prompt(&ch)));
                *challenge.borrow_mut() = Some(ch);
            }
            defer_set_fs_step(&ui, 2);
        }
    });

    // Step 2 → 3 (C34 type-back): pre-check the 3 answers against the held mnemonic
    // + challenge positions; only the matching path invokes the consuming
    // `verify_type_back`. A wrong answer re-issues a fresh challenge (per the core's
    // per-attempt contract) and keeps the Sealed state, so the user can retry.
    ui.on_fs_confirm_next({
        let weak = ui.as_weak();
        let wizard = wizard.clone();
        let challenge = challenge.clone();
        move || {
            let ui = weak.unwrap();
            // One challenge word per field (ISC-C34); trim stray whitespace. An
            // empty field yields an empty answer, which fails the precheck.
            let answers: Vec<String> = [
                ui.get_fs_confirm_1(),
                ui.get_fs_confirm_2(),
                ui.get_fs_confirm_3(),
            ]
            .iter()
            .map(|w| w.trim().to_owned())
            .collect();
            let mnemonic = ui.get_fs_mnemonic().to_string();

            let passed = challenge
                .borrow()
                .as_ref()
                .is_some_and(|ch| type_back_precheck(ch, &mnemonic, &answers));

            if !passed {
                // Re-issue a fresh challenge (keeps the Sealed state intact).
                if let Wizard::Sealed(s) = &*wizard.borrow() {
                    let ch = s.issue_type_back_challenge(&mut OsRng);
                    ui.set_fs_typeback_prompt(SharedString::from(typeback_prompt(&ch)));
                    *challenge.borrow_mut() = Some(ch);
                }
                ui.set_fs_confirm_1(SharedString::from(""));
                ui.set_fs_confirm_2(SharedString::from(""));
                ui.set_fs_confirm_3(SharedString::from(""));
                ui.set_auth_error(SharedString::from(
                    "Those words don't match — here's a new set to try.",
                ));
                refocus_auth(&ui);
                return;
            }

            let sealed = wizard.borrow_mut().take_sealed();
            let ch = challenge.borrow_mut().take();
            let (Some(sealed), Some(ch)) = (sealed, ch) else {
                ui.set_auth_error(SharedString::from(
                    "Enrollment state lost — please start over.",
                ));
                defer_set_fs_step(&ui, 0);
                return;
            };
            match sealed.verify_type_back(ch, &answers) {
                Ok(verified) => {
                    *wizard.borrow_mut() = Wizard::Verified(verified);
                    ui.set_auth_error(SharedString::from(""));
                    defer_set_fs_step(&ui, 3);
                }
                Err(_) => {
                    // Pre-check passed but core rejected — should be unreachable; the
                    // Sealed state is now consumed, so restart enrollment cleanly.
                    ui.set_auth_error(SharedString::from(
                        "Couldn't verify the phrase — please start over.",
                    ));
                    defer_set_fs_step(&ui, 0);
                }
            }
        }
    });

    // Step 3 finish: finalize with the display name, persist the profile, enter.
    ui.on_fs_finish({
        let weak = ui.as_weak();
        let wizard = wizard.clone();
        let state = state.clone();
        let net = net.clone();
        let crypto = crypto.clone();
        let profile_root = profile_root.clone();
        move |name| {
            let ui = weak.unwrap();
            let name = name.to_string();
            if name.trim().is_empty() {
                ui.set_auth_error(SharedString::from("Pick a name others will see."));
                refocus_auth(&ui); // stay on the name field so the user can retry by typing
                return;
            }
            let Some(verified) = wizard.borrow_mut().take_verified() else {
                ui.set_auth_error(SharedString::from(
                    "Enrollment state lost — please start over.",
                ));
                defer_set_fs_step(&ui, 0);
                return;
            };
            let (server_id, address) = relay_target();
            let bootstrap = BootstrapAnchor { server_id, address };
            let ready = match verified.finalize(Some(name), bootstrap) {
                Ok(r) => r,
                Err(e) => {
                    ui.set_auth_error(SharedString::from(format!("Couldn't finish: {e}")));
                    defer_set_fs_step(&ui, 0); // verified consumed — restart
                    return;
                }
            };
            let materials = ready.into_session_materials();
            let root = profile_root.borrow().clone();
            if let Err(e) = write_first_start(&root, &materials, None, false) {
                // Do NOT enter the shell without a persisted profile.
                ui.set_auth_error(SharedString::from(format!(
                    "Couldn't save your profile: {e}"
                )));
                refocus_auth(&ui); // stay on the name step so the user can retry
                return;
            }
            state
                .borrow_mut()
                .set_profile(Profile::from_materials(materials, root));
            ui.set_auth_error(SharedString::from(""));
            enter_main(&ui, &state, &net, &crypto);
        }
    });

    // Daily-login Unlock: open the blob under the passphrase, restore, enter.
    ui.on_unlock_submit({
        let weak = ui.as_weak();
        let state = state.clone();
        let net = net.clone();
        let crypto = crypto.clone();
        let profile_root = profile_root.clone();
        move |pass| {
            let ui = weak.unwrap();
            let pass = pass.to_string();
            let root = profile_root.borrow().clone();
            let (config, blob) = match load_for_unlock(&root) {
                Ok(x) => x,
                Err(e) => {
                    ui.set_auth_error(SharedString::from(format!("Couldn't read profile: {e}")));
                    refocus_auth(&ui);
                    return;
                }
            };
            let opened = match seeds::open(&blob, &pass, config.profile_id, config.argon2) {
                Ok(o) => o,
                Err(seeds::BlobError::AuthenticationFailed) => {
                    ui.set_auth_error(SharedString::from("Wrong passphrase."));
                    // Clear the (masked) field so the user retypes from a known-empty
                    // start — no cursor stranded at the end of invisible text.
                    ui.set_unlock_passphrase(SharedString::from(""));
                    refocus_auth(&ui);
                    return;
                }
                Err(e) => {
                    ui.set_auth_error(SharedString::from(format!("Couldn't unlock: {e}")));
                    refocus_auth(&ui);
                    return;
                }
            };
            let materials = match session_materials_from_unlock(
                opened.seeds,
                opened.key,
                opened.index_key,
                config,
                blob.clone(),
                Vec::new(),
            ) {
                Ok(m) => m,
                Err(e) => {
                    ui.set_auth_error(SharedString::from(format!(
                        "Couldn't restore identity: {e}"
                    )));
                    refocus_auth(&ui);
                    return;
                }
            };
            state
                .borrow_mut()
                .set_profile(Profile::from_materials(materials, root));
            ui.set_auth_error(SharedString::from(""));
            ui.set_unlock_passphrase(SharedString::from(""));
            enter_main(&ui, &state, &net, &crypto);
        }
    });
}

/// Resolve the profile location and route the opening screen: an existing profile →
/// Unlock, none → the first-start wizard. Stashes the chosen root in `profile_root`
/// for the auth callbacks. Only the windowed (`desktop`) path routes at startup; the
/// offscreen build sets screens directly via flags, so this is unused there.
#[cfg_attr(not(feature = "desktop"), allow(dead_code))]
fn route_startup(ui: &AppWindow, profile_root: &Rc<RefCell<PathBuf>>, portable: bool) {
    match resolve(ResolveArgs {
        config_flag: None,
        portable,
    }) {
        Ok(ResolvedProfileRoot::Existing { root, .. }) => {
            *profile_root.borrow_mut() = root;
            ui.set_screen(SharedString::from("unlock"));
        }
        Ok(ResolvedProfileRoot::FirstStart { default_root }) => {
            *profile_root.borrow_mut() = default_root;
            ui.set_screen(SharedString::from("first-start"));
            ui.set_fs_step(0);
        }
        Err(e) => {
            ui.set_screen(SharedString::from("first-start"));
            ui.set_fs_step(0);
            ui.set_auth_error(SharedString::from(format!(
                "Using a default profile location ({e})."
            )));
        }
    }
    // Focus the active auth field, DEFERRED off this startup path (focusing during
    // construction re-enters Slint's property graph and panics; a 0ms single-shot
    // runs it once the window is live — the same pattern as the join-input focus).
    let w = ui.as_weak();
    defer(move || {
        if let Some(ui) = w.upgrade() {
            ui.invoke_focus_auth();
        }
    });
}

/// A fixed sample recovery phrase for offscreen rendering of the wizard's mnemonic /
/// confirm steps (never used at runtime — the real mnemonic comes from FirstStart).
const SAMPLE_MNEMONIC: &str = "abandon ability able about above absent absorb abstract \
absurd abuse access accident account accuse achieve acid acoustic acquire across act \
action actor actress actual";

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // X11 opt-in (`DAEMONSEED_X11=1` or `--x11`): force winit onto XWayland by
    // unsetting WAYLAND_DISPLAY before Slint initializes its backend (winit 0.30's
    // Wayland pointer path drops button events under VM software rendering).
    let force_x11 = std::env::var("DAEMONSEED_X11").is_ok_and(|v| v == "1" || v == "true")
        || args.iter().any(|a| a == "--x11");
    if force_x11 {
        // SAFETY: top of `main`, before any thread spawns or backend init.
        unsafe { std::env::remove_var("WAYLAND_DISPLAY") };
    }

    // Headless desktop-integration management (scriptable; the same work the first-run
    // prompt does interactively). These register/remove the .desktop + icon and exit
    // without opening a window.
    if args.iter().any(|a| a == "--install") {
        match desktop_integration::install() {
            Ok(m) => {
                println!("{m}");
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("desktop integration failed: {e}");
                std::process::exit(1);
            }
        }
    }
    if args.iter().any(|a| a == "--remove") {
        match desktop_integration::remove() {
            Ok(m) => {
                println!("{m}");
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("desktop integration removal failed: {e}");
                std::process::exit(1);
            }
        }
    }

    let mut screenshot: Option<String> = None;
    let mut switch: Option<i32> = None;
    let mut scroll: Option<f32> = None;
    let mut materialize: Option<String> = None;
    let mut fs_step_flag: i32 = 0;
    let self_check_requested = args.iter().any(|a| a == "--self-check");
    let show_join = args.iter().any(|a| a == "--show-join");
    let show_new = args.iter().any(|a| a == "--show-new");
    let show_palette = args.iter().any(|a| a == "--show-palette");
    let show_about = args.iter().any(|a| a == "--show-about");
    let show_unread = args.iter().any(|a| a == "--show-unread");
    let show_tab_coherence = args.iter().any(|a| a == "--show-tab-coherence");
    // ISC-C62 proof: materialize a circle then apply a synthetic relay rendezvous so
    // the rail shows the relay-derived adj-noun label instead of the `#<hex>`
    // placeholder (the live path runs on the CircleJoined event, which needs a relay).
    let show_joined_label = args.iter().any(|a| a == "--joined-label");
    // Offscreen fixture render of the populated Shares-tab browse tree (no relay):
    // injects a synthetic catalog + one expanded/previewed share so the PNG shows the
    // tree without a live connection.
    let show_shares = args.iter().any(|a| a == "--show-shares");
    let show_publish = args.iter().any(|a| a == "--show-publish");
    let show_desktop_prompt = args.iter().any(|a| a == "--show-desktop-prompt");
    // Round-6 routing: `--portable` resolves the profile under CWD (else XDG).
    // `--first-start [step]` / `--unlock` are OFFSCREEN-only render flags for the
    // new auth screens (windowed routing always uses `resolve`). `portable` feeds
    // the windowed `route_startup`, so it's only read under the `desktop` feature.
    #[cfg_attr(not(feature = "desktop"), allow(unused_variables))]
    let portable = args.iter().any(|a| a == "--portable");
    let first_start_flag = args.iter().any(|a| a == "--first-start");
    let unlock_flag = args.iter().any(|a| a == "--unlock");
    for w in args.windows(2) {
        match w[0].as_str() {
            "--screenshot" => screenshot = Some(w[1].clone()),
            "--switch" => switch = w[1].parse().ok(),
            "--scroll" => scroll = w[1].parse().ok(),
            "--materialize" => materialize = Some(w[1].clone()),
            "--first-start" => fs_step_flag = w[1].parse().unwrap_or(0),
            _ => {}
        }
    }
    // `offscreen` decides windowed vs offscreen under the `desktop` feature; absent
    // it the build is always offscreen, so silence the lint there.
    #[cfg_attr(not(feature = "desktop"), allow(unused_variables))]
    let offscreen = screenshot.is_some()
        || switch.is_some()
        || scroll.is_some()
        || materialize.is_some()
        || show_join
        || show_new
        || show_palette
        || show_about
        || show_unread
        || show_tab_coherence
        || show_joined_label
        || show_shares
        || show_publish
        || show_desktop_prompt
        || first_start_flag
        || unlock_flag
        || self_check_requested;

    // Bring up crypto before any Connect OR any materialize (derive_cot_key). A
    // failure is non-fatal to the SHELL (the UI still renders); the lobby just
    // stays offline. Always init now (self-check materializes, so it needs it too).
    let crypto = init_crypto();

    // Round-6 auth state, shared into the wizard/unlock callbacks: the FirstStart
    // machine and the profile root to write/read.
    let wizard = Rc::new(RefCell::new(Wizard::Empty));
    // The current C34 type-back challenge (3 word positions), issued on entry to the
    // confirm step and re-issued per failed attempt.
    let challenge: Rc<RefCell<Option<TypeBackChallenge>>> = Rc::new(RefCell::new(None));
    let profile_root = Rc::new(RefCell::new(PathBuf::new()));

    #[cfg(feature = "desktop")]
    if !offscreen {
        // Slint's winit backend opens a zbus connection on THIS (main) thread to watch
        // the xdg Settings portal (dark-mode / accent — `spawn_xdg_settings_watcher`).
        // zbus is forced onto its *tokio* executor here: the Shares-tab folder picker
        // pulls `rfd` → `ashpd`, which depends on `zbus` with its `tokio` default, and
        // Cargo feature-unification applies that to Slint's `zbus` too. A tokio-executor
        // zbus connect calls `spawn_blocking`, which panics ("there is no reactor
        // running") unless the calling thread has an ambient tokio runtime. The event
        // loop blocks the main thread, so a current-thread runtime can't drive zbus's
        // tasks — enter a MULTI-thread runtime for the loop's lifetime so its worker +
        // blocking pools service Slint's settings-watcher connection. (Without this the
        // windowed app panics at startup the moment rfd is in the dependency graph.)
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("build main-thread tokio runtime for Slint's zbus settings watcher");
        let _rt_guard = rt.enter();
        // The Shares folder pickers run their xdg-portal dialogs on this long-lived
        // runtime instead of a throwaway per-pick one (#33). Set before any UI wiring
        // so the first pick already has it.
        let _ = PICKER_RT.set(rt.handle().clone());
        let (ui, state, net, browser) = build_ui();
        wire_auth(
            &ui,
            &state,
            &net,
            crypto.clone(),
            wizard.clone(),
            challenge.clone(),
            profile_root.clone(),
        );
        // The drain timer runs for the whole app life; the Connect is deferred to
        // the auth-success callbacks (no connecting under the auth gate).
        let _live = start_drain(&ui, state, net, browser);
        route_startup(&ui, &profile_root, portable);
        // First-run: offer to self-register the .desktop + icon (AppImage only, not yet
        // integrated, not declined). The overlay defers itself to the main screen.
        ui.set_desktop_prompt_open(desktop_integration::should_prompt());
        // #39: re-grab keyboard focus when the window regains activation, so input
        // survives an app-switch. Slint exposes no window `active` property to .slint,
        // so this lives at the winit backend. defer() the refocus off the event handler
        // to avoid re-entering the focus machinery synchronously.
        {
            use i_slint_backend_winit::winit::event::WindowEvent;
            use i_slint_backend_winit::{EventResult, WinitWindowAccessor};
            // Restore the last window size (size only — the WM constrains an oversized
            // value, and omitting position avoids landing off-screen on a different
            // monitor; load_window_size() sanity-clamps absurd values).
            if let Some((w, h)) = load_window_size(&profile_root.borrow()) {
                ui.window().set_size(slint::PhysicalSize::new(w, h));
            } else {
                // No saved size yet (fresh identity): winit does not reliably honour
                // the .slint preferred-width/height on first map, so the window comes
                // up square. Apply the design default explicitly. LOGICAL px keeps it
                // DPI-independent (the restore branch above uses physical because
                // winit's Resized event reports physical px).
                ui.window()
                    .set_size(slint::LogicalSize::new(W as f32, H as f32));
            }
            let weak = ui.as_weak();
            // Latest size, persisted once on close (one write per session, no disk churn
            // during a drag-resize). The size follows the resolved profile root, so a
            // --portable / --config instance saves into its own directory, not XDG.
            let last_size = std::rc::Rc::new(std::cell::Cell::new(None::<(u32, u32)>));
            let ws_root = profile_root.clone();
            ui.window().on_winit_window_event(move |_w, event| {
                match event {
                    // #39: re-grab keyboard focus on activation so input survives an
                    // app-switch. defer() off the handler to avoid re-entering the focus
                    // machinery synchronously.
                    WindowEvent::Focused(true) => {
                        let weak = weak.clone();
                        defer(move || {
                            if let Some(ui) = weak.upgrade() {
                                refocus_active_field(&ui);
                            }
                        });
                    }
                    WindowEvent::Resized(sz) => last_size.set(Some((sz.width, sz.height))),
                    WindowEvent::CloseRequested => {
                        if let Some((w, h)) = last_size.get() {
                            save_window_size(&ws_root.borrow(), w, h);
                        }
                    }
                    _ => {}
                }
                EventResult::Propagate
            });
        }
        ui.run().expect("run windowed");
        return;
    }

    // Offscreen software platform — needed for invoke/get/set even when no PNG is
    // produced (--self-check still needs the platform + AppWindow).
    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    slint::platform::set_platform(Box::new(GuiPlatform {
        window: window.clone(),
    }))
    .expect("set_platform");
    let (ui, state, net, browser) = build_ui();
    wire_auth(
        &ui,
        &state,
        &net,
        crypto.clone(),
        wizard.clone(),
        challenge.clone(),
        profile_root.clone(),
    );
    ui.show().expect("show");
    window.set_size(slint::PhysicalSize::new(W, H));

    if self_check_requested {
        self_check(&ui, &state, &net);
        return;
    }

    // Keep the drain alive until the render completes (offscreen renders frames
    // synchronously; the net thread is harmless either way).
    let mut _live: Option<LiveNet> = None;

    if first_start_flag {
        // Render a wizard step (no networking). Steps ≥1 need a phrase to show.
        ui.set_screen(SharedString::from("first-start"));
        ui.set_fs_step(fs_step_flag);
        if fs_step_flag >= 1 {
            ui.set_fs_mnemonic(SharedString::from(SAMPLE_MNEMONIC));
        }
        if fs_step_flag == 2 {
            // The live prompt is issued by fs_saved_next, which a direct step-set
            // bypasses — seed a representative C34 prompt so the PNG shows the step.
            ui.set_fs_typeback_prompt(SharedString::from(
                "Type words #4, #12 and #22 of your recovery phrase.",
            ));
            // Seed the three single-word type-back boxes so the PNG shows the
            // populated 3-field layout (ISC-C34); an over-long word in the first
            // box still exercises the per-box clip.
            ui.set_fs_confirm_1(SharedString::from("becomeunknowncallupperexecute"));
            ui.set_fs_confirm_2(SharedString::from("grit"));
            ui.set_fs_confirm_3(SharedString::from("real"));
        }
        if fs_step_flag == 0 {
            // Seed a passphrase + a deliberately MISMATCHED confirm, then drive the
            // real next-callback so the PNG proves the confirm guard blocks (auth-error
            // shown, no advance / no sealing on a mismatch).
            ui.set_fs_passphrase(SharedString::from("correct horse battery staple"));
            ui.set_fs_passphrase_confirm(SharedString::from("correct horse battery stapler"));
            ui.invoke_fs_passphrase_next();
        }
    } else if unlock_flag {
        ui.set_screen(SharedString::from("unlock"));
        // Seed a sample passphrase so the offscreen PNG exercises the masked field
        // (mirrors SAMPLE_MNEMONIC for the wizard) — lets the password-mask render
        // (● U+25CF, from the bundled DejaVu font) be regression-checked headlessly.
        ui.set_unlock_passphrase(SharedString::from("correct horse battery"));
    } else if show_shares {
        // Populated Shares-tab tree, fixture-driven (no relay): a synthetic catalog +
        // one expanded/previewed share (its `reports` folder opened) so the PNG shows
        // shares, folders, files, depth, sizes, and disclosure carets.
        ui.set_active_tab(1);
        {
            let mut b = browser.borrow_mut();
            b.set_shares(
                [
                    ("id-quiet", "quiet-harbor", "harbor#aa"),
                    ("id-amber", "amber-lantern", "lantern#bb"),
                ],
                None,
            );
            let quiet = b.rows()[0].id;
            b.toggle(quiet); // expand (ignore the would-be FetchShare; we load directly)
            b.load_manifest(
                "id-quiet",
                &[
                    ManifestRow {
                        rel_path: "reports/q3-summary.pdf".into(),
                        size: 1_258_291,
                        index: 0,
                    },
                    ManifestRow {
                        rel_path: "reports/figures/chart.png".into(),
                        size: 348_160,
                        index: 1,
                    },
                    ManifestRow {
                        rel_path: "raw/dataset.csv".into(),
                        size: 18_874_368,
                        index: 2,
                    },
                    ManifestRow {
                        rel_path: "README.md".into(),
                        size: 2048,
                        index: 3,
                    },
                ],
            );
            if let Some(reports) = b.rows().iter().find(|r| r.label == "reports").map(|r| r.id) {
                b.toggle(reports);
            }
        }
        apply_share_rows(&ui, &browser.borrow());
        // Seed the Shares-tab status line with the auto-republish restore notice
        // (the real production string, via `publish_status_line`) so the PNG
        // regression-checks that "Restored N shares from last session" renders in
        // the rendered `share-status` widget — the connect-time restore surface (#34).
        ui.set_share_status(SharedString::from(publish_status_line(
            true, "", 0, 3, None,
        )));
        // Show the rail-footer download meter mid-download too (fixture).
        ui.set_download_label(SharedString::from("Downloading… 42%"));
        ui.set_download_progress(0.42);
    } else if show_publish {
        // Publish overlay over the Shares tab, fixture-driven (no relay): a couple of
        // live shares so the PNG shows the list, the Unpublish affordance, the name
        // field, and the empty-state path is exercised by the unit/render of an empty
        // set elsewhere.
        ui.set_active_tab(1);
        {
            let mut st = state.borrow_mut();
            st.add_my_share(
                "id-mine-1".into(),
                "trip-photos".into(),
                42,
                "/shares/trip".into(),
            );
            st.add_my_share(
                "id-mine-2".into(),
                "tax-2025".into(),
                7,
                "/shares/tax".into(),
            );
        }
        apply_my_shares(&ui, &state.borrow());
        ui.set_publish_status(SharedString::from(
            "Published \u{201c}trip-photos\u{201d} · 42 file(s)",
        ));
        ui.set_publish_open(true);
    } else if show_desktop_prompt {
        // Offscreen render of the first-run "add to applications?" prompt (main screen).
        ui.set_screen(SharedString::from("main"));
        ui.set_desktop_prompt_open(true);
    } else {
        // Main shell offscreen: connect (renders connection-status) + drive flags.
        _live = Some(start_drain(
            &ui,
            state.clone(),
            net.clone(),
            browser.clone(),
        ));
        connect_now(&ui, &state, &net, &crypto);
        if let Some(phrase) = materialize.as_deref() {
            materialize_and_select(&ui, &state, &net, phrase);
        }
        if show_joined_label {
            // Materialize a circle, then simulate the post-join rendezvous so the rail
            // shows the relay-derived adj-noun label (ISC-C62) — the offscreen analog
            // of the CircleJoined handler.
            let phrase = state::generate_circle_phrase().unwrap_or_default();
            if materialize_and_select(&ui, &state, &net, &phrase) {
                let cid = state.borrow().active_circle_id();
                if let Some(cid) = cid {
                    let addr = daemonseed_core::cot::AssetAddr::from_bytes(
                        [0x5a; daemonseed_core::cot::ASSET_ADDR_LEN],
                    );
                    let mut st = state.borrow_mut();
                    if let Some(idx) = st.set_circle_rendezvous(cid, addr) {
                        rebuild_rail(&ui, &st);
                        apply_view(&ui, st.current(), idx as i32);
                    }
                }
            }
        }
        if show_join {
            ui.invoke_open_join();
        }
        if show_new {
            ui.invoke_open_new();
        }
        if show_palette {
            ui.set_palette_open(true);
        }
        if show_about {
            ui.set_about_open(true);
        }
        if show_unread {
            // #64 fixture: materialize a circle, return to the Lobby, then receive a
            // non-own message in the now-unfocused circle so its rail dot renders.
            materialize_and_select(&ui, &state, &net, "demo unread fixture phrase");
            let mut st = state.borrow_mut();
            st.switch_to(0, String::new(), 0.0);
            st.push_message(1, "ally".into(), "ping".into(), false);
            rebuild_rail(&ui, &st);
            // Reflect the Lobby as the focused row so the circle (idx 1) is the
            // unfocused one carrying the dot.
            apply_view(&ui, st.current(), 0);
        }
        if show_tab_coherence {
            // Tidiness proof: with the public Shares tab open, entering a circle from
            // the rail should land on "Circle shares" (tab 2), not the public tab.
            materialize_and_select(&ui, &state, &net, "demo tab coherence phrase");
            ui.invoke_switch_circle(0); // back to the Lobby
            ui.set_active_tab(1); // public Shares tab open
            ui.invoke_switch_circle(1); // enter the circle from the rail
        }
        if let Some(n) = switch {
            ui.invoke_switch_circle(n);
        }
        if let Some(s) = scroll {
            ui.set_scroll_y(s);
        }
    }

    let path = screenshot.unwrap_or_else(|| "daemonseed-gui.png".into());
    render_png(&window, &path);
    drop(_live);
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;

    // 24 real BIP-39 words (positions 0..=23) so a challenge can sample from them.
    const PHRASE: &str = "abandon ability able about above absent absorb abstract absurd \
        abuse access accident account accuse achieve acid acoustic acquire across act \
        action actor actress actual";

    fn sample_challenge() -> TypeBackChallenge {
        TypeBackChallenge::new(PHRASE, &mut OsRng)
    }

    fn correct_answers(ch: &TypeBackChallenge) -> Vec<String> {
        let words: Vec<&str> = PHRASE.split_whitespace().collect();
        ch.positions()
            .iter()
            .map(|p| words[*p].to_owned())
            .collect()
    }

    #[test]
    fn precheck_accepts_correct_answers() {
        let ch = sample_challenge();
        assert!(type_back_precheck(&ch, PHRASE, &correct_answers(&ch)));
    }

    #[test]
    fn precheck_is_case_insensitive_and_trims() {
        let ch = sample_challenge();
        let ans: Vec<String> = correct_answers(&ch)
            .iter()
            .map(|w| format!("  {} ", w.to_uppercase()))
            .collect();
        assert!(type_back_precheck(&ch, PHRASE, &ans));
    }

    #[test]
    fn publish_status_line_distinguishes_restore_from_fresh_publish() {
        // Fresh user-driven publish: per-share "Published …" with the file count.
        assert_eq!(
            publish_status_line(false, "trip-photos", 42, 1, None),
            "Published \u{201c}trip-photos\u{201d} · 42 file(s)"
        );
        // Fresh publish whose write-through persistence failed surfaces inline.
        assert_eq!(
            publish_status_line(false, "trip-photos", 42, 1, Some("disk full")),
            "Published \u{201c}trip-photos\u{201d} · served this session only (disk full)"
        );
        // Auto-republish on connect reads as a restore summary (pluralized), and
        // ignores the per-share name / file_count / persist_err.
        assert_eq!(
            publish_status_line(true, "trip-photos", 42, 1, None),
            "Restored 1 share from last session"
        );
        assert_eq!(
            publish_status_line(true, "ignored", 0, 3, Some("ignored")),
            "Restored 3 shares from last session"
        );
    }

    #[test]
    fn precheck_rejects_wrong_word() {
        let ch = sample_challenge();
        let mut ans = correct_answers(&ch);
        ans[0] = "zzzzz".to_owned();
        assert!(!type_back_precheck(&ch, PHRASE, &ans));
    }

    #[test]
    fn precheck_rejects_wrong_count() {
        let ch = sample_challenge();
        let mut short = correct_answers(&ch);
        short.pop();
        assert!(!type_back_precheck(&ch, PHRASE, &short));
        assert!(!type_back_precheck(&ch, PHRASE, &[]));
    }

    #[test]
    fn prompt_names_each_position_one_based() {
        let ch = sample_challenge();
        let p = typeback_prompt(&ch);
        for pos in ch.positions() {
            assert!(
                p.contains(&format!("#{}", pos + 1)),
                "prompt {p:?} missing #{}",
                pos + 1
            );
        }
        assert!(p.contains("Type words"));
        assert!(p.ends_with("of your recovery phrase."));
    }
}
