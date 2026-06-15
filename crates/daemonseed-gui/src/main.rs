//! daemonseed-gui — Slint client.
//!
//! Round 2 made the shell **interactive** over a RAM-only per-circle [`state`]
//! layer (click-to-switch rail; each circle keeps its own draft + scroll). Round 3
//! wired the **public Lobby room to real networking** (the [`net`] actor). Round 4
//! adds **circle plumbing**: Join-a-circle and New-circle flows that *materialize*
//! a circle into the rail at runtime, each carrying the Round-5 net contract
//! (phrase → `derive_cot_key` → `CotKey` + a rendezvous slot). The binary now
//! seeds **Lobby-only** (empty-state for circles; the Lobby stays pinned + real),
//! and the composer Send on a materialized circle routes to a clearly-marked
//! Round-5 `SendCircle` seam (local-echo stub — circles are materialized-but-MUTE
//! this round; no networking).
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
//! real callbacks and prints `SELF-CHECK PASS` (panics → non-zero exit).

mod net;
mod state;

slint::include_modules!();

use daemonseed_core::passphrase::strength::estimate_circle;
use net::{NetCommand, NetEvent, NetHandle};
use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType, Rgb565Pixel};
use slint::platform::{Platform, PlatformError, WindowAdapter};
use slint::{ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel};
use state::{CircleState, GuiState, Msg};
use std::cell::{Cell, RefCell};
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
        })
        .collect();
    ui.set_circles(ModelRc::from(Rc::new(VecModel::from(circles))));
    ui.set_only_lobby(st.only_lobby());
}

/// Materialize a circle from `phrase`, rebuild the rail, switch to it, and
/// autofocus the composer. Returns `false` if derivation failed (rare — a crypto
/// backend error). Shared by the submit-join / submit-new callbacks and the
/// `--materialize` offscreen flag.
fn materialize_and_select(ui: &AppWindow, state: &Rc<RefCell<GuiState>>, phrase: &str) -> bool {
    let ok = {
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
                true
            }
            Err(_) => false,
        }
    };
    if ok {
        // Autofocus the composer so the user can type immediately (caraka note).
        ui.invoke_focus_composer();
    }
    ok
}

/// Build the shell, own the RAM-only state, and wire ALL interactive callbacks
/// (rail switch, composer send, and the round-4 circle-plumbing surfaces).
/// Returns the window AND the shared state so the caller can wire real networking
/// and drive the offscreen verification flags.
fn build_ui() -> (AppWindow, Rc<RefCell<GuiState>>) {
    let ui = AppWindow::new().expect("create AppWindow");
    // Round-4 seed: Lobby only (empty-state for circles; Lobby pinned + real).
    let state = Rc::new(RefCell::new(GuiState::lobby_only()));

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
            let live_draft = ui.get_draft().to_string();
            let live_scroll = ui.get_scroll_y();
            {
                let mut st = state.borrow_mut();
                st.switch_to(target as usize, live_draft, live_scroll);
                let active = st.active();
                apply_view(&ui, st.current(), active as i32);
            }
            ui.invoke_focus_composer();
        }
    });

    // Open the Join overlay (from the rail empty-state or the palette). Reset the
    // phrase + strength so the overlay opens clean.
    ui.on_open_join({
        let weak = ui.as_weak();
        move || {
            let ui = weak.unwrap();
            ui.set_join_phrase(SharedString::from(""));
            ui.set_join_phrase_strong(false);
            ui.set_join_open(true);
        }
    });

    // Open the New-circle overlay: pre-generate a strong (132-bit) diceware phrase
    // — one-tap, the ≥128-bit bar at zero friction (brief #2).
    ui.on_open_new({
        let weak = ui.as_weak();
        move || {
            let ui = weak.unwrap();
            let phrase = state::generate_circle_phrase().unwrap_or_default();
            ui.set_new_phrase(SharedString::from(phrase.as_str()));
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

    // Submit Join: GATE on the ≥128-bit circle floor (ISC-C9, precautionary
    // default — block a weak phrase rather than warn). A weak phrase is KEPT in the
    // field so the user can strengthen it in place (the overlay stays open and the
    // calm recovery line is showing). A green phrase materializes + selects.
    ui.on_submit_join({
        let weak = ui.as_weak();
        let state = state.clone();
        move |text| {
            let ui = weak.unwrap();
            let phrase = text.to_string();
            if !estimate_circle(&phrase).is_circle_green() {
                ui.set_join_phrase_strong(false);
                return; // blocked — keep the overlay + phrase for strengthening
            }
            if materialize_and_select(&ui, &state, &phrase) {
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
        move |text| {
            let ui = weak.unwrap();
            let phrase = text.to_string();
            if phrase.trim().is_empty() {
                return;
            }
            if materialize_and_select(&ui, &state, &phrase) {
                ui.set_new_open(false);
            }
        }
    });

    // Initial view = the seed's active circle (the Lobby).
    {
        let st = state.borrow();
        let active = st.active();
        apply_view(&ui, st.current(), active as i32);
    }

    let files = vec![
        FileData {
            name: "reports/q3-summary.pdf".into(),
            size: "1.2 MB".into(),
            checked: true,
        },
        FileData {
            name: "reports/figures/chart.png".into(),
            size: "340 KB".into(),
            checked: true,
        },
        FileData {
            name: "raw/dataset.csv".into(),
            size: "18 MB".into(),
            checked: false,
        },
    ];
    ui.set_files(ModelRc::from(Rc::new(VecModel::from(files))));

    // Action registry: one list, two surfaces (this palette + the rail empty-state
    // mouse-home). New circle / Join a circle now drive the real overlays.
    let actions = vec![
        ActionData {
            label: "Go to Lobby".into(),
            shortcut: "⌘1".into(),
        },
        ActionData {
            label: "New circle".into(),
            shortcut: "⌘N".into(),
        },
        ActionData {
            label: "Join a circle".into(),
            shortcut: "⌘J".into(),
        },
        ActionData {
            label: "Fetch a share".into(),
            shortcut: "⌘F".into(),
        },
    ];
    ui.set_actions(ModelRc::from(Rc::new(VecModel::from(actions))));

    (ui, state)
}

/// Everything the running app must keep alive for its whole lifetime. **If this
/// (or the `Timer` / `NetHandle` inside it) drops, the event drain and the net
/// thread silently die while the build still passes** — so it is held until
/// `ui.run()` returns (windowed) or the offscreen render completes.
struct LiveNet {
    _net: Rc<RefCell<NetHandle>>,
    _timer: Timer,
}

/// Wire the Lobby to real networking: build the net actor, fire a `Connect`
/// (auto-joins the default public room), install the composer `send-message`
/// callback, and start a repeating timer that drains [`NetEvent`]s onto the UI
/// thread non-blocking. Returns the [`LiveNet`] owner the caller MUST keep alive.
fn wire_net(ui: &AppWindow, state: Rc<RefCell<GuiState>>) -> LiveNet {
    let net = Rc::new(RefCell::new(
        NetHandle::new().expect("build daemonseed-gui net actor"),
    ));

    {
        let (server_id, address) = relay_target();
        let _ = net
            .borrow()
            .send(NetCommand::Connect { server_id, address });
    }

    // Composer Send / Enter. Lobby (index 0) → real sealed public-room message.
    // A materialized circle → the **Round-5 `SendCircle` seam**: for now a
    // clearly-marked LOCAL-ECHO stub (NOT wired to the net actor — circles are
    // materialized-but-mute this round). Round 5 replaces the local echo with a
    // `NetCommand::SendCircle{cot_key, rendezvous, text}` against the per-circle
    // net contract the state layer already carries.
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
            let active = state.borrow().active();
            if active == LOBBY {
                let _ = net.borrow().send(NetCommand::SendRoom { text });
                ui.set_draft(SharedString::from(""));
                let mut st = state.borrow_mut();
                let active = st.active();
                st.set_draft(active, String::new());
            } else {
                // ── Round-5 SendCircle seam (local-echo stub, NOT net) ──
                let mut st = state.borrow_mut();
                st.push_message(active, "you".to_owned(), text, true);
                let active = st.active();
                st.set_draft(active, String::new());
                apply_view(&ui, st.current(), active as i32);
            }
        }
    });

    // Drain timer: ~33ms repeated, CAPPED non-blocking loop.
    let timer = Timer::default();
    {
        let weak = ui.as_weak();
        let state = state.clone();
        let net = net.clone();
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
                apply_net_event(&ui, &state, evt);
                n += 1;
                if n > 256 {
                    break;
                }
            }
        });
    }

    LiveNet {
        _net: net,
        _timer: timer,
    }
}

/// Apply one [`NetEvent`] to the UI + the Lobby's RAM state.
fn apply_net_event(ui: &AppWindow, state: &Rc<RefCell<GuiState>>, evt: NetEvent) {
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
        NetEvent::Message { who, text, mine } => {
            // Always fold the message into the Lobby's RAM state; refresh the
            // visible transcript only when the Lobby is the active circle.
            let mut st = state.borrow_mut();
            st.push_message(LOBBY, who, text, mine);
            let active = st.active();
            if active == LOBBY {
                apply_view(ui, st.current(), active as i32);
            }
        }
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
fn self_check(ui: &AppWindow, state: &Rc<RefCell<GuiState>>) {
    const SENTINEL: &str = "SENTINEL-DRAFT";
    // A genuinely-strong phrase (12 distinct BIP-39 words) so the join gate is moot.
    const PHRASE: &str =
        "abandon ability able about above absent absorb abstract absurd abuse access accident";

    assert!(
        materialize_and_select(ui, state, PHRASE),
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

    let mut screenshot: Option<String> = None;
    let mut switch: Option<i32> = None;
    let mut scroll: Option<f32> = None;
    let mut materialize: Option<String> = None;
    let self_check_requested = args.iter().any(|a| a == "--self-check");
    let show_join = args.iter().any(|a| a == "--show-join");
    let show_new = args.iter().any(|a| a == "--show-new");
    for w in args.windows(2) {
        match w[0].as_str() {
            "--screenshot" => screenshot = Some(w[1].clone()),
            "--switch" => switch = w[1].parse().ok(),
            "--scroll" => scroll = w[1].parse().ok(),
            "--materialize" => materialize = Some(w[1].clone()),
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
        || self_check_requested;

    // Bring up crypto before any Connect OR any materialize (derive_cot_key). A
    // failure is non-fatal to the SHELL (the UI still renders); the lobby just
    // stays offline. Always init now (self-check materializes, so it needs it too).
    let crypto = init_crypto();

    #[cfg(feature = "desktop")]
    if !offscreen {
        let (ui, state) = build_ui();
        let _live = match &crypto {
            Ok(()) => Some(wire_net(&ui, state)),
            Err(reason) => {
                ui.set_connection_status(SharedString::from(format!("offline · {reason}")));
                ui.set_connected(false);
                None
            }
        };
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
    let (ui, state) = build_ui();
    ui.show().expect("show");
    window.set_size(slint::PhysicalSize::new(W, H));

    if self_check_requested {
        self_check(&ui, &state);
        return;
    }

    // Wire real networking on the offscreen path too (renders connection-status).
    let _live = match &crypto {
        Ok(()) => Some(wire_net(&ui, state.clone())),
        Err(reason) => {
            ui.set_connection_status(SharedString::from(format!("offline · {reason}")));
            ui.set_connected(false);
            None
        }
    };

    // Drive the round-4 verification surfaces before rendering.
    if let Some(phrase) = materialize.as_deref() {
        materialize_and_select(&ui, &state, phrase);
    }
    if show_join {
        ui.invoke_open_join();
    }
    if show_new {
        ui.invoke_open_new();
    }
    if let Some(n) = switch {
        ui.invoke_switch_circle(n);
    }
    if let Some(s) = scroll {
        ui.set_scroll_y(s);
    }

    let path = screenshot.unwrap_or_else(|| "daemonseed-gui.png".into());
    render_png(&window, &path);
}
