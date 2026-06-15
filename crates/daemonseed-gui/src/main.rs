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
            // Autofocus the composer so the user can type immediately (caraka note).
            ui.invoke_focus_composer();
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
fn build_ui() -> (AppWindow, Rc<RefCell<GuiState>>, Rc<RefCell<NetHandle>>) {
    let ui = AppWindow::new().expect("create AppWindow");
    // Round-4 seed: Lobby only (empty-state for circles; Lobby pinned + real).
    let state = Rc::new(RefCell::new(GuiState::lobby_only()));
    // The net actor is built HERE (round 5) so the circle-plumbing callbacks can
    // reach it (materialize → JoinCircle; circle Send → SendCircle). `NetHandle::new`
    // is crypto-independent — only Connect needs crypto — so it never fails on
    // crypto; the Connect + drain timer are started later by `start_net`.
    let net = Rc::new(RefCell::new(
        NetHandle::new().expect("build daemonseed-gui net actor"),
    ));

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
            // Focus the phrase field so the user can type / paste immediately.
            ui.invoke_focus_join_input();
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
            if phrase.trim().is_empty() {
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

    (ui, state, net)
}

/// Everything the running app must keep alive for its whole lifetime. **If this
/// (or the `Timer` / `NetHandle` inside it) drops, the event drain and the net
/// thread silently die while the build still passes** — so it is held until
/// `ui.run()` returns (windowed) or the offscreen render completes.
struct LiveNet {
    _net: Rc<RefCell<NetHandle>>,
    _timer: Timer,
}

/// Start real networking against the net actor `build_ui` created: fire `Connect`
/// (auto-joins the default public room) when crypto is up, and start a repeating
/// timer that drains [`NetEvent`]s onto the UI thread non-blocking. The composer
/// send callback was wired in `build_ui` (it needs the net handle too). On a
/// crypto-init failure the shell still renders — the Lobby just stays offline; the
/// drain timer still runs so circle errors surface. Returns the [`LiveNet`] owner
/// the caller MUST keep alive.
fn start_net(
    ui: &AppWindow,
    state: Rc<RefCell<GuiState>>,
    net: Rc<RefCell<NetHandle>>,
    crypto: &Result<(), String>,
) -> LiveNet {
    match crypto {
        Ok(()) => {
            let (server_id, address) = relay_target();
            let _ = net
                .borrow()
                .send(NetCommand::Connect { server_id, address });
        }
        Err(reason) => {
            ui.set_connection_status(SharedString::from(format!("offline · {reason}")));
            ui.set_connected(false);
        }
    }

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
        NetEvent::CircleJoined { circle_id } => {
            // The circle is already in the rail (materialized locally); the
            // subscription is now live. Nothing visual required — keep it quiet.
            let _ = circle_id;
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
                st.push_message(idx, who, text, mine);
                let active = st.active();
                if active == idx {
                    apply_view(ui, st.current(), active as i32);
                }
            }
        }
        NetEvent::CircleError { circle_id, reason } => {
            // Non-fatal (the connection may still be up). Surface on the status
            // line for felt-test diagnostics; no per-circle status surface yet.
            let _ = circle_id;
            ui.set_connection_status(SharedString::from(format!("circle: {reason}")));
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
        let (ui, state, net) = build_ui();
        let _live = start_net(&ui, state, net, &crypto);
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
    let (ui, state, net) = build_ui();
    ui.show().expect("show");
    window.set_size(slint::PhysicalSize::new(W, H));

    if self_check_requested {
        self_check(&ui, &state, &net);
        return;
    }

    // Start real networking on the offscreen path too (renders connection-status).
    let _live = start_net(&ui, state.clone(), net.clone(), &crypto);

    // Drive the verification surfaces before rendering.
    if let Some(phrase) = materialize.as_deref() {
        materialize_and_select(&ui, &state, &net, phrase);
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
