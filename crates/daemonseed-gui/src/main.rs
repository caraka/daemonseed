//! daemonseed-gui — Slint client.
//!
//! Round 2 made the shell **interactive** over a RAM-only per-circle [`state`]
//! layer (click-to-switch rail; each circle keeps its own draft + scroll). Round 3
//! wired the **public Lobby room to real networking**: the [`net`] actor (a
//! Slint-free, dedicated-thread tokio runtime, mirroring `daemonseed-tui`'s net
//! actor) connects to the relay, auto-joins the default public room, and the
//! Lobby (rail index 0) shows REAL AEAD-sealed chat — messages in, sealed
//! messages out — while the UI thread never blocks (commands are fire-and-forget;
//! [`NetEvent`]s drain non-blocking on a `slint::Timer`). The other rail circles
//! keep the round-2 local-stub behaviour. Connection identity is ephemeral
//! (`ClientIdentity::ephemeral`, like the TUI); there is no persistent
//! identity/first-start yet — that is a separate milestone.
//!
//! Two run modes. **Windowed** (the `desktop` feature) opens a real winit window,
//! software-rendered (no GL) — the felt-test surface. **Offscreen**
//! (`--screenshot <path>`) renders the shell to a PNG; it is the only mode a
//! headless *terminal* can verify — the host has a display, the agent does not.
//!
//! Offscreen verification flags: `--switch <n>` drives the real switch callback
//! before rendering; `--scroll <px>` sets the (negative-when-scrolled) viewport-y
//! so a render SHOWS the scroll sign; `--self-check` runs a live retention
//! round-trip through the real callback and prints `SELF-CHECK PASS` (panics →
//! non-zero exit) on success.
//!
//! Verification oracle: render cost was already cleared by the perf spike
//! (state-preserving switch ~1.6ms, 220ms easing ~1.4ms/frame on this renderer).

mod net;
mod state;

slint::include_modules!();

use net::{NetCommand, NetEvent, NetHandle};
use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType, Rgb565Pixel};
use slint::platform::{Platform, PlatformError, WindowAdapter};
use slint::{ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel};
use state::{CircleState, GuiState, Msg};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

/// The Lobby is rail index 0 — the only circle wired to the real public room in
/// this slice. Other circles keep the round-2 local-stub behaviour.
const LOBBY: usize = 0;

/// Default relay (the alpha1 fra1 VPS). Overridable via env so a tester can point
/// at their own relay without a rebuild. Mirrors the TUI's connect target.
fn relay_target() -> (String, String) {
    let id =
        std::env::var("DAEMONSEED_RELAY_ID").unwrap_or_else(|_| "fra1#06177b08dc06".to_owned());
    let addr = std::env::var("DAEMONSEED_RELAY_ADDR").unwrap_or_else(|_| "167.86.91.98".to_owned());
    // The relay listens on :443; append it if the env value is bare.
    let addr = if addr.contains(':') {
        addr
    } else {
        format!("{addr}:443")
    };
    (id, addr)
}

/// Bring up the process-wide CryptoProvider + oxicrypt module the cli/tui/server
/// share, before any `Connect` runs on the net thread (they are process-wide, so
/// installing here covers the actor's thread). Errors are surfaced to the UI as
/// "offline · …" via the caller; a failure here means connect would fail anyway.
/// Returns `Ok(())` on success or a human-readable reason.
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

// The windowed path (Slint's winit backend, still software-rendered) lives inline
// in `main()` under the `desktop` feature — `cargo run -p daemonseed-gui
// --features desktop` opens a real window on the Wayland head. The base build is
// offscreen-only so it compiles + verifies from a headless terminal.

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

/// Build the shell, own the RAM-only state, and wire the interactive callbacks.
/// Returns the window AND the shared state so the caller can wire real
/// networking (the Lobby publish path + the event-drain timer) against it.
fn build_ui() -> (AppWindow, Rc<RefCell<GuiState>>) {
    let ui = AppWindow::new().expect("create AppWindow");
    let state = Rc::new(RefCell::new(GuiState::demo()));

    // Rail model — built once from the circle metas (names/subs are static).
    {
        let st = state.borrow();
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
    }
    ui.set_active_tab(0);

    // Interactive rail: capture live edits into the active circle, then switch.
    ui.on_switch_circle({
        let weak = ui.as_weak();
        let state = state.clone();
        move |target| {
            let ui = weak.unwrap();
            let live_draft = ui.get_draft().to_string();
            let live_scroll = ui.get_scroll_y();
            let mut st = state.borrow_mut();
            st.switch_to(target as usize, live_draft, live_scroll);
            let active = st.active();
            apply_view(&ui, st.current(), active as i32);
        }
    });

    // Initial view = the demo's active circle.
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

    // Action registry: the single list bound to the palette overlay here, and
    // (in round 2) to the rail / mouse surfaces — palette mirrors, never owns.
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
/// (or specifically the `Timer` or `NetHandle` inside it) drops, the event drain
/// and the net thread silently die while the build still passes** — so it is held
/// until `ui.run()` returns (windowed) or the offscreen render completes.
struct LiveNet {
    /// The net actor handle (channels + thread). Shared `RefCell` so the drain
    /// timer can `try_recv` (&mut) and the send-message callback can `send` (&).
    /// Held here belt-and-suspenders (the UI callbacks also clone it); dropping
    /// the last clone would end the actor thread. Underscore: held for lifetime,
    /// not read through this field.
    _net: Rc<RefCell<NetHandle>>,
    /// The repeating drain timer. Dropping it stops the drain.
    _timer: Timer,
}

/// Wire the Lobby to real networking: build the net actor, fire a `Connect`
/// (which auto-joins the default public room), install the composer `send-message`
/// callback (Lobby → real `SendRoom`; other circles → local stub), and start a
/// repeating timer that drains [`NetEvent`]s onto the UI thread non-blocking.
///
/// Returns the [`LiveNet`] owner the caller MUST keep alive.
fn wire_net(ui: &AppWindow, state: Rc<RefCell<GuiState>>) -> LiveNet {
    let net = Rc::new(RefCell::new(
        NetHandle::new().expect("build daemonseed-gui net actor"),
    ));

    // Kick off the connection. The actor auto-joins the default public room once
    // Authenticated; events flow back via the drain timer below.
    {
        let (server_id, address) = relay_target();
        let _ = net
            .borrow()
            .send(NetCommand::Connect { server_id, address });
    }

    // Composer Send / Enter: when the Lobby is active, publish a REAL sealed
    // public-room message and clear the draft; otherwise keep the round-2 local
    // stub (append to the active circle's transcript).
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
                // Fire-and-forget; the local echo arrives back as a NetEvent and
                // the drain timer appends it (single render path, no double-add).
                let _ = net.borrow().send(NetCommand::SendRoom { text });
                ui.set_draft(SharedString::from(""));
                // Persist the cleared draft into the Lobby's RAM state too.
                let mut st = state.borrow_mut();
                let active = st.active();
                st.set_draft(active, String::new());
            } else {
                // Non-Lobby: local stub. Append to the active circle and clear.
                let mut st = state.borrow_mut();
                let who = "you".to_owned();
                st.push_message(active, who, text, true);
                let active = st.active();
                st.set_draft(active, String::new());
                let c = st.current().clone();
                drop(st);
                apply_view(&ui, &c, active as i32);
            }
        }
    });

    // Drain timer: ~33ms repeated, CAPPED non-blocking loop. Applies each event
    // to the UI and into the Lobby's RAM state (so a later switch-back keeps the
    // transcript). A disconnected actor is treated as offline — never a panic.
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
                        // Actor thread gone → offline. No panic.
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
            // Always fold the message into the Lobby's RAM state so a switch-back
            // keeps it; refresh the visible transcript only when the Lobby is
            // the active circle.
            let mut st = state.borrow_mut();
            st.push_message(LOBBY, who, text, mine);
            let active = st.active();
            if active == LOBBY {
                let c = st.current().clone();
                drop(st);
                apply_view(ui, &c, active as i32);
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

/// Live retention round-trip through the REAL switch callback (asserts at the
/// UI-property level). Proves draft + scroll survive a circle switch end-to-end,
/// not just a state swap. Panics on failure (→ non-zero exit).
fn self_check(ui: &AppWindow) {
    const SENTINEL_DRAFT: &str = "SENTINEL-DRAFT";
    // Within the active circle's scroll range (~24 messages) so it isn't clamped.
    const SENTINEL_SCROLL: f32 = -120.0;

    let init = ui.get_active();
    ui.set_draft(SENTINEL_DRAFT.into());
    ui.set_scroll_y(SENTINEL_SCROLL);
    // Switch away through the real callback, then back.
    ui.invoke_switch_circle(3);
    ui.invoke_switch_circle(init);

    let got_draft = ui.get_draft();
    let got_scroll = ui.get_scroll_y();
    assert_eq!(
        got_draft.as_str(),
        SENTINEL_DRAFT,
        "draft not retained across switch: got {got_draft:?}"
    );
    assert!(
        (got_scroll - SENTINEL_SCROLL).abs() < f32::EPSILON,
        "scroll not retained across switch: got {got_scroll}, want {SENTINEL_SCROLL}"
    );
    println!("SELF-CHECK PASS");
}

fn main() {
    // `--screenshot <path>` forces the offscreen render — the only mode a headless
    // terminal can verify. `--switch <n>` drives the real switch callback before
    // rendering. `--self-check` runs a live retention round-trip and exits.
    // `--x11` / `DAEMONSEED_X11=1` forces XWayland (see below). Absent a render
    // flag + the `desktop` feature → a real winit window.
    let args: Vec<String> = std::env::args().collect();

    // X11 opt-in (`DAEMONSEED_X11=1` or `--x11`): force winit onto X11/XWayland by
    // unsetting WAYLAND_DISPLAY before Slint initializes its backend. winit 0.30's
    // Wayland pointer path drops button events under VM software rendering (clicks
    // dead while rendering + timers keep working); XWayland is reliable. Native
    // Wayland stays the DEFAULT — opt-in only — so real desktops are unaffected.
    // On non-Linux (e.g. a Windows host) WAYLAND_DISPLAY is simply absent, so this
    // is a harmless no-op there; it matters for the Linux/Wayland VM guest.
    let force_x11 = std::env::var("DAEMONSEED_X11").is_ok_and(|v| v == "1" || v == "true")
        || args.iter().any(|a| a == "--x11");
    if force_x11 {
        // SAFETY: top of `main`, before any thread spawns or backend init — the
        // process is single-threaded here, so the env mutation cannot race.
        unsafe { std::env::remove_var("WAYLAND_DISPLAY") };
    }
    let mut screenshot: Option<String> = None;
    let mut switch: Option<i32> = None;
    // `--scroll <px>` sets the (negative-when-scrolled) viewport-y before render —
    // a verification affordance to SHOW the scroll sign, not just assert it.
    let mut scroll: Option<f32> = None;
    let self_check_requested = args.iter().any(|a| a == "--self-check");
    for w in args.windows(2) {
        if w[0] == "--screenshot" {
            screenshot = Some(w[1].clone());
        }
        if w[0] == "--switch" {
            switch = w[1].parse().ok();
        }
        if w[0] == "--scroll" {
            scroll = w[1].parse().ok();
        }
    }
    // `offscreen` is only read under the `desktop` feature (it decides windowed vs
    // offscreen); without it the build is always offscreen, so silence the lint.
    #[cfg_attr(not(feature = "desktop"), allow(unused_variables))]
    let offscreen =
        screenshot.is_some() || switch.is_some() || scroll.is_some() || self_check_requested;

    // Bring up crypto before any Connect. A failure is non-fatal to the SHELL
    // (the UI still renders); it just means the lobby stays offline — surfaced on
    // the status line. `--self-check` never touches the net, so skip init there.
    let crypto = if self_check_requested {
        Ok(())
    } else {
        init_crypto()
    };

    #[cfg(feature = "desktop")]
    if !offscreen {
        // Windowed via Slint's default (winit) backend — the Wayland-head felt-test.
        let (ui, state) = build_ui();
        // Hold `_live` for the whole windowed lifetime — dropping it would kill
        // the drain timer + net thread silently. It lives until `ui.run()` returns.
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

    // Offscreen software platform — needed for invoke/get/set to work even when no
    // PNG is produced (--self-check still needs the platform + AppWindow).
    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    slint::platform::set_platform(Box::new(GuiPlatform {
        window: window.clone(),
    }))
    .expect("set_platform");
    let (ui, state) = build_ui();
    ui.show().expect("show");
    window.set_size(slint::PhysicalSize::new(W, H));

    if self_check_requested {
        self_check(&ui);
        return;
    }

    // Wire real networking on the offscreen path too (it renders the
    // connection-status; against an unreachable relay it shows connecting/offline
    // — fine). `_live` is held until the render completes at the end of `main`.
    let _live = match &crypto {
        Ok(()) => Some(wire_net(&ui, state.clone())),
        Err(reason) => {
            ui.set_connection_status(SharedString::from(format!("offline · {reason}")));
            ui.set_connected(false);
            None
        }
    };

    // Drive the REAL switch callback so the render reflects the switched circle.
    if let Some(n) = switch {
        ui.invoke_switch_circle(n);
    }
    // Apply a verification scroll LAST (after any switch reset scroll-y) so the
    // PNG SHOWS the viewport-y sign, not just asserts it.
    if let Some(s) = scroll {
        ui.set_scroll_y(s);
    }

    // Render AFTER any switch/scroll so the PNG reflects the active circle.
    let path = screenshot.unwrap_or_else(|| "daemonseed-gui.png".into());
    render_png(&window, &path);
}
