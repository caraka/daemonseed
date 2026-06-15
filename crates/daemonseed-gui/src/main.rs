//! daemonseed-gui — Slint client (round-2 scaffold).
//!
//! Round 2 makes the shell **interactive** and adds a **RAM-only per-circle state
//! layer**: clicking a circle in the rail switches to it, and each circle
//! remembers its own half-typed draft and scroll position across switches
//! (everything resets on relaunch — no persistence). The state machine lives in
//! [`state`] (plain Rust, Slint-free, unit-tested). This is mechanics only — there
//! is still NO `daemonseed-core` wiring, no network, no async; all data is stub.
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

mod state;

slint::include_modules!();

use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType, Rgb565Pixel};
use slint::platform::{Platform, PlatformError, WindowAdapter};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};
use state::{CircleState, GuiState, Msg};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

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

/// Build the shell, own the RAM-only state, and wire the interactive callbacks
/// (no daemonseed-core wiring — all data is stub).
fn build_ui() -> AppWindow {
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

    ui
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
    // Absent any of these + `desktop` feature → a real winit window.
    let args: Vec<String> = std::env::args().collect();
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

    #[cfg(feature = "desktop")]
    if !offscreen {
        // Windowed via Slint's default (winit) backend — the Wayland-head felt-test.
        let ui = build_ui();
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
    let ui = build_ui();
    ui.show().expect("show");
    window.set_size(slint::PhysicalSize::new(W, H));

    if self_check_requested {
        self_check(&ui);
        return;
    }

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
