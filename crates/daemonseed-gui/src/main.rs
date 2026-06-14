//! daemonseed-gui — Slint client (round-1 scaffold).
//!
//! Round 1 is the **software-renderer shell** ported from the proven perf spike:
//! the brief's three-zone shell + alpha tab nav (Chat / Shares / a "coming soon"
//! circle-shares placeholder), backed by stub in-memory data.
//!
//! Two run modes. **Windowed** (the `desktop` feature) opens a real winit window,
//! software-rendered (no GL) — the felt-test surface. **Offscreen**
//! (`--screenshot <path>`) renders the shell to a PNG; it is the only mode a
//! headless *terminal* can verify — the host has a display, the agent does not.
//! `daemonseed-core` is NOT wired yet — all data is stub.
//!
//! Verification oracle: render cost was already cleared by the perf spike
//! (state-preserving switch ~1.6ms, 220ms easing ~1.4ms/frame on this renderer).

slint::include_modules!();

use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType, Rgb565Pixel};
use slint::platform::{Platform, PlatformError, WindowAdapter};
use slint::{ModelRc, SharedString, VecModel};
use std::cell::Cell;
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

/// Populate the shell with stub in-memory data (no daemonseed-core wiring).
fn build_ui() -> AppWindow {
    let ui = AppWindow::new().expect("create AppWindow");

    let names = ["Lobby", "midnight-signal", "garden-fence", "harbor-lights"];
    let subs = [
        "public lobby · amazon-fra1",
        "4 here · sealed",
        "2 here · sealed",
        "3 here · sealed",
    ];
    let initials = ["L", "m", "g", "h"];
    let pinned = [true, false, false, false];
    let circles: Vec<CircleData> = (0..names.len())
        .map(|i| CircleData {
            name: names[i].into(),
            sub: subs[i].into(),
            initial: initials[i].into(),
            pinned: pinned[i],
        })
        .collect();
    ui.set_circles(ModelRc::from(Rc::new(VecModel::from(circles))));
    ui.set_active(1);
    ui.set_active_tab(0);
    ui.set_header_name("midnight-signal".into());
    ui.set_header_sub("4 here · end-to-end sealed".into());
    ui.set_draft("ready when you are".into());

    let messages: Vec<MsgData> = (0..24)
        .map(|i| {
            let mine = i % 3 == 0;
            MsgData {
                who: if mine {
                    SharedString::from("wandering-otter")
                } else {
                    SharedString::from(format!("daemon-{i:02}"))
                },
                text: SharedString::from(format!("message line {i} — lorem ipsum dolor sit amet")),
                mine,
            }
        })
        .collect();
    ui.set_messages(ModelRc::from(Rc::new(VecModel::from(messages))));

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

fn main() {
    // `--screenshot <path>` forces the offscreen render — the only mode a headless
    // terminal can verify. Absent + `desktop` feature → a real winit window.
    let args: Vec<String> = std::env::args().collect();
    let mut screenshot: Option<String> = None;
    for w in args.windows(2) {
        if w[0] == "--screenshot" {
            screenshot = Some(w[1].clone());
        }
    }

    #[cfg(feature = "desktop")]
    if screenshot.is_none() {
        // Windowed via Slint's default (winit) backend — the Wayland-head felt-test.
        let ui = build_ui();
        ui.run().expect("run windowed");
        return;
    }

    // Offscreen software render → PNG.
    let path = screenshot.unwrap_or_else(|| "daemonseed-gui.png".into());
    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    slint::platform::set_platform(Box::new(GuiPlatform {
        window: window.clone(),
    }))
    .expect("set_platform");
    let ui = build_ui();
    ui.show().expect("show");
    window.set_size(slint::PhysicalSize::new(W, H));
    render_png(&window, &path);
}
