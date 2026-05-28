//! M11 MVP gate — 4-daemon end-to-end transaction.
//!
//! This test is the **MVP-gate scenario** named in
//! `ds-mvp-implementation-plan.md` §M11 (the entire milestone hinges on it).
//! It boots one `daemonseed-server` subprocess plus four `daemonseed-tui`
//! subprocesses (each on its own PTY) and drives the scripted 8-step
//! transaction described in §M11's "MVP gate scenario" against them. A
//! single pass/fail bit is the deliverable (ISC-42); the structured
//! failure report (ISC-43) is emitted on stderr via the [`Gate`] helper
//! when an assertion trips.
//!
//! ## Why `#[ignore]`
//!
//! The test depends on already-built `daemonseed-server` and
//! `daemonseed-tui` release binaries and spawns real subprocesses on
//! pseudo-terminals. That makes it noticeably slower (~tens of seconds)
//! than the rest of the workspace test suite and unsuitable for the
//! default `cargo test --workspace` loop. The canonical entry point is
//! `cargo xtask mvp-gate`, which builds the binaries first and then runs
//! this test with `--ignored`. Running directly:
//!
//! ```bash
//! cargo build --release --workspace
//! cargo test --release -p daemonseed-integration-tests \
//!     --test m11_mvp_gate -- --ignored --nocapture
//! ```
//!
//! ## Workstream C status (this file grows with each commit)
//!
//! - **C1 (this commit)**: foundation only — brings the harness up,
//!   asserts each daemon's first-start passphrase prompt rendered, and
//!   tears down cleanly. ISC-32 partially exercised (subprocess spawn);
//!   ISC-44 closed (the `cargo xtask mvp-gate` entry point exists and
//!   propagates this test's exit code).
//! - **C2**: Step 1 — full first-start flow on all four daemons.
//! - **C3**: Steps 2-4 — Authenticated, public-space, circle chat.
//! - **C4**: Steps 5-7 — share fetch, federation, deprecation.
//! - **C5**: Step 8 + the structured failure report + final pass/fail.

#![forbid(unsafe_code)]

mod common;

use std::time::Duration;

use common::gate::{Gate, ServerProcess};

/// Smoke-level boot of the harness. Brings up one server + four daemons,
/// asserts each daemon paints its initial frame — `daemonseed-tui` opens
/// on the Welcome landing screen ("[Enter] begin first-start"), the
/// pre-first-start affordance rendered by `ui::render_welcome` — and
/// lets the RAII Drop chains tear everything down.
///
/// On its own this is a thin assertion, but it closes the bring-up risk
/// (ports, oxicrypt module init, PTY spawn, env-var isolation between
/// daemons) before C2 starts feeding keystrokes — when C2 wait_for's
/// the post-Enter passphrase screen, "did the TUI even boot?" is
/// already answered. The Welcome string is structurally tied to
/// `Screen::Welcome` (the only `App::new()` initial state per the App
/// constructor's invariant), so matching it proves the spawned binary
/// got past oxicrypt module init + TLS provider install + crossterm
/// raw-mode setup + the first ratatui draw.
#[test]
#[ignore = "spawns real binaries; entry point is `cargo xtask mvp-gate`"]
fn mvp_gate_smoke_brings_up_four_daemons() {
    let server = ServerProcess::spawn(Some("relay-mvp"))
        .expect("server subprocess spawns + binds to its ephemeral port");
    let gate = Gate::with_daemons(server, 4).expect("four PTY-attached daemons spawn");

    // The Welcome screen is the App::new initial state and the only
    // screen rendered before the user presses Enter. The exact text
    // "begin first-start" is pinned at `ui::render_welcome` and tested
    // there; ratatui's Paragraph widget cursor-moves between each space-
    // separated word so multi-word substrings won't be contiguous in
    // the raw PTY byte stream — we match the hyphenated single-word
    // "first-start" instead, which IS rendered as one contiguous span
    // and appears nowhere else in the app's text. Matching it proves
    // the spawned binary got past oxicrypt module init, the rustls
    // provider install, crossterm raw-mode setup, and the first
    // ratatui draw — exactly the bring-up surface that subprocess load
    // would regress where in-process tests didn't.
    for daemon in &gate.daemons {
        if let Err(e) = daemon.wait_for("first-start", Duration::from_secs(8)) {
            eprintln!("{}", gate.failure_report(&format!("daemon-boot: {e}")));
            panic!(
                "daemon {} never reached the Welcome screen: {e}",
                daemon.tag
            );
        }
    }

    // Drop order: daemons first (each kills its TUI child), then the
    // server (kills the server child). Both are RAII; nothing else to
    // do here — a clean exit is the C1 deliverable.
}
