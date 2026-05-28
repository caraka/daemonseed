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

/// **Gate step 1 — cold first-start on all four daemons.**
///
/// Closes ISC-33 (the scripted-keystroke fixture pattern) and ISC-34
/// (gate step 1: cold first-start on D4 — the cold path runs on every
/// daemon in this gate because step 5 / 6 / 7 need three other
/// post-first-start identities anyway; ISC-41's recovery-vs-cold
/// byte-identical check focuses on D4 specifically in step 8).
///
/// The driver runs the same scripted ritual on every daemon in
/// lockstep — Welcome → Enter → strong passphrase → Enter (argon) →
/// the displayed mnemonic re-typed for round-trip verify → Enter →
/// accept the adj-noun default name → Enter (argon again) → clear
/// the bundled-canonical prefill from the bootstrap field and type
/// the test server's `<server-id>@<host:port>` → Enter → Main.
///
/// Each daemon's captured 24-word mnemonic is returned via
/// `FirstStartCapture` so step-8's recovery-flow driver (C5) can
/// drive the exact same materials through the recovery path and
/// assert byte-identical handle / cot-key derivation (ISC-41 /
/// A-C17). For C2 the captures are only sanity-checked (every
/// daemon's mnemonic is exactly 24 BIP-39 words, and the four
/// mnemonics are mutually distinct — proof the RNG is alive and the
/// extractor isn't returning a constant).
#[test]
#[ignore = "spawns real binaries; entry point is `cargo xtask mvp-gate`"]
fn mvp_gate_step1_all_daemons_finish_first_start() {
    let server = ServerProcess::spawn(Some("relay-mvp"))
        .expect("server subprocess spawns + binds to its ephemeral port");
    let bootstrap = server.bootstrap_handle();
    let mut gate = Gate::with_daemons(server, 4).expect("four PTY-attached daemons spawn");

    // Known-green for the C12 strength meter — pinned in the TUI's
    // own first_start unit tests as the canonical passing passphrase.
    let passphrase = "correct horse battery staple table mountain";

    let captures = match gate.all_complete_first_start(passphrase, &bootstrap) {
        Ok(caps) => caps,
        Err(e) => {
            eprintln!("{}", gate.failure_report(&format!("step-1: {e}")));
            panic!("first-start failed on at least one daemon: {e}");
        }
    };

    assert_eq!(captures.len(), 4, "expected one capture per daemon");
    for cap in &captures {
        let n = cap.mnemonic.split_whitespace().count();
        assert_eq!(n, 24, "{}: mnemonic has {n} words, expected 24", cap.tag);
    }

    // Four independent first-starts must produce four distinct
    // mnemonics — if any two collide, either the harness is reading
    // the same daemon's screen twice or the per-process getrandom
    // state isn't independent (a real bring-up bug worth catching).
    use std::collections::BTreeSet;
    let unique: BTreeSet<&str> = captures.iter().map(|c| c.mnemonic.as_str()).collect();
    assert_eq!(
        unique.len(),
        4,
        "expected four distinct mnemonics across daemons; got {} unique",
        unique.len()
    );
}
