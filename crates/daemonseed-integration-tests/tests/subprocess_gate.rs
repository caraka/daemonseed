//! Subprocess-driven end-to-end gate.
//!
//! Boots one `daemonseed-server` subprocess plus four `daemonseed-tui`
//! subprocesses (each on its own pseudo-terminal), drives a scripted
//! transaction across all four daemons, and emits a single pass/fail
//! exit code. Catches regressions that in-process integration tests
//! can't surface: process-global state collisions, async-runtime init
//! ordering across two separate runtimes (server multi-thread builder
//! vs TUI current-thread LocalSet), crossterm raw-mode setup, signal
//! handling, the oxicrypt module gate's process-wide install race.
//!
//! Structured failure reports (server log tails + per-daemon rendered
//! screen) land on stderr via [`common::gate::Gate::failure_report`]
//! when an assertion trips.
//!
//! ## Why `#[ignore]`
//!
//! Depends on already-built `daemonseed-server` and `daemonseed-tui`
//! release binaries; spawns real subprocesses on PTYs. The canonical
//! entry point is `cargo xtask mvp-gate`, which builds the binaries
//! first and propagates this test's exit code. Direct invocation:
//!
//! ```bash
//! cargo build --release --workspace
//! cargo test --release -p daemonseed-integration-tests \
//!     --test subprocess_gate -- --ignored --nocapture
//! ```

#![forbid(unsafe_code)]

mod common;

use std::time::Duration;

use common::gate::{Gate, ServerProcess};

/// Bring-up smoke. Spawns the harness, waits for every daemon to paint
/// its initial Welcome frame, tears down cleanly. Closes the
/// bring-up risk (ports / module init / PTY spawn / env isolation)
/// before any keystroke-scripted test runs.
#[test]
#[ignore = "spawns real binaries; entry point is `cargo xtask mvp-gate`"]
fn four_daemons_bring_up_against_real_server() {
    let server = ServerProcess::spawn(Some("relay-mvp"))
        .expect("server subprocess spawns + binds to its ephemeral port");
    let gate = Gate::with_daemons(server, 4).expect("four PTY-attached daemons spawn");

    // "first-start" is a single contiguous span in `ui::render_welcome`'s
    // body; ratatui's Paragraph widget cursor-moves between space-
    // separated words so multi-word substrings won't be contiguous in
    // the raw PTY byte stream. Matching the hyphenated single-word form
    // proves the spawned binary got past oxicrypt module init, the
    // rustls provider install, crossterm raw-mode setup, and the first
    // ratatui draw.
    for daemon in &gate.daemons {
        if let Err(e) = daemon.wait_for("first-start", Duration::from_secs(8)) {
            eprintln!("{}", gate.failure_report(&format!("daemon-boot: {e}")));
            panic!(
                "daemon {} never reached the Welcome screen: {e}",
                daemon.tag
            );
        }
    }
}

/// Cold first-start on every daemon: Welcome → strong passphrase →
/// displayed mnemonic re-typed for round-trip verify → empty display
/// name (floor `#<12hex>` handle) → test server's
/// `<server-id>@<host:port>` bootstrap → Main.
///
/// Captures each daemon's 24-word mnemonic via
/// [`common::gate::FirstStartCapture`] so the recovery driver can drive
/// byte-identical re-derivation. Asserts four distinct mnemonics —
/// a collision would mean either the harness is reading the same
/// daemon's screen twice or the per-process getrandom state isn't
/// independent.
#[test]
#[ignore = "spawns real binaries; entry point is `cargo xtask mvp-gate`"]
fn four_daemons_complete_cold_first_start() {
    let server = ServerProcess::spawn(Some("relay-mvp"))
        .expect("server subprocess spawns + binds to its ephemeral port");
    let bootstrap = server.bootstrap_handle();
    let mut gate = Gate::with_daemons(server, 4).expect("four PTY-attached daemons spawn");

    // Known-green for the C12 strength meter — pinned in the TUI's
    // own first_start unit tests as a canonical passing passphrase.
    let passphrase = "correct horse battery staple table mountain";

    let captures = match gate.all_complete_first_start(passphrase, &bootstrap) {
        Ok(caps) => caps,
        Err(e) => {
            eprintln!("{}", gate.failure_report(&format!("first-start: {e}")));
            panic!("first-start failed on at least one daemon: {e}");
        }
    };

    assert_eq!(captures.len(), 4, "expected one capture per daemon");
    for cap in &captures {
        let n = cap.mnemonic.split_whitespace().count();
        assert_eq!(n, 24, "{}: mnemonic has {n} words, expected 24", cap.tag);
    }

    use std::collections::BTreeSet;
    let unique: BTreeSet<&str> = captures.iter().map(|c| c.mnemonic.as_str()).collect();
    assert_eq!(
        unique.len(),
        4,
        "expected four distinct mnemonics across daemons; got {} unique",
        unique.len()
    );
}

/// Every daemon reaches Authenticated: status bar shows the green
/// "connected to" string, which only the Versioned→Authenticated
/// type-state transition emits. Exercises TLS-1.3 + APP_HELLO +
/// mutual ML-DSA-87 identity-proof (channel-bound to the rustls TLS
/// exporter) + per-server trust-slider with TOFU pin — all the way
/// across subprocess boundaries.
#[test]
#[ignore = "spawns real binaries; entry point is `cargo xtask mvp-gate`"]
fn four_daemons_authenticate_against_real_server() {
    let server = ServerProcess::spawn(Some("relay-mvp"))
        .expect("server subprocess spawns + binds to its ephemeral port");
    let bootstrap = server.bootstrap_handle();
    let mut gate = Gate::with_daemons(server, 4).expect("four PTY-attached daemons spawn");

    let passphrase = "correct horse battery staple table mountain";
    if let Err(e) = gate.all_complete_first_start(passphrase, &bootstrap) {
        eprintln!("{}", gate.failure_report(&format!("first-start: {e}")));
        panic!("first-start failed: {e}");
    }

    if let Err(e) = gate.wait_all_authenticated(Duration::from_secs(15)) {
        eprintln!("{}", gate.failure_report(&format!("authenticate: {e}")));
        panic!("at least one daemon failed to reach Authenticated: {e}");
    }
}

/// Four-way circle join + sealed chat fan-out via the CoT relay. All
/// four daemons derive the same cot_key from the same phrase and
/// rendezvous at the same opaque relay address; D1 publishes a sealed
/// message; D2/D3/D4 each render the body in their chat transcripts.
/// Proves the end-to-end relay-encryption + fan-out works against
/// real subprocess clients.
#[test]
#[ignore = "spawns real binaries; entry point is `cargo xtask mvp-gate`"]
fn four_daemons_circle_chat_round_trip() {
    let server = ServerProcess::spawn(Some("relay-mvp"))
        .expect("server subprocess spawns + binds to its ephemeral port");
    let bootstrap = server.bootstrap_handle();
    let mut gate = Gate::with_daemons(server, 4).expect("four PTY-attached daemons spawn");

    let passphrase = "correct horse battery staple table mountain";
    if let Err(e) = gate.all_complete_first_start(passphrase, &bootstrap) {
        eprintln!("{}", gate.failure_report(&format!("first-start: {e}")));
        panic!("first-start failed: {e}");
    }
    if let Err(e) = gate.wait_all_authenticated(Duration::from_secs(15)) {
        eprintln!("{}", gate.failure_report(&format!("authenticate: {e}")));
        panic!("authenticate failed: {e}");
    }

    // High-entropy circle phrase; any four daemons typing the same
    // string derive the same cot_key (no relay-side trust dependency).
    let phrase = "circle-mvp-gate-very-strong-phrase-for-four-daemon-relay-2026";
    if let Err(e) = gate.all_join_circle(phrase, Duration::from_secs(10)) {
        eprintln!("{}", gate.failure_report(&format!("circle-join: {e}")));
        panic!("circle join failed: {e}");
    }

    let body = "gate-canary-chat-fanout";
    if let Err(e) = gate.daemon_send_chat(0, body) {
        eprintln!("{}", gate.failure_report(&format!("chat-send: {e}")));
        panic!("D1 send failed: {e}");
    }
    if let Err(e) = gate.wait_for_chat_on_others(0, body, Duration::from_secs(10)) {
        eprintln!("{}", gate.failure_report(&format!("chat-fanout: {e}")));
        panic!("chat fan-out failed — at least one peer never saw the message: {e}");
    }
}

/// Mention rendering + mute suppression. D2 publishes a message
/// containing `@<D1-handle>`; D1's transcript renders the body
/// (the yellow-span highlight is unit-tested in the TUI; this test
/// exercises the same code path against real binaries). D2 then
/// toggles mute on D1's handle; D1 publishes a uniquely-identifiable
/// canary; D2's screen does NOT contain it after a 2-second relay-
/// settle window AND D3's screen DOES — together proving the
/// silent / unilateral / no-leak mute property, not "message lost".
#[test]
#[ignore = "spawns real binaries; entry point is `cargo xtask mvp-gate`"]
fn four_daemons_mention_highlight_and_mute_suppression() {
    let server = ServerProcess::spawn(Some("relay-mvp"))
        .expect("server subprocess spawns + binds to its ephemeral port");
    let bootstrap = server.bootstrap_handle();
    let mut gate = Gate::with_daemons(server, 4).expect("four PTY-attached daemons spawn");

    let passphrase = "correct horse battery staple table mountain";
    gate.all_complete_first_start(passphrase, &bootstrap)
        .unwrap_or_else(|e| {
            eprintln!("{}", gate.failure_report(&format!("first-start: {e}")));
            panic!("first-start failed: {e}");
        });
    gate.wait_all_authenticated(Duration::from_secs(15))
        .unwrap_or_else(|e| {
            eprintln!("{}", gate.failure_report(&format!("authenticate: {e}")));
            panic!("authenticate failed: {e}");
        });

    let phrase = "circle-mvp-gate-very-strong-phrase-for-four-daemon-relay-2026";
    gate.all_join_circle(phrase, Duration::from_secs(10))
        .unwrap_or_else(|e| {
            eprintln!("{}", gate.failure_report(&format!("circle-join: {e}")));
            panic!("circle join failed: {e}");
        });

    // D1 publishes the first canary; D2/D3/D4 each receive it.
    gate.daemon_send_chat(0, "canary-from-d1").unwrap();
    gate.wait_for_chat_on_others(0, "canary-from-d1", Duration::from_secs(10))
        .unwrap_or_else(|e| {
            eprintln!("{}", gate.failure_report(&format!("d1-fanout: {e}")));
            panic!("d1 fanout failed: {e}");
        });

    // After D1's chat: D2's screen contains exactly D1's handle.
    let d2_handles = gate.extract_handles(1).expect("extract D2 screen handles");
    let d1_handle = d2_handles
        .first()
        .expect("D1's handle visible in D2's transcript after D1's chat fan-out")
        .clone();

    // D2 publishes the second canary; D1/D3/D4 receive it.
    gate.daemon_send_chat(1, "canary-from-d2").unwrap();
    gate.wait_for_chat_on_others(1, "canary-from-d2", Duration::from_secs(10))
        .unwrap_or_else(|e| {
            eprintln!("{}", gate.failure_report(&format!("d2-fanout: {e}")));
            panic!("d2 fanout failed: {e}");
        });

    // D1's screen now has its own handle (local echo) + D2's (fan-out).
    // D2's handle is the one that isn't D1's known handle.
    let d1_handles = gate.extract_handles(0).expect("extract D1 screen handles");
    let d2_handle = d1_handles
        .into_iter()
        .find(|h| h != &d1_handle)
        .expect("D2's handle present in D1's transcript after D2's chat fan-out");

    // Mention: D2 publishes a message containing @<D1-handle>; D1
    // receives and renders the body. find_self_mentions on D1's side
    // recognises the @<#hex> token against D1's own Handle.
    let mention_body = format!("@{d1_handle} ping-mention");
    gate.daemon_send_chat(1, &mention_body).unwrap();
    if let Err(e) = gate
        .daemons
        .first()
        .unwrap()
        .wait_for_visible("ping-mention", Duration::from_secs(10))
    {
        eprintln!("{}", gate.failure_report(&format!("mention-fanout: {e}")));
        panic!("D1 never rendered the @mention: {e}");
    }

    // Mute: D2 toggles mute on D1's handle. D2's transcript should
    // suppress every subsequent message from D1 (client-local;
    // never leaks to peers).
    gate.daemon_mute(1, &d1_handle).unwrap();
    let muted_canary = "canary-muted-d1-after-d2-mute";
    gate.daemon_send_chat(0, muted_canary).unwrap();
    if let Err(e) = gate.assert_chat_absent_on(1, muted_canary, Duration::from_secs(2)) {
        eprintln!("{}", gate.failure_report(&format!("mute-suppression: {e}")));
        panic!("mute did NOT suppress D1's canary on D2: {e}");
    }
    // Sanity: D3 must still receive the canary. Without this the
    // absence-on-D2 assertion could pass for the wrong reason
    // ("message lost") rather than the right one ("suppressed").
    gate.daemons
        .get(2)
        .unwrap()
        .wait_for_visible(muted_canary, Duration::from_secs(3))
        .unwrap_or_else(|e| {
            eprintln!("{}", gate.failure_report(&format!("mute-sanity: {e}")));
            panic!("D3 didn't receive the muted canary — message lost: {e}");
        });

    // Expose d2_handle so the compiler doesn't flag it as unused
    // until the recovery driver extracts the same handles for its
    // byte-identical assertion. Shape-only assertion.
    assert!(d2_handle.starts_with('#') && d2_handle.len() == 13);
}
