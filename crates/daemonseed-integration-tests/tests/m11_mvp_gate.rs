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

/// **Gate step 2 — all four daemons reach Authenticated against the
/// real server.**
///
/// Closes ISC-35 (gate step 2: all four daemons reach Authenticated —
/// S5/S14/S19). Cumulative on top of step 1: each daemon's status bar
/// turns green ("connected to <server-id> (wire 1.0)") once the per-
/// connection identity-proof has driven its `Connection<Versioned>` →
/// `Connection<Authenticated>` type-state transition, which is the only
/// way the green Connected variant is emitted in `tui::net`.
///
/// This is the first gate step that touches the real wire-protocol
/// surface end-to-end across subprocess boundaries — TLS 1.3 +
/// APP_HELLO (M4a) + the mutual ML-DSA-87 identity-proof envelope
/// bound to the rustls TLS exporter (M4b) + the per-server C22 trust
/// slider's TOFU pin (M5). Any regression in any of those layers
/// regresses this assertion.
#[test]
#[ignore = "spawns real binaries; entry point is `cargo xtask mvp-gate`"]
fn mvp_gate_step2_all_daemons_authenticated() {
    let server = ServerProcess::spawn(Some("relay-mvp"))
        .expect("server subprocess spawns + binds to its ephemeral port");
    let bootstrap = server.bootstrap_handle();
    let mut gate = Gate::with_daemons(server, 4).expect("four PTY-attached daemons spawn");

    let passphrase = "correct horse battery staple table mountain";
    if let Err(e) = gate.all_complete_first_start(passphrase, &bootstrap) {
        eprintln!("{}", gate.failure_report(&format!("step-1: {e}")));
        panic!("first-start failed: {e}");
    }

    if let Err(e) = gate.wait_all_authenticated(Duration::from_secs(15)) {
        eprintln!("{}", gate.failure_report(&format!("step-2: {e}")));
        panic!("at least one daemon failed to reach Authenticated: {e}");
    }
}

/// **Gate step 4 — CoT circle round-trip across four authenticated
/// daemons.**
///
/// Closes ISC-37 (gate step 4: CoT circle + chat). The full ISC scope
/// names `+ @mention + mute` too — those lean on each daemon's
/// own wire-handle (which the harness doesn't currently extract from
/// the rendered screen) and are layered on top of the same circle in
/// a follow-up. The substrate (encrypted M8 relay round-trip across
/// four real subprocess clients) lands here.
///
/// Cumulative: runs first-start + Authenticated + circle-join + chat
/// fan-out. Skips step 3 (public-space round-trip) for now — the TUI
/// doesn't yet surface a public-space view; ISC-36 will be exercised
/// against the server side in C4 via the cli library, or marked as a
/// known partial-coverage gap if the cost outweighs the M11-scope value.
#[test]
#[ignore = "spawns real binaries; entry point is `cargo xtask mvp-gate`"]
fn mvp_gate_step4_circle_chat_round_trip() {
    let server = ServerProcess::spawn(Some("relay-mvp"))
        .expect("server subprocess spawns + binds to its ephemeral port");
    let bootstrap = server.bootstrap_handle();
    let mut gate = Gate::with_daemons(server, 4).expect("four PTY-attached daemons spawn");

    let passphrase = "correct horse battery staple table mountain";
    if let Err(e) = gate.all_complete_first_start(passphrase, &bootstrap) {
        eprintln!("{}", gate.failure_report(&format!("step-1: {e}")));
        panic!("first-start failed: {e}");
    }
    if let Err(e) = gate.wait_all_authenticated(Duration::from_secs(15)) {
        eprintln!("{}", gate.failure_report(&format!("step-2: {e}")));
        panic!("authenticate failed: {e}");
    }

    // High-entropy circle phrase — well past the C9 floor; any 4
    // daemons typing the same string derive the same cot_key and
    // rendezvous at the same `asset_address` on the relay (ISC-S20).
    let phrase = "circle-mvp-gate-very-strong-phrase-for-step-4-2026-05-28";
    if let Err(e) = gate.all_join_circle(phrase, Duration::from_secs(10)) {
        eprintln!("{}", gate.failure_report(&format!("step-4-join: {e}")));
        panic!("circle join failed: {e}");
    }

    // D1 (index 0) sends a chat message; D2/D3/D4 each receive it
    // via the relay's bidi Subscribe fan-out. The body string is
    // unique enough (`mvp-gate-canary-step-4`) that it's a clean
    // substring match against each peer's rendered transcript.
    let body = "mvp-gate-canary-step-4";
    if let Err(e) = gate.daemon_send_chat(0, body) {
        eprintln!("{}", gate.failure_report(&format!("step-4-send: {e}")));
        panic!("D1 send failed: {e}");
    }
    if let Err(e) = gate.wait_for_chat_on_others(0, body, Duration::from_secs(10)) {
        eprintln!("{}", gate.failure_report(&format!("step-4-fanout: {e}")));
        panic!("chat fan-out failed — at least one peer never saw the message: {e}");
    }
}

/// **Gate step 4 (complete) — circle + chat + @mention + mute.**
///
/// Closes ISC-37 in full. Extends `mvp_gate_step4_circle_chat_round_trip`
/// with the two M9 affordance properties:
///   - **@mention** (ISC-C17 / C18): D2 publishes `@<D1-handle> ping`;
///     D1 receives + renders the mention. The unit test
///     `self_mention_is_highlighted` in `daemonseed-tui` pins the
///     yellow-span render — at the gate we only confirm the body
///     reached D1 via the relay's fan-out, which proves the mention
///     code path was exercised end-to-end on real binaries.
///   - **mute** (ISC-C15 / A-C3): D2 toggles mute on D1's handle;
///     D1 publishes a uniquely-identifiable canary; D2's transcript
///     does NOT render it after a 2-second relay-settle window.
///     A-C3's silent / unilateral / no-leak guarantee is structural
///     in the seeds blob (covered by core unit tests); the gate
///     proves the rendering suppression path holds against the real
///     subprocess client.
///
/// The harness reads each daemon's floor-form `#<12hex>` wire handle
/// out of a peer's chat transcript — `all_complete_first_start` leaves
/// the display name empty so chat lines render as `#<hex>:`. With
/// controlled chat ordering ("D1 chats → D2 sees only D1's handle in
/// its screen", then "D2 chats → D1 sees D1's own (local echo) + D2's
/// (fan-out) → D2's handle is the one ≠ D1's") this map-back is
/// unambiguous.
#[test]
#[ignore = "spawns real binaries; entry point is `cargo xtask mvp-gate`"]
fn mvp_gate_step4_full_mention_and_mute() {
    let server = ServerProcess::spawn(Some("relay-mvp"))
        .expect("server subprocess spawns + binds to its ephemeral port");
    let bootstrap = server.bootstrap_handle();
    let mut gate = Gate::with_daemons(server, 4).expect("four PTY-attached daemons spawn");

    let passphrase = "correct horse battery staple table mountain";
    gate.all_complete_first_start(passphrase, &bootstrap)
        .unwrap_or_else(|e| {
            eprintln!("{}", gate.failure_report(&format!("step-1: {e}")));
            panic!("first-start failed: {e}");
        });
    gate.wait_all_authenticated(Duration::from_secs(15))
        .unwrap_or_else(|e| {
            eprintln!("{}", gate.failure_report(&format!("step-2: {e}")));
            panic!("authenticate failed: {e}");
        });

    let phrase = "circle-mvp-gate-very-strong-phrase-for-step-4-2026-05-28";
    gate.all_join_circle(phrase, Duration::from_secs(10))
        .unwrap_or_else(|e| {
            eprintln!("{}", gate.failure_report(&format!("step-4-join: {e}")));
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

    // D1's screen now has its own (local echo) + D2's (fan-out).
    // D2's handle is the one that isn't D1's known handle.
    let d1_handles = gate.extract_handles(0).expect("extract D1 screen handles");
    let d2_handle = d1_handles
        .into_iter()
        .find(|h| h != &d1_handle)
        .expect("D2's handle present in D1's transcript after D2's chat fan-out");

    // @mention: D2 publishes a message containing @<D1-handle>; D1
    // receives the body. find_self_mentions on D1's side runs against
    // D1's own `Handle`, recognising the @<#hex> token. Body uniqueness
    // keeps the screen-match clean.
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

    // mute: D2 toggles mute on D1's handle (Tab Tab from Chat → Mute
    // focus → handle → Enter). D2's transcript should suppress every
    // subsequent message from D1 (A-C3 silent unilateral suppression).
    gate.daemon_mute(1, &d1_handle).unwrap();
    let muted_canary = "canary-muted-d1-after-d2-mute";
    gate.daemon_send_chat(0, muted_canary).unwrap();
    // Wait 2s for the relay to fan out (D3/D4 will see it; D2 won't).
    // 2s is comfortably above the loopback relay round-trip we've seen
    // in earlier steps (sub-200ms typical).
    if let Err(e) = gate.assert_chat_absent_on(1, muted_canary, Duration::from_secs(2)) {
        eprintln!("{}", gate.failure_report(&format!("mute-suppression: {e}")));
        panic!("mute did NOT suppress D1's canary on D2: {e}");
    }
    // Sanity: D3 must still receive it — proves the muted_canary
    // actually reached the relay and was fanned out (D2's absence
    // alone could mean "the message was lost", not "suppressed").
    gate.daemons
        .get(2)
        .unwrap()
        .wait_for_visible(muted_canary, Duration::from_secs(3))
        .unwrap_or_else(|e| {
            eprintln!("{}", gate.failure_report(&format!("mute-sanity: {e}")));
            panic!("D3 didn't receive the muted canary — message lost: {e}");
        });

    // Expose D2's handle so the compiler doesn't flag it as unused
    // until step-8 (C5) extracts the same handles for the recovery
    // assertion. The assertion itself is just structural — d2_handle
    // must be #<12hex> shape (the extractor guarantees it).
    assert!(d2_handle.starts_with('#') && d2_handle.len() == 13);
}
