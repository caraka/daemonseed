//! daemonseed-tui binary — terminal lifecycle + event loop.
//!
//! This is the thin terminal driver around the testable state machine in
//! [`daemonseed_tui::app`]. It owns raw-mode / alternate-screen setup and
//! teardown and the blocking event loop; all interactive logic lives in the
//! library so it can be unit-tested and PTY-driven without a terminal.

#![forbid(unsafe_code)]

use std::io;
use std::time::Duration;

use daemonseed_server::kats::CNSA_2_0_KATS;
use daemonseed_server::tls::install_provider;
use daemonseed_tui::app::App;
use daemonseed_tui::net::{NetCommand, NetHandle};
use daemonseed_tui::ui;
use oxicrypt_module::{AlgorithmProfile, initialize_with_profile};
use ratatui::crossterm::event::{self, Event};

/// Event-loop poll interval. Bounds redraw latency for time-driven UI (toasts,
/// indexer-progress ticks) without busy-spinning.
const TICK: Duration = Duration::from_millis(100);

fn main() -> io::Result<()> {
    // Bring up the same process-wide CryptoProvider the cli/server use, before
    // touching the terminal — a failure here should print plainly, not corrupt
    // a raw-mode screen. First-start sealing needs the module Operational;
    // connect (later workstream) needs the rustls provider installed.
    if let Err(e) = initialize_with_profile(CNSA_2_0_KATS, AlgorithmProfile::Cnsa2) {
        eprintln!("daemonseed-tui: crypto module init failed: {e}");
        return Err(io::Error::other(e.to_string()));
    }
    if let Err(e) = install_provider() {
        eprintln!("daemonseed-tui: TLS provider install failed: {e}");
        return Err(io::Error::other(e.to_string()));
    }

    // The network actor (tokio runtime + connect driver) is built before raw
    // mode so a runtime-build failure prints plainly.
    let net = match NetHandle::new() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("daemonseed-tui: network runtime build failed: {e}");
            return Err(e);
        }
    };

    let mut terminal = ratatui::init();
    let result = run(&mut terminal, net);
    ratatui::restore();
    result
}

fn run(terminal: &mut ratatui::DefaultTerminal, mut net: NetHandle) -> io::Result<()> {
    let mut app = App::new();
    while !app.should_quit() {
        terminal.draw(|frame| ui::render(&app, frame))?;

        // Drain network events into UI state (non-blocking).
        for event in net.drain_events() {
            app.on_net_event(event);
        }

        if event::poll(TICK)?
            && let Event::Key(key) = event::read()?
        {
            app.on_key(key);
        }

        // Hand any queued commands to the network actor.
        if let Some(req) = app.take_pending_connect() {
            let _ = net.send(NetCommand::Connect {
                server_id: req.server_id,
                address: req.address,
                trusted: req.trusted,
            });
        }
        if let Some(phrase) = app.take_pending_join() {
            let _ = net.send(NetCommand::JoinCircle { phrase });
        }
        if let Some(chat) = app.take_pending_chat() {
            let _ = net.send(NetCommand::SendChat {
                body: chat.body,
                sender_handle: chat.sender_handle,
            });
        }
        if app.take_pending_share_refresh() {
            let _ = net.send(NetCommand::RefreshShares);
        }
    }
    Ok(())
}
