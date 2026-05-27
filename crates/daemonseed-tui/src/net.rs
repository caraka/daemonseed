//! Network actor — the async side of the TUI.
//!
//! The render loop is synchronous (a blocking crossterm poll), but the daemon
//! protocol is async. This module bridges them with the standard actor shape:
//! the binary owns a [`NetHandle`] holding a tokio runtime and two channels —
//! [`NetCommand`]s flow in, [`NetEvent`]s flow out. The render thread sends
//! commands and drains events with non-blocking `try_recv`, so a slow connect
//! (or, later, a cold share-index walk, ISC-A-C7) never blocks the UI.
//!
//! [`NetCommand`] and [`NetEvent`] are plain data, so [`crate::app::App`] folds
//! events in via `App::on_net_event` without ever touching the runtime — which
//! keeps `App` unit-testable and the PTY gate deterministic.

use daemonseed_cli::connect::connect;
use daemonseed_cli::identity_proof::ClientIdentity;
use daemonseed_core::federation::store::{InMemoryTrustStore, ServerEntry, TrustStore};
use daemonseed_core::handle::Handle;
use daemonseed_core::storage::seeds::CounterState;
use tokio::sync::mpsc;

/// A command from the UI to the network actor.
#[derive(Debug, Clone)]
pub enum NetCommand {
    /// Open a connection to `server_id` at `address`, in the given trust mode
    /// (C22), running TLS + APP_HELLO + identity-proof to Authenticated.
    Connect {
        server_id: String,
        address: String,
        trusted: bool,
    },
}

/// An event from the network actor back to the UI. Plain data — folded into
/// [`crate::app::App`] by `on_net_event` with no runtime dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetEvent {
    /// The connection reached Authenticated (ISC-47).
    Connected {
        /// The verified server handle.
        server: String,
        /// Negotiated wire version, `MAJOR.MINOR`.
        version: String,
        /// A non-blocking C22 key-rotation notice, if the trusted-mode server
        /// presented a new (undismissed) key.
        rotation_notice: Option<String>,
    },
    /// The connection attempt failed; `message` is a human-readable cause.
    ConnectFailed { message: String },
}

/// Owns the network thread and the command/event channels. Held by the binary
/// for the life of the session; dropped on quit (dropping `cmd_tx` ends the
/// actor loop, which returns the runtime and joins the thread).
pub struct NetHandle {
    cmd_tx: mpsc::UnboundedSender<NetCommand>,
    evt_rx: mpsc::UnboundedReceiver<NetEvent>,
    _thread: std::thread::JoinHandle<()>,
}

impl NetHandle {
    /// Spawn a dedicated network thread running a current-thread tokio runtime
    /// and the actor loop.
    ///
    /// A *current-thread* runtime is deliberate: [`connect`] takes
    /// `&mut dyn TrustStore`, which is not `Send`, so its future cannot be
    /// `tokio::spawn`ed onto a multi-thread runtime. Driving it inline on a
    /// single-threaded runtime sidesteps the `Send` bound. Concurrency across
    /// connections (later workstreams) uses `spawn_local` on a `LocalSet` here.
    ///
    /// Caller contract: the process-wide CryptoProvider must already be
    /// installed (the binary does this at startup) — [`connect`] builds a
    /// rustls `ClientConfig` against it.
    pub fn new() -> std::io::Result<Self> {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (evt_tx, evt_rx) = mpsc::unbounded_channel();
        let thread = std::thread::Builder::new()
            .name("daemonseed-tui-net".to_owned())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build current-thread net runtime");
                rt.block_on(net_actor(cmd_rx, evt_tx));
            })?;
        Ok(Self {
            cmd_tx,
            evt_rx,
            _thread: thread,
        })
    }

    /// Queue a command for the network actor. Fails only if the actor stopped.
    pub fn send(&self, cmd: NetCommand) -> Result<(), NetCommand> {
        self.cmd_tx.send(cmd).map_err(|e| e.0)
    }

    /// Drain all currently-available events without blocking. Called once per
    /// render tick.
    pub fn drain_events(&mut self) -> Vec<NetEvent> {
        let mut out = Vec::new();
        while let Ok(evt) = self.evt_rx.try_recv() {
            out.push(evt);
        }
        out
    }
}

/// The actor loop: receive commands and drive each inline (one network
/// operation at a time on the current-thread runtime).
async fn net_actor(
    mut cmd_rx: mpsc::UnboundedReceiver<NetCommand>,
    evt_tx: mpsc::UnboundedSender<NetEvent>,
) {
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            NetCommand::Connect {
                server_id,
                address,
                trusted,
            } => {
                let evt = do_connect(&server_id, &address, trusted).await;
                let _ = evt_tx.send(evt);
            }
        }
    }
}

/// Drive a single connect to Authenticated and map the result to a [`NetEvent`].
///
/// Mirrors the cli `connect` binary path: an ephemeral client identity (D8), an
/// in-memory counter, and an in-memory trust store seeded with one entry for the
/// dialed server in the requested C22 mode. Trusted-mode first-contact pins the
/// presented key (TOFU); untrusted mode requires a pre-imported key (none here,
/// so untrusted first-contact will refuse — the C22 import UX lands with the
/// server-management screen).
async fn do_connect(server_id: &str, address: &str, trusted: bool) -> NetEvent {
    let fail = |message: String| NetEvent::ConnectFailed { message };

    let identity = match ClientIdentity::ephemeral() {
        Ok(i) => i,
        Err(e) => return fail(format!("identity: {e}")),
    };
    let server_handle = match server_id.parse::<Handle>() {
        Ok(h) => h,
        Err(_) => return fail("server-id is not a valid <name>#<12hex> handle".to_owned()),
    };
    let mut counters = CounterState::default();
    let mut trust = InMemoryTrustStore::new();
    // Trusted mode TOFU-pins the presented key on first contact. Untrusted mode
    // needs the operator's full key pre-imported out-of-band (ISC-C22) — that
    // import path is the server-management screen, not yet built, so untrusted
    // first-contact is reported as needing a key rather than silently refused.
    if trusted {
        trust.upsert(ServerEntry::new_trusted(server_handle, address.to_owned()));
    } else {
        return fail("untrusted mode requires importing the operator key first".to_owned());
    }

    match connect(server_id, address, &identity, &mut counters, &mut trust).await {
        Ok(outcome) => NetEvent::Connected {
            server: outcome.server_handle,
            version: outcome.version.to_string(),
            rotation_notice: outcome.rotation_notice,
        },
        Err(e) => fail(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn net_event_variants_are_data() {
        let c = NetEvent::Connected {
            server: "relay#aabbccddeeff".to_owned(),
            version: "1.0".to_owned(),
            rotation_notice: None,
        };
        let f = NetEvent::ConnectFailed {
            message: "boom".to_owned(),
        };
        assert_ne!(c, f);
    }
}
