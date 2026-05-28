//! M11 MVP-gate PTY harness.
//!
//! Spawns a single `daemonseed-server` subprocess and N `daemonseed-tui`
//! subprocesses, each `tui` attached to its own pseudo-terminal pair, and
//! exposes the keystroke / screen-snapshot primitives the gate's 8-step
//! transaction is built on top of.
//!
//! The harness is deliberately confined to `tests/common/` rather than the
//! library crate so that the shipping `daemonseed-integration-tests` lib
//! never compiles `portable-pty`. The end goal is ISC-A1: no test-only
//! surface in any ship binary, not just in the binary surface but in the
//! dependency graph as well — a `cargo tree -p daemonseed-tui` after this
//! milestone still resolves to zero PTY crates.
//!
//! ## Why subprocesses, not in-process
//!
//! The whole point of the MVP gate is to catch the regressions that the
//! in-process integration tests *cannot* surface: dynamic-link / process-
//! global state errors, async-runtime initialisation races between the
//! server's `tokio::runtime::Builder::new_multi_thread()` and the TUI's
//! `LocalSet`-on-current-thread layout, PTY/TTY assumptions in
//! `crossterm`, signal handling, and any subtle module-init ordering bug
//! in the `oxicrypt_module` gate's process-wide install. The spec is
//! explicit (see PRD §C / ds-mvp-implementation-plan.md §M11 line 130):
//! "Pass = ship to the 4-daemon test group. Fail = backtrack to the
//! regressing milestone."
//!
//! ## Why no `--script` flag on the shipping TUI
//!
//! Per PRD decision D2 (and the precautionary-default rule pinned in
//! memory): the gate drives the TUI via PTY keystrokes, never via a
//! test-only `--script` flag added to the shipping binary. The harness
//! is the test harness; the shipping binary stays interactive-only.

#![allow(dead_code)] // Workstream C grows this file incrementally; future
// commits consume more of the surface than C1's smoke test exercises.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail};
use portable_pty::{CommandBuilder, MasterPty, PtySize, native_pty_system};

// ── Workspace discovery ─────────────────────────────────────────────

/// Walk up from `CARGO_MANIFEST_DIR` until a `Cargo.toml` containing
/// `[workspace]` is found. Used to locate `target/<profile>/<binary>`
/// when the integration test is invoked from inside the crate root.
fn workspace_root() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = dir.join("Cargo.toml");
        if let Ok(text) = std::fs::read_to_string(&candidate)
            && text.contains("[workspace]")
        {
            return dir;
        }
        if !dir.pop() {
            panic!(
                "workspace root not found above {}",
                env!("CARGO_MANIFEST_DIR")
            );
        }
    }
}

/// Resolve the path to a built binary. Honours `CARGO_TARGET_DIR` if set,
/// otherwise falls back to `<workspace>/target/<profile>/<name>`. The
/// `profile` argument is `"release"` for the gate (matches `cargo xtask
/// mvp-gate`); test-time debug runs pass `"debug"`.
pub fn target_bin(profile: &str, name: &str) -> PathBuf {
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join("target"));
    target_dir.join(profile).join(name)
}

/// `target_bin` plus a precondition assertion. Surfaces a friendly error
/// pointing the operator at the build command if the binary is missing —
/// the xtask wrapper builds first, but a developer running the integration
/// test directly with `cargo test --test m11_mvp_gate -- --ignored` will
/// hit this if they skip the build step.
pub fn require_release_bin(name: &str) -> Result<PathBuf> {
    let path = target_bin("release", name);
    if !path.exists() {
        bail!(
            "{} not found at {} — run `cargo build --release --workspace` \
             (or `cargo xtask mvp-gate`, which builds and then runs)",
            name,
            path.display()
        );
    }
    Ok(path)
}

// ── ServerProcess ────────────────────────────────────────────────────

/// A live `daemonseed-server` subprocess plus the temp data dir its
/// config + seed live in. RAII: `Drop` SIGKILLs the child and cleans the
/// temp directory.
pub struct ServerProcess {
    child: Child,
    /// The TCP address the server was configured to listen on. The
    /// harness chose an ephemeral 127.0.0.1 port before spawning and
    /// pinned it into the config TOML.
    pub addr: String,
    /// The canonical `<name>#<12hex>` ServerId — pre-computed from the
    /// seed before spawning so the harness can pre-fill the TUI's
    /// bootstrap-relay field with the exact handle the server will
    /// answer to.
    pub server_id: String,
    /// Owning the TempDir keeps it alive (cleanup on drop) for the whole
    /// `ServerProcess` lifetime.
    data_dir: tempfile::TempDir,
    /// Captured stdout / stderr log paths (inside `data_dir`). Surfaced
    /// in the structured-failure report (ISC-43) — the harness tails
    /// them on assertion failure.
    pub stdout_log: PathBuf,
    pub stderr_log: PathBuf,
}

impl ServerProcess {
    /// Spawn a fresh server with an ephemeral 127.0.0.1 port + a
    /// brand-new seed.
    ///
    /// `display_name` controls the `<name>#<hash>` vs floor `#<hash>`
    /// shape (ISC-C4 / C4b). The harness initialises the oxicrypt
    /// module gate idempotently before deriving the server id; the
    /// spawned binary repeats the same init in its own process — two
    /// independent processes, no shared state.
    pub fn spawn(display_name: Option<&str>) -> Result<Self> {
        ensure_module_operational();

        let port = pick_ephemeral_port()?;
        let addr = format!("127.0.0.1:{port}");

        let data_dir = tempfile::tempdir().context("mkdir server data tempdir")?;
        let key_path = data_dir.path().join("seed.bin");
        let config_path = data_dir.path().join("daemonseed.toml");
        let stdout_log = data_dir.path().join("server.stdout.log");
        let stderr_log = data_dir.path().join("server.stderr.log");

        // Pre-generate the seed so the harness can pre-compute the
        // server-id. The server's own `load_or_generate` reads this
        // file back verbatim on boot — same code path, no key drift.
        let seed = daemonseed_server::identity::load_or_generate(&key_path)
            .context("generate server seed")?;
        let server_id =
            daemonseed_server::identity::derive_server_id(&seed, display_name.map(str::to_owned))
                .context("derive server id")?;

        let display_line = display_name
            .map(|n| format!("display_name = \"{n}\"\n"))
            .unwrap_or_default();
        let toml_text = format!(
            "listen_addr = \"{addr}\"\nkey_path = {key:?}\n{display_line}",
            key = key_path,
        );
        std::fs::write(&config_path, toml_text).context("write server config")?;

        let bin = require_release_bin("daemonseed-server")?;
        let stdout_file = std::fs::File::create(&stdout_log).context("create stdout log")?;
        let stderr_file = std::fs::File::create(&stderr_log).context("create stderr log")?;
        let child = Command::new(&bin)
            .arg("--config")
            .arg(&config_path)
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .with_context(|| format!("spawn {}", bin.display()))?;

        let server = Self {
            child,
            addr,
            server_id: server_id.to_string(),
            data_dir,
            stdout_log,
            stderr_log,
        };
        server.wait_ready(Duration::from_secs(10))?;
        Ok(server)
    }

    /// Poll-connect the server's listen address until success or
    /// timeout. The accept loop is up the moment the TCP listener
    /// binds, so this is a robust readiness check that doesn't depend
    /// on the server printing any specific log line.
    fn wait_ready(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if TcpStream::connect_timeout(
                &self
                    .addr
                    .parse()
                    .with_context(|| format!("parse server addr {}", self.addr))?,
                Duration::from_millis(200),
            )
            .is_ok()
            {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(50));
        }
        bail!(
            "server at {} did not become ready within {:?}",
            self.addr,
            timeout
        );
    }

    /// `<name>#<12hex>@<host>:<port>` — the canonical bootstrap-relay
    /// override the TUI's first-start screen accepts (ISC-C37 / S11).
    pub fn bootstrap_handle(&self) -> String {
        format!("{}@{}", self.server_id, self.addr)
    }

    /// Tail the last `lines` lines of either captured stream. Used by
    /// the failure-report path (ISC-43) — the gate emits a structured
    /// report on failure that includes a server-log tail alongside
    /// each daemon's PTY snapshot.
    pub fn tail(&self, which: WhichLog, lines: usize) -> String {
        let path = match which {
            WhichLog::Stdout => &self.stdout_log,
            WhichLog::Stderr => &self.stderr_log,
        };
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let collected: Vec<&str> = text.lines().rev().take(lines).collect();
                collected.into_iter().rev().collect::<Vec<_>>().join("\n")
            }
            Err(_) => String::new(),
        }
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Selector for `ServerProcess::tail` / `PtyTui::snapshot`. Named
/// because the two paths the failure report draws from are not
/// symmetric — the server has two captured streams; a PTY has one
/// combined byte stream.
#[derive(Copy, Clone, Debug)]
pub enum WhichLog {
    Stdout,
    Stderr,
}

// ── PtyTui ───────────────────────────────────────────────────────────

/// One `daemonseed-tui` subprocess plus the pseudo-terminal pair it's
/// attached to. The reader half is drained by a background thread into
/// a shared `Vec<u8>`; the writer half is owned and exposed via
/// [`PtyTui::send`].
///
/// RAII: `Drop` kills the child. The owning thread polling the reader
/// observes EOF and exits naturally.
pub struct PtyTui {
    /// Kept alive so the child's slave-PTY side stays open. The
    /// underlying file descriptor is closed when this drops.
    _master: Box<dyn MasterPty + Send>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
    writer: Box<dyn Write + Send>,
    buffer: Arc<Mutex<Vec<u8>>>,
    /// HOME / XDG dirs pointed inside this TempDir so each daemon's
    /// first-start sealing lands in an isolated location. Kept alive
    /// for the PTY's lifetime.
    pub home: tempfile::TempDir,
    /// Short tag for failure-report output ("D1" / "D2" / ...). Set by
    /// [`Gate::with_daemons`].
    pub tag: String,
}

impl PtyTui {
    /// Spawn one `daemonseed-tui` attached to a fresh PTY. The PTY
    /// size matches a reasonable terminal default (40 rows × 120 cols)
    /// — wide enough that the trust-history list and the share two-
    /// pane layout fit without wrapping artifacts in screen snapshots.
    pub fn spawn(tag: impl Into<String>) -> Result<Self> {
        let tag = tag.into();
        let home = tempfile::tempdir().context("mkdir tui home tempdir")?;
        let bin = require_release_bin("daemonseed-tui")?;

        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: 40,
                cols: 120,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| anyhow!("openpty failed: {e}"))?;

        let mut cmd = CommandBuilder::new(&bin);
        cmd.env("HOME", home.path());
        cmd.env("XDG_CONFIG_HOME", home.path().join(".config"));
        cmd.env("XDG_DATA_HOME", home.path().join(".data"));
        cmd.env("XDG_STATE_HOME", home.path().join(".state"));
        // `xterm-256color` so crossterm's terminfo lookup hits a
        // well-known profile; without TERM, crossterm falls back to
        // a stripped-down profile that elides colour escapes the
        // assertion snippets rely on.
        cmd.env("TERM", "xterm-256color");

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| anyhow!("spawn_command failed: {e}"))?;
        drop(pair.slave); // the child holds the slave fd now

        let writer = pair
            .master
            .take_writer()
            .map_err(|e| anyhow!("take_writer failed: {e}"))?;
        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| anyhow!("try_clone_reader failed: {e}"))?;

        let buffer: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let buf_clone = buffer.clone();
        thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if let Ok(mut guard) = buf_clone.lock() {
                            guard.extend_from_slice(&chunk[..n]);
                        }
                    }
                }
            }
        });

        Ok(Self {
            _master: pair.master,
            child,
            writer,
            buffer,
            home,
            tag,
        })
    }

    /// Send the raw byte sequence to the TUI's stdin. Caller is
    /// responsible for the keystroke encoding — printable characters
    /// pass through, control characters (`"\r"` for Enter, `"\t"` for
    /// Tab, `"\x1b"` for Escape) match crossterm's parser.
    pub fn send(&mut self, keys: &str) -> Result<()> {
        self.writer
            .write_all(keys.as_bytes())
            .with_context(|| format!("write to {} pty", self.tag))?;
        self.writer.flush().ok();
        Ok(())
    }

    /// Snapshot every byte the TUI has written to the PTY so far. Used
    /// by [`Self::wait_for`] and the failure-report path. Lossy UTF-8
    /// because terminal escapes legitimately contain non-UTF-8 byte
    /// sequences and we want the snapshot to be greppable.
    pub fn snapshot(&self) -> String {
        let guard = self.buffer.lock().unwrap();
        String::from_utf8_lossy(&guard).into_owned()
    }

    /// Block until `needle` appears anywhere in the snapshot or
    /// `timeout` elapses. Polls every 50ms — fast enough to feel
    /// snappy in the failure case, slow enough to keep CPU low when
    /// the screen is settling.
    ///
    /// On timeout, the error message includes the tail of the
    /// snapshot so the operator can see what the screen *did* look
    /// like — most "wait_for failed" mysteries are obvious from the
    /// last frame.
    pub fn wait_for(&self, needle: &str, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.snapshot().contains(needle) {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(50));
        }
        let snap = self.snapshot();
        let tail: String = snap.chars().rev().take(1200).collect::<String>();
        let tail: String = tail.chars().rev().collect();
        bail!(
            "{}: did not see {:?} within {:?}; last screen tail:\n{tail}",
            self.tag,
            needle,
            timeout
        );
    }

    /// Tail the last `bytes` bytes of the captured PTY output. Used by
    /// the failure-report path (ISC-43); cap at ~200 lines worth of
    /// screen to keep failure dumps bounded.
    pub fn tail_screen(&self, bytes: usize) -> String {
        let snap = self.snapshot();
        if snap.len() <= bytes {
            snap
        } else {
            snap[snap.len() - bytes..].to_owned()
        }
    }
}

impl Drop for PtyTui {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

// ── Gate aggregator ──────────────────────────────────────────────────

/// One server + N daemons + the structured-failure reporter. The 8-step
/// transaction in `tests/m11_mvp_gate.rs` builds on top of this.
pub struct Gate {
    pub server: ServerProcess,
    pub daemons: Vec<PtyTui>,
}

impl Gate {
    /// Bring up `count` daemons against one server. Daemons are tagged
    /// `"D1"`..`"D{count}"` so failure reports name them legibly.
    pub fn with_daemons(server: ServerProcess, count: usize) -> Result<Self> {
        let mut daemons = Vec::with_capacity(count);
        for i in 1..=count {
            daemons.push(PtyTui::spawn(format!("D{i}"))?);
        }
        Ok(Self { server, daemons })
    }

    /// Render a structured failure report — server log tails + each
    /// daemon's screen tail — for the assertion-failure path. The xtask
    /// wrapper surfaces this to stdout so a failed gate run is
    /// self-diagnosing without needing to dig through tempdirs.
    pub fn failure_report(&self, assertion: &str) -> String {
        let mut out = String::new();
        out.push_str("===== M11 MVP-GATE FAILURE =====\n");
        out.push_str(&format!("Assertion: {assertion}\n"));
        out.push_str(&format!("Server addr:   {}\n", self.server.addr));
        out.push_str(&format!("Server id:     {}\n", self.server.server_id));
        out.push_str("\n----- server stderr (tail) -----\n");
        out.push_str(&self.server.tail(WhichLog::Stderr, 80));
        out.push_str("\n----- server stdout (tail) -----\n");
        out.push_str(&self.server.tail(WhichLog::Stdout, 40));
        for daemon in &self.daemons {
            out.push_str(&format!("\n----- {} screen tail -----\n", daemon.tag));
            out.push_str(&daemon.tail_screen(4_000));
        }
        out.push_str("\n===== end failure report =====\n");
        out
    }
}

// ── Module-init helper ───────────────────────────────────────────────

/// Idempotent oxicrypt-module gate. Both the harness side (to call
/// `derive_server_id`) and the spawned server (independently, in its
/// own process) need the gate in the Operational state — this is the
/// harness-side guard. Safe to call from many tests concurrently
/// thanks to the testing helper's own `Once` underneath.
pub fn ensure_module_operational() {
    oxitls_rustls_provider::testing::ensure_module_operational();
}

// ── Port picker ──────────────────────────────────────────────────────

/// Bind 127.0.0.1:0, read the assigned port, drop the listener. There
/// is a tiny TOCTOU window between drop and the server's bind; in
/// practice the OS does not aggressively recycle ephemeral ports under
/// the load this harness generates, and a collision surfaces as a
/// readable bind error on server stdout (which the wait_ready timeout
/// will then trip). Acceptable for a test harness.
fn pick_ephemeral_port() -> Result<u16> {
    let l = TcpListener::bind("127.0.0.1:0").context("bind ephemeral port")?;
    let port = l.local_addr().context("local_addr")?.port();
    drop(l);
    Ok(port)
}
