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
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail};
use daemonseed_core::identity::keys::SignKeypair;
use daemonseed_core::public_space::content_address;
use daemonseed_proto::v1 as wire;
use portable_pty::{CommandBuilder, MasterPty, PtySize, native_pty_system};
use prost::Message as _;
use vt100::Parser as VtParser;

/// PTY rows the harness opens its emulator with. Wide enough for the
/// trust-history list + share two-pane + the 24-word mnemonic body
/// without ratatui's `Wrap { trim: true }` collapsing words across
/// lines in a way that breaks our row-aware extraction.
const PTY_ROWS: u16 = 40;
/// PTY columns. 120 fits every M11 screen's footer line without
/// truncation and gives the mnemonic body enough room for ~10 words
/// per line (≈ 60 chars typical), which keeps the extraction logic
/// simple.
const PTY_COLS: u16 = 120;

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
/// test directly with `cargo test --test subprocess_gate -- --ignored` will
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

// ── Public-space seed (ISC-S7 / S8 / S9 / A-S3) ──────────────────────

/// A signed public-space dataset for seeding a [`ServerProcess`] — the
/// operator artifacts a relay would normally load from disk (ISC-S7/S8/S9).
///
/// Built by [`PublicSpaceSeed::build`], which mints one operator ML-DSA-87
/// signing key, signs the MOTD and each announcement post under it, and emits
/// the exact on-disk forms the server's `PublicSpaceState::load` consumes: a
/// plaintext signer-whitelist (one hex full pubkey per line), an encoded
/// `SignedArtifact` for the MOTD, and one encoded `SignedArtifact` per post.
/// Because the same operator key signs everything and its pubkey is the sole
/// whitelist entry, every artifact verifies server-side at load AND client-side
/// at fetch (ISC-A-S3) — so a daemon's public-space view shows them as
/// provenance-verified.
pub struct PublicSpaceSeed {
    /// Lines for the signer-whitelist file (hex-encoded full ML-DSA-87 keys).
    whitelist_lines: Vec<String>,
    /// Encoded `SignedArtifact` bytes for the MOTD, if any.
    motd_bytes: Option<Vec<u8>>,
    /// `(filename, encoded SignedArtifact bytes)` per post. The filename is
    /// `hex(content_address)`, matching the server's own `UploadPost` persist
    /// shape; `load_posts` reads every file in the dir regardless of name.
    posts: Vec<(String, Vec<u8>)>,
    /// Operator-defined topic set the posts belong to (ISC-S7).
    topics: Vec<String>,
}

impl PublicSpaceSeed {
    /// Build a seed: one operator signer, an optional MOTD, and N posts given
    /// as `(topic, body)` pairs. All artifacts are signed under the same
    /// freshly-derived operator key whose public key becomes the lone
    /// whitelist entry.
    pub fn build(motd_text: Option<&str>, posts: &[(&str, &str)]) -> Result<Self> {
        ensure_module_operational();
        // Deterministic operator key — the gate is reproducible, and the key
        // never leaves the test process.
        let operator = SignKeypair::from_ml_dsa_seed(&[0x5A; 32])
            .map_err(|e| anyhow!("derive operator signing key: {e:?}"))?;
        let pubkey = operator.public_key().to_vec();
        let whitelist_lines = vec![hex::encode(&pubkey)];

        let sign_artifact = |signed_payload: Vec<u8>| -> Result<wire::SignedArtifact> {
            let signature = operator
                .sign(&signed_payload)
                .map_err(|e| anyhow!("sign public-space payload: {e:?}"))?
                .to_vec();
            Ok(wire::SignedArtifact {
                signed_payload,
                signer_pubkey: pubkey.clone(),
                signature,
            })
        };

        let motd_bytes = match motd_text {
            Some(text) => {
                let payload = wire::MotdPayload {
                    text: text.to_owned(),
                    signed_timestamp_ms: 1,
                };
                Some(sign_artifact(payload.encode_to_vec())?.encode_to_vec())
            }
            None => None,
        };

        let mut post_files = Vec::with_capacity(posts.len());
        let mut topics: Vec<String> = Vec::new();
        for (i, (topic, body)) in posts.iter().enumerate() {
            let payload = wire::PostPayload {
                topic: (*topic).to_owned(),
                body: (*body).to_owned(),
                // Distinct ascending timestamps so server-side ordering is
                // well-defined (ISC-S7); value is otherwise advisory.
                signed_timestamp_ms: (i as i64) + 1,
            };
            let signed_payload = payload.encode_to_vec();
            let addr = content_address(&signed_payload)
                .map_err(|e| anyhow!("derive post content address: {e:?}"))?;
            let filename = hex::encode(addr.as_bytes());
            post_files.push((filename, sign_artifact(signed_payload)?.encode_to_vec()));
            if !topics.iter().any(|t| t == topic) {
                topics.push((*topic).to_owned());
            }
        }

        Ok(Self {
            whitelist_lines,
            motd_bytes,
            posts: post_files,
            topics,
        })
    }

    /// Write the seed's files under `dir` and return the TOML config lines
    /// (with absolute paths) the server needs to load them. Called from
    /// [`ServerProcess::spawn_inner`] with the server's own data tempdir.
    fn materialize(&self, dir: &Path) -> Result<String> {
        let whitelist_path = dir.join("signers.txt");
        std::fs::write(
            &whitelist_path,
            format!("{}\n", self.whitelist_lines.join("\n")),
        )
        .context("write signer whitelist")?;

        let mut lines = format!("signer_whitelist_path = {whitelist_path:?}\n");

        if let Some(motd) = &self.motd_bytes {
            let motd_path = dir.join("motd.signed");
            std::fs::write(&motd_path, motd).context("write motd")?;
            lines.push_str(&format!("motd_path = {motd_path:?}\n"));
        }

        if !self.posts.is_empty() {
            let posts_dir = dir.join("posts");
            std::fs::create_dir_all(&posts_dir).context("mkdir posts dir")?;
            for (name, bytes) in &self.posts {
                std::fs::write(posts_dir.join(name), bytes)
                    .with_context(|| format!("write post {name}"))?;
            }
            lines.push_str(&format!("posts_dir = {posts_dir:?}\n"));
        }

        if !self.topics.is_empty() {
            let quoted: Vec<String> = self.topics.iter().map(|t| format!("{t:?}")).collect();
            lines.push_str(&format!("topics = [{}]\n", quoted.join(", ")));
        }

        Ok(lines)
    }
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
        Self::spawn_inner(display_name, None)
    }

    /// Like [`Self::spawn`] but seeds the relay's public space (ISC-S7/S8/S9)
    /// from `seed`: the signed MOTD, announcement posts, and signer whitelist
    /// are written into the server's data tempdir and referenced from its TOML
    /// config, so the booted relay verify-and-serves them (ISC-A-S3).
    pub fn spawn_seeded(display_name: Option<&str>, seed: &PublicSpaceSeed) -> Result<Self> {
        Self::spawn_inner(display_name, Some(seed))
    }

    fn spawn_inner(display_name: Option<&str>, ps_seed: Option<&PublicSpaceSeed>) -> Result<Self> {
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
        // Public-space seed (optional): write the operator artifacts into the
        // data tempdir and fold the path-bearing config lines into the TOML.
        let public_space_lines = match ps_seed {
            Some(s) => s.materialize(data_dir.path())?,
            None => String::new(),
        };
        let toml_text = format!(
            "listen_addr = \"{addr}\"\nkey_path = {key:?}\n{display_line}{public_space_lines}",
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
                rows: PTY_ROWS,
                cols: PTY_COLS,
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

    /// Replay every captured PTY byte through a fresh VT100 parser and
    /// return the resulting screen-text — one line per terminal row,
    /// trailing whitespace trimmed, joined with `\n`. ratatui paints
    /// each Span via an ANSI cursor-position escape followed by the
    /// visible glyphs, so the raw byte stream interleaves content and
    /// control sequences; the parser folds both into a 2D cell grid we
    /// can read like a real terminal. Used by [`Self::screen_text`],
    /// [`Self::wait_for_visible`], and the mnemonic extractor.
    fn rendered_screen(&self) -> String {
        let mut parser = VtParser::new(PTY_ROWS, PTY_COLS, 0);
        let guard = self.buffer.lock().unwrap();
        parser.process(&guard);
        let screen = parser.screen();
        let mut out = String::with_capacity(usize::from(PTY_ROWS) * usize::from(PTY_COLS));
        for row in 0..PTY_ROWS {
            let line = screen.contents_between(row, 0, row, PTY_COLS);
            // Strip trailing spaces left by empty cells.
            let trimmed = line.trim_end();
            out.push_str(trimmed);
            out.push('\n');
        }
        out
    }

    /// The currently-visible terminal contents as plain text. Word
    /// separators are real spaces (vt100 reconstructs them from cell
    /// positions), so multi-word substring assertions work the way a
    /// human would expect — "First start — choose a passphrase" is
    /// one contiguous match.
    pub fn screen_text(&self) -> String {
        self.rendered_screen()
    }

    /// Like [`Self::wait_for`] but matches against the vt100-rendered
    /// screen rather than the raw byte stream. Use this for any
    /// multi-word assertion or anything that would otherwise have
    /// ANSI escapes interleaved through it.
    pub fn wait_for_visible(&self, needle: &str, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.screen_text().contains(needle) {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(50));
        }
        let screen = self.screen_text();
        bail!(
            "{}: did not see {:?} in rendered screen within {:?}; last screen:\n{screen}",
            self.tag,
            needle,
            timeout
        );
    }

    /// Reset the captured PTY byte buffer to empty. Used by the gate's
    /// step driver between scripted screens when a needle from the
    /// previous step would otherwise mask the transition (e.g. two
    /// adjacent first-start screens that share a footer phrase).
    pub fn reset_buffer(&self) {
        if let Ok(mut g) = self.buffer.lock() {
            g.clear();
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

    /// Send the same keystroke sequence to every daemon sequentially.
    /// Used by the gate's scripted-transaction driver — every step
    /// advances all four daemons in lockstep.
    pub fn broadcast_keys(&mut self, keys: &str) -> Result<()> {
        for d in &mut self.daemons {
            d.send(keys)?;
        }
        Ok(())
    }

    /// Block until every daemon's rendered screen contains `needle`.
    /// Each daemon's wait_for_visible runs sequentially against its own
    /// deadline (each daemon has the full `timeout` budget), so a slow
    /// argon run on one daemon doesn't compete with another's deadline.
    pub fn wait_for_all_visible(&self, needle: &str, timeout: Duration) -> Result<()> {
        for d in &self.daemons {
            d.wait_for_visible(needle, timeout)?;
        }
        Ok(())
    }

    /// Run the cold first-start ritual on every daemon end-to-end:
    /// Welcome → Passphrase → ShowMnemonic → VerifyRoundTrip →
    /// DisplayName → Bootstrap → Main. Returns each daemon's captured
    /// 24-word mnemonic in tag order so step 8 can drive the recovery
    /// path with the exact materials the cold path produced.
    ///
    /// The bootstrap string overrides whatever bundled-canonical anchor
    /// the TUI prefills (200 backspaces are sent before typing so any
    /// prefill is cleared — `200 ≫ max bundled length`). Default
    /// display name (the adj-noun prefill) is accepted on every daemon
    /// — the gate identifies daemons by their tag, not by handle.
    pub fn all_complete_first_start(
        &mut self,
        passphrase: &str,
        bootstrap: &str,
    ) -> Result<Vec<FirstStartCapture>> {
        // Welcome → press Enter to enter first-start.
        self.wait_for_all_visible("begin first-start", Duration::from_secs(10))?;
        self.broadcast_keys("\r")?;

        // FsStep::Passphrase — type the passphrase, advance.
        self.wait_for_all_visible("choose a passphrase", Duration::from_secs(5))?;
        for d in &mut self.daemons {
            d.send(passphrase)?;
        }
        // Argon2id runs on Enter; cap at 30s per daemon for the
        // OWASP 2024 desktop defaults the binary uses
        // (`ArgonParams::desktop_default()` = 19 MiB / t=2 / p=1 —
        // sub-second on a modern host, but the cap covers slow CI rigs).
        self.broadcast_keys("\r")?;

        // FsStep::ShowMnemonic — capture the mnemonic before advancing.
        self.wait_for_all_visible("write these 24 words down", Duration::from_secs(30))?;
        let mut captures: Vec<FirstStartCapture> = Vec::with_capacity(self.daemons.len());
        for d in &self.daemons {
            let words = extract_mnemonic(&d.screen_text()).with_context(|| {
                format!(
                    "{}: failed to extract mnemonic from ShowMnemonic screen:\n{}",
                    d.tag,
                    d.screen_text()
                )
            })?;
            captures.push(FirstStartCapture {
                tag: d.tag.clone(),
                mnemonic: words,
            });
        }
        self.broadcast_keys("\r")?;

        // FsStep::VerifyRoundTrip — re-type each daemon's own 24 words.
        self.wait_for_all_visible("re-type all 24 words", Duration::from_secs(5))?;
        for (d, cap) in self.daemons.iter_mut().zip(&captures) {
            d.send(&cap.mnemonic)?;
            d.send("\r")?;
        }

        // FsStep::DisplayName — clear the adj-noun prefill and submit
        // empty. The empty branch in `on_display_name` produces
        // `chosen = None`, which makes the daemon's wire handle the
        // floor form `#<12hex>`. The hex prefix is then literally
        // present in any chat transcript that renders this daemon's
        // messages (the chat line uses `DisplayMode::Default`, which
        // for the None-display-name branch returns `#<hex>`) — the
        // harness extracts it from a peer's screen for the @mention
        // and mute drivers in C4a. argon-once again on Enter
        // (passphrase re-derive for the verified seed materials), so
        // cap at 30s per daemon.
        self.wait_for_all_visible("display name", Duration::from_secs(30))?;
        let mut backspaces = String::with_capacity(64);
        for _ in 0..64 {
            backspaces.push('\x7f');
        }
        for d in &mut self.daemons {
            d.send(&backspaces)?;
        }
        self.broadcast_keys("\r")?;

        // FsStep::Bootstrap — clear the bundled-canonical prefill, type
        // the test server's <server-id>@<host:port>, advance.
        self.wait_for_all_visible("bootstrap relay", Duration::from_secs(5))?;
        let mut backspaces = String::with_capacity(200);
        for _ in 0..200 {
            backspaces.push('\x7f');
        }
        for d in &mut self.daemons {
            d.send(&backspaces)?;
            d.send(bootstrap)?;
            d.send("\r")?;
        }

        // Main reached — the default focus is Chat, whose footer line
        // contains "compose" (unique to the Main view's Chat focus).
        self.wait_for_all_visible("compose", Duration::from_secs(10))?;

        Ok(captures)
    }

    /// Block until every daemon's status bar shows "connected to" —
    /// the green Connected state rendered by `ui::render_status_bar`
    /// once the per-connection identity-proof exchange has driven the
    /// `Connection<Versioned>` → `Connection<Authenticated>` type-state
    /// transition (ISC-S5/S14/S19/A-C18). The TUI binary's main-loop
    /// drains `App::take_pending_connect` straight after first-start
    /// completes, so by the time this is called the dial is already
    /// in flight; the handshake (TLS 1.3 + APP_HELLO + identity-proof
    /// envelopes) settles in under a second on loopback.
    pub fn wait_all_authenticated(&self, timeout: Duration) -> Result<()> {
        self.wait_for_all_visible("connected to", timeout)
    }

    /// Drive every daemon into JoinCircle focus, type the same phrase,
    /// send Enter; wait until every status bar shows "circle joined".
    /// Both `on_key_join` and the underlying core derive the same
    /// cot_key from the same phrase, so all four daemons rendezvous
    /// at the same `asset_address` on the server (ISC-S20 / S17 /
    /// A-S2 — the relay sees opaque CotFrame ciphertext).
    ///
    /// After join completes, every daemon's `main_focus` is reset
    /// back to Chat (`on_key_join` does this on Enter), which is the
    /// state `daemon_send_chat` assumes.
    pub fn all_join_circle(&mut self, phrase: &str, timeout: Duration) -> Result<()> {
        // From Chat focus → Tab → JoinCircle focus.
        self.broadcast_keys("\t")?;
        self.wait_for_all_visible("circle phrase", Duration::from_secs(3))?;
        for d in &mut self.daemons {
            d.send(phrase)?;
            d.send("\r")?;
        }
        self.wait_for_all_visible("circle joined", timeout)?;
        Ok(())
    }

    /// Have the daemon at `idx` type `body` on its Chat compose box
    /// and press Enter. The TUI binary's main-loop drains
    /// `App::take_pending_chat` into a NetCommand::SendChat, which
    /// the net actor seals (AES-256-GCM under cot_key) and publishes
    /// over the held CoT subscribe stream — exactly the M8 send path.
    /// Local echo lands the message in the sender's own transcript;
    /// the relay fans it out to every other subscriber.
    pub fn daemon_send_chat(&mut self, idx: usize, body: &str) -> Result<()> {
        let daemon = self
            .daemons
            .get_mut(idx)
            .ok_or_else(|| anyhow!("no daemon at index {idx}"))?;
        daemon.send(body)?;
        daemon.send("\r")?;
        Ok(())
    }

    /// Wait until every daemon's rendered screen contains `body` (a
    /// substring of the chat message body, NOT the wire handle prefix).
    /// Skips the daemon at `sender_idx` because its own local echo is
    /// not load-bearing for the relay-fan-out assertion (and exercising
    /// it conflates the local-echo and relay-relay paths).
    pub fn wait_for_chat_on_others(
        &self,
        sender_idx: usize,
        body: &str,
        timeout: Duration,
    ) -> Result<()> {
        for (i, d) in self.daemons.iter().enumerate() {
            if i == sender_idx {
                continue;
            }
            d.wait_for_visible(body, timeout)?;
        }
        Ok(())
    }

    /// Extract every `#<12hex>` floor-form handle that appears as a
    /// chat-line sender prefix (`#<12hex>:` at the start of a line,
    /// possibly after a leading `│` border cell) in `peer_idx`'s
    /// rendered screen. Deduplicated, returned in order of first
    /// appearance.
    ///
    /// Scoping to the chat-line shape is load-bearing: the status
    /// bar advertises the server's `<name>#<12hex>` id, so a naive
    /// "first `#<12hex>` on screen" would map every daemon's view
    /// of the relay to the server's handle, breaking the
    /// daemon-handle map-back the mute / @mention drivers rely on.
    /// The `:` immediately after the hash prefix is what the chat
    /// renderer emits and the status bar / footer never do.
    pub fn extract_handles(&self, peer_idx: usize) -> Result<Vec<String>> {
        let peer = self
            .daemons
            .get(peer_idx)
            .ok_or_else(|| anyhow!("no daemon at index {peer_idx}"))?;
        let screen = peer.screen_text();
        let mut seen: Vec<String> = Vec::new();
        for line in screen.lines() {
            // Skip the leading box-border cell if present, then look
            // for `#<12hex>:` at the line head.
            let trimmed = line.trim_start_matches('│').trim_start();
            if let Some(rest) = trimmed.strip_prefix('#') {
                if rest.len() < 13 {
                    continue;
                }
                let (hex, after) = rest.split_at(12);
                if !after.starts_with(':') {
                    continue;
                }
                if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    continue;
                }
                let candidate = format!("#{hex}");
                if !seen.iter().any(|s| s == &candidate) {
                    seen.push(candidate);
                }
            }
        }
        Ok(seen)
    }

    /// Daemon at `idx` enters Mute focus and toggles mute for `target`
    /// (the full `#<12hex>` handle). The TUI's Tab cycle from Chat is
    /// Chat→JoinCircle→Mute→Shares→Hide→Servers→TrustHistory, so two
    /// Tabs land on Mute. Enter on a non-empty handle toggles the
    /// session-scoped mute list; subsequent message renders strip
    /// matching senders (A-C3 — silent / unilateral, never leaks to
    /// peers).
    pub fn daemon_mute(&mut self, idx: usize, target: &str) -> Result<()> {
        let daemon = self
            .daemons
            .get_mut(idx)
            .ok_or_else(|| anyhow!("no daemon at index {idx}"))?;
        daemon.send("\t\t")?; // Chat → JoinCircle → Mute
        daemon.send(target)?;
        daemon.send("\r")?;
        // Hop back to Chat focus so the next chat sends/observations
        // run in the same starting state every other helper assumes.
        // Tab cycle from Mute: Mute→Shares→Hide→Servers→TrustHistory→Chat
        // → JoinCircle → Mute (8 steps full loop), so 5 Tabs land back
        // on Chat.
        daemon.send("\t\t\t\t\t")?;
        Ok(())
    }

    /// Block the calling thread for `wait` to let any in-flight relay
    /// fan-out settle, then assert that `peer_idx`'s rendered screen
    /// does NOT contain `body`. Used by the mute test to prove
    /// suppression — absence is unobservable instantly, so the settle
    /// delay matches the relay's worst-case fan-out latency under the
    /// gate's loopback load.
    pub fn assert_chat_absent_on(&self, peer_idx: usize, body: &str, wait: Duration) -> Result<()> {
        thread::sleep(wait);
        let peer = self
            .daemons
            .get(peer_idx)
            .ok_or_else(|| anyhow!("no daemon at index {peer_idx}"))?;
        let screen = peer.screen_text();
        if screen.contains(body) {
            bail!(
                "{}: expected NO occurrence of {:?} in screen but found one:\n{screen}",
                peer.tag,
                body
            );
        }
        Ok(())
    }

    /// Drive the daemon at `idx` from Chat focus into the Public Space pane
    /// (7 Tabs: Chat→JoinCircle→Mute→Shares→Hide→Servers→TrustHistory→
    /// PublicSpace). Opening the pane queues a `RefreshPublicSpace`, so the
    /// MOTD + announcements fetch over the live `AppSession` begins
    /// immediately; the caller then asserts on the rendered content. Returns
    /// once the pane's footer ("public space") is on screen.
    pub fn daemon_open_public_space(&mut self, idx: usize) -> Result<()> {
        let daemon = self
            .daemons
            .get_mut(idx)
            .ok_or_else(|| anyhow!("no daemon at index {idx}"))?;
        daemon.send("\t\t\t\t\t\t\t")?; // 7 Tabs: Chat → … → PublicSpace
        daemon.wait_for_visible("public space", Duration::from_secs(5))
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
            out.push_str(&format!("\n----- {} rendered screen -----\n", daemon.tag));
            out.push_str(&daemon.screen_text());
        }
        out.push_str("\n===== end failure report =====\n");
        out
    }
}

/// What a daemon's cold-first-start ritual produced: the tag (D1..Dn)
/// and the captured 24-word recovery mnemonic. The recovery path
/// (step 8 / ISC-41) re-uses the same mnemonic against a fresh
/// install of the same daemon to prove byte-identical key derivation.
#[derive(Debug, Clone)]
pub struct FirstStartCapture {
    pub tag: String,
    /// 24-word BIP-39 mnemonic, single-space-separated (the canonical
    /// form daemonseed_core's mnemonic-display + round-trip verify use).
    pub mnemonic: String,
}

// ── Mnemonic extraction from a rendered ShowMnemonic screen ──────────

/// Pull the 24-word mnemonic out of a vt100-rendered ShowMnemonic
/// screen.
///
/// Strategy:
/// 1. Find the body block's title `"write these 24 words down"` and
///    start scanning the rendered text right after it.
/// 2. Stop the scan the moment the footer marker `"["` (the first
///    bracket of `[Enter] I've written it down ...`) is reached — the
///    footer contains real BIP-39 words like `"down"`, `"skip"`, and
///    `"cancel"` that would otherwise contaminate the mnemonic.
/// 3. Within that window, accept only tokens that are members of the
///    BIP-39 English wordlist. The lowercase + length filter alone is
///    not enough — box-drawing characters fail it anyway, but
///    incidental words like `"these"` would slip through; BIP-39
///    membership is the tight upper bound.
fn extract_mnemonic(rendered: &str) -> Result<String> {
    let body_marker = "write these 24 words down";
    let start = rendered
        .find(body_marker)
        .map(|i| i + body_marker.len())
        .ok_or_else(|| anyhow!("ShowMnemonic title not found in rendered screen"))?;
    let after = &rendered[start..];

    // Stop at the footer marker to keep footer BIP-39 words out.
    let stop = after.find('[').unwrap_or(after.len());
    let body = &after[..stop];

    // ratatui paints box-drawing borders flush against the body cells
    // (`│mango ...`), so the first word of each wrapped row is glued
    // to a `│`. Trim any leading/trailing non-lowercase-ASCII chars
    // before checking BIP-39 membership.
    let wordlist = bip39::Language::English.word_list();
    let mut words: Vec<String> = Vec::with_capacity(24);
    for raw in body.split_whitespace() {
        let token = raw.trim_matches(|c: char| !c.is_ascii_lowercase());
        if !(3..=8).contains(&token.len()) {
            continue;
        }
        if wordlist.contains(&token) {
            words.push(token.to_owned());
            if words.len() == 24 {
                break;
            }
        }
    }
    if words.len() != 24 {
        bail!(
            "extracted {} BIP-39 words from ShowMnemonic body, expected 24; got: {:?}",
            words.len(),
            words
        );
    }
    Ok(words.join(" "))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mnemonic_extractor_handles_simple_screen() {
        // Minimal stand-in for a rendered ShowMnemonic screen: the
        // title marker, the 24 words wrapped across a few lines (no
        // box drawing — the real renderer's borders are non-alphabetic
        // so they're transparent to the extractor anyway), and a
        // footer line that includes phrases the extractor must reject.
        let body = "│ write these 24 words down                                                  │\n\
             │ abandon ability able about above absent absorb abstract absurd abuse access │\n\
             │ accident account accuse achieve acid acoustic acquire across act action add │\n\
             │ address adjust                                                              │\n\
             │ [Enter] I've written it down   [s] skip (type-back)   [Esc] cancel         │\n";
        let got = extract_mnemonic(body).expect("extracts 24 words");
        assert_eq!(got.split_whitespace().count(), 24);
        assert!(got.starts_with("abandon ability able"));
        assert!(got.ends_with("address adjust"));
    }

    #[test]
    fn mnemonic_extractor_rejects_short_screen() {
        let body = "│ write these 24 words down │\n│ only three words here │\n";
        let err = extract_mnemonic(body).expect_err("must reject < 24 words");
        let msg = format!("{err:?}");
        assert!(msg.contains("expected 24"), "got: {msg}");
    }
}
