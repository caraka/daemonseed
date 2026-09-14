//! Integration test: a first contact made while the recipient is offline is found
//! when the recipient returns, attributed to the identity that signed it, and a
//! hello whose opening claims that identity under another key is not.
//!
//! Serves founding claim FC4 of `docs/design/direct-messaging.md`:
//!
//! - **FC4 First contact.** Knowing only someone's published identity, a user can
//!   start a conversation while they are offline, they find it when they return,
//!   and nobody can make the user accept a request under a name that is not
//!   theirs.
//!
//! ## A step is a process
//!
//! "B is offline" is a statement about processes, so every step runs as a
//! separate operating system process against a persisted state directory. The
//! driver re-executes its own binary with `--exact <step> --ignored`, passing
//! the step's role and state directory in the environment, and waits for the
//! child to exit before starting the next. Before every spawn it asserts that
//! every child it started has been reaped, and while a step runs it asserts that
//! no process of any other role is alive. A step run on its own, with no
//! environment, prints a line saying so and returns.
//!
//! ## The run
//!
//! 1. **B publishes its advert** and stops. A first contact encapsulates to it,
//!    so B has to have been online once.
//! 2. **A knocks.** A publishes its own advert and writes a first contact to the
//!    identity B published, carrying one message. No B process exists. A
//!    records its hello's slot and bytes.
//! 3. **C forges a hello under A's name.** C, a third identity, writes an
//!    ordinary first contact to B, then overwrites its own channel's control
//!    subkey with an opening whose writer field names A's identity key. The
//!    signature is still C's, so the opening claims a writer who did not sign
//!    it. C checks both openings locally before writing: its own verifies and
//!    the forgery does not. C records its hello's slot and bytes, and the
//!    sequence number and sealed bytes of the forged control write.
//! 4. **B collects,** after A and C have both stopped. Before its first pass it
//!    waits until C's slot holds exactly C's hello bytes and C's control subkey
//!    holds exactly the forged bytes at a network sequence number no lower than
//!    C's write. It then runs collection passes until A's request surfaces,
//!    writing down every item of every pass and how many were at C's slot, and
//!    afterwards checks the same bytes again through its own node.
//!
//! ## What is asserted
//!
//! [`attributed_to_the_signer`] is the whole end-state check, a value so the
//! tests at the foot of this file can run it over hand-built notes. It requires
//! a contact request whose identity public key is byte-equal to A's, on A's
//! channel, at A's slot; the forged bytes on the network before B's passes and
//! unchanged in B's copies after them; and nothing surfaced in any pass on C's
//! channel, at C's slot, under
//! C's key, or under A's key other than A's own request. A's and C's hellos in
//! the same slot fail the run as a slot collision, to be re-run.
//!
//! Attribution is compared as identity public keys, never as a name: the
//! protocol has no display name, and a key that differs in one byte is another
//! identity.
//!
//! ## What the negative arm proves, and what it does not
//!
//! `flows::collect` skips a slot silently whether its hello fails to
//! decapsulate, its opening fails to open, or the opening fails to verify, and
//! this test cannot see which. What it proves: with C's hello and the forged
//! opening both on the network, byte for byte, before the first pass, no pass
//! surfaced anything for that hello, and the same passes surfaced A's
//! genuine request, so the scan was reading the drop. A request under C's key
//! would mean B had read C's genuine opening instead of the forgery, and it
//! fails the run. What it does not prove: that the refusal was the signature
//! check rather than an earlier failure on the same slot.
//!
//! Only the before-check is taken from the network. The after-check runs on B's
//! node once it has read those records, so B's local copies can answer it, and
//! it shows only that B's copies did not change during the passes.
//!
//! ## What this needs to run
//!
//! The driver is `#[ignore]`d. It needs:
//!
//! - the public Veilid network reachable;
//! - three free UDP ports: [`A_PORT`], [`B_PORT`] and [`C_PORT`], one per role;
//! - the `--ignored` flag.
//!
//! So:
//!
//!     cargo test -p daemonseed-veilid-net --test two_node_dm_offline -- \
//!         --ignored --nocapture
//!
//! Expect well over an hour. Every step joins the network from cold, and B's
//! collection waits for writes to spread through the distributed hash table.
//! A step's own output goes to a file beside its state directory, which the
//! driver echoes when the step exits and quotes the tail of when it fails.
//!
//! The harness's own bookkeeping is covered by tests that run without a
//! network, at the foot of this file.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use daemonseed_core::dm::advert::{self, AdvertKeys};
use daemonseed_core::dm::channel::{self, ChannelOpening, Control};
use daemonseed_core::dm::drop as drop_plane;
use daemonseed_core::dm::flows::{self, FirstContact, FlowError, Me, Records, Surfaced};
use daemonseed_core::dm::store::Store;
use daemonseed_core::identity::keys::{
    derive_identity_keys, Identity, IdentityKeys, SignKeypair, IDENTITY_PK_LEN,
};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::storage::seeds::AEAD_KEY_LEN;
use daemonseed_veilid_net::{VeilidNet, VeilidNetConfig, VeilidRecords};

// ── what a run is configured with ────────────────────────────────────────────

/// The at-rest key each role's store seals under. Per-run scratch directories,
/// so this is a fixture rather than a secret.
const AT_REST: [u8; AEAD_KEY_LEN] = [0x4d; AEAD_KEY_LEN];

/// The budget for one hop: a write, its spread, and a reader's next look.
const HOP: Duration = Duration::from_secs(600);

/// The budget for a hop whose reading half is a whole drop scan, which is one
/// read per slot.
const DROP_SCAN_HOP: Duration = Duration::from_secs(2700);

/// How long the attach is given before a step gives up on the network.
const ATTACH_SECS: u64 = 180;

/// What the node's graceful close is given once a step's work is done.
const NODE_CLOSE: Duration = Duration::from_secs(30);

/// How long one step may take before the driver kills it and fails.
const STEP_BUDGET: Duration = Duration::from_secs(5400);

/// How often a step retries a read whose answer is still spreading.
const POLL: Duration = Duration::from_secs(20);

/// How often the driver looks at a running child.
const CHILD_POLL: Duration = Duration::from_millis(500);

/// How many lines of a failed step's output the driver quotes back.
const STDERR_TAIL_LINES: usize = 40;

/// The message A's first contact carries, and the one C's carries.
const MESSAGE_0: &str = "a first contact, written while the recipient is offline";
const FORGED_BODY: &str = "a first contact whose opening will claim another writer";

/// The UDP ports the three roles listen on, one per role.
const A_PORT: &str = ":5194";
const B_PORT: &str = ":5195";
const C_PORT: &str = ":5196";

/// The environment a step reads its instructions from.
const ENV_STATE: &str = "DAEMONSEED_DM_OFFLINE_STATE";
const ENV_ROLE: &str = "DAEMONSEED_DM_OFFLINE_ROLE";

// ── roles and steps ──────────────────────────────────────────────────────────

/// Which identity a step runs as.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role {
    /// The initiator.
    A,
    /// The recipient, offline while A and C write.
    B,
    /// A third identity that forges a hello under A's name.
    C,
}

const ROLES: [Role; 3] = [Role::A, Role::B, Role::C];

impl Role {
    fn name(self) -> &'static str {
        match self {
            Role::A => "a",
            Role::B => "b",
            Role::C => "c",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        ROLES.into_iter().find(|role| role.name() == name)
    }

    fn port(self) -> &'static str {
        match self {
            Role::A => A_PORT,
            Role::B => B_PORT,
            Role::C => C_PORT,
        }
    }

    fn dir(self, state: &Path) -> PathBuf {
        state.join(self.name())
    }

    fn recovery_phrase_path(self, state: &Path) -> PathBuf {
        self.dir(state).join("recovery-phrase")
    }

    fn notes_path(self, state: &Path) -> PathBuf {
        self.dir(state).join("notes")
    }
}

/// One step of the run. Each runs as its own process.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Step {
    /// B publishes the advert a first contact encapsulates to, and stops.
    BPublishes,
    /// A publishes its advert and knocks at B, and stops.
    AKnocks,
    /// C knocks at B and overwrites its opening to name A as the writer.
    CForges,
    /// B collects, with A and C both stopped.
    BCollects,
}

/// The run, in order.
const SEQUENCE: [Step; 4] = [
    Step::BPublishes,
    Step::AKnocks,
    Step::CForges,
    Step::BCollects,
];

impl Step {
    fn role(self) -> Role {
        match self {
            Step::BPublishes | Step::BCollects => Role::B,
            Step::AKnocks => Role::A,
            Step::CForges => Role::C,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Step::BPublishes => "b-publishes",
            Step::AKnocks => "a-knocks",
            Step::CForges => "c-forges",
            Step::BCollects => "b-collects",
        }
    }

    fn test_name(self) -> &'static str {
        match self {
            Step::BPublishes => "steps::b_publishes_its_advert",
            Step::AKnocks => "steps::a_knocks_while_b_is_offline",
            Step::CForges => "steps::c_forges_a_hello_under_as_name",
            Step::BCollects => "steps::b_collects_after_a_has_stopped",
        }
    }
}

// ── the notes file ───────────────────────────────────────────────────────────

/// One item a collection pass surfaced, as B writes it down.
#[derive(Clone, PartialEq, Eq, Debug)]
struct SurfacedLine {
    /// The collection pass, counted from 1.
    pass: u32,
    /// `request`, `dropped`, `started-over`, `accepted`, `failed` or
    /// `already-collected`.
    kind: String,
    /// The drop slot, where the item names one.
    slot: Option<u16>,
    /// The identity public key the item is attributed to, where it names one.
    identity: Option<Vec<u8>>,
    /// The channel lookup key, where the item names one.
    lookup: Option<Vec<u8>>,
}

/// What one collection pass returned, in total and at C's slot.
#[derive(Clone, PartialEq, Eq, Debug)]
struct PassLine {
    pass: u32,
    items: usize,
    at_forged_slot: usize,
}

/// What one role has written down across its steps.
///
/// Line-oriented. Keys and bytes are hex, `~` for an empty byte string, and `-`
/// for an absent field, so every line of a kind has the same number of fields.
#[derive(Default, Clone, PartialEq, Eq, Debug)]
struct Notes {
    /// The steps this role has completed, by label.
    done: Vec<String>,
    /// This role's identity public key.
    identity: Option<Vec<u8>>,
    /// The lookup key of the channel this role writes.
    lookup: Option<Vec<u8>>,
    /// The drop slot this role's hello landed in.
    hello_slot: Option<u16>,
    /// The sealed bytes of this role's hello.
    hello: Option<Vec<u8>>,
    /// C: the local sequence number of its forged control write.
    forged_control_seq: Option<u64>,
    /// C: the sealed bytes of its forged control write.
    forged_control: Option<Vec<u8>>,
    /// B: every collection pass.
    passes: Vec<PassLine>,
    /// B: every item of every pass.
    surfaced: Vec<SurfacedLine>,
    /// B: C's hello and the forged opening were on the network, byte for byte,
    /// before the first pass.
    forged_before: bool,
    /// B: the same bytes, read after the last pass through B's own node, which
    /// may answer from its local copies.
    forged_after: bool,
    /// How long each step took, in milliseconds.
    timings: Vec<(String, u64)>,
}

impl Notes {
    fn encode(&self) -> String {
        let absent = || "-".to_owned();
        let mut out = String::new();
        for label in &self.done {
            out.push_str(&format!("done {label}\n"));
        }
        if let Some(identity) = &self.identity {
            out.push_str(&format!("identity {}\n", bytes_field(identity)));
        }
        if let Some(lookup) = &self.lookup {
            out.push_str(&format!("lookup {}\n", bytes_field(lookup)));
        }
        if let Some(slot) = self.hello_slot {
            out.push_str(&format!("hello-slot {slot}\n"));
        }
        if let Some(hello) = &self.hello {
            out.push_str(&format!("hello {}\n", bytes_field(hello)));
        }
        if let Some(seq) = self.forged_control_seq {
            out.push_str(&format!("forged-control-seq {seq}\n"));
        }
        if let Some(control) = &self.forged_control {
            out.push_str(&format!("forged-control {}\n", bytes_field(control)));
        }
        for pass in &self.passes {
            out.push_str(&format!(
                "pass {} {} {}\n",
                pass.pass, pass.items, pass.at_forged_slot
            ));
        }
        for line in &self.surfaced {
            out.push_str(&format!(
                "surfaced {} {} {} {} {}\n",
                line.pass,
                line.kind,
                line.slot.map_or_else(absent, |s| s.to_string()),
                line.identity.as_deref().map_or_else(absent, bytes_field),
                line.lookup.as_deref().map_or_else(absent, bytes_field),
            ));
        }
        if self.forged_before {
            out.push_str("evidence forged-before\n");
        }
        if self.forged_after {
            out.push_str("evidence forged-after\n");
        }
        for (label, millis) in &self.timings {
            out.push_str(&format!("timing {label} {millis}\n"));
        }
        out
    }

    fn parse(text: &str) -> Result<Self, String> {
        let number = |s: &str| s.parse::<u64>().ok();
        let count = |s: &str| s.parse::<usize>().ok();
        let slot = |s: &str| s.parse::<u16>().ok();
        let pass = |s: &str| s.parse::<u32>().ok();
        let mut out = Self::default();
        for (n, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let at = n + 1;
            let fields: Vec<&str> = line.split(' ').collect();
            match fields.as_slice() {
                ["done", label] => out.done.push((*label).to_owned()),
                ["identity", h] => out.identity = Some(required(h, at, parse_bytes)?),
                ["lookup", h] => out.lookup = Some(required(h, at, parse_bytes)?),
                ["hello-slot", s] => out.hello_slot = Some(required(s, at, slot)?),
                ["hello", h] => out.hello = Some(required(h, at, parse_bytes)?),
                ["forged-control-seq", s] => {
                    out.forged_control_seq = Some(required(s, at, number)?)
                }
                ["forged-control", h] => out.forged_control = Some(required(h, at, parse_bytes)?),
                ["pass", p, items, at_forged] => out.passes.push(PassLine {
                    pass: required(p, at, pass)?,
                    items: required(items, at, count)?,
                    at_forged_slot: required(at_forged, at, count)?,
                }),
                ["surfaced", p, kind, s, identity, lookup] => out.surfaced.push(SurfacedLine {
                    pass: required(p, at, pass)?,
                    kind: (*kind).to_owned(),
                    slot: optional(s, at, slot)?,
                    identity: optional(identity, at, parse_bytes)?,
                    lookup: optional(lookup, at, parse_bytes)?,
                }),
                ["evidence", "forged-before"] => out.forged_before = true,
                ["evidence", "forged-after"] => out.forged_after = true,
                ["timing", label, millis] => out
                    .timings
                    .push(((*label).to_owned(), required(millis, at, number)?)),
                _ => return Err(format!("line {at}: unknown record {line:?}")),
            }
        }
        Ok(out)
    }

    /// Read the file, or empty notes where there is none yet.
    fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display())),
            Err(_) => Self::default(),
        }
    }

    fn save(&self, path: &Path) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("the role's directory exists");
        }
        std::fs::write(path, self.encode()).expect("the notes file writes");
    }

    fn mark_done(&mut self, step: Step) {
        if !self.done.iter().any(|d| d == step.label()) {
            self.done.push(step.label().to_owned());
        }
    }
}

/// A field that must be present and parse.
fn required<T>(field: &str, at: usize, parse: impl Fn(&str) -> Option<T>) -> Result<T, String> {
    parse(field).ok_or_else(|| format!("line {at}: {field:?} does not parse"))
}

/// A field that is `-` or parses.
fn optional<T>(
    field: &str,
    at: usize,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<Option<T>, String> {
    if field == "-" {
        return Ok(None);
    }
    required(field, at, parse).map(Some)
}

/// Bytes as lowercase hex, or `~` for no bytes, so the field is never empty.
fn bytes_field(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "~".to_owned();
    }
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The inverse of [`bytes_field`]. `None` on an empty, odd-length or non-hex
/// string.
fn parse_bytes(text: &str) -> Option<Vec<u8>> {
    if text == "~" {
        return Some(Vec::new());
    }
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return None;
    }
    let raw = text.as_bytes();
    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

// ── the harness ──────────────────────────────────────────────────────────────

/// One child process this harness started.
struct Tracked {
    label: String,
    /// The role the child runs as, or `None` for a fixture that has none.
    role: Option<Role>,
    pid: u32,
    child: Child,
    status: Option<ExitStatus>,
    log: PathBuf,
}

/// Every step child this harness has started, and the process rules over them.
///
/// Both rules are values rather than panics, so a control can assert each one
/// fails.
struct Supervisor {
    state: PathBuf,
    tracked: Vec<Tracked>,
}

impl Supervisor {
    fn new(state: PathBuf) -> Self {
        Self {
            state,
            tracked: Vec::new(),
        }
    }

    /// Re-execute this test binary running `test_name` and nothing else, and
    /// return the child's index.
    fn spawn(
        &mut self,
        label: &str,
        role: Option<Role>,
        test_name: &str,
        env: &[(&str, &str)],
    ) -> std::io::Result<usize> {
        let exe = std::env::current_exe()?;
        let log = self
            .state
            .join(format!("{label}-{}.log", self.tracked.len()));
        let mut cmd = Command::new(exe);
        cmd.arg("--exact")
            .arg(test_name)
            .arg("--ignored")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .stdout(Stdio::inherit())
            .stderr(Stdio::from(File::create(&log)?));
        for (key, value) in env {
            cmd.env(key, value);
        }
        let child = cmd.spawn()?;
        eprintln!("harness: {label} started as pid {}", child.id());
        self.tracked.push(Tracked {
            label: label.to_owned(),
            role,
            pid: child.id(),
            child,
            status: None,
            log,
        });
        Ok(self.tracked.len() - 1)
    }

    /// Echo one child's captured output, and return it.
    fn drain_log(&self, index: usize) -> String {
        let text = std::fs::read_to_string(&self.tracked[index].log).unwrap_or_default();
        let label = &self.tracked[index].label;
        eprintln!("harness: ---- {label} ----\n{text}harness: ---- end {label} ----");
        text
    }

    /// Every unreaped child whose role `counts`, named.
    fn alive_where(&mut self, counts: impl Fn(Option<Role>) -> bool) -> Vec<String> {
        let mut alive = Vec::new();
        for tracked in &mut self.tracked {
            if tracked.status.is_some() {
                continue;
            }
            match tracked.child.try_wait() {
                Ok(Some(status)) => tracked.status = Some(status),
                Ok(None) if counts(tracked.role) => {
                    alive.push(format!("{} (pid {})", tracked.label, tracked.pid))
                }
                Ok(None) => {}
                Err(e) => alive.push(format!("{} (pid {}): {e}", tracked.label, tracked.pid)),
            }
        }
        alive
    }

    /// At a step boundary, no step process exists.
    fn boundary_is_clear(&mut self) -> Result<(), String> {
        let alive = self.alive_where(|_| true);
        if alive.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "still running at the boundary: {}",
                alive.join(", ")
            ))
        }
    }

    /// While `role` runs, no process of any other role exists.
    fn no_other_role_alive(&mut self, role: Role) -> Result<(), String> {
        let alive = self.alive_where(|other| other.is_some_and(|other| other != role));
        if alive.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "another role is running while {} runs: {}",
                role.name(),
                alive.join(", ")
            ))
        }
    }

    /// Wait for the child at `index`, asserting the role rule on every look,
    /// and killing it if it outlasts `budget`.
    fn wait_exclusive(
        &mut self,
        index: usize,
        role: Option<Role>,
        budget: Duration,
    ) -> Result<ExitStatus, String> {
        let started = Instant::now();
        loop {
            if let Some(role) = role {
                self.no_other_role_alive(role)?;
            }
            let tracked = &mut self.tracked[index];
            if let Some(status) = tracked.status {
                return Ok(status);
            }
            match tracked.child.try_wait() {
                Ok(Some(status)) => {
                    tracked.status = Some(status);
                    return Ok(status);
                }
                Ok(None) if started.elapsed() >= budget => {
                    let _ = tracked.child.kill();
                    tracked.status = tracked.child.wait().ok();
                    return Err(format!(
                        "{} did not exit within {}s",
                        tracked.label,
                        budget.as_secs()
                    ));
                }
                Ok(None) => std::thread::sleep(CHILD_POLL),
                Err(e) => return Err(format!("{}: {e}", tracked.label)),
            }
        }
    }

    /// Spawn one child with the boundary clear, wait for it under the role
    /// rule, and report what its exit status and output say.
    fn run_child(
        &mut self,
        label: &str,
        role: Option<Role>,
        test_name: &str,
        env: &[(&str, &str)],
    ) -> Result<(), String> {
        self.boundary_is_clear()?;
        let index = self
            .spawn(label, role, test_name, env)
            .map_err(|e| format!("{label} did not spawn: {e}"))?;
        let waited = self.wait_exclusive(index, role, STEP_BUDGET);
        let text = self.drain_log(index);
        let status = waited?;
        if status.success() {
            return Ok(());
        }
        let lines: Vec<&str> = text.lines().collect();
        let tail = &lines[lines.len().saturating_sub(STDERR_TAIL_LINES)..];
        Err(format!(
            "{label} exited {status:?}; its last {} line(s):\n{}",
            tail.len(),
            tail.join("\n")
        ))
    }

    fn kill_all(&mut self) {
        for tracked in &mut self.tracked {
            if tracked.status.is_some() {
                continue;
            }
            let _ = tracked.child.kill();
            tracked.status = tracked.child.wait().ok();
        }
    }

    /// Run one step to a clean exit, then read back its own record that it ran.
    fn run_to_exit(&mut self, step: Step) {
        let state = self.state.to_string_lossy().into_owned();
        let env = [(ENV_STATE, state.as_str()), (ENV_ROLE, step.role().name())];
        if let Err(e) = self.run_child(step.label(), Some(step.role()), step.test_name(), &env) {
            panic!("{e}");
        }
        let notes = Notes::load(&step.role().notes_path(&self.state));
        ran(step, &notes).unwrap_or_else(|e| panic!("{e}"));
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.kill_all();
    }
}

/// Whether a step's notes record that it ran.
///
/// A `--exact` name matching no test runs nothing and exits 0, which is
/// otherwise indistinguishable from a step that did its work.
fn ran(step: Step, notes: &Notes) -> Result<(), String> {
    if notes.done.iter().any(|d| d == step.label()) {
        Ok(())
    } else {
        Err(format!(
            "{} left no record of having run; its notes name {:?}",
            step.label(),
            notes.done
        ))
    }
}

// ── the oracle ───────────────────────────────────────────────────────────────

/// Lay out a fresh state directory: one recovery phrase per role.
fn lay_out_state(state: &Path) {
    for role in ROLES {
        std::fs::create_dir_all(role.dir(state)).expect("the role's directory is created");
        let phrase = Mnemonic::generate()
            .expect("the operating system's generator")
            .to_phrase();
        std::fs::write(role.recovery_phrase_path(state), phrase)
            .expect("the recovery phrase writes");
    }
}

/// FC4's end state, from the three roles' notes.
///
/// A value rather than a set of assertions so the tests at the foot of this
/// file can show each clause fails on the input it exists to refuse.
fn attributed_to_the_signer(a: &Notes, b: &Notes, c: &Notes) -> Result<(), String> {
    let a_pk = a.identity.as_ref().ok_or("A recorded no identity")?;
    let c_pk = c.identity.as_ref().ok_or("C recorded no identity")?;
    let a_lookup = a.lookup.as_ref().ok_or("A recorded no channel")?;
    let c_lookup = c.lookup.as_ref().ok_or("C recorded no channel")?;
    let a_slot = a.hello_slot.ok_or("A recorded no hello slot")?;
    let c_slot = c.hello_slot.ok_or("C recorded no hello slot")?;
    if a_pk == c_pk {
        return Err("A and C hold the same identity key, so attribution proves nothing".into());
    }
    if a_slot == c_slot {
        return Err(format!(
            "A's and C's hellos share slot {c_slot}: slot collision, re-run"
        ));
    }
    if b.passes.is_empty() {
        return Err("B recorded no collection pass".into());
    }

    let a_request = |line: &SurfacedLine| {
        line.kind == "request"
            && line.identity.as_ref() == Some(a_pk)
            && line.lookup.as_ref() == Some(a_lookup)
            && line.slot == Some(a_slot)
    };
    if !b.surfaced.iter().any(a_request) {
        return Err(format!(
            "B surfaced no contact request under A's identity key, on A's channel, at A's slot; \
             B surfaced {:?}",
            b.surfaced
        ));
    }

    if !b.forged_before {
        return Err(
            "B never saw C's hello and forged opening on the network before collecting, so \
             their refusal proves nothing"
                .into(),
        );
    }
    if !b.forged_after {
        return Err(
            "B's copies of C's hello and forged opening did not match after B's passes, so B \
             may have collected without them"
                .into(),
        );
    }

    for pass in &b.passes {
        if pass.at_forged_slot > 0 {
            return Err(format!(
                "pass {} surfaced {} item(s) at C's slot",
                pass.pass, pass.at_forged_slot
            ));
        }
    }

    for line in &b.surfaced {
        if line.identity.as_ref() == Some(a_pk) && !a_request(line) {
            if line.lookup.as_ref() == Some(c_lookup) || line.slot == Some(c_slot) {
                return Err(format!(
                    "the hello C forged under A's name was surfaced as A: {line:?}"
                ));
            }
            return Err(format!(
                "an item other than A's request is attributed to A: {line:?}"
            ));
        }
        if line.lookup.as_ref() == Some(c_lookup) {
            return Err(format!(
                "an item on C's channel was surfaced; the forged opening cannot verify, so B \
                 read something other than the forgery: {line:?}"
            ));
        }
        if line.slot == Some(c_slot) {
            return Err(format!("an item at C's hello slot was surfaced: {line:?}"));
        }
        if line.identity.as_ref() == Some(c_pk) {
            return Err(format!(
                "an item under C's key was surfaced, so B verified an opening C signed rather \
                 than the forgery: {line:?}"
            ));
        }
    }
    Ok(())
}

/// A copy of `genuine` whose writer field claims `claimed`, with the signature
/// left as it was.
fn forge_writer(genuine: &ChannelOpening, claimed: &[u8; IDENTITY_PK_LEN]) -> ChannelOpening {
    let mut forged = ChannelOpening::decode(&genuine.encode()).expect("an opening round-trips");
    forged.writer_identity_pk = Box::new(*claimed);
    forged
}

/// FC4's probe on the live network.
#[test]
#[ignore = "attaches to the public Veilid network, one process per step; opt-in, run with --ignored"]
fn a_first_contact_made_while_b_is_offline_is_found_attributed_to_a() {
    let state = tempfile::tempdir().expect("a state directory");
    lay_out_state(state.path());
    let mut supervisor = Supervisor::new(state.path().to_path_buf());

    for step in SEQUENCE {
        supervisor.run_to_exit(step);
    }

    let [a, b, c] = ROLES.map(|role| Notes::load(&role.notes_path(state.path())));
    for notes in [&a, &b, &c] {
        for (label, millis) in &notes.timings {
            eprintln!("timing: {label} took {:.1}s", *millis as f64 / 1000.0);
        }
    }
    for pass in &b.passes {
        eprintln!(
            "pass {}: {} item(s), {} at C's slot",
            pass.pass, pass.items, pass.at_forged_slot
        );
    }
    attributed_to_the_signer(&a, &b, &c)
        .expect("B finds A's request under A's key, and C's forgery is not shown as anyone");
}

// ── one step, as a process ───────────────────────────────────────────────────

fn fill(buf: &mut [u8]) -> Result<(), ()> {
    getrandom::fill(buf).map_err(|_| ())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs()
}

/// This role's identity, derived from the recovery phrase its directory holds.
fn identity_of(role: Role, state: &Path) -> IdentityKeys {
    let path = role.recovery_phrase_path(state);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mnemonic = Mnemonic::from_phrase(text.trim()).expect("the recovery phrase parses");
    derive_identity_keys(&mnemonic, Identity::Primary)
        .expect("the identity derives from its phrase")
}

fn store_of(role: Role, state: &Path) -> Store {
    Store::open(role.dir(state).join("dm-flows"), &AT_REST).expect("the store opens")
}

/// Publish this role's advert under the keys its store holds, minting and
/// persisting them first where there are none.
fn publish_advert(store: &Store, records: &mut VeilidRecords, signer: &SignKeypair) -> AdvertKeys {
    let keys = match store.load_advert_keys().expect("the advert keys read") {
        Some(snapshot) => AdvertKeys::restore(snapshot),
        None => {
            let keys = AdvertKeys::new(now_secs(), fill).expect("advert keys mint");
            store
                .persist_advert_keys(&keys.snapshot())
                .expect("the advert keys persist");
            keys
        }
    };
    let bytes = keys.advert_bytes(signer).expect("the advert signs");
    let owner = advert::derive_owner_seed(signer.public_key()).expect("the advert owner seed");
    records
        .publish_advert(&owner, advert::ADVERT_SUBKEYS, &bytes)
        .expect("the advert publishes");
    keys
}

/// An identity key another role wrote into its notes.
fn identity_from(notes: &Notes, role: Role) -> [u8; IDENTITY_PK_LEN] {
    let bytes = notes
        .identity
        .as_deref()
        .unwrap_or_else(|| panic!("{} has written no identity", role.name()));
    <[u8; IDENTITY_PK_LEN]>::try_from(bytes).expect("an identity key")
}

/// Retry `attempt` on [`POLL`] until it answers, or fail naming the hop.
async fn until<T>(hop: &str, budget: Duration, mut attempt: impl FnMut() -> Option<T>) -> T {
    let started = Instant::now();
    let mut tries = 0u32;
    loop {
        tries += 1;
        if let Some(found) = attempt() {
            eprintln!(
                "[{:>7.1}s] {hop} — after {tries} attempt(s)",
                started.elapsed().as_secs_f64()
            );
            return found;
        }
        assert!(
            started.elapsed() < budget,
            "timed out after {}s over {tries} attempt(s) waiting for {hop}",
            budget.as_secs()
        );
        tokio::time::sleep(POLL).await;
    }
}

/// Knock at `recipient`, retrying only while its advert has not arrived, and
/// return the conversation's lookup key, hello slot and sealed hello bytes.
async fn knock(
    store: &Store,
    records: &mut VeilidRecords,
    me: &Me<'_>,
    recipient: &[u8; IDENTITY_PK_LEN],
    body: &str,
) -> ([u8; 32], u16, Vec<u8>) {
    let outcome = until(
        "the recipient's advert, and a knock into its drop",
        HOP,
        || match flows::first_contact(
            store,
            records,
            me,
            recipient,
            body.as_bytes(),
            fill,
            now_secs(),
        ) {
            Ok(outcome) => Some(outcome),
            Err(FlowError::NoAdvert) => None,
            Err(e) => panic!("the knock failed: {e}"),
        },
    )
    .await;
    let FirstContact::Opened {
        peer,
        outgoing_lookup_key,
        hello_slot,
        ..
    } = outcome
    else {
        panic!("a first knock opens a conversation; it was {outcome:?}");
    };
    let conv = store
        .load_conv(&peer)
        .expect("the store answers")
        .expect("the conversation record exists");
    let hello = conv
        .outstanding_hello
        .as_ref()
        .expect("the hello is persisted until it is collected");
    assert_eq!(
        hello.slot, hello_slot,
        "the persisted hello is the one written"
    );
    (outgoing_lookup_key, hello_slot, hello.sealed.to_vec())
}

async fn run_step(step: Step) {
    let Some(state) = std::env::var_os(ENV_STATE) else {
        eprintln!(
            "{}: no {ENV_STATE} — this is a child process of the driver test in this \
             file, and does nothing on its own",
            step.label()
        );
        return;
    };
    let state = PathBuf::from(state);
    let role = step.role();
    let named_role = std::env::var(ENV_ROLE)
        .ok()
        .and_then(|name| Role::from_name(&name))
        .expect("the role in the environment is one this file knows");
    assert_eq!(
        named_role,
        role,
        "{}: spawned as the wrong role",
        step.label()
    );

    daemonseed_core::kats::initialize_module_unsigned_test_binary().expect("oxicrypt init");
    let started = Instant::now();

    let keys = identity_of(role, &state);
    let signer = &keys.signing;
    let me = Me {
        signer,
        channel_root: &keys.dm_channel_root,
    };

    let (node, _events) = VeilidNet::start(node_config(role, &role.dir(&state).join("node")))
        .await
        .expect("the node starts");
    node.attach_and_wait(ATTACH_SECS)
        .await
        .expect("the node reaches the public network");
    let mut records = VeilidRecords::new(
        node.dm_records_parts()
            .await
            .expect("the node hands out its transport"),
    )
    .expect("a step runs on a multi-thread runtime");

    let store = store_of(role, &state);
    let advert_keys = publish_advert(&store, &mut records, signer);
    let mut notes = Notes::load(&role.notes_path(&state));
    notes.identity = Some(signer.public_key().to_vec());

    match step {
        Step::BPublishes => {}
        Step::AKnocks => a_knocks(&store, &mut records, &me, &state, &mut notes).await,
        Step::CForges => c_forges(&store, &mut records, &me, &state, &mut notes).await,
        Step::BCollects => {
            b_collects(&store, &mut records, &me, &advert_keys, &state, &mut notes).await
        }
    }

    notes.mark_done(step);
    notes.timings.push((
        step.label().to_owned(),
        started.elapsed().as_millis() as u64,
    ));
    notes.save(&role.notes_path(&state));
    node.shutdown(NODE_CLOSE).await;
}

/// A publishes (above) and knocks at the identity B published.
async fn a_knocks(
    store: &Store,
    records: &mut VeilidRecords,
    me: &Me<'_>,
    state: &Path,
    notes: &mut Notes,
) {
    let recipient = identity_from(&Notes::load(&Role::B.notes_path(state)), Role::B);
    let (lookup, slot, hello) = knock(store, records, me, &recipient, MESSAGE_0).await;
    eprintln!("A: knocked into slot {slot}");
    notes.lookup = Some(lookup.to_vec());
    notes.hello_slot = Some(slot);
    notes.hello = Some(hello);
}

/// C knocks at B, then overwrites its own opening with one naming A as the
/// writer, under C's signature, and records what it wrote.
async fn c_forges(
    store: &Store,
    records: &mut VeilidRecords,
    me: &Me<'_>,
    state: &Path,
    notes: &mut Notes,
) {
    let recipient = identity_from(&Notes::load(&Role::B.notes_path(state)), Role::B);
    let claimed = identity_from(&Notes::load(&Role::A.notes_path(state)), Role::A);
    let (lookup, slot, hello) = knock(store, records, me, &recipient, FORGED_BODY).await;

    let loaded = store.load().expect("C's store reloads");
    let conv = loaded
        .convs
        .iter()
        .find(|conv| conv.state.outgoing_lookup_key == lookup)
        .expect("C's conversation record exists");
    let genuine = ChannelOpening::decode(
        conv.state
            .own_opening
            .as_deref()
            .expect("C's opening is persisted")
            .as_slice(),
    )
    .expect("C's opening decodes");
    let forged = forge_writer(&genuine, &claimed);

    // The control on the forgery: C's own opening verifies for B and the
    // forged one does not, so what B refuses is the claim.
    genuine
        .verify(&recipient, &lookup, genuine.advert_serial)
        .expect("C's genuine opening verifies");
    assert!(
        forged
            .verify(&recipient, &lookup, forged.advert_serial)
            .is_err(),
        "an opening claiming A as writer under C's signature must not verify"
    );

    let key = conv
        .state
        .own_control_key
        .as_ref()
        .expect("C's control key is persisted");
    let sealed = channel::seal_control_with_key(
        key,
        &Control {
            opening: Some(forged),
            collected_cursor: 0,
            closed: false,
        },
    )
    .expect("the forged control seals");
    records
        .write_channel(&lookup, channel::CONTROL_SUBKEY, &sealed)
        .expect("C overwrites its own control subkey");
    let seq = until(
        "C's forged control write has a sequence number",
        HOP,
        || {
            let reports = records.inspect_channel(&lookup).ok()?;
            let control = reports.get(usize::from(channel::CONTROL_SUBKEY))?;
            (!control.pending).then_some(control.local_seq?)
        },
    )
    .await;
    eprintln!("C: hello in slot {slot}, forged opening written at sequence {seq}");
    notes.lookup = Some(lookup.to_vec());
    notes.hello_slot = Some(slot);
    notes.hello = Some(hello);
    notes.forged_control_seq = Some(seq);
    notes.forged_control = Some(sealed);
}

/// What B has to find on the network for the negative arm to mean anything.
struct Forged {
    slot: u16,
    hello: Vec<u8>,
    lookup: [u8; 32],
    control_seq: u64,
    control: Vec<u8>,
    /// A's hello, so a slot holding it is reported as a collision.
    a_hello: Vec<u8>,
}

/// `Some` once C's slot holds exactly C's hello and C's control subkey holds
/// exactly the forged bytes at a network number no lower than C's write.
fn forged_on_network(
    records: &mut VeilidRecords,
    drop_owner: &drop_plane::DropOwnerSeed,
    forged: &Forged,
) -> Option<()> {
    // Slot 0 takes a fresh scan of the drop; a single-slot read is answered
    // from whatever scan is current, and a stale one would skip the read.
    let _ = records.read_drop_slot(drop_owner, drop_plane::DROP_SUBKEYS, 0);
    let slot_bytes = records
        .read_drop_slot(drop_owner, drop_plane::DROP_SUBKEYS, forged.slot)
        .ok()??;
    assert!(
        slot_bytes != forged.a_hello,
        "C's slot {} holds A's hello: slot collision, re-run",
        forged.slot
    );
    if slot_bytes != forged.hello {
        return None;
    }
    let reports = records.inspect_channel(&forged.lookup).ok()?;
    let network = reports
        .get(usize::from(channel::CONTROL_SUBKEY))?
        .network_seq?;
    if network < forged.control_seq {
        return None;
    }
    let control = records
        .read_channel(&forged.lookup, channel::CONTROL_SUBKEY)
        .ok()??;
    (control == forged.control).then_some(())
}

/// B, with A and C both stopped, confirms the forged hello is on the network,
/// collects until A's request surfaces, and confirms it is still there.
async fn b_collects(
    store: &Store,
    records: &mut VeilidRecords,
    me: &Me<'_>,
    advert_keys: &AdvertKeys,
    state: &Path,
    notes: &mut Notes,
) {
    let a_notes = Notes::load(&Role::A.notes_path(state));
    let c_notes = Notes::load(&Role::C.notes_path(state));
    let a_pk = identity_from(&a_notes, Role::A);
    let a_slot = a_notes.hello_slot.expect("A recorded its hello slot");
    let forged = Forged {
        slot: c_notes.hello_slot.expect("C recorded its hello slot"),
        hello: c_notes.hello.clone().expect("C recorded its hello"),
        lookup: c_notes
            .lookup
            .as_deref()
            .and_then(|l| l.try_into().ok())
            .expect("C recorded its channel"),
        control_seq: c_notes
            .forged_control_seq
            .expect("C recorded its control write's sequence"),
        control: c_notes
            .forged_control
            .clone()
            .expect("C recorded its control write"),
        a_hello: a_notes.hello.clone().expect("A recorded its hello"),
    };
    assert_ne!(
        a_slot, forged.slot,
        "A's and C's hellos landed in the same slot: slot collision, re-run"
    );
    let drop_owner =
        drop_plane::derive_owner_seed(me.signer.public_key()).expect("B's drop owner seed");

    until(
        "C's hello and forged opening are on the network",
        DROP_SCAN_HOP,
        || forged_on_network(records, &drop_owner, &forged),
    )
    .await;
    notes.forged_before = true;

    let mut pass = 0u32;
    until("A's request surfaces in B's drop", DROP_SCAN_HOP, || {
        pass += 1;
        let surfaced = flows::collect(store, records, me, advert_keys, |_| false)
            .expect("B's own store answers");
        let lines: Vec<SurfacedLine> = surfaced.iter().map(|one| line_of(pass, one)).collect();
        let found = lines.iter().any(|line| {
            line.kind == "request" && line.identity.as_deref() == Some(a_pk.as_slice())
        });
        notes.passes.push(PassLine {
            pass,
            items: lines.len(),
            at_forged_slot: lines
                .iter()
                .filter(|line| line.slot == Some(forged.slot))
                .count(),
        });
        eprintln!("B: pass {pass} surfaced {surfaced:?}");
        notes.surfaced.extend(lines);
        found.then_some(())
    })
    .await;

    until(
        "C's hello and forged opening still match through B's own node",
        HOP,
        || forged_on_network(records, &drop_owner, &forged),
    )
    .await;
    notes.forged_after = true;
}

/// One surfaced item as B writes it down.
fn line_of(pass: u32, one: &Surfaced) -> SurfacedLine {
    let named = |kind: &str, identity: &[u8]| SurfacedLine {
        pass,
        kind: kind.to_owned(),
        slot: None,
        identity: Some(identity.to_vec()),
        lookup: None,
    };
    match one {
        Surfaced::ContactRequest(request) => SurfacedLine {
            pass,
            kind: "request".to_owned(),
            slot: Some(request.slot),
            identity: Some(request.identity.to_vec()),
            lookup: Some(request.lookup_key.to_vec()),
        },
        Surfaced::Dropped { identity } => named("dropped", identity.as_slice()),
        Surfaced::StartedOver { identity, .. } => named("started-over", identity.as_slice()),
        Surfaced::Failed { identity, .. } => named("failed", identity.as_slice()),
        Surfaced::AlreadyCollected { identity } => named("already-collected", identity.as_slice()),
        Surfaced::Accepted(_) => SurfacedLine {
            pass,
            kind: "accepted".to_owned(),
            slot: None,
            identity: None,
            lookup: None,
        },
    }
}

/// The steps, as the test functions the driver re-executes. Each is a
/// multi-thread runtime because the record store blocks its worker.
mod steps {
    use super::{run_step, Step};

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "one step of this file's driver test; it is spawned by it, with its state directory in the environment"]
    async fn b_publishes_its_advert() {
        run_step(Step::BPublishes).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "one step of this file's driver test; it is spawned by it, with its state directory in the environment"]
    async fn a_knocks_while_b_is_offline() {
        run_step(Step::AKnocks).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "one step of this file's driver test; it is spawned by it, with its state directory in the environment"]
    async fn c_forges_a_hello_under_as_name() {
        run_step(Step::CForges).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "one step of this file's driver test; it is spawned by it, with its state directory in the environment"]
    async fn b_collects_after_a_has_stopped() {
        run_step(Step::BCollects).await;
    }
}

/// A node config with a fresh node identity, this role's port and its own
/// storage directory.
fn node_config(role: Role, dir: &Path) -> VeilidNetConfig {
    let id = derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap();
    let mut cfg = VeilidNetConfig::new(id.veilid_node_seed, dir.to_string_lossy().into_owned());
    cfg.namespace = format!("two_node_dm_offline_{}", role.name());
    cfg.listen_address = Some(role.port().to_owned());
    cfg
}

// ── the harness's own tests, which need no network ───────────────────────────

/// How long the holding fixture holds.
const FIXTURE_HOLD: Duration = Duration::from_secs(30);

/// What a fixture step is given to start, write its file and exit.
const FIXTURE_BUDGET: Duration = Duration::from_secs(60);

/// Fixture steps for the harness tests. None touches the network; each writes
/// a file first, which is the positive control on the spawn itself.
mod fakes {
    use std::path::PathBuf;

    #[test]
    #[ignore = "a fixture process for this file's harness tests; it is spawned, never run on its own"]
    fn a_step_that_exits_at_once() {
        if let Some(state) = std::env::var_os(super::ENV_STATE) {
            std::fs::write(PathBuf::from(state).join("fixture-exited"), "exited")
                .expect("the fixture's file writes");
        }
    }

    #[test]
    #[ignore = "a fixture process for this file's harness tests; it is spawned, never run on its own"]
    fn a_step_that_fails() {
        if let Some(state) = std::env::var_os(super::ENV_STATE) {
            std::fs::write(PathBuf::from(state).join("fixture-failed"), "failed")
                .expect("the fixture's file writes");
        }
        panic!("this step could not do its part of the run");
    }

    #[test]
    #[ignore = "a fixture process for this file's harness tests; it is spawned, never run on its own"]
    fn a_step_that_outlives_its_boundary() {
        if let Some(state) = std::env::var_os(super::ENV_STATE) {
            std::fs::write(PathBuf::from(state).join("fixture-holding"), "holding")
                .expect("the fixture's file writes");
        }
        std::thread::sleep(super::FIXTURE_HOLD);
    }
}

fn wait_for_file(path: &Path, budget: Duration) {
    let started = Instant::now();
    while !path.exists() {
        assert!(
            started.elapsed() < budget,
            "{} did not appear within {}s",
            path.display(),
            budget.as_secs()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_step_that_has_exited_leaves_the_boundary_clear() {
    let state = tempfile::tempdir().expect("a state directory");
    let dir = state.path().to_string_lossy().into_owned();
    let mut supervisor = Supervisor::new(state.path().to_path_buf());

    supervisor
        .run_child(
            "exits",
            Some(Role::A),
            "fakes::a_step_that_exits_at_once",
            &[(ENV_STATE, dir.as_str())],
        )
        .expect("the fixture step exits cleanly");
    assert!(
        state.path().join("fixture-exited").exists(),
        "the fixture step must actually have run"
    );
    supervisor
        .boundary_is_clear()
        .expect("a step that has been waited for leaves the boundary clear");
}

/// The control: a live step fails the boundary check made before every spawn.
#[test]
fn a_step_that_outlives_its_boundary_fails_the_boundary_check() {
    let state = tempfile::tempdir().expect("a state directory");
    let dir = state.path().to_string_lossy().into_owned();
    let mut supervisor = Supervisor::new(state.path().to_path_buf());

    supervisor
        .spawn(
            "outlives",
            Some(Role::A),
            "fakes::a_step_that_outlives_its_boundary",
            &[(ENV_STATE, dir.as_str())],
        )
        .expect("the fixture spawns");
    wait_for_file(&state.path().join("fixture-holding"), FIXTURE_BUDGET);

    let failure = supervisor
        .boundary_is_clear()
        .expect_err("a live step must fail the boundary check");
    assert!(
        failure.contains("outlives"),
        "the failure names the step: {failure}"
    );
    let refused = supervisor
        .run_child(
            "next",
            Some(Role::A),
            "fakes::a_step_that_exits_at_once",
            &[(ENV_STATE, dir.as_str())],
        )
        .expect_err("a step must not start while another is running");
    assert!(
        refused.contains("outlives"),
        "the refusal names the step: {refused}"
    );

    supervisor.kill_all();
    supervisor
        .boundary_is_clear()
        .expect("the boundary is clear once the step is killed and reaped");
}

/// A live process of B fails the rule A's steps run under, and not the rule
/// B's own steps run under.
#[test]
fn a_live_process_of_another_role_fails_the_role_check() {
    let state = tempfile::tempdir().expect("a state directory");
    let dir = state.path().to_string_lossy().into_owned();
    let mut supervisor = Supervisor::new(state.path().to_path_buf());

    supervisor
        .spawn(
            "b-lingers",
            Some(Role::B),
            "fakes::a_step_that_outlives_its_boundary",
            &[(ENV_STATE, dir.as_str())],
        )
        .expect("the fixture spawns");
    wait_for_file(&state.path().join("fixture-holding"), FIXTURE_BUDGET);

    let failure = supervisor
        .no_other_role_alive(Role::A)
        .expect_err("B alive while A runs must fail");
    assert!(
        failure.contains("b-lingers"),
        "the failure names B's process: {failure}"
    );
    supervisor
        .no_other_role_alive(Role::B)
        .expect("B's own process does not fail B's rule");

    supervisor.kill_all();
    supervisor
        .no_other_role_alive(Role::A)
        .expect("nothing of B's is alive once it is reaped");
}

#[test]
fn a_step_that_fails_is_reported_with_its_own_output() {
    let state = tempfile::tempdir().expect("a state directory");
    let dir = state.path().to_string_lossy().into_owned();
    let mut supervisor = Supervisor::new(state.path().to_path_buf());

    let failure = supervisor
        .run_child(
            "fails",
            Some(Role::C),
            "fakes::a_step_that_fails",
            &[(ENV_STATE, dir.as_str())],
        )
        .expect_err("a step that fails must fail the driver");
    assert!(
        state.path().join("fixture-failed").exists(),
        "the fixture must have run"
    );
    assert!(
        failure.contains("fails exited"),
        "names the step: {failure}"
    );
    assert!(
        failure.contains("could not do its part of the run"),
        "quotes the step's own output: {failure}"
    );
}

#[test]
fn a_step_with_no_record_of_running_is_refused() {
    let mut notes = Notes::default();
    ran(Step::AKnocks, &notes).expect_err("empty notes are not a step that ran");
    notes.mark_done(Step::BPublishes);
    ran(Step::AKnocks, &notes).expect_err("another step's record is not this step's");
    notes.mark_done(Step::AKnocks);
    notes.mark_done(Step::AKnocks);
    ran(Step::AKnocks, &notes).expect("a recorded step ran");
    assert_eq!(
        notes.done,
        vec!["b-publishes".to_owned(), "a-knocks".to_owned()]
    );
}

#[test]
fn a_notes_file_round_trips_and_refuses_what_it_did_not_write() {
    let written = Notes {
        done: vec!["b-collects".to_owned()],
        identity: Some(vec![0xab; IDENTITY_PK_LEN]),
        lookup: Some(vec![0x01; 32]),
        hello_slot: Some(17),
        hello: Some(Vec::new()),
        forged_control_seq: Some(4),
        forged_control: Some(vec![0x5c; 12]),
        passes: vec![
            PassLine {
                pass: 1,
                items: 0,
                at_forged_slot: 0,
            },
            PassLine {
                pass: 2,
                items: 2,
                at_forged_slot: 0,
            },
        ],
        surfaced: vec![
            SurfacedLine {
                pass: 2,
                kind: "request".to_owned(),
                slot: Some(3),
                identity: Some(vec![0x10; IDENTITY_PK_LEN]),
                lookup: Some(vec![0x20; 32]),
            },
            SurfacedLine {
                pass: 2,
                kind: "accepted".to_owned(),
                slot: None,
                identity: None,
                lookup: None,
            },
        ],
        forged_before: true,
        forged_after: true,
        timings: vec![("b-collects".to_owned(), 1234)],
    };
    assert_eq!(Notes::parse(&written.encode()).expect("parses"), written);

    let state = tempfile::tempdir().expect("a state directory");
    let path = Role::B.notes_path(state.path());
    written.save(&path);
    assert_eq!(Notes::load(&path), written);
    assert_eq!(
        Notes::load(&Role::A.notes_path(state.path())),
        Notes::default()
    );

    assert!(Notes::parse("nonsense 1").is_err());
    assert!(Notes::parse("identity zz").is_err());
    assert!(
        Notes::parse("hello -").is_err(),
        "a byte field is never absent"
    );
    assert!(Notes::parse("hello-slot notanumber").is_err());
    assert!(Notes::parse("pass 1 2").is_err());
    assert!(Notes::parse("surfaced 1 request 3 ab").is_err());
    assert!(Notes::parse("evidence something-else").is_err());
    assert!(Notes::parse("done a-knocks\nhello ~\nevidence forged-before\n").is_ok());
}

/// Notes for the end-state tests: A's request surfaced in pass 2 of two, the
/// forged hello on the network before and after, nothing at C's slot.
fn attribution_fixture() -> (Notes, Notes, Notes) {
    let a = Notes {
        identity: Some(vec![0x0a; IDENTITY_PK_LEN]),
        lookup: Some(vec![0xa1; 32]),
        hello_slot: Some(3),
        ..Notes::default()
    };
    let c = Notes {
        identity: Some(vec![0x0c; IDENTITY_PK_LEN]),
        lookup: Some(vec![0xc1; 32]),
        hello_slot: Some(9),
        ..Notes::default()
    };
    let b = Notes {
        passes: vec![
            PassLine {
                pass: 1,
                items: 0,
                at_forged_slot: 0,
            },
            PassLine {
                pass: 2,
                items: 1,
                at_forged_slot: 0,
            },
        ],
        surfaced: vec![request(2, 3, &[0x0a; IDENTITY_PK_LEN], &[0xa1; 32])],
        forged_before: true,
        forged_after: true,
        ..Notes::default()
    };
    (a, b, c)
}

fn request(pass: u32, slot: u16, identity: &[u8], lookup: &[u8]) -> SurfacedLine {
    SurfacedLine {
        pass,
        kind: "request".to_owned(),
        slot: Some(slot),
        identity: Some(identity.to_vec()),
        lookup: Some(lookup.to_vec()),
    }
}

fn named(pass: u32, kind: &str, identity: &[u8]) -> SurfacedLine {
    SurfacedLine {
        pass,
        kind: kind.to_owned(),
        slot: None,
        identity: Some(identity.to_vec()),
        lookup: None,
    }
}

#[test]
fn the_end_state_check_catches_each_way_attribution_can_fail() {
    let (a, b, c) = attribution_fixture();
    attributed_to_the_signer(&a, &b, &c).expect("A's request under A's key passes");
    let a_pk = a.identity.clone().expect("fixture");
    let c_pk = c.identity.clone().expect("fixture");
    let a_lookup = a.lookup.clone().expect("fixture");
    let c_lookup = c.lookup.clone().expect("fixture");
    let third = vec![0x0e; IDENTITY_PK_LEN];
    let fails = |b: &Notes, what: &str, needle: &str| {
        let failure = attributed_to_the_signer(&a, b, &c).expect_err(what);
        assert!(failure.contains(needle), "{what}: {failure}");
    };

    let mut none = b.clone();
    none.surfaced.clear();
    fails(&none, "no request from A", "no contact request");

    let mut near = a_pk.clone();
    *near.last_mut().expect("a key has bytes") ^= 1;
    let mut one_byte_off = b.clone();
    one_byte_off.surfaced = vec![request(2, 3, &near, &a_lookup)];
    fails(
        &one_byte_off,
        "a key one byte from A's",
        "no contact request",
    );

    let mut wrong_channel = b.clone();
    wrong_channel.surfaced = vec![request(2, 3, &a_pk, &[0xee; 32])];
    fails(
        &wrong_channel,
        "A's key on another channel",
        "no contact request",
    );

    let mut wrong_slot = b.clone();
    wrong_slot.surfaced.push(request(2, 5, &a_pk, &a_lookup));
    fails(
        &wrong_slot,
        "A's request at a slot A did not write",
        "attributed to A",
    );

    let mut forged_as_a = b.clone();
    forged_as_a.surfaced.push(request(2, 9, &a_pk, &c_lookup));
    fails(&forged_as_a, "the forged hello surfaced as A", "forged");

    let mut a_failed = b.clone();
    a_failed.surfaced.push(named(1, "failed", &a_pk));
    fails(
        &a_failed,
        "A's key on a non-request item",
        "attributed to A",
    );

    // The genuine opening read instead of the forgery: C's own request.
    let mut genuine_read = b.clone();
    genuine_read.surfaced.push(request(2, 9, &c_pk, &c_lookup));
    fails(
        &genuine_read,
        "a C-keyed request on C's channel",
        "C's channel",
    );

    let mut third_on_c = b.clone();
    third_on_c.surfaced.push(request(1, 11, &third, &c_lookup));
    fails(&third_on_c, "a third key on C's channel", "C's channel");

    let mut at_c_slot = b.clone();
    at_c_slot.surfaced.push(request(1, 9, &third, &[0xdd; 32]));
    fails(&at_c_slot, "an item at C's slot", "C's hello slot");

    let mut c_keyed = b.clone();
    c_keyed.surfaced.push(named(2, "started-over", &c_pk));
    fails(&c_keyed, "an item under C's key anywhere", "under C's key");

    let mut counted = b.clone();
    counted.passes[0].at_forged_slot = 1;
    fails(&counted, "a pass with an item at C's slot", "at C's slot");

    let mut no_passes = b.clone();
    no_passes.passes.clear();
    fails(&no_passes, "no collection pass", "no collection pass");

    let mut not_before = b.clone();
    not_before.forged_before = false;
    fails(
        &not_before,
        "the forgery unseen before",
        "before collecting",
    );
    let mut not_after = b.clone();
    not_after.forged_after = false;
    fails(&not_after, "the forgery gone after", "after B's passes");

    let same_key = Notes {
        identity: Some(a_pk.clone()),
        ..c.clone()
    };
    attributed_to_the_signer(&a, &b, &same_key).expect_err("A and C sharing a key must fail");

    let collided = Notes {
        hello_slot: Some(3),
        ..c.clone()
    };
    let failure = attributed_to_the_signer(&a, &b, &collided).expect_err("a shared slot must fail");
    assert!(failure.contains("slot collision, re-run"), "{failure}");

    // A third identity's unrelated request elsewhere is not a failure.
    let mut unrelated = b.clone();
    unrelated.surfaced.push(request(2, 40, &third, &[0x77; 32]));
    attributed_to_the_signer(&a, &unrelated, &c).expect("an unrelated request passes");
}

/// The forgery C writes fails verification, and only because of the claim: the
/// same helper naming C's own key leaves an opening that verifies.
#[test]
fn an_opening_claiming_another_writer_does_not_verify() {
    // Tolerated rather than asserted: another test in this binary may have
    // initialized the module already.
    let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
    let derive = || {
        derive_identity_keys(
            &Mnemonic::generate().expect("the operating system's generator"),
            Identity::Primary,
        )
        .expect("an identity derives")
    };
    let (a, b, c) = (derive(), derive(), derive());
    let lookup = [0x33u8; 32];
    let genuine = ChannelOpening::build(
        &c.signing,
        b.signing.public_key(),
        &lookup,
        &[0x5a; 1568],
        7,
    )
    .expect("the opening signs");

    genuine
        .verify(b.signing.public_key(), &lookup, 7)
        .expect("C's genuine opening verifies");
    let forged = forge_writer(&genuine, a.signing.public_key());
    assert_eq!(
        forged.writer_identity_pk.as_slice(),
        a.signing.public_key().as_slice()
    );
    assert!(
        forged.verify(b.signing.public_key(), &lookup, 7).is_err(),
        "an opening naming A under C's signature must not verify"
    );
    forge_writer(&genuine, c.signing.public_key())
        .verify(b.signing.public_key(), &lookup, 7)
        .expect("the helper naming the real signer leaves a verifying opening");
}

#[test]
fn every_step_names_its_own_function_and_role() {
    for (i, step) in SEQUENCE.iter().enumerate() {
        for other in SEQUENCE.iter().skip(i + 1) {
            assert_ne!(step.test_name(), other.test_name());
            assert_ne!(step.label(), other.label());
        }
        assert!(step.test_name().starts_with("steps::"));
        assert!(step.label().starts_with(step.role().name()));
    }
    for role in ROLES {
        assert_eq!(Role::from_name(role.name()), Some(role));
    }
    assert_eq!(Role::from_name("neither"), None);
    assert_ne!(Role::A.port(), Role::B.port());
    assert_ne!(Role::B.port(), Role::C.port());
    assert_ne!(Role::A.port(), Role::C.port());
    // B is offline while A and C write: every step of theirs precedes B's
    // collection.
    let collect_at = SEQUENCE
        .iter()
        .position(|s| *s == Step::BCollects)
        .expect("B collects");
    for writer in [Step::AKnocks, Step::CForges] {
        let at = SEQUENCE
            .iter()
            .position(|s| *s == writer)
            .expect("the writer runs");
        assert!(
            at < collect_at,
            "{} must run before B collects",
            writer.label()
        );
    }
}

#[test]
fn a_byte_field_round_trips_including_empty_and_refuses_what_it_did_not_write() {
    let bytes = [0u8, 1, 0x7f, 0xff];
    assert_eq!(
        parse_bytes(&bytes_field(&bytes)).as_deref(),
        Some(bytes.as_slice())
    );
    assert_eq!(bytes_field(&[]), "~");
    assert_eq!(parse_bytes("~"), Some(Vec::new()));
    assert_eq!(parse_bytes(""), None);
    assert_eq!(parse_bytes("abc"), None);
    assert_eq!(parse_bytes("zz"), None);
}
