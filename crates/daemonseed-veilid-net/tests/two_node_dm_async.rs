//! Integration test (#467): a direct-message conversation completes between two
//! correspondents who are never running at the same time, and survives a kill at
//! every point where one of them stops.
//!
//! Serves the first two founding claims of `docs/design/direct-messaging.md`:
//!
//! - **FC1 Asynchronous.** Two people who are never online at the same time can
//!   hold a conversation.
//! - **FC2 Restart-safe.** A restart on either side, at any moment, loses no
//!   message and shows nothing false.
//!
//! ## A step is a process, and that is the whole of the claim
//!
//! FC1's probe says that at no moment do both processes exist. A test holding
//! two drivers in one process cannot make that statement, however carefully it
//! stops one before starting the other: both are in the same address space, both
//! their nodes are attached, and anything either kept in memory is still
//! reachable. So each step of the conversation runs in a **separate operating
//! system process**. The test re-executes its own binary with
//! `--exact <the step's test name> --ignored`, passing the step's role and state
//! directory in the environment, waits for that child to exit, and only then
//! starts the next one. Before every spawn it asserts that every child it has
//! ever started has been reaped — so a step that outlived its boundary fails the
//! run rather than passing unnoticed.
//!
//! Each step is itself an `#[ignore]`d test function. It reads its role from the
//! environment, brings up one node for that role against one state directory,
//! performs its part of the conversation, writes down what it opened, and exits.
//! Run on its own with no environment it prints a line saying it is a child of
//! the drivers here and returns, so a bare `--ignored` sweep of this target does
//! not turn the steps red. The two `fakes::` fixtures are `#[ignore]`d for a
//! different reason — they exist only to be spawned — and one of them sleeps for
//! [`FIXTURE_HOLD`], so such a sweep runs green and takes that long.
//!
//! ## The conversation
//!
//! 1. **B publishes its key record.** A conversation starts from a published
//!    identity, so B has to have been online once before A can knock. This is
//!    that occasion, and it is a step like any other: one process, alone.
//! 2. **A knocks, carrying message 0.** A first contact carries the first
//!    message body, so the knock is message 0 rather than a separate write.
//! 3. **B collects, accepts and replies.** B opens message 0 from its doorbell,
//!    answers the request, and sends its reply on the channel the acceptance
//!    establishes.
//! 4. **A collects, and replies in the same run.** A comes back holding only
//!    what its knock left on disk, opens B's acceptance and B's reply, and then
//!    sends one of its own. It may speak only because collecting the acceptance
//!    established the correspondence *in this process*: a run that found the
//!    correspondence on disk and nothing else is refused with
//!    `RefusalReason::NotEstablishedThisSession`, which is why the reply is not
//!    a step of its own.
//! 5. **B collects A's reply**, and in doing so publishes the cursor that
//!    settles B's own messages.
//! 6. **A confirms.** A runs once more and reads B's acknowledgement, so its
//!    own reply shows as collected.
//!
//! Steps 5 and 6 are what make the containment below falsifiable rather than
//! vacuous: without them neither side ever reads the other's cursor over its
//! last message, and a `settled` set that is empty satisfies any containment.
//!
//! Every step publishes its own role's key record first. The write is the same
//! bytes every time, and a correspondent that finds the record missing has
//! nothing to verify a frame against.
//!
//! ## What each side writes down, and what is read back
//!
//! A step appends to a result file under its own state directory: each body it
//! opened, and each of its own sequence numbers a correspondent's
//! acknowledgement confirmed collected. The driver test reads both files after
//! the last step and asserts against them rather than against anything it
//! watched happen — the processes that saw the conversation are gone by then,
//! which is the point.
//!
//! [`conversation_completed`] is the whole end-state check, and it is a value
//! rather than a set of assertions so that it can be exercised here over
//! hand-built results. It requires: **message 0 opened** in B's file, **B's
//! reply opened** in A's file, **A's reply opened** in B's file, a **non-empty
//! `settled` set on each side**, and — FC2's second half — that **nothing shows
//! as collected that was not**, every sequence number one side records as
//! confirmed collected appearing among those the other side records as opened.
//! The containment is the only one of the five that a blank file would satisfy,
//! which is what the other four are there for.
//!
//! ## The key schedule and the state
//!
//! `docs/design/direct-messaging.md` names the per-message key schedule and the
//! conversation's at-rest records without naming the modules that hold them.
//! They are `daemonseed_core::dm::ratchet` and
//! `daemonseed_core::storage::dm_store`, reached through [`DmPersist`], and the
//! steps compose those: a body opens under the key the conversation's own
//! ratchet derived, never one this file makes up.
//!
//! **A resumed step recovers its `settled` set from those records and its
//! `opened` set from the snapshot.** The outbox on disk says which of a side's
//! own messages a correspondent's cursor has passed, so that half survives a
//! kill outright. Opened bodies do not: the layer keeps no message store — a
//! collected body lives in memory for as long as the process does — so the
//! snapshot a step writes at its boundary is the only record of them. That is
//! why the snapshot is taken after the driver has gone quiet rather than at the
//! last assertion.
//!
//! ## What this needs to run
//!
//! Both tests are `#[ignore]`d. They need:
//!
//! - the public Veilid network reachable — where attach is blocked,
//!   `attach_and_wait` returns after its full timeout and the step fails;
//! - two free UDP ports: [`A_PORT`] for A and [`B_PORT`] for B, one per role and
//!   reused across that role's steps because only one of them is ever running;
//! - the `--ignored` flag, which is what opts in to all of it.
//!
//! So:
//!
//!     cargo test -p daemonseed-veilid-net --test two_node_dm_async -- \
//!         --ignored --nocapture
//!
//! The two take the network in turn whatever flags are passed: each holds
//! [`ONE_AT_A_TIME`] for its whole run, so they cannot overlap even under a
//! parallel runner.
//!
//! Expect hours. Every step joins the network from cold, a proof of work is
//! minted at the difficulty production uses, and every hop waits for a write to
//! spread through the distributed hash table it lives in. The second test runs
//! each step twice.
//!
//! A step's own output goes to a file beside its state directory, which the
//! driver echoes when the step exits and quotes the tail of when it fails.
//!
//! **A step spawns no process of its own** — its node is tokio tasks in the
//! step's own process — so killing the child is the whole kill, and the kill
//! path signals it directly rather than a process group.
//!
//! The harness's own bookkeeping — the one-process rule and the result file —
//! is covered by tests that run without a network, at the foot of this file.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use daemonseed_core::dm::admission::AdmissionPolicy;
use daemonseed_core::dm::keyrec;
use daemonseed_core::dm::outbox::DeliveryState;
use daemonseed_core::dm::persist::DmPersist;
use daemonseed_core::dm::pow::PowDifficulty;
use daemonseed_core::identity::keys::{
    derive_identity_keys, Identity, IdentityKeys, IDENTITY_PK_LEN,
};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::storage::seeds::AEAD_KEY_LEN;
use daemonseed_veilid_net::{
    DmCommand, DmDriver, DmDriverConfig, DmDriverHandle, DmDriverParts, DmEvent, DmIdentity, PkLt,
    RequestId, VeilidNet, VeilidNetConfig, VeilidNetHandle, WallClock,
};
use tokio::sync::mpsc::Receiver;

// ── what a run is configured with ────────────────────────────────────────────

/// The at-rest key each side's [`DmPersist`] seals under. Per-run scratch
/// directories, so this is a fixture rather than a secret.
const AT_REST: [u8; AEAD_KEY_LEN] = [0x2b; AEAD_KEY_LEN];

/// The driver's wake cadence. Every sweep, publish and fetch is planned on a
/// tick, so this is what moves the conversation: fast enough that a hop is not
/// dominated by waiting for the next wakeup, slow enough not to re-read the
/// distributed hash table faster than a write can spread through it.
const IDLE_TICK: Duration = Duration::from_secs(15);

/// The budget for one hop: a write, its spread, and a correspondent's next sweep
/// of it. A doorbell sweep reads every subkey of the record and a page sweep
/// every subkey of its own, each a separate network round trip, so a hop is one
/// tick plus an open plus a whole sweep.
const HOP: Duration = Duration::from_secs(600);

/// How long a step keeps its driver running after its last assertion, so the
/// cadence that publishes what it composed gets to run before the process goes
/// away.
///
/// **A composed frame is not a published one.** The driver plans the write on a
/// tick, and a step that exited on the `Composed` event would leave the bytes in
/// its outbox and nothing on the network for the correspondent to find.
const PUBLISH_WINDOW: Duration = Duration::from_secs(300);

/// How long a resumed step keeps its driver running before stopping.
///
/// A process that comes back after a kill re-seeds anything its outbox still
/// holds. That is the whole of what the resumption has to show, and it happens
/// on the driver's own cadence, so the window has to cover one.
const RESUME_WINDOW: Duration = Duration::from_secs(300);

/// How long the attach is given before a step gives up on the network.
const ATTACH_SECS: u64 = 180;

/// How long a driver is given to stop once it is asked.
const STOP: Duration = Duration::from_secs(120);

/// What is left of the node's graceful close once its driver has stopped.
const NODE_CLOSE: Duration = Duration::from_secs(30);

/// How long one step of the conversation may take before the driver gives up on
/// it. Generous: a step joins the network from cold, mints a proof of work, and
/// waits out several hops.
const STEP_BUDGET: Duration = Duration::from_secs(5400);

/// The budget for a hop that waits on an acknowledgement. Longer than [`HOP`] by
/// construction: the correspondent has first to collect the message, which is an
/// ordinary hop, its acknowledgement is floored before the write is permitted,
/// and the sender then reads the record back on its own cadence.
const ACK_HOP: Duration = Duration::from_secs(900);

/// How long the driver's event stream must be silent before a step calls it
/// quiet and takes its snapshot. One idle cadence plus room for a sweep the
/// cadence planned.
const QUIESCE_IDLE: Duration = Duration::from_secs(60);

/// How many lines of a failed step's output the driver quotes back.
const STDERR_TAIL_LINES: usize = 40;

/// How long a step held at its boundary waits to be killed before failing.
/// Nothing but a broken driver leaves it holding, and a process that held for
/// ever would outlive the run.
const HOLD_CAP: Duration = Duration::from_secs(3600);

/// The first message, carried by the knock, and the reply. Distinct from each
/// other and from anything a zero fill or a padding could produce, so a frame
/// opened at the wrong position could not pass for the right one.
const MESSAGE_0: &str = "message zero, sent while nobody is listening";
const REPLY: &str = "the reply, sent to nobody in particular";
const A_REPLY: &str = "and one more, answering the reply";

/// The UDP ports the two roles listen on, one per role.
const A_PORT: &str = ":5190";
const B_PORT: &str = ":5191";

/// The two driver tests take the network in turn.
///
/// Each holds this for its whole run, so no flag and no runner can put two of
/// them on the network at once — every step of either would then be competing
/// with a step of the other for the thing FC1 is a claim about. Poisoning is
/// tolerated: a panicking driver test leaves the lock poisoned and the next one
/// still has to run.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// The environment a step reads its instructions from. Set by the driver tests
/// on every child they spawn.
const ENV_STATE: &str = "DAEMONSEED_DM_ASYNC_STATE";
const ENV_ROLE: &str = "DAEMONSEED_DM_ASYNC_ROLE";
const ENV_BOUNDARY: &str = "DAEMONSEED_DM_ASYNC_BOUNDARY";

// ── roles and steps ──────────────────────────────────────────────────────────

/// Which correspondent a step runs as.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role {
    A,
    B,
}

impl Role {
    fn name(self) -> &'static str {
        match self {
            Role::A => "a",
            Role::B => "b",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "a" => Some(Role::A),
            "b" => Some(Role::B),
            _ => None,
        }
    }

    /// The UDP port this role's node listens on. One per role and reused across
    /// that role's steps, because only one of them is ever running.
    fn port(self) -> &'static str {
        match self {
            Role::A => A_PORT,
            Role::B => B_PORT,
        }
    }

    /// Everything this role keeps between its steps.
    fn dir(self, state: &Path) -> PathBuf {
        state.join(self.name())
    }

    fn mnemonic_path(self, state: &Path) -> PathBuf {
        self.dir(state).join("mnemonic")
    }

    fn result_path(self, state: &Path) -> PathBuf {
        self.dir(state).join("result")
    }
}

/// One step of the conversation. Each runs as its own process.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Step {
    /// B publishes the identity A knocks at, and stops.
    BPublishes,
    /// A knocks, carrying message 0, and stops.
    AKnocks,
    /// B opens message 0, accepts, replies, and stops.
    BCollectsAndReplies,
    /// A opens the acceptance and B's reply, then sends one of its own.
    ACollectsAndReplies,
    /// B opens A's reply, publishing the cursor that settles B's own messages.
    BCollectsTheReply,
    /// A reads B's acknowledgement, so A's reply shows as collected.
    AConfirms,
}

/// The conversation, in order.
const CONVERSATION: [Step; 6] = [
    Step::BPublishes,
    Step::AKnocks,
    Step::BCollectsAndReplies,
    Step::ACollectsAndReplies,
    Step::BCollectsTheReply,
    Step::AConfirms,
];

impl Step {
    fn role(self) -> Role {
        match self {
            Step::BPublishes | Step::BCollectsAndReplies | Step::BCollectsTheReply => Role::B,
            Step::AKnocks | Step::ACollectsAndReplies | Step::AConfirms => Role::A,
        }
    }

    /// The step's name in a result file and in a failure message.
    fn label(self) -> &'static str {
        match self {
            Step::BPublishes => "b-publishes",
            Step::AKnocks => "a-knocks",
            Step::BCollectsAndReplies => "b-collects-and-replies",
            Step::ACollectsAndReplies => "a-collects-and-replies",
            Step::BCollectsTheReply => "b-collects-the-reply",
            Step::AConfirms => "a-confirms-collection",
        }
    }

    /// The test function that is this step, as `--exact` names it.
    fn test_name(self) -> &'static str {
        match self {
            Step::BPublishes => "steps::b_publishes_its_key_record",
            Step::AKnocks => "steps::a_knocks_carrying_message_zero",
            Step::BCollectsAndReplies => "steps::b_collects_accepts_and_replies",
            Step::ACollectsAndReplies => "steps::a_collects_the_acceptance_and_replies",
            Step::BCollectsTheReply => "steps::b_collects_the_reply",
            Step::AConfirms => "steps::a_confirms_its_reply_was_collected",
        }
    }
}

/// What a step does when its work is finished.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Boundary {
    /// Stop the driver, close the node, exit.
    Exit,
    /// Write the boundary marker and hold, to be killed where it stands.
    Hold,
}

impl Boundary {
    fn name(self) -> &'static str {
        match self {
            Boundary::Exit => "exit",
            Boundary::Hold => "hold",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "exit" => Some(Boundary::Exit),
            "hold" => Some(Boundary::Hold),
            _ => None,
        }
    }
}

// ── the result file ──────────────────────────────────────────────────────────

/// What one role has recorded across its steps.
///
/// Written by the step processes and read by the driver test after every one of
/// them is gone, so it is the only thing either side of the conversation leaves
/// behind. Line-oriented, with bodies hex-encoded so a body holding a space or a
/// newline survives the round trip, and `-` for an empty body so every line has
/// the same number of fields.
#[derive(Default, PartialEq, Eq, Debug)]
struct StepResult {
    /// Each `(seq, body)` this role opened.
    opened: Vec<(u64, String)>,
    /// Each of this role's own sequence numbers a correspondent's
    /// acknowledgement confirmed collected.
    settled: Vec<u64>,
    /// The steps this role has completed, by label.
    done: Vec<String>,
    /// The steps this role has resumed after a kill, by label, with the number
    /// of correspondences its store held when it came back.
    resumed: Vec<String>,
}

impl StepResult {
    fn encode(&self) -> String {
        let mut out = String::new();
        for (seq, body) in &self.opened {
            out.push_str(&format!("opened {seq} {}\n", hex_encode(body)));
        }
        for seq in &self.settled {
            out.push_str(&format!("settled {seq}\n"));
        }
        for label in &self.done {
            out.push_str(&format!("done {label}\n"));
        }
        for note in &self.resumed {
            out.push_str(&format!("resumed {note}\n"));
        }
        out
    }

    fn parse(text: &str) -> Result<Self, String> {
        let mut out = Self::default();
        for (n, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let mut fields = line.splitn(3, ' ');
            let kind = fields.next().unwrap_or_default();
            match kind {
                "opened" => {
                    let seq = fields
                        .next()
                        .and_then(|s| s.parse::<u64>().ok())
                        .ok_or_else(|| format!("line {}: no sequence number", n + 1))?;
                    let body = fields
                        .next()
                        .and_then(hex_decode)
                        .ok_or_else(|| format!("line {}: no body", n + 1))?;
                    out.opened.push((seq, body));
                }
                "settled" => {
                    let seq = fields
                        .next()
                        .and_then(|s| s.parse::<u64>().ok())
                        .ok_or_else(|| format!("line {}: no sequence number", n + 1))?;
                    out.settled.push(seq);
                }
                "done" => out.done.push(
                    fields
                        .next()
                        .ok_or_else(|| format!("line {}: no label", n + 1))?
                        .to_owned(),
                ),
                "resumed" => {
                    let label = fields
                        .next()
                        .ok_or_else(|| format!("line {}: no label", n + 1))?;
                    let rest = fields.next().unwrap_or_default();
                    out.resumed.push(if rest.is_empty() {
                        label.to_owned()
                    } else {
                        format!("{label} {rest}")
                    });
                }
                other => return Err(format!("line {}: unknown record {other:?}", n + 1)),
            }
        }
        Ok(out)
    }

    /// Read the file, or an empty result where there is none yet.
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
        std::fs::write(path, self.encode()).expect("the result file writes");
    }

    fn has_done(&self, step: Step) -> bool {
        self.done.iter().any(|d| d == step.label())
    }

    fn mark_done(&mut self, step: Step) {
        if !self.has_done(step) {
            self.done.push(step.label().to_owned());
        }
    }

    fn opened_seqs(&self) -> Vec<u64> {
        let mut seqs: Vec<u64> = self.opened.iter().map(|(seq, _)| *seq).collect();
        seqs.sort_unstable();
        seqs.dedup();
        seqs
    }
}

/// A body as lowercase hex, or `-` when it is empty.
fn hex_encode(body: &str) -> String {
    if body.is_empty() {
        return "-".to_owned();
    }
    let mut out = String::with_capacity(body.len() * 2);
    for byte in body.as_bytes() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The inverse of [`hex_encode`]. `None` on anything it did not write.
fn hex_decode(text: &str) -> Option<String> {
    if text == "-" {
        return Some(String::new());
    }
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(text.len() / 2);
    let raw = text.as_bytes();
    for pair in raw.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        bytes.push((hi * 16 + lo) as u8);
    }
    String::from_utf8(bytes).ok()
}

// ── the harness ──────────────────────────────────────────────────────────────

/// One child process this harness started.
struct Tracked {
    label: String,
    pid: u32,
    child: Child,
    status: Option<ExitStatus>,
    /// Where this child's own output went, so the driver can echo it when the
    /// child exits and quote its tail when the child fails.
    log: PathBuf,
}

/// Every step child this harness has started, and the one-process rule over
/// them.
///
/// The rule is a value rather than a panic ([`Supervisor::boundary_is_clear`])
/// so that a control can assert it fails: a check that can only panic cannot be
/// shown to fire.
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

    /// Re-execute this test binary, running `test_name` and nothing else.
    ///
    /// The child's own output is captured rather than inherited, so a step that
    /// fails can be quoted back in the failure that names it. It is echoed whole
    /// when the child exits, which keeps the timeline a `--nocapture` run
    /// prints, one step behind.
    fn spawn(&mut self, label: &str, test_name: &str, env: &[(&str, &str)]) -> std::io::Result<()> {
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
            pid: child.id(),
            child,
            status: None,
            log,
        });
        Ok(())
    }

    /// Echo one child's captured output, and return it.
    fn drain_log(&self, index: usize) -> String {
        let text = std::fs::read_to_string(&self.tracked[index].log).unwrap_or_default();
        let label = &self.tracked[index].label;
        eprintln!("harness: ---- {label} ----\n{text}harness: ---- end {label} ----");
        text
    }

    /// Spawn one child, wait for it, and report what its exit status and output
    /// say — as a value, so a control can assert that a failing step is caught.
    fn run_child(
        &mut self,
        label: &str,
        test_name: &str,
        env: &[(&str, &str)],
    ) -> Result<(), String> {
        let index = self.tracked.len();
        self.spawn(label, test_name, env)
            .map_err(|e| format!("{label} did not spawn: {e}"))?;
        let status = self.wait_at(index, STEP_BUDGET);
        let text = self.drain_log(index);
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

    /// Every step child that has not been reaped, named.
    fn still_alive(&mut self) -> Vec<String> {
        let mut alive = Vec::new();
        for tracked in &mut self.tracked {
            if tracked.status.is_some() {
                continue;
            }
            match tracked.child.try_wait() {
                Ok(Some(status)) => tracked.status = Some(status),
                Ok(None) => alive.push(format!("{} (pid {})", tracked.label, tracked.pid)),
                Err(e) => alive.push(format!("{} (pid {}): {e}", tracked.label, tracked.pid)),
            }
        }
        alive
    }

    /// FC1's rule: at a step boundary, no step process exists.
    fn boundary_is_clear(&mut self) -> Result<(), String> {
        let alive = self.still_alive();
        if alive.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "still running at the boundary: {}",
                alive.join(", ")
            ))
        }
    }

    /// Wait for the child at `index`, killing it and failing if it outlasts
    /// `budget`.
    fn wait_at(&mut self, index: usize, budget: Duration) -> ExitStatus {
        let started = Instant::now();
        loop {
            let tracked = &mut self.tracked[index];
            if let Some(status) = tracked.status {
                return status;
            }
            match tracked.child.try_wait().expect("the child is waitable") {
                Some(status) => {
                    tracked.status = Some(status);
                    return status;
                }
                None if started.elapsed() >= budget => {
                    let label = tracked.label.clone();
                    let _ = tracked.child.kill();
                    tracked.status = tracked.child.wait().ok();
                    panic!("{label} did not exit within {}s", budget.as_secs());
                }
                None => std::thread::sleep(Duration::from_millis(500)),
            }
        }
    }

    /// Kill and reap everything still running.
    fn kill_all(&mut self) {
        for tracked in &mut self.tracked {
            if tracked.status.is_some() {
                continue;
            }
            let _ = tracked.child.kill();
            tracked.status = tracked.child.wait().ok();
        }
    }

    fn env_for(&self, step: Step, boundary: Boundary) -> Vec<(String, String)> {
        vec![
            (
                ENV_STATE.to_owned(),
                self.state.to_string_lossy().into_owned(),
            ),
            (ENV_ROLE.to_owned(), step.role().name().to_owned()),
            (ENV_BOUNDARY.to_owned(), boundary.name().to_owned()),
        ]
    }

    /// Run one step to a clean exit, with the one-process rule asserted on both
    /// sides of it.
    fn run_to_exit(&mut self, step: Step) {
        self.boundary_is_clear()
            .expect("a step starts only once every earlier one has exited");
        let env = self.env_for(step, Boundary::Exit);
        let borrowed: Vec<(&str, &str)> =
            env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        if let Err(e) = self.run_child(step.label(), step.test_name(), &borrowed) {
            panic!("{e}");
        }
        // **The step's own record that it ran, read back here rather than
        // trusted.** A `--exact` name matching no test runs nothing and exits 0,
        // which is otherwise indistinguishable from a step that did its work —
        // and the difference would not surface until an assertion about the
        // conversation failed, hours and several steps later.
        let result = StepResult::load(&step.role().result_path(&self.state));
        assert!(
            result.has_done(step),
            "{} left no record of having run; its result file names {:?}",
            step.label(),
            result.done
        );
    }

    /// Run one step until it reaches its boundary, then kill it where it stands.
    fn run_and_kill_at_boundary(&mut self, step: Step) {
        self.boundary_is_clear()
            .expect("a step starts only once every earlier one has exited");
        let marker = self.state.join(format!("{}.boundary", step.label()));
        let _ = std::fs::remove_file(&marker);
        let env = self.env_for(step, Boundary::Hold);
        let borrowed: Vec<(&str, &str)> =
            env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let index = self.tracked.len();
        self.spawn(step.label(), step.test_name(), &borrowed)
            .expect("the step spawns");

        let started = Instant::now();
        while !marker.exists() {
            assert!(
                started.elapsed() < STEP_BUDGET,
                "{} did not reach its boundary within {}s",
                step.label(),
                STEP_BUDGET.as_secs()
            );
            if let Some(status) = self.tracked[index]
                .child
                .try_wait()
                .expect("the child is waitable")
            {
                self.tracked[index].status = Some(status);
                panic!(
                    "{} exited ({status:?}) before reaching its boundary",
                    step.label()
                );
            }
            std::thread::sleep(Duration::from_millis(500));
        }

        // **Killing the child is the whole kill.** A step spawns no process of
        // its own — its node is tokio tasks inside it — so there is no group to
        // signal and nothing survives this that a group kill would reach.
        eprintln!("harness: killing {} at its boundary", step.label());
        let _ = self.tracked[index].child.kill();
        self.wait_at(index, STOP);
        self.drain_log(index);
    }
}

impl Drop for Supervisor {
    /// Nothing this harness started outlives it, whichever assertion failed.
    fn drop(&mut self) {
        self.kill_all();
    }
}

// ── the two oracles ──────────────────────────────────────────────────────────

/// Lay out a fresh state directory: one mnemonic per role, and nothing else.
///
/// The identities are generated here and derived in the step processes, so no
/// step holds the other role's secret. A knocks at the identity B *published*,
/// which B writes out in its first step.
fn lay_out_state(state: &Path) -> [PathBuf; 2] {
    for role in [Role::A, Role::B] {
        std::fs::create_dir_all(role.dir(state)).expect("the role's directory is created");
        let mnemonic = Mnemonic::generate().expect("a mnemonic");
        std::fs::write(role.mnemonic_path(state), mnemonic.to_phrase())
            .expect("the mnemonic writes");
    }
    [Role::A.result_path(state), Role::B.result_path(state)]
}

/// What the two result files have to say, once every step process is gone.
///
/// A value rather than a set of assertions, so the check itself can be run here
/// over hand-built results: four of its five clauses are what stop the fifth
/// passing on an empty file, and a check that can only panic cannot be shown to
/// catch any of them.
fn conversation_completed(a: &StepResult, b: &StepResult) -> Result<(), String> {
    if !b
        .opened
        .iter()
        .any(|(seq, body)| *seq == 0 && body.as_str() == MESSAGE_0)
    {
        return Err(format!("B never opened message 0; B opened {:?}", b.opened));
    }
    if !a
        .opened
        .iter()
        .any(|(seq, body)| *seq == 1 && body.as_str() == REPLY)
    {
        return Err(format!("A never opened B's reply; A opened {:?}", a.opened));
    }
    if !b
        .opened
        .iter()
        .any(|(seq, body)| *seq == 1 && body.as_str() == A_REPLY)
    {
        return Err(format!("B never opened A's reply; B opened {:?}", b.opened));
    }
    if a.settled.is_empty() {
        return Err(
            "A shows nothing collected: B's cursor never passed one of A's messages".into(),
        );
    }
    if b.settled.is_empty() {
        return Err(
            "B shows nothing collected: A's cursor never passed one of B's messages".into(),
        );
    }

    // FC2's second half, both ways: a sequence number one side shows as
    // collected is one the other side opened.
    let a_opened = a.opened_seqs();
    let b_opened = b.opened_seqs();
    for seq in &a.settled {
        if !b_opened.contains(seq) {
            return Err(format!(
                "A shows its sequence {seq} collected, but B opened only {b_opened:?}"
            ));
        }
    }
    for seq in &b.settled {
        if !a_opened.contains(seq) {
            return Err(format!(
                "B shows its sequence {seq} collected, but A opened only {a_opened:?}"
            ));
        }
    }
    Ok(())
}

/// FC1's probe: the conversation completes with the two processes never alive
/// together.
#[test]
#[ignore = "attaches to the public Veilid network, one process per step of the conversation; opt-in, run with --ignored"]
fn a_conversation_completes_with_the_two_processes_never_alive_together() {
    let _network = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let state = tempfile::tempdir().expect("a state directory");
    let [a_result, b_result] = lay_out_state(state.path());
    let mut supervisor = Supervisor::new(state.path().to_path_buf());

    for step in CONVERSATION {
        supervisor.run_to_exit(step);
    }

    conversation_completed(&StepResult::load(&a_result), &StepResult::load(&b_result))
        .expect("the conversation completes across processes that are never alive together");
}

/// FC2's probe: the same conversation, with a kill at every step boundary and
/// each step resumed from the state left on disk.
#[test]
#[ignore = "attaches to the public Veilid network, two processes per step of the conversation; opt-in, run with --ignored"]
fn a_conversation_survives_a_kill_at_every_step_boundary() {
    let _network = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let state = tempfile::tempdir().expect("a state directory");
    let [a_result, b_result] = lay_out_state(state.path());
    let mut supervisor = Supervisor::new(state.path().to_path_buf());

    for step in CONVERSATION {
        // The step does its work, writes down what it opened, and is killed
        // where it stands rather than stopping.
        supervisor.run_and_kill_at_boundary(step);
        // The same step again, over the same state directory. It finds its own
        // work recorded, so it comes back as a resumption: the store is reopened,
        // the outbox re-seeds anything the kill left unpublished, and the run
        // carries on from there.
        supervisor.run_to_exit(step);
    }

    let a = StepResult::load(&a_result);
    let b = StepResult::load(&b_result);
    assert_eq!(
        a.resumed.len() + b.resumed.len(),
        CONVERSATION.len(),
        "every step must have been resumed exactly once; A {:?}, B {:?}",
        a.resumed,
        b.resumed
    );
    conversation_completed(&a, &b)
        .expect("the conversation survives a kill at every step boundary");
}

// ── one step, as a process ───────────────────────────────────────────────────

/// One driver's event stream plus every event it has produced so far.
///
/// Retaining them is what makes the waits composable: a hop that arrives while
/// an earlier one is still being waited for is buffered rather than dropped, so
/// the order the assertions are written in does not have to be the order the
/// network delivers in.
struct Side {
    who: String,
    rx: Receiver<DmEvent>,
    seen: Vec<DmEvent>,
    started: Instant,
}

impl Side {
    fn new(who: &str, rx: Receiver<DmEvent>) -> Self {
        Self {
            who: who.to_owned(),
            rx,
            seen: Vec::new(),
            started: Instant::now(),
        }
    }

    /// Seconds since this step began, for the timeline a `--nocapture` run
    /// prints.
    fn at(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }

    /// Wait until `pick` matches an event this side has produced, or fail naming
    /// the hop. Already-buffered events are scanned first.
    async fn wait_for<T>(
        &mut self,
        hop: &str,
        budget: Duration,
        mut pick: impl FnMut(&DmEvent) -> Option<T>,
    ) -> T {
        let hop_started = Instant::now();
        if let Some(found) = self.seen.iter().find_map(&mut pick) {
            eprintln!("[{:>7.1}s] {}: {hop} — already seen", self.at(), self.who);
            return found;
        }
        loop {
            let left = budget.saturating_sub(hop_started.elapsed());
            assert!(
                !left.is_zero(),
                "{}: timed out after {}s waiting for {hop}; events so far: {:?}",
                self.who,
                budget.as_secs(),
                self.seen
            );
            match tokio::time::timeout(left, self.rx.recv()).await {
                Ok(Some(event)) => {
                    let matched = pick(&event);
                    eprintln!("[{:>7.1}s] {}: {event:?}", self.at(), self.who);
                    self.seen.push(event);
                    if let Some(found) = matched {
                        eprintln!(
                            "[{:>7.1}s] {}: {hop} in {:.1}s",
                            self.at(),
                            self.who,
                            hop_started.elapsed().as_secs_f64()
                        );
                        return found;
                    }
                }
                Ok(None) => panic!("{}: the driver stopped before {hop}", self.who),
                Err(_) => panic!(
                    "{}: timed out after {}s waiting for {hop}; events so far: {:?}",
                    self.who,
                    budget.as_secs(),
                    self.seen
                ),
            }
        }
    }

    /// Keep buffering events until none has arrived for `idle`, or `cap` runs
    /// out. Asserts nothing.
    ///
    /// **This is what a step waits on before it writes its snapshot.** A driver
    /// publishes what a step composed on its own cadence and reports what it
    /// collected as the sweeps land, so a snapshot taken at the last assertion
    /// is taken while the driver is still working — and in the kill test the
    /// difference between that moment and a quiet one is evidence the kill takes
    /// with it.
    async fn drain_until_idle(&mut self, idle: Duration, cap: Duration) {
        let until = Instant::now() + cap;
        loop {
            let left = until.saturating_duration_since(Instant::now()).min(idle);
            if left.is_zero() {
                return;
            }
            match tokio::time::timeout(left, self.rx.recv()).await {
                Ok(Some(event)) => {
                    eprintln!("[{:>7.1}s] {}: {event:?}", self.at(), self.who);
                    self.seen.push(event);
                }
                Ok(None) | Err(_) => return,
            }
        }
    }

    /// Every sequence number of this side's own a correspondent's
    /// acknowledgement confirmed collected.
    fn settled(&self) -> Vec<u64> {
        self.seen
            .iter()
            .filter_map(|e| match e {
                DmEvent::Delivery {
                    seq,
                    state: DeliveryState::ConfirmedCollected,
                    ..
                } => Some(*seq),
                _ => None,
            })
            .collect()
    }

    /// Fail naming any refusal this side was given. A send that was refused
    /// leaves no frame on the network, and the correspondent's step would then
    /// time out with nothing saying why.
    fn assert_nothing_was_refused(&self) {
        let refusals: Vec<&DmEvent> = self
            .seen
            .iter()
            .filter(|e| matches!(e, DmEvent::Refused { .. } | DmEvent::AcceptFailed { .. }))
            .collect();
        assert!(refusals.is_empty(), "{}: refused: {refusals:?}", self.who);
    }
}

/// A node config with a fresh node identity, this role's listen port, and its
/// own storage dir.
///
/// The node identity is per-node and unrelated to the conversation: nothing
/// about a doorbell slot, a page address or a message key derives from a node
/// key, which is why it is generated per step rather than carried with the user
/// identity across one.
fn node_config(role: Role, dir: &Path) -> VeilidNetConfig {
    let id = derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap();
    let mut cfg = VeilidNetConfig::new(id.veilid_node_seed, dir.to_string_lossy().into_owned());
    cfg.namespace = format!("two_node_dm_async_{}", role.name());
    cfg.listen_address = Some(role.port().to_owned());
    cfg
}

/// This role's user identity, derived from the mnemonic its state directory
/// holds.
///
/// **The mnemonic is what persists, not the keys.** A step takes its identity by
/// value, so deriving it the way a front end does at start-up is the faithful
/// version: a step that inherited keys from an earlier one would not be a
/// separate process at all.
fn identity_of(role: Role, state: &Path) -> IdentityKeys {
    let path = role.mnemonic_path(state);
    let phrase =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mnemonic = Mnemonic::from_phrase(phrase.trim()).expect("the mnemonic parses");
    derive_identity_keys(&mnemonic, Identity::Primary).expect("identity")
}

/// The parts this step's driver is built from.
fn parts(
    keys: IdentityKeys,
    node: Arc<VeilidNetHandle>,
    root: &Path,
) -> DmDriverParts<VeilidNetHandle> {
    DmDriverParts {
        dht: node,
        clock: WallClock::system(),
        identity: DmIdentity {
            signing: Arc::new(keys.signing),
            kem: keys.kem,
            doorbell_slot_secret: keys.dm_doorbell_slot_secret,
        },
        persist: DmPersist::open(root.join("dm"), &AT_REST).expect("persist opens"),
        cfg: DmDriverConfig {
            idle_tick: IDLE_TICK,
            policy: AdmissionPolicy::Open,
            // The shipped difficulty on both sides. A recipient always verifies
            // at production, so a reduced mint would be dropped by the admission
            // path this oracle exists to run.
            pow_difficulty: PowDifficulty::PRODUCTION,
        },
        spent_tokens: None,
    }
}

/// Publish this role's DM key record, awaited.
///
/// The front end's job rather than the driver's, and awaited rather than spawned
/// so a knock cannot race a record that has not been written: a refusal caused
/// by the step's own ordering would be indistinguishable from the transport
/// losing the write.
async fn publish_key_record(node: &VeilidNetHandle, keys: &IdentityKeys) {
    let record = keyrec::build_encoded(
        &keys.signing,
        keys.kem.encapsulation_key(),
        keyrec::DM_KEY_RECORD_VERSION,
        keyrec::DM_KEY_RECORD_INVITE_ONLY,
    )
    .expect("key record builds");
    let owner_seed = *keyrec::derive_owner_seed(keys.signing.public_key())
        .expect("key-record owner seed")
        .as_bytes();
    node.publish_dm_key_record(owner_seed, record)
        .await
        .expect("key record publishes");
}

/// Every sequence number the outbox records on disk show as collected.
///
/// **The half of a side's evidence that survives a kill outright.** A running
/// driver reports a settlement as an event and a killed process takes every
/// event it held with it; the outbox record does not go anywhere. Opened bodies
/// have no equivalent — the layer keeps no message store — so they come from the
/// snapshot instead.
///
/// Opened read-only, beside the driver's own handle: this draws the outbox, it
/// never drives it.
fn settled_on_disk(root: &Path) -> Vec<u64> {
    let persist = DmPersist::open(root.join("dm"), &AT_REST).expect("the store on disk reopens");
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_millis() as i64;
    let mut seqs = Vec::new();
    for label in persist
        .store()
        .correspondences()
        .expect("the store lists its correspondences")
    {
        let Some(outbox) = persist
            .read_outbox(&label, now_ms)
            .expect("the outbox reads")
        else {
            continue;
        };
        for entry in outbox.iter() {
            if matches!(entry.delivery_state(), DeliveryState::ConfirmedCollected) {
                seqs.push(entry.seq());
            }
        }
    }
    seqs.sort_unstable();
    seqs.dedup();
    seqs
}

/// Where B writes the identity it has published, and A reads it.
fn published_identity_path(state: &Path) -> PathBuf {
    state.join("b-identity")
}

/// Stop one driver and wait until its event stream closes.
///
/// The closed stream is the only signal that the driver is gone, and waiting for
/// it is what makes the next step's process the only one holding this state.
async fn stop(handle: &DmDriverHandle, side: &mut Side) {
    handle
        .send(DmCommand::Shutdown)
        .await
        .expect("the driver takes the shutdown");
    let asked = Instant::now();
    loop {
        let left = STOP.saturating_sub(asked.elapsed());
        assert!(
            !left.is_zero(),
            "{}: the driver did not stop within {}s",
            side.who,
            STOP.as_secs()
        );
        match tokio::time::timeout(left, side.rx.recv()).await {
            Ok(Some(event)) => side.seen.push(event),
            Ok(None) => break,
            Err(_) => panic!(
                "{}: the driver did not stop within {}s",
                side.who,
                STOP.as_secs()
            ),
        }
    }
    eprintln!("[{:>7.1}s] {}: stopped", side.at(), side.who);
}

/// Run one step of the conversation, in this process, and leave.
async fn run_step(step: Step) {
    let Some(state) = std::env::var_os(ENV_STATE) else {
        eprintln!(
            "{}: no {ENV_STATE} — this is a child process of the two driver tests \
             in this file, and does nothing on its own",
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
        "{}: spawned as {named_role:?} but it is {role:?}'s step",
        step.label()
    );
    let boundary = std::env::var(ENV_BOUNDARY)
        .ok()
        .and_then(|name| Boundary::from_name(&name))
        .expect("the boundary in the environment is one this file knows");

    daemonseed_core::kats::initialize_module_unsigned_test_binary().expect("oxicrypt init");

    let mut result = StepResult::load(&role.result_path(&state));
    let resuming = result.has_done(step);

    let keys = identity_of(role, &state);
    let own_pk: PkLt = Box::new(*keys.signing.public_key());
    let (node, _events) = VeilidNet::start(node_config(role, &role.dir(&state).join("node")))
        .await
        .expect("the node starts");
    node.attach_and_wait(ATTACH_SECS)
        .await
        .expect("the node reaches the public network");
    publish_key_record(&node, &keys).await;
    if role == Role::B {
        std::fs::write(
            published_identity_path(&state),
            hex_encode_bytes(own_pk.as_slice()),
        )
        .expect("the published identity writes");
    }

    let node = Arc::new(node);
    let (handle, events) = DmDriver::spawn(parts(keys, Arc::clone(&node), &role.dir(&state)));
    let mut side = Side::new(role.name(), events);

    if resuming {
        resume(step, &mut side, &mut result, &state).await;
    } else {
        match step {
            // B's record is already written, above. Nothing else is owed: the
            // quiesce below is what makes this a real occasion of B being online
            // rather than a bare write.
            Step::BPublishes => {}
            Step::AKnocks => a_knocks(&handle, &mut side, &state).await,
            Step::BCollectsAndReplies => {
                b_collects_accepts_and_replies(&handle, &mut side, &mut result).await
            }
            Step::ACollectsAndReplies => {
                a_collects_and_replies(&handle, &mut side, &mut result).await
            }
            Step::BCollectsTheReply => b_collects_the_reply(&mut side, &mut result).await,
            Step::AConfirms => a_confirms_its_reply_was_collected(&mut side).await,
        }
        result.mark_done(step);
    }

    // **Quiesce, then snapshot.** The driver is still publishing and still
    // sweeping when the last assertion returns, so the snapshot waits for its
    // event stream to go quiet — otherwise the kill test's kill lands between a
    // settlement and the record of it.
    side.drain_until_idle(QUIESCE_IDLE, PUBLISH_WINDOW).await;
    side.assert_nothing_was_refused();
    result.settled.extend(side.settled());
    result.settled.extend(settled_on_disk(&role.dir(&state)));
    result.settled.sort_unstable();
    result.settled.dedup();
    result.save(&role.result_path(&state));

    match boundary {
        Boundary::Hold => hold_at_boundary(&state, step).await,
        Boundary::Exit => {
            stop(&handle, &mut side).await;
            node.shutdown(NODE_CLOSE).await;
        }
    }
}

/// A knocks at the identity B published, carrying message 0.
async fn a_knocks(handle: &DmDriverHandle, side: &mut Side, state: &Path) {
    let path = published_identity_path(state);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let bytes = hex_decode_bytes(text.trim()).expect("the published identity decodes");
    let recipient: PkLt = Box::new(
        <[u8; IDENTITY_PK_LEN]>::try_from(bytes.as_slice())
            .expect("the published identity is an identity key"),
    );

    handle
        .send(DmCommand::FirstContact {
            recipient,
            body: MESSAGE_0.into(),
        })
        .await
        .expect("the first contact queues");
    side.wait_for("A's knock is composed", HOP, |e| {
        matches!(
            e,
            DmEvent::Delivery {
                seq: 0,
                state: DeliveryState::Composed,
                ..
            }
        )
        .then_some(())
    })
    .await;
}

/// B opens message 0 from its doorbell, accepts, and replies on the channel the
/// acceptance establishes.
async fn b_collects_accepts_and_replies(
    handle: &DmDriverHandle,
    side: &mut Side,
    result: &mut StepResult,
) {
    let (request, from, body): (RequestId, PkLt, String) = side
        .wait_for("the knock arrives at B's doorbell", HOP, |e| match e {
            DmEvent::ContactRequest {
                request,
                from,
                body,
                ..
            } => Some((request.clone(), from.clone(), body.clone())),
            _ => None,
        })
        .await;
    // The knock is message 0 of A's direction, and opening it is what B has to
    // show for FC1.
    result.opened.push((0, body));

    handle
        .send(DmCommand::Accept { request })
        .await
        .expect("the accept queues");
    side.wait_for("B's acceptance is composed", HOP, |e| {
        matches!(
            e,
            DmEvent::Delivery {
                seq: 0,
                state: DeliveryState::Composed,
                ..
            }
        )
        .then_some(())
    })
    .await;

    handle
        .send(DmCommand::Send {
            to: from,
            body: REPLY.into(),
        })
        .await
        .expect("the reply queues");
    side.wait_for("B's reply is composed", HOP, |e| {
        matches!(
            e,
            DmEvent::Delivery {
                seq: 1,
                state: DeliveryState::Composed,
                ..
            }
        )
        .then_some(())
    })
    .await;
}

/// A comes back holding only what its knock left on disk, opens what B wrote
/// while A was gone, and sends one of its own.
async fn a_collects_and_replies(handle: &DmDriverHandle, side: &mut Side, result: &mut StepResult) {
    // Nothing here is sent by a command. B's acceptance and reply were written
    // while this process did not exist, and what A opens is what the records on
    // the network hold, under keys A's own store re-derived.
    let accepted = side
        .wait_for("A collects B's acceptance", HOP, |e| match e {
            DmEvent::Message { seq: 0, body, .. } => Some(body.clone()),
            _ => None,
        })
        .await;
    assert_eq!(
        accepted, "",
        "the acceptance carries no body; a non-empty one is a different frame"
    );
    result.opened.push((0, accepted));

    let (peer, reply): (PkLt, String) = side
        .wait_for("A collects B's reply", HOP, |e| match e {
            DmEvent::Message {
                from, seq: 1, body, ..
            } => Some((from.clone(), body.clone())),
            _ => None,
        })
        .await;
    assert_eq!(reply, REPLY, "A must recover the exact body B sent");
    result.opened.push((1, reply));

    // **A may speak only because it has just collected the acceptance.** A run
    // that found this correspondence on disk and nothing else is refused with
    // `RefusalReason::NotEstablishedThisSession`, which is why the reply belongs
    // in this step rather than in one of its own.
    handle
        .send(DmCommand::Send {
            to: peer,
            body: A_REPLY.into(),
        })
        .await
        .expect("A's reply queues");
    side.wait_for("A's reply is composed", HOP, |e| {
        matches!(
            e,
            DmEvent::Delivery {
                seq: 1,
                state: DeliveryState::Composed,
                ..
            }
        )
        .then_some(())
    })
    .await;
}

/// B opens A's reply. Collecting it is what publishes the cursor that settles
/// B's own messages, which is the only way B's side of the containment below
/// becomes something a run can refute.
async fn b_collects_the_reply(side: &mut Side, result: &mut StepResult) {
    let body = side
        .wait_for("B collects A's reply", HOP, |e| match e {
            DmEvent::Message { seq: 1, body, .. } => Some(body.clone()),
            _ => None,
        })
        .await;
    assert_eq!(body, A_REPLY, "B must recover the exact body A sent");
    result.opened.push((1, body));
}

/// A reads B's acknowledgement, so A's own reply shows as collected.
///
/// A fetch rather than a send, so it needs no re-establishment: what this run
/// does is read the record B wrote and settle the outbox entry already on disk.
async fn a_confirms_its_reply_was_collected(side: &mut Side) {
    side.wait_for("A's reply is confirmed collected", ACK_HOP, |e| {
        matches!(
            e,
            DmEvent::Delivery {
                seq: 1,
                state: DeliveryState::ConfirmedCollected,
                ..
            }
        )
        .then_some(())
    })
    .await;
}

/// Come back after a kill, over the state directory the killed process left.
///
/// The store on disk is the whole of what this process has: everything the
/// killed one held in memory is gone. The roster is the first thing the driver
/// says and is read from those records, so waiting for it is how this run knows
/// the store reopened; the window that follows lets the outbox re-seed anything
/// the kill left unpublished.
///
/// **The evidence comes back from the records, not from that roster.** A count
/// of correspondences says the store is readable and nothing about what the
/// killed process had achieved, so the settled set is re-derived from the outbox
/// records themselves — anything that landed between the snapshot and the kill
/// is recovered here rather than lost.
async fn resume(step: Step, side: &mut Side, result: &mut StepResult, state: &Path) {
    side.wait_for("the roster the store on disk holds", HOP, |e| {
        matches!(e, DmEvent::Roster { .. }).then_some(())
    })
    .await;
    side.drain_until_idle(QUIESCE_IDLE, RESUME_WINDOW).await;
    let recovered = settled_on_disk(&step.role().dir(state));
    result
        .resumed
        .push(format!("{} {}", step.label(), recovered.len()));
    result.settled.extend(recovered);
}

/// Write the boundary marker and hold, to be killed where this process stands.
///
/// The driver test waits for the marker before it kills, so the kill lands after
/// the step's work is on disk and before the process has stopped anything — which
/// is what a step boundary is.
async fn hold_at_boundary(state: &Path, step: Step) {
    let marker = state.join(format!("{}.boundary", step.label()));
    std::fs::write(&marker, step.label()).expect("the boundary marker writes");
    eprintln!("{}: at its boundary, holding for the kill", step.label());
    tokio::time::sleep(HOLD_CAP).await;
    panic!(
        "{} held at its boundary for {}s and was never killed",
        step.label(),
        HOLD_CAP.as_secs()
    );
}

/// Bytes as lowercase hex.
fn hex_encode_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The inverse of [`hex_encode_bytes`].
fn hex_decode_bytes(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
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

/// The four steps, as the test functions the driver tests re-execute.
///
/// Each is `#[ignore]`d: it is spawned with its role and state directory in the
/// environment, and run on its own with neither it prints a line and returns.
mod steps {
    use super::{run_step, Step};

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "one step of this file's driver tests; it is spawned by them, with its state directory in the environment"]
    async fn b_publishes_its_key_record() {
        run_step(Step::BPublishes).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "one step of this file's driver tests; it is spawned by them, with its state directory in the environment"]
    async fn a_knocks_carrying_message_zero() {
        run_step(Step::AKnocks).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "one step of this file's driver tests; it is spawned by them, with its state directory in the environment"]
    async fn b_collects_accepts_and_replies() {
        run_step(Step::BCollectsAndReplies).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "one step of this file's driver tests; it is spawned by them, with its state directory in the environment"]
    async fn a_collects_the_acceptance_and_replies() {
        run_step(Step::ACollectsAndReplies).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "one step of this file's driver tests; it is spawned by them, with its state directory in the environment"]
    async fn b_collects_the_reply() {
        run_step(Step::BCollectsTheReply).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "one step of this file's driver tests; it is spawned by them, with its state directory in the environment"]
    async fn a_confirms_its_reply_was_collected() {
        run_step(Step::AConfirms).await;
    }
}

// ── the harness's own tests, which need no network ───────────────────────────

/// How long the fixture step below holds, so the boundary check has a live
/// process to catch. Long enough to be caught, short enough to end the run on
/// its own if a kill is ever missed.
const FIXTURE_HOLD: Duration = Duration::from_secs(30);

/// What a fixture step is given to start, write its file and exit.
const FIXTURE_BUDGET: Duration = Duration::from_secs(60);

/// Fixture steps for the harness's own tests. Neither touches the network.
///
/// Each writes a file before doing anything else, and the tests below assert
/// that file exists. That is the positive control on the spawn itself: a
/// `--exact` name that matches nothing runs no test and still exits 0, which
/// would otherwise read exactly like a fixture that ran and passed.
mod fakes {
    use std::path::PathBuf;

    /// A step that announces itself and exits at once.
    #[test]
    #[ignore = "a fixture process for this file's harness tests; it is spawned, never run on its own"]
    fn a_step_that_exits_at_once() {
        if let Some(state) = std::env::var_os(super::ENV_STATE) {
            std::fs::write(PathBuf::from(state).join("fixture-exited"), "exited")
                .expect("the fixture's file writes");
        }
    }

    /// A step that announces itself and then fails, the way a step whose own
    /// assertions did not hold fails.
    #[test]
    #[ignore = "a fixture process for this file's harness tests; it is spawned, never run on its own"]
    fn a_step_that_fails() {
        if let Some(state) = std::env::var_os(super::ENV_STATE) {
            std::fs::write(PathBuf::from(state).join("fixture-failed"), "failed")
                .expect("the fixture's file writes");
        }
        panic!("this step could not do its part of the conversation");
    }

    /// A step that announces itself and then outlives its boundary.
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

/// Wait for `path` to appear, or fail.
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

/// A step that has exited leaves the boundary clear.
#[test]
fn a_step_that_has_exited_leaves_the_boundary_clear() {
    let state = tempfile::tempdir().expect("a state directory");
    let mut supervisor = Supervisor::new(state.path().to_path_buf());
    let env = [(ENV_STATE, state.path().to_string_lossy().into_owned())];
    let borrowed: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();

    supervisor
        .spawn("exits", "fakes::a_step_that_exits_at_once", &borrowed)
        .expect("the fixture spawns");
    let status = supervisor.wait_at(0, FIXTURE_BUDGET);

    assert!(
        status.success(),
        "the fixture step exits cleanly: {status:?}"
    );
    assert!(
        state.path().join("fixture-exited").exists(),
        "the fixture step must actually have run; without its file a name that \
         matched no test would look the same"
    );
    supervisor
        .boundary_is_clear()
        .expect("a step that has been waited for leaves the boundary clear");
}

/// The control: a step that outlives its boundary fails the check the driver
/// tests make before every spawn.
#[test]
fn a_step_that_outlives_its_boundary_fails_the_boundary_check() {
    let state = tempfile::tempdir().expect("a state directory");
    let mut supervisor = Supervisor::new(state.path().to_path_buf());
    let env = [(ENV_STATE, state.path().to_string_lossy().into_owned())];
    let borrowed: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();

    supervisor
        .spawn(
            "outlives",
            "fakes::a_step_that_outlives_its_boundary",
            &borrowed,
        )
        .expect("the fixture spawns");
    wait_for_file(&state.path().join("fixture-holding"), FIXTURE_BUDGET);

    let failure = supervisor
        .boundary_is_clear()
        .expect_err("a live step must fail the boundary check");
    assert!(
        failure.contains("outlives"),
        "the failure must name the step still running: {failure}"
    );

    supervisor.kill_all();
    supervisor
        .boundary_is_clear()
        .expect("the boundary is clear once the step is killed and reaped");
}

/// The result file round-trips everything a step writes into it, including an
/// empty body and a body holding the separator.
#[test]
fn a_result_file_round_trips() {
    let written = StepResult {
        opened: vec![
            (0, MESSAGE_0.to_owned()),
            (1, String::new()),
            (2, "a body with spaces\nand a newline".to_owned()),
        ],
        settled: vec![0, 1],
        done: vec!["a-knocks".to_owned()],
        resumed: vec!["a-knocks 1".to_owned()],
    };

    let read_back = StepResult::parse(&written.encode()).expect("the result file parses");
    assert_eq!(read_back, written);

    let state = tempfile::tempdir().expect("a state directory");
    let path = Role::A.result_path(state.path());
    written.save(&path);
    assert_eq!(StepResult::load(&path), written);
    assert_eq!(read_back.opened_seqs(), vec![0, 1, 2]);
}

/// A result file that is not there yet reads as an empty one, so a step's first
/// run and its resumption take the same path to their own record.
#[test]
fn an_absent_result_file_reads_as_empty() {
    let state = tempfile::tempdir().expect("a state directory");
    let empty = StepResult::load(&Role::A.result_path(state.path()));
    assert_eq!(empty, StepResult::default());
    assert!(!empty.has_done(Step::AKnocks));

    let mut marked = empty;
    marked.mark_done(Step::AKnocks);
    marked.mark_done(Step::AKnocks);
    assert_eq!(marked.done, vec!["a-knocks".to_owned()]);

    // Per step, not per role: a role whose first step ran has not thereby run
    // its later one, and a resumption is decided from this.
    assert!(marked.has_done(Step::AKnocks));
    assert!(!marked.has_done(Step::ACollectsAndReplies));
    assert!(!marked.has_done(Step::AConfirms));
}

/// `opened_seqs` sorts and deduplicates, so the containment check reads one
/// sequence number once however many times a side opened at it.
#[test]
fn opened_seqs_sorts_and_deduplicates() {
    let result = StepResult {
        opened: vec![
            (2, "c".to_owned()),
            (0, "a".to_owned()),
            (2, "c again".to_owned()),
            (1, "b".to_owned()),
        ],
        ..StepResult::default()
    };
    assert_eq!(result.opened_seqs(), vec![0, 1, 2]);
}

/// A result file the harness did not write is an error, not an empty result. A
/// silently-ignored line would drop a side's evidence and read as a side that
/// opened nothing.
#[test]
fn a_result_file_it_did_not_write_is_an_error() {
    assert!(StepResult::parse("nonsense 1").is_err());
    assert!(StepResult::parse("opened notanumber ff").is_err());
    assert!(StepResult::parse("opened 1 zz").is_err());
    assert!(StepResult::parse("settled\n").is_err());
    // The control: the shapes it does write still parse. `ff` is among the
    // refusals above rather than here — a body is a `String`, and a lone `0xff`
    // is not one.
    assert!(StepResult::parse("opened 1 ff").is_err());
    assert!(StepResult::parse("opened 1 61\nsettled 2\ndone a-knocks\n").is_ok());
}

/// The end-state check passes on a completed conversation and fails, naming
/// what is wrong, on each way one can be incomplete.
#[test]
fn the_end_state_check_catches_each_way_a_conversation_is_incomplete() {
    let complete_a = || StepResult {
        opened: vec![(0, String::new()), (1, REPLY.to_owned())],
        settled: vec![0, 1],
        done: Vec::new(),
        resumed: Vec::new(),
    };
    let complete_b = || StepResult {
        opened: vec![(0, MESSAGE_0.to_owned()), (1, A_REPLY.to_owned())],
        settled: vec![0, 1],
        done: Vec::new(),
        resumed: Vec::new(),
    };
    conversation_completed(&complete_a(), &complete_b()).expect("a completed conversation passes");

    // A sequence one side shows collected that the other never opened.
    let mut a = complete_a();
    a.settled.push(7);
    let failure = conversation_completed(&a, &complete_b())
        .expect_err("a settlement with no matching opened message must fail");
    assert!(
        failure.contains('7'),
        "the failure must name the sequence: {failure}"
    );

    // Neither side's settled set may be empty: an empty one satisfies the
    // containment above without the peer's cursor ever having passed anything.
    let mut a = complete_a();
    a.settled.clear();
    conversation_completed(&a, &complete_b()).expect_err("an empty settled set on A must fail");
    let mut b = complete_b();
    b.settled.clear();
    conversation_completed(&complete_a(), &b).expect_err("an empty settled set on B must fail");

    // Each positive fact in turn.
    let mut b = complete_b();
    b.opened.retain(|(seq, _)| *seq != 0);
    conversation_completed(&complete_a(), &b).expect_err("B not opening message 0 must fail");
    let mut a = complete_a();
    a.opened.retain(|(seq, _)| *seq != 1);
    conversation_completed(&a, &complete_b()).expect_err("A not opening B's reply must fail");
    let mut b = complete_b();
    b.opened.retain(|(seq, _)| *seq != 1);
    conversation_completed(&complete_a(), &b).expect_err("B not opening A's reply must fail");
}

/// A step that fails is reported by the driver with the tail of its own output,
/// rather than as a bare status nobody can act on.
#[test]
fn a_step_that_fails_is_reported_with_its_own_output() {
    let state = tempfile::tempdir().expect("a state directory");
    let mut supervisor = Supervisor::new(state.path().to_path_buf());
    let env = [(ENV_STATE, state.path().to_string_lossy().into_owned())];
    let borrowed: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();

    let failure = supervisor
        .run_child("fails", "fakes::a_step_that_fails", &borrowed)
        .expect_err("a step that fails must fail the driver");

    assert!(
        state.path().join("fixture-failed").exists(),
        "the fixture step must actually have run"
    );
    assert!(
        failure.contains("fails exited"),
        "the failure must name the step and its status: {failure}"
    );
    assert!(
        failure.contains("could not do its part of the conversation"),
        "the failure must quote the step's own output: {failure}"
    );
}

/// Every step names a distinct test function and label, and each belongs to the
/// role its name says. A step pointing at another step's function would run the
/// wrong half of the conversation and report nothing about it.
#[test]
fn every_step_names_its_own_function_and_role() {
    for (i, step) in CONVERSATION.iter().enumerate() {
        for other in CONVERSATION.iter().skip(i + 1) {
            assert_ne!(step.test_name(), other.test_name());
            assert_ne!(step.label(), other.label());
        }
        assert!(
            step.test_name().starts_with("steps::"),
            "{} must name a function in the steps module",
            step.label()
        );
        assert!(
            step.label().starts_with(step.role().name()),
            "{}'s label must name its role",
            step.label()
        );
    }
    assert_eq!(Role::from_name(Role::A.name()), Some(Role::A));
    assert_eq!(Role::from_name(Role::B.name()), Some(Role::B));
    assert_eq!(Role::from_name("neither"), None);
    assert_ne!(Role::A.port(), Role::B.port());
    let root = Path::new("/state");
    assert_ne!(Role::A.dir(root), Role::B.dir(root));
    assert_ne!(Role::A.result_path(root), Role::B.result_path(root));
    assert_eq!(
        Boundary::from_name(Boundary::Hold.name()),
        Some(Boundary::Hold)
    );
    assert_eq!(
        Boundary::from_name(Boundary::Exit.name()),
        Some(Boundary::Exit)
    );
    assert_eq!(Boundary::from_name("neither"), None);
}

/// The hex the result file and the published identity use round-trips, and
/// refuses what it did not write.
#[test]
fn the_hex_round_trips_and_refuses_what_it_did_not_write() {
    assert_eq!(hex_decode(&hex_encode("")).as_deref(), Some(""));
    assert_eq!(
        hex_decode(&hex_encode(MESSAGE_0)).as_deref(),
        Some(MESSAGE_0)
    );
    assert_eq!(hex_decode("0"), None);
    assert_eq!(hex_decode("zz"), None);

    let bytes = [0u8, 1, 0x7f, 0xff];
    assert_eq!(
        hex_decode_bytes(&hex_encode_bytes(&bytes)).as_deref(),
        Some(bytes.as_slice())
    );
    assert_eq!(hex_decode_bytes("abc"), None);
}
