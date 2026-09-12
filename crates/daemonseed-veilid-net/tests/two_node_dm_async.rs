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
//! both sides in one process cannot make that statement, however carefully it
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
//! 1. **B publishes its advert.** A conversation starts from an advert a
//!    knocker encapsulates to, so B has to have been online once before A can
//!    knock. This is that occasion, and it is a step like any other: one
//!    process, alone.
//! 2. **A knocks, carrying message 0.** A first contact carries the first
//!    message body, so the knock is message 0 rather than a separate write.
//! 3. **B collects, accepts and replies.** B reads its drop, opens message 0
//!    from the hello it finds, and accepts — and its reply is turn 0 of B's own
//!    direction, carried by the acceptance rather than written after it.
//! 4. **A collects, and replies in the same run.** A comes back holding only
//!    what its knock left on disk, opens B's acceptance and the reply it
//!    carried, and then sends one of its own. It may speak only once the
//!    acceptance is in hand: a side still awaiting one is refused an ordinary
//!    message, which is why the reply is not a step of its own.
//! 5. **B collects A's reply**, and in doing so publishes the cursor that
//!    settles B's own messages.
//! 6. **A confirms.** A runs once more and reads the cursor B published, so its
//!    own reply shows as collected.
//!
//! Steps 5 and 6 are what make the containment below falsifiable rather than
//! vacuous: without them neither side ever reads the other's cursor over its
//! last message, and a `settled` set that is empty satisfies any containment.
//!
//! Every step publishes its own role's advert first. The write is the same
//! bytes every time, and a correspondent that finds the record missing has
//! nothing to encapsulate a hello to.
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
//! `docs/design/direct-messaging.md` § Flows names the steps and § Records the
//! shapes they read and write. The steps below call
//! `daemonseed_core::dm::flows` for every one of them, over
//! `daemonseed_veilid_net::VeilidRecords`, so a body opens under the key the
//! conversation's own chain derived and never one this file makes up, and the
//! records it opens are on the network rather than in a map.
//!
//! **A resumed step recovers its `settled` set from those records and its
//! `opened` set from the snapshot.** The conversation record on disk says how
//! far a correspondent's cursor has passed, so that half survives a
//! kill outright. Opened bodies do not: the layer keeps no message store — a
//! collected body lives in memory for as long as the process does — so the
//! snapshot a step writes at its boundary is the only record of them.
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
use std::sync::Mutex;
use std::time::{Duration, Instant};

use daemonseed_core::dm::advert::{self, AdvertKeys};
use daemonseed_core::dm::channel;
use daemonseed_core::dm::flows::{self, FlowError, Me, Records, Resumed, Surfaced};
use daemonseed_core::dm::store::Store;
use daemonseed_core::identity::keys::{
    derive_identity_keys, Identity, SignKeypair, IDENTITY_PK_LEN, ML_DSA_SEED_LEN,
};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::storage::dm_store::CorrespondenceLabel;
use daemonseed_core::storage::seeds::AEAD_KEY_LEN;
use daemonseed_veilid_net::{VeilidNet, VeilidNetConfig, VeilidRecords, WriteCountsSnapshot};

// ── what a run is configured with ────────────────────────────────────────────

/// The at-rest key each side's [`DmPersist`] seals under. Per-run scratch
/// directories, so this is a fixture rather than a secret.
const AT_REST: [u8; AEAD_KEY_LEN] = [0x2b; AEAD_KEY_LEN];

/// The budget for one hop: a write, its spread, and a correspondent's next sweep
/// of it. A doorbell sweep reads every subkey of the record and a page sweep
/// every subkey of its own, each a separate network round trip, so a hop is one
/// tick plus an open plus a whole sweep.
const HOP: Duration = Duration::from_secs(600);

/// How long the attach is given before a step gives up on the network.
const ATTACH_SECS: u64 = 180;

/// How long a step killed at its boundary is given to die.
const STOP: Duration = Duration::from_secs(120);

/// What the node's graceful close is given once a step's work is done.
const NODE_CLOSE: Duration = Duration::from_secs(30);

/// How long one step of the conversation may take before the driver gives up on
/// it. Generous: a step joins the network from cold, mints a proof of work, and
/// waits out several hops.
const STEP_BUDGET: Duration = Duration::from_secs(5400);

/// The budget for a hop whose reading half is a whole drop scan.
///
/// Longer than [`HOP`] by construction, and by roughly the ratio of the work.
/// A drop is 256 slots and the record store reads one subkey per call, so a
/// scan is 256 separate reads on one open record — where a hop's reading half
/// is otherwise a single subkey. The budget covers several scans, because a
/// hello that has not spread yet is found by scanning again.
const DROP_SCAN_HOP: Duration = Duration::from_secs(2700);

/// The budget for a hop that waits on an acknowledgement. Longer than [`HOP`] by
/// construction: the correspondent has first to collect the message, which is an
/// ordinary hop, its acknowledgement is floored before the write is permitted,
/// and the sender then reads the record back on its own cadence.
const ACK_HOP: Duration = Duration::from_secs(900);

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

    /// Where this role's ML-DSA identity seed lives. The seed is the whole of
    /// what persists between a role's steps: the signing keypair and every
    /// channel owner seed come back out of it.
    fn identity_seed_path(self, state: &Path) -> PathBuf {
        self.dir(state).join("identity-seed")
    }

    fn result_path(self, state: &Path) -> PathBuf {
        self.dir(state).join("result")
    }
}

/// One step of the conversation. Each runs as its own process.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Step {
    /// B publishes the advert A knocks at, and stops.
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
            Step::BPublishes => "steps::b_publishes_its_advert",
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
    /// Close the node, exit.
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
    /// What each completed step wrote, by label.
    ///
    /// **The write budget as a number rather than a claim.**
    /// `docs/design/direct-messaging.md` § Write budget gives a ceiling per
    /// flow, and the flows count writes by counting calls — so a step that
    /// wrote twice where the design allows one would put the layer over a
    /// ceiling the substrate enforces, with every assertion about the
    /// conversation still passing.
    wrote: Vec<(String, WriteCountsSnapshot)>,
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
        for (label, w) in &self.wrote {
            out.push_str(&format!(
                "wrote {label} {} {} {} {} {}\n",
                w.hello, w.erase, w.control, w.ring, w.advert
            ));
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
                "wrote" => {
                    let label = fields
                        .next()
                        .ok_or_else(|| format!("line {}: no label", n + 1))?
                        .to_owned();
                    let counts: Vec<u64> = fields
                        .next()
                        .unwrap_or_default()
                        .split(' ')
                        .map(|f| f.parse::<u64>().map_err(|_| format!("line {}", n + 1)))
                        .collect::<core::result::Result<_, _>>()?;
                    let [hello, erase, control, ring, advert] = counts.as_slice() else {
                        return Err(format!("line {}: a write record has five counts", n + 1));
                    };
                    out.wrote.push((
                        label,
                        WriteCountsSnapshot {
                            hello: *hello,
                            erase: *erase,
                            control: *control,
                            ring: *ring,
                            advert: *advert,
                        },
                    ));
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

    /// What the step labelled `label` wrote, or `None` where it left no record.
    fn writes_of(&self, step: Step) -> Option<WriteCountsSnapshot> {
        self.wrote
            .iter()
            .find(|(label, _)| label == step.label())
            .map(|(_, counts)| *counts)
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

/// Lay out a fresh state directory: one identity seed per role, and nothing
/// else.
///
/// The seeds are drawn here and the identities derived from them in the step
/// processes, so no step holds the other role's secret. A knocks at the
/// identity B *published*, which B writes out in its first step.
fn lay_out_state(state: &Path) -> [PathBuf; 2] {
    for role in [Role::A, Role::B] {
        std::fs::create_dir_all(role.dir(state)).expect("the role's directory is created");
        let mut seed = [0u8; ML_DSA_SEED_LEN];
        getrandom::fill(&mut seed).expect("the operating system's generator");
        std::fs::write(role.identity_seed_path(state), hex_encode_bytes(&seed))
            .expect("the identity seed writes");
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
        .any(|(seq, body)| *seq == 0 && body.as_str() == REPLY)
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

/// The steps the kill variant kills at, in order.
///
/// Hoisted out of the test so the schedule is a value: a variant that quietly
/// skipped a step would still complete the conversation and still pass every
/// end-state assertion, because the step it skipped killing simply ran once
/// like any other. [`the_kill_schedule_covers_every_step_once`] is what refuses
/// that.
fn boundary_schedule() -> Vec<Step> {
    CONVERSATION.to_vec()
}

/// What `docs/design/direct-messaging.md` § Write budget allows each step, and
/// what each step must have written to have done its part.
///
/// A value rather than a set of assertions so the check can be run here over
/// hand-built results: a ceiling nothing ever reaches is satisfied by a layer
/// that writes nothing at all, which is why each step's floor is checked too.
/// Adverts are excluded — one per step, published by the harness on the layer's
/// own schedule rather than by any flow.
fn within_the_write_budget(a: &StepResult, b: &StepResult) -> Result<(), String> {
    // First contact: at most four writes — the channel opening, message 0, the
    // hello and one re-pick of the hello.
    check_step(
        a,
        Step::AKnocks,
        &[("control", 1, 1), ("ring", 1, 1), ("hello", 1, 2)],
    )?;
    // Acceptance: this side's opening, the reply it carries, the hello back with
    // at most one re-pick, and the erase of the hello it collected.
    check_step(
        b,
        Step::BCollectsAndReplies,
        &[
            ("control", 1, 1),
            ("ring", 1, 1),
            ("hello", 1, 2),
            ("erase", 1, 1),
        ],
    )?;
    // An ordinary message is one ring write, and A's acceptance-collection step
    // sends one. The erase is of the acceptance hello A collected.
    check_step(
        a,
        Step::ACollectsAndReplies,
        &[("ring", 1, 1), ("erase", 1, 1), ("hello", 0, 0)],
    )?;
    // A collection batch publishes at most one cursor and writes nothing else.
    check_step(
        b,
        Step::BCollectsTheReply,
        &[("control", 0, 1), ("ring", 0, 0), ("hello", 0, 0)],
    )?;
    check_step(
        a,
        Step::AConfirms,
        &[("control", 0, 1), ("ring", 0, 0), ("hello", 0, 0)],
    )?;
    Ok(())
}

/// Assert one step's counts against `(kind, floor, ceiling)` bounds.
fn check_step(result: &StepResult, step: Step, bounds: &[(&str, u64, u64)]) -> Result<(), String> {
    let counts = result
        .writes_of(step)
        .ok_or_else(|| format!("{} recorded no write counts", step.label()))?;
    for (kind, floor, ceiling) in bounds {
        let wrote = match *kind {
            "hello" => counts.hello,
            "erase" => counts.erase,
            "control" => counts.control,
            "ring" => counts.ring,
            other => return Err(format!("no such write kind: {other}")),
        };
        if wrote < *floor {
            return Err(format!(
                "{} wrote {wrote} {kind} write(s), fewer than the {floor} its part needs: {counts:?}",
                step.label()
            ));
        }
        if wrote > *ceiling {
            return Err(format!(
                "{} wrote {wrote} {kind} write(s), over the {ceiling} the write budget allows: {counts:?}",
                step.label()
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

    let a = StepResult::load(&a_result);
    let b = StepResult::load(&b_result);
    conversation_completed(&a, &b)
        .expect("the conversation completes across processes that are never alive together");
    within_the_write_budget(&a, &b).expect("no step exceeds the design's write budget");
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

    for step in boundary_schedule() {
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
    // **Per side, not summed.** A total says the right number of resumptions
    // happened somewhere; it does not say one side resumed at all, and a run
    // where one side's steps all resumed twice and the other's never would
    // satisfy it while leaving half the resume path unexercised.
    for (role, result) in [(Role::A, &a), (Role::B, &b)] {
        let steps = boundary_schedule()
            .iter()
            .filter(|step| step.role() == role)
            .count();
        assert_eq!(
            result.resumed.len(),
            steps,
            "{}: every one of its {steps} step(s) must have been resumed exactly once; {:?}",
            role.name(),
            result.resumed
        );
    }
    conversation_completed(&a, &b)
        .expect("the conversation survives a kill at every step boundary");
    within_the_write_budget(&a, &b)
        .expect("no step exceeds the design's write budget across a kill and a resumption");
}

// ── one step, as a process ───────────────────────────────────────────────────

/// How long a step waits between attempts at a read whose answer is still
/// spreading through the distributed hash table.
///
/// A flow reports an absent record as an ordinary outcome — no advert yet, no
/// hello in any slot — because that is what a plain read of an unwritten subkey
/// returns. So a step that has to wait for a correspondent's write to arrive
/// waits by reading again, and this is how often.
const POLL: Duration = Duration::from_secs(20);

/// Entropy for the flows that draw it.
///
/// Every key a conversation rests on comes through here, so it is the operating
/// system's generator and not a seeded one: a run against the live network
/// publishes records under these keys.
fn fill(buf: &mut [u8]) -> Result<(), ()> {
    getrandom::fill(buf).map_err(|_| ())
}

/// Seconds since the epoch, which is what an advert's window is measured in.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs()
}

/// This role's identity seed, from the file its state directory holds.
///
/// **The seed is what persists, and both halves of an identity come out of
/// it.** The signing keypair signs adverts and openings, and the same seed
/// derives every channel owner seed this side writes under, so a step that
/// inherited either from an earlier one would not be a separate process at all.
fn identity_seed_of(role: Role, state: &Path) -> [u8; ML_DSA_SEED_LEN] {
    let path = role.identity_seed_path(state);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let bytes = hex_decode_bytes(text.trim()).expect("the identity seed decodes");
    <[u8; ML_DSA_SEED_LEN]>::try_from(bytes.as_slice()).expect("an ML-DSA seed's length")
}

/// This role's conversation store, under its own state directory.
fn store_of(role: Role, state: &Path) -> Store {
    Store::open(role.dir(state).join("dm-flows"), &AT_REST).expect("the store opens")
}

/// Load this role's advert keys, minting them on the first step, and publish
/// the advert they name.
///
/// Published on every step rather than once: an advert record is world-writable
/// and has no time to live, so a correspondent that finds it missing has
/// nothing to verify a hello's encapsulation against, and the design's answer
/// to both is that the owner rewrites it. One write.
fn publish_advert(store: &Store, records: &mut VeilidRecords, signer: &SignKeypair) -> AdvertKeys {
    let keys = advert_keys_of(store);
    let bytes = keys.advert_bytes(signer).expect("the advert signs");
    let owner = advert::derive_owner_seed(signer.public_key()).expect("the advert owner seed");
    records
        .publish_advert(&owner, advert::ADVERT_SUBKEYS, &bytes)
        .expect("the advert publishes");
    keys
}

/// This role's advert keys: the ones its store holds, or a fresh pair persisted
/// before it is used.
///
/// **The keys have to be the same in every step, and nothing in memory carries
/// between steps.** A correspondent encapsulates a hello to the advert key it
/// read, so a step that minted a second pair would publish an advert nobody's
/// outstanding hello can be opened under, and the conversation would stop with
/// every record in place. The persist precedes the publish for the same reason
/// § Flows orders every persist before the write it enables: an advert whose
/// secret never reached disk is one nobody can open a hello against.
fn advert_keys_of(store: &Store) -> AdvertKeys {
    match store.load_advert_keys().expect("the advert keys read") {
        Some(snapshot) => AdvertKeys::restore(snapshot),
        None => {
            let keys = AdvertKeys::new(now_secs(), fill).expect("advert keys mint");
            store
                .persist_advert_keys(&keys.snapshot())
                .expect("the advert keys persist");
            keys
        }
    }
}

/// Open every channel this side owns, and return how many were opened.
///
/// **A write to a channel needs the owner keypair, and a lookup key is not
/// one.** The lookup key a hello discloses is a public key, so the record store
/// holds the keypair only for channels opened in this process — which is what a
/// relaunch has to redo before it can write. The owner seed comes back from the
/// identity seed, the correspondent and the generation the store holds, so
/// nothing about it survives a kill except the inputs it is derived from.
///
/// The lookup key that comes back is asserted equal to the one the store
/// recorded. That is the positive control on the derivation: a seed derived
/// under the wrong inputs would open a perfectly valid record that the
/// correspondent never reads, and every write to it would succeed.
fn reopen_own_channels(store: &Store, records: &mut VeilidRecords, me: &Me<'_>) -> usize {
    let loaded = store.load().expect("the store reloads");
    for conv in &loaded.convs {
        let owner = channel::derive_owner_seed(
            me.identity_seed,
            &conv.state.peer_identity_pk,
            conv.state.generation,
        )
        .expect("the channel owner seed");
        let lookup_key = records
            .open_channel(&owner, channel::CHANNEL_SUBKEYS)
            .expect("the channel opens");
        assert_eq!(
            lookup_key, conv.state.outgoing_lookup_key,
            "the re-derived channel owner must address the record the store recorded"
        );
    }
    loaded.convs.len()
}

/// Every sequence number of this side's own that a correspondent's cursor has
/// passed.
///
/// **The half of a side's evidence that survives a kill outright.** A cursor
/// the flows read is written into the conversation record, and that record does
/// not go anywhere; opened bodies have no equivalent, because the layer keeps
/// no message store, so they come from the snapshot a step writes instead.
fn settled_on_disk(store: &Store) -> Vec<u64> {
    let loaded = store.load().expect("the store reloads");
    let mut seqs = Vec::new();
    for conv in &loaded.convs {
        seqs.extend(0..conv.state.peer_collected);
    }
    seqs.sort_unstable();
    seqs.dedup();
    seqs
}

/// The one correspondence this side holds, which every step after the first has
/// exactly one of.
fn only_correspondence(store: &Store) -> CorrespondenceLabel {
    let loaded = store.load().expect("the store reloads");
    assert_eq!(
        loaded.convs.len(),
        1,
        "this conversation has one correspondent; the store holds {}",
        loaded.convs.len()
    );
    loaded
        .convs
        .into_iter()
        .next()
        .expect("one conversation")
        .peer
}

/// Where B writes the identity it has published, and A reads it.
fn published_identity_path(state: &Path) -> PathBuf {
    state.join("b-identity")
}

/// Retry `attempt` until it answers, or fail naming the hop.
///
/// What a step waits on is a correspondent's write spreading far enough through
/// the distributed hash table for this node's read to find it, and the only
/// thing that reports it has is the read itself. So the wait is a read repeated
/// on a cadence, and the budget is what makes a correspondent that never wrote
/// a failure rather than a hang.
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

    let seed = identity_seed_of(role, &state);
    let signer = SignKeypair::from_ml_dsa_seed(&seed).expect("the identity derives from its seed");
    let me = Me {
        signer: &signer,
        identity_seed: &seed,
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
    let advert_keys = publish_advert(&store, &mut records, &signer);
    let reopened = reopen_own_channels(&store, &mut records, &me);
    eprintln!(
        "{}: {reopened} channel(s) of its own reopened",
        step.label()
    );
    if role == Role::B {
        std::fs::write(
            published_identity_path(&state),
            hex_encode_bytes(signer.public_key().as_slice()),
        )
        .expect("the published identity writes");
    }

    if resuming {
        resume(step, &store, &mut records, &mut result);
    } else {
        match step {
            // B's advert is already written, above. Nothing else is owed: this
            // is the occasion of B having been online once, which is what a
            // first contact needs of it.
            Step::BPublishes => {}
            Step::AKnocks => a_knocks(&store, &mut records, &me, &state).await,
            Step::BCollectsAndReplies => {
                b_collects_accepts_and_replies(&store, &mut records, &me, &advert_keys, &mut result)
                    .await
            }
            Step::ACollectsAndReplies => {
                a_collects_and_replies(&store, &mut records, &me, &advert_keys, &mut result).await
            }
            Step::BCollectsTheReply => {
                b_collects_the_reply(&store, &mut records, &mut result).await
            }
            Step::AConfirms => {
                a_confirms_its_reply_was_collected(&store, &mut records, &mut result).await
            }
        }
        result.mark_done(step);
        // Taken after the step's work and before the boundary, so a kill cannot
        // take the record of what was written with it. The advert publish above
        // is counted apart from the flows' writes, which is what lets the
        // budgets below be asserted against § Write budget's own numbers.
        let counts = records.write_counts();
        eprintln!("{}: wrote {counts:?}", step.label());
        result.wrote.push((step.label().to_owned(), counts));
    }

    result.settled.extend(settled_on_disk(&store));
    result.settled.sort_unstable();
    result.settled.dedup();
    result.save(&role.result_path(&state));

    match boundary {
        Boundary::Hold => hold_at_boundary(&state, step).await,
        Boundary::Exit => node.shutdown(NODE_CLOSE).await,
    }
}

/// A knocks at the identity B published, carrying message 0.
///
/// The knock is retried only while B's advert has not arrived. That is the one
/// outcome a re-run repeats safely: the advert is read before anything is
/// persisted or written, so a run that stops there has left nothing behind, and
/// every later stop resumes from the conversation record instead.
async fn a_knocks(store: &Store, records: &mut VeilidRecords, me: &Me<'_>, state: &Path) {
    let path = published_identity_path(state);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let bytes = hex_decode_bytes(text.trim()).expect("the published identity decodes");
    let recipient = <[u8; IDENTITY_PK_LEN]>::try_from(bytes.as_slice())
        .expect("the published identity is an identity key");

    let opened = until(
        "B's advert, and A's knock into B's drop",
        HOP,
        || match flows::first_contact(
            store,
            records,
            me,
            &recipient,
            MESSAGE_0.as_bytes(),
            fill,
            now_secs(),
        ) {
            Ok(outcome) => Some(outcome),
            Err(FlowError::NoAdvert) => None,
            Err(e) => panic!("A's knock failed: {e}"),
        },
    )
    .await;
    eprintln!("A: knocked — {opened:?}");
}

/// B reads its drop, opens message 0 from the hello it finds, accepts, and
/// replies on the channel the acceptance establishes.
async fn b_collects_accepts_and_replies(
    store: &Store,
    records: &mut VeilidRecords,
    me: &Me<'_>,
    advert_keys: &AdvertKeys,
    result: &mut StepResult,
) {
    let request = until("A's knock arrives in B's drop", DROP_SCAN_HOP, || {
        let surfaced = flows::collect(store, records, me, advert_keys, |_| false)
            .expect("B's own store answers");
        surfaced.into_iter().find_map(|one| match one {
            Surfaced::ContactRequest(request) => Some(request),
            Surfaced::Failed { error, .. } => panic!("B could not settle a hello: {error}"),
            _ => None,
        })
    })
    .await;

    let accepted = flows::accept(
        store,
        records,
        me,
        &request,
        REPLY.as_bytes(),
        fill,
        now_secs(),
    )
    .expect("B accepts the contact request");
    // The knock is message 0 of A's direction, and opening it is what B has to
    // show for FC1.
    for (seq, body) in accepted.bodies.iter().enumerate() {
        result.opened.push((seq as u64, body_text(body)));
    }
    assert!(
        result
            .opened
            .iter()
            .any(|(seq, body)| *seq == 0 && body == MESSAGE_0),
        "B must recover the exact body A knocked with; it opened {:?}",
        result.opened
    );
}

/// A comes back holding only what its knock left on disk, opens what B wrote
/// while A did not exist, and sends one of its own.
///
/// Nothing here is sent until the acceptance is in hand. A run that found the
/// correspondence on disk and nothing else is still awaiting acceptance, and
/// the flow refuses an ordinary message while it is — which is why the reply
/// belongs in this step rather than in one of its own.
async fn a_collects_and_replies(
    store: &Store,
    records: &mut VeilidRecords,
    me: &Me<'_>,
    advert_keys: &AdvertKeys,
    result: &mut StepResult,
) {
    let acceptance = until("B's acceptance arrives in A's drop", DROP_SCAN_HOP, || {
        let surfaced = flows::collect(store, records, me, advert_keys, |_| false)
            .expect("A's own store answers");
        surfaced.into_iter().find_map(|one| match one {
            Surfaced::Accepted(acceptance) => Some(acceptance),
            Surfaced::Failed { error, .. } => panic!("A could not settle a hello: {error}"),
            _ => None,
        })
    })
    .await;

    for (seq, body) in acceptance.bodies.iter().enumerate() {
        result.opened.push((seq as u64, body_text(body)));
    }
    assert!(
        result
            .opened
            .iter()
            .any(|(seq, body)| *seq == 0 && body == REPLY),
        "A must recover the exact body B replied with; it opened {:?}",
        result.opened
    );

    let seq = flows::send_message(store, records, &acceptance.peer, A_REPLY.as_bytes(), fill)
        .expect("A's reply sends");
    assert_eq!(seq, 1, "A's reply follows the message its knock carried");
}

/// B opens A's reply. Collecting it is what publishes the cursor that settles
/// B's own messages, which is the only way B's side of the containment becomes
/// something a run can refute.
async fn b_collects_the_reply(store: &Store, records: &mut VeilidRecords, result: &mut StepResult) {
    let peer = only_correspondence(store);
    let batch = until("A's reply arrives in its channel", HOP, || {
        let batch = flows::collect_batch(store, records, &peer).expect("B's own store answers");
        (!batch.bodies.is_empty()).then_some(batch)
    })
    .await;
    assert_eq!(
        batch.bodies.len(),
        1,
        "A wrote one message since B's cursor"
    );
    assert_eq!(
        body_text(&batch.bodies[0]),
        A_REPLY,
        "B must recover the exact body A sent"
    );
    result
        .opened
        .push((batch.my_collected - 1, body_text(&batch.bodies[0])));
}

/// A reads B's published cursor, so A's own reply shows as collected.
///
/// A collection first, because B's cursor rides inside a message where B has
/// written one and in its control subkey where it has not, and only the batch
/// reads the first of those. The cursor read that follows is what settles a
/// reply B answered with nothing.
async fn a_confirms_its_reply_was_collected(
    store: &Store,
    records: &mut VeilidRecords,
    result: &mut StepResult,
) {
    let peer = only_correspondence(store);
    let collected = until("B's cursor passes A's reply", ACK_HOP, || {
        flows::collect_batch(store, records, &peer).expect("A's own store answers");
        let cursor = flows::peer_cursor(store, records, &peer).expect("A's own store answers")?;
        (cursor > 1).then_some(cursor)
    })
    .await;
    result.settled.extend(0..collected);
}

/// Come back after a kill, over the state directory the killed process left.
///
/// The store on disk is the whole of what this process has. Its own channels
/// are opened again above, which is what a relaunch owes the record store, and
/// any hello the kill left outstanding is rewritten from the bytes the store
/// holds rather than minted again — the encapsulation is fixed, so a rewrite is
/// the same hello and not a second one.
///
/// **The evidence comes back from the records, not from the count.** The number
/// of correspondences says the store is readable and nothing about what the
/// killed process had achieved, so the settled set is re-derived from the
/// conversation records themselves.
fn resume(step: Step, store: &Store, records: &mut VeilidRecords, result: &mut StepResult) {
    let loaded = store.load().expect("the store reloads");
    let mut rewritten = 0usize;
    for conv in &loaded.convs {
        match flows::resume_first_contact(store, records, &conv.peer)
            .expect("a rewrite of an outstanding hello")
        {
            Resumed::Rewrote(_) => rewritten += 1,
            Resumed::Nothing => {}
        }
    }
    let recovered = settled_on_disk(store);
    result.resumed.push(format!(
        "{} {} {rewritten}",
        step.label(),
        loaded.convs.len()
    ));
    result.settled.extend(recovered);
}

/// Write the boundary marker and hold, to be killed where this process stands.
///
/// The driver test waits for the marker before it kills, so the kill lands
/// after the step's work is on disk and before the process has stopped
/// anything — which is what a step boundary is.
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

/// One opened body as the text it was sent as.
fn body_text(body: &[u8]) -> String {
    String::from_utf8(body.to_vec()).expect("a body this file sent is text")
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

/// The six steps, as the test functions the driver tests re-execute.
///
/// Each is `#[ignore]`d: it is spawned with its role and state directory in the
/// environment, and run on its own with neither it prints a line and returns.
///
/// Each is a **multi-thread** runtime, and that is a requirement rather than a
/// default. The record store bridges the flows' synchronous calls onto the
/// asynchronous transport by blocking the worker they run on, which is sound
/// only where there are other workers to carry the node meanwhile.
mod steps {
    use super::{run_step, Step};

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "one step of this file's driver tests; it is spawned by them, with its state directory in the environment"]
    async fn b_publishes_its_advert() {
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

/// A node config with a fresh node identity, this role's listen port, and its
/// own storage dir.
///
/// The node identity is per-node and unrelated to the conversation: nothing
/// about a drop slot, a channel address or a message key derives from a node
/// key, which is why it is generated per step rather than carried with the user
/// identity across one.
fn node_config(role: Role, dir: &Path) -> VeilidNetConfig {
    let id = derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap();
    let mut cfg = VeilidNetConfig::new(id.veilid_node_seed, dir.to_string_lossy().into_owned());
    cfg.namespace = format!("two_node_dm_async_{}", role.name());
    cfg.listen_address = Some(role.port().to_owned());
    cfg
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
        wrote: vec![(
            "a-knocks".to_owned(),
            WriteCountsSnapshot {
                hello: 2,
                erase: 0,
                control: 1,
                ring: 1,
                advert: 1,
            },
        )],
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
    // A opened one body: B's reply, which is sequence 0 of B's direction
    // because the acceptance carries it. B opened two: A's knock at sequence 0
    // and A's reply at sequence 1. Each side's settled set is what the other's
    // cursor has actually passed, so B's holds only sequence 0 — A's reply
    // carried a cursor over B's first message and nothing has carried one over
    // A's own last message except the cursor A reads in its final step.
    let complete_a = || StepResult {
        opened: vec![(0, REPLY.to_owned())],
        settled: vec![0, 1],
        done: Vec::new(),
        resumed: Vec::new(),
        wrote: Vec::new(),
    };
    let complete_b = || StepResult {
        opened: vec![(0, MESSAGE_0.to_owned()), (1, A_REPLY.to_owned())],
        settled: vec![0],
        done: Vec::new(),
        resumed: Vec::new(),
        wrote: Vec::new(),
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
    a.opened.retain(|(seq, _)| *seq != 0);
    conversation_completed(&a, &complete_b()).expect_err("A not opening B's reply must fail");
    let mut b = complete_b();
    b.opened.retain(|(seq, _)| *seq != 1);
    conversation_completed(&complete_a(), &b).expect_err("B not opening A's reply must fail");
}

/// The kill variant kills at every step of the conversation, once each.
///
/// The control on [`boundary_schedule`]: a schedule that dropped a step would
/// leave that step killed at no boundary, and the conversation would still
/// complete.
#[test]
fn the_kill_schedule_covers_every_step_once() {
    let schedule = boundary_schedule();
    assert_eq!(
        schedule.len(),
        CONVERSATION.len(),
        "the kill variant kills at every step: {schedule:?}"
    );
    for step in CONVERSATION {
        assert_eq!(
            schedule.iter().filter(|s| **s == step).count(),
            1,
            "{} must be killed at exactly once",
            step.label()
        );
    }
}

/// A role's advert keys are the same in a second step as in the first.
///
/// **Nothing in memory crosses a step, so this is what makes a conversation
/// possible at all.** A correspondent encapsulates its hello to the advert key
/// it read; a second call that minted a fresh pair would publish an advert that
/// no outstanding hello can be opened under, and the conversation would stop
/// with every record in place and no error anywhere.
#[test]
fn a_roles_advert_keys_survive_between_steps() {
    // The store seals its records, so the module has to be up before it opens.
    // Tolerated rather than asserted: another test in this binary may have
    // initialized it already, and a second call is not a failure of this one.
    let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
    let root = tempfile::tempdir().expect("a store directory");
    let first = {
        let store = Store::open(root.path().join("dm-flows"), &AT_REST).expect("the store opens");
        advert_keys_of(&store)
    };
    // A separate `Store` over the same directory, as a separate step process
    // would open it.
    let second = {
        let store = Store::open(root.path().join("dm-flows"), &AT_REST).expect("the store reopens");
        advert_keys_of(&store)
    };
    assert_eq!(
        first.serial(),
        second.serial(),
        "the serial is the same key"
    );
    assert_eq!(first.not_before(), second.not_before());
    assert_eq!(
        first.encapsulation_key(),
        second.encapsulation_key(),
        "a correspondent's hello is encapsulated to this key; it must not change"
    );
}

/// A step's write counts survive the result file, and a step with none is
/// distinguishable from one that wrote nothing.
#[test]
fn a_steps_write_counts_round_trip_through_the_result_file() {
    let mut result = StepResult::default();
    result.wrote.push((
        Step::AKnocks.label().to_owned(),
        WriteCountsSnapshot {
            hello: 2,
            erase: 0,
            control: 1,
            ring: 1,
            advert: 1,
        },
    ));
    let parsed = StepResult::parse(&result.encode()).expect("the record parses");
    assert_eq!(parsed.writes_of(Step::AKnocks).map(|c| c.hello), Some(2));
    assert_eq!(parsed.writes_of(Step::AKnocks).map(|c| c.control), Some(1));
    assert_eq!(
        parsed.writes_of(Step::AConfirms),
        None,
        "a step that recorded nothing is absent, not zero"
    );
}

/// The budget check passes on a run inside it and fails, naming the step, on a
/// run over it or short of it.
///
/// A value rather than a set of assertions for the reason
/// [`conversation_completed`] is one: four of its clauses are what stop the
/// ceiling being satisfied by a layer that wrote nothing.
#[test]
fn the_write_budget_check_catches_a_step_over_and_under_its_allowance() {
    let within = || {
        let a = StepResult {
            wrote: vec![
                (
                    Step::AKnocks.label().to_owned(),
                    WriteCountsSnapshot {
                        hello: 1,
                        control: 1,
                        ring: 1,
                        advert: 1,
                        erase: 0,
                    },
                ),
                (
                    Step::ACollectsAndReplies.label().to_owned(),
                    WriteCountsSnapshot {
                        ring: 1,
                        erase: 1,
                        advert: 1,
                        hello: 0,
                        control: 0,
                    },
                ),
                (
                    Step::AConfirms.label().to_owned(),
                    WriteCountsSnapshot {
                        control: 1,
                        advert: 1,
                        hello: 0,
                        erase: 0,
                        ring: 0,
                    },
                ),
            ],
            ..StepResult::default()
        };
        let b = StepResult {
            wrote: vec![
                (
                    Step::BCollectsAndReplies.label().to_owned(),
                    WriteCountsSnapshot {
                        hello: 2,
                        control: 1,
                        ring: 1,
                        erase: 1,
                        advert: 1,
                    },
                ),
                (
                    Step::BCollectsTheReply.label().to_owned(),
                    WriteCountsSnapshot {
                        control: 1,
                        advert: 1,
                        hello: 0,
                        erase: 0,
                        ring: 0,
                    },
                ),
            ],
            ..StepResult::default()
        };
        (a, b)
    };
    let (a, b) = within();
    within_the_write_budget(&a, &b).expect("a run inside the budget passes");

    // A hello re-picked twice is one more write than § Write budget allows.
    let (mut a, b) = within();
    a.wrote[0].1.hello = 3;
    let over = within_the_write_budget(&a, &b).expect_err("a third hello must fail");
    assert!(
        over.contains(Step::AKnocks.label()),
        "the failure must name the step: {over}"
    );

    // A first contact that wrote no message slot did not carry message 0.
    let (mut a, b) = within();
    a.wrote[0].1.ring = 0;
    within_the_write_budget(&a, &b).expect_err("a first contact with no message must fail");

    // A step that recorded nothing at all is not a step inside the budget.
    let (a, mut b) = within();
    b.wrote.clear();
    let missing = within_the_write_budget(&a, &b).expect_err("a step with no record must fail");
    assert!(
        missing.contains(Step::BCollectsAndReplies.label()),
        "the failure must name the step: {missing}"
    );
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
