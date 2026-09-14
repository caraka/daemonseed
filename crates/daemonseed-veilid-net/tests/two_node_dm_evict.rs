//! Integration test: when the network loses a channel subkey holding an
//! outstanding message, the owner's `SyncSet` inspect reports the loss, and the
//! owner's rewrite from its outbox puts back the exact bytes.
//!
//! Serves `docs/design/direct-messaging.md` § Eviction detection and its open
//! question: whether `inspect_dht_record` with `DHTReportScope::SyncSet` reports
//! an eviction on the live network.
//!
//! ## How the loss is produced, and why it is waited for
//!
//! File references are to `veilid-core` 0.5.7.
//!
//! - **Another node cannot zero the subkey.** A DFLT-schema subkey accepts a
//!   value only when its writer is the record owner
//!   (`storage_manager/schema.rs:48-80`, "wrong writer"), and that check runs on
//!   every set, inbound and outbound (`storage_manager/set_value.rs:233,435,759`).
//!   A channel's owner keypair is derived from its owner's identity secret, so no
//!   other identity holds it.
//! - **A holder of the owner keypair can overwrite, and that is not a loss.** A
//!   write carries the next sequence number (`DHTReportScope::UpdateSet`,
//!   `veilid_api/types/dht/dht_record_report.rs`), so the network's number moves
//!   ahead of the writer's local one. § Eviction detection counts only an absent
//!   or lower network number as a loss.
//! - **A loss cannot be staged by killing a writer before its flush.** Veilid
//!   saves its queue of writes still to be flushed (`storage_manager/mod.rs:598-618`)
//!   and reloads it at start (`storage_manager/mod.rs:637`), so the value leaves
//!   on the next run.
//!
//! So this test waits for real eviction. Storage nodes evict the least recently
//! touched record, and `record_store/record_store_inner/record_index.rs:259`
//! touches a record whenever `with_record` reads it. After A has written, the
//! driver leaves the channel untouched for a quiet period, then has a separate
//! observer look, and repeats until a look reports a loss or the rounds run out.
//! Rounds that end with no loss fail the test as "eviction was not observed",
//! which means the claim was not probed, not that it was refused.
//!
//! **The observer is a fresh node, and A's channel inspect precedes any open of
//! A's channel.** Opening a record a node already holds locally queues a
//! rehydration that pushes the local copy back to the network
//! (`storage_manager/open_record.rs:38-50`, `storage_manager/rehydrate.rs:50-57`).
//! A node with no local copy takes the network path and queues nothing, so the
//! observer's look does not repair what it is looking for.
//!
//! ## Every look carries a positive control
//!
//! An inspect that reaches nobody returns no network numbers, which reads
//! exactly like an evicted record, and a node that has only just attached may
//! not reach anyone yet. So every look, the observer's and A's, is bracketed by
//! a control: the looking role publishes its own advert, which confirms the
//! write left the node, and then inspects it before and after the channel. A
//! look whose control does not report a network number at or above its local
//! one is "network not answering". It is never a loss and never a pass.
//!
//! The control is a different record from A's channel. A look whose fanout
//! reaches the advert's holders and none of the channel's still reads as a loss,
//! and nothing here tells those two apart.
//!
//! ## What a repair must show
//!
//! Veilid keeps a subkey's sequence number when a write carries the same data
//! and writer as the local copy (`storage_manager/set_value.rs:212-219`). A
//! message slot is rewritten with its outbox ciphertext, byte-identical to A's
//! local copy, so a rewritten slot comes back at the established number, exactly
//! as a rehydrated one does. The control subkey is resealed under a fresh nonce,
//! so its rewrite does move the number.
//!
//! So a lost control subkey counts as repaired when A rewrote it and its
//! restored network number is above the established one. A lost message slot
//! counts as repaired on ordering evidence instead: a fresh observer's look,
//! taken after A's inspect and before A's rewrite step, still shows it lost;
//! A's write returned; and a later look shows the network at or above the
//! established number, with the bytes a fresh node reads back identical to the
//! outbox entry. A slot that look already shows restored was repaired before
//! the rewrite, by rehydration, and fails the run.
//!
//! The look is not immediately before the write. A's rewrite step opens its
//! channel before writing, and that open can queue a rehydration of its own, so
//! the evidence shows the slot was still lost when A's step began, not that A's
//! write is what restored it.
//!
//! ## Timing, and what it does not probe
//!
//! The run records when the observer's look answered and when A's inspect
//! answered, requires them in that order, and requires A's report within
//! `delivery::POLL_INTERVAL_MIN` of the look. That bounds this harness's own
//! turnaround. It does not probe the runner's poll cadence, which nothing here
//! drives.
//!
//! ## The run, one process per step
//!
//! 1. **B publishes its advert** and stops.
//! 2. **A establishes its channel.** A writes a first contact to B, which puts
//!    the channel opening in the control subkey and message 0 in slot 1. B never
//!    collects, so the message stays outstanding. A records its outbox and waits
//!    until both subkeys are on the network.
//! 3. **Quiet, then the observer looks,** repeated until an answered look sees
//!    a subkey's network number absent or below A's recorded one.
//! 4. **A inspects**, controlled, before its store touches the channel.
//! 5. **The observer looks again**, controlled, before A's rewrite step.
//! 6. **A rewrites** every lost subkey: message slots from the outbox entries its
//!    store holds, the control subkey resealed from its conversation record. A
//!    then waits until the network holds its numbers again.
//! 7. **The observer reads back** each outstanding slot from the network.
//!
//! [`eviction_repaired`] is the whole end-state check, a value so the tests at
//! the foot of this file can run it over hand-built notes.
//!
//! ## What this needs to run
//!
//! The driver is `#[ignore]`d. It needs:
//!
//! - the public Veilid network reachable;
//! - three free UDP ports: [`A_PORT`], [`B_PORT`] and [`O_PORT`];
//! - the `--ignored` flag;
//! - optionally [`ENV_QUIET_SECS`] and [`ENV_ROUNDS`], the quiet period and the
//!   number of rounds, which default to [`DEFAULT_QUIET`] and
//!   [`DEFAULT_ROUNDS`] and are refused outside [`QUIET_FLOOR`] to
//!   [`QUIET_CEILING`] and 1 to [`ROUNDS_CEILING`]. A look is itself a read, so
//!   a quiet period shorter than the network's eviction age keeps the record
//!   alive.
//!
//! So:
//!
//!     cargo test -p daemonseed-veilid-net --test two_node_dm_evict -- \
//!         --ignored --nocapture
//!
//! Expect days with the defaults.
//!
//! The harness's own bookkeeping is covered by tests that run without a
//! network, at the foot of this file.

use std::ffi::OsString;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use daemonseed_core::dm::advert::{self, AdvertKeys};
use daemonseed_core::dm::channel::{self, ChannelOpening, Control};
use daemonseed_core::dm::delivery::POLL_INTERVAL_MIN;
use daemonseed_core::dm::flows::{self, FirstContact, FlowError, Me, Records};
use daemonseed_core::dm::store::Store;
use daemonseed_core::identity::keys::{
    derive_identity_keys, Identity, IdentityKeys, SignKeypair, IDENTITY_PK_LEN,
};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::storage::seeds::AEAD_KEY_LEN;
use daemonseed_veilid_net::dm::runner::SubkeyReport;
use daemonseed_veilid_net::{VeilidNet, VeilidNetConfig, VeilidRecords};

// ── what a run is configured with ────────────────────────────────────────────

const AT_REST: [u8; AEAD_KEY_LEN] = [0x5e; AEAD_KEY_LEN];

/// The budget for one hop: a write, its spread, and a reader's next look.
const HOP: Duration = Duration::from_secs(600);

const ATTACH_SECS: u64 = 180;

const NODE_CLOSE: Duration = Duration::from_secs(30);

/// How long one step may take before the driver kills it and fails.
const STEP_BUDGET: Duration = Duration::from_secs(5400);

/// How often a step retries a read whose answer is still spreading.
const POLL: Duration = Duration::from_secs(20);

const CHILD_POLL: Duration = Duration::from_millis(500);

const STDERR_TAIL_LINES: usize = 40;

/// The default quiet period before each look.
const DEFAULT_QUIET: Duration = Duration::from_secs(6 * 60 * 60);

/// The shortest quiet period accepted. A look is a read, so anything shorter
/// keeps the record touched.
const QUIET_FLOOR: Duration = Duration::from_secs(60);

/// The longest quiet period accepted.
const QUIET_CEILING: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// The default number of quiet periods before the test gives up.
const DEFAULT_ROUNDS: u32 = 28;

/// The most rounds accepted.
const ROUNDS_CEILING: u32 = 1000;

const MESSAGE_0: &str = "an outstanding message the network is left to lose";

const A_PORT: &str = ":5197";
const B_PORT: &str = ":5198";
const O_PORT: &str = ":5199";

const ENV_STATE: &str = "DAEMONSEED_DM_EVICT_STATE";
const ENV_ROLE: &str = "DAEMONSEED_DM_EVICT_ROLE";
const ENV_ROUND: &str = "DAEMONSEED_DM_EVICT_ROUND";
/// Seconds of quiet before each look.
const ENV_QUIET_SECS: &str = "DAEMONSEED_DM_EVICT_QUIET_SECS";
/// How many quiet periods before the test gives up.
const ENV_ROUNDS: &str = "DAEMONSEED_DM_EVICT_ROUNDS";

/// The record a report line is about.
const CHANNEL: &str = "channel";
const CONTROL_BEFORE: &str = "control-before";
const CONTROL_AFTER: &str = "control-after";

// ── roles and steps ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role {
    /// The channel's owner.
    A,
    /// The recipient, whose advert A writes to and who never collects.
    B,
    /// The observer, a fresh node on every run, with an identity only for its
    /// own control advert.
    O,
}

const ROLES: [Role; 3] = [Role::A, Role::B, Role::O];

impl Role {
    fn name(self) -> &'static str {
        match self {
            Role::A => "a",
            Role::B => "b",
            Role::O => "o",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        ROLES.into_iter().find(|role| role.name() == name)
    }

    fn port(self) -> &'static str {
        match self {
            Role::A => A_PORT,
            Role::B => B_PORT,
            Role::O => O_PORT,
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Step {
    BPublishes,
    AEstablishes,
    ObserverLooks,
    AInspects,
    ObserverLooksBeforeRewrite,
    ARewrites,
    ObserverReadsBack,
}

const STEPS: [Step; 7] = [
    Step::BPublishes,
    Step::AEstablishes,
    Step::ObserverLooks,
    Step::AInspects,
    Step::ObserverLooksBeforeRewrite,
    Step::ARewrites,
    Step::ObserverReadsBack,
];

impl Step {
    fn role(self) -> Role {
        match self {
            Step::BPublishes => Role::B,
            Step::AEstablishes | Step::AInspects | Step::ARewrites => Role::A,
            Step::ObserverLooks | Step::ObserverLooksBeforeRewrite | Step::ObserverReadsBack => {
                Role::O
            }
        }
    }

    fn label(self) -> &'static str {
        match self {
            Step::BPublishes => "b-publishes",
            Step::AEstablishes => "a-establishes",
            Step::ObserverLooks => "o-looks",
            Step::AInspects => "a-inspects",
            Step::ObserverLooksBeforeRewrite => "o-looks-before-rewrite",
            Step::ARewrites => "a-rewrites",
            Step::ObserverReadsBack => "o-reads-back",
        }
    }

    fn test_name(self) -> &'static str {
        match self {
            Step::BPublishes => "steps::b_publishes_its_advert",
            Step::AEstablishes => "steps::a_establishes_a_channel_with_an_outstanding_message",
            Step::ObserverLooks => "steps::o_looks_at_the_channel_from_a_fresh_node",
            Step::AInspects => "steps::a_inspects_its_channel_first",
            Step::ObserverLooksBeforeRewrite => "steps::o_looks_again_before_the_rewrite",
            Step::ARewrites => "steps::a_rewrites_from_its_outbox",
            Step::ObserverReadsBack => "steps::o_reads_the_rewritten_slot_back",
        }
    }
}

// ── the notes file ───────────────────────────────────────────────────────────

/// One subkey of one inspect, as a step writes it down.
#[derive(Clone, PartialEq, Eq, Debug)]
struct ReportLine {
    /// `established`, `observed-<round>`, `inspected`, `before-rewrite` (the
    /// observer's), `a-before-rewrite` (A's own) or `restored`.
    phase: String,
    /// [`CHANNEL`], [`CONTROL_BEFORE`] or [`CONTROL_AFTER`].
    record: String,
    subkey: u16,
    local: Option<u64>,
    network: Option<u64>,
    pending: bool,
    /// Wall-clock seconds when the inspect answered.
    at_secs: u64,
}

#[derive(Default, Clone, PartialEq, Eq, Debug)]
struct Notes {
    done: Vec<String>,
    /// This role's identity public key.
    identity: Option<Vec<u8>>,
    /// The lookup key of A's channel.
    lookup: Option<Vec<u8>>,
    /// A's outstanding outbox entries, `(seq, ciphertext)`.
    outbox: Vec<(u64, Vec<u8>)>,
    reports: Vec<ReportLine>,
    /// Phases whose channel inspect answered no network number for any subkey
    /// of a record this node holds.
    network_silent: Vec<String>,
    /// The subkeys A rewrote.
    rewrote: Vec<u16>,
    /// What the observer read back, `(seq, bytes)`.
    read_back: Vec<(u64, Vec<u8>)>,
    /// How long each step took, in milliseconds.
    timings: Vec<(String, u64)>,
}

impl Notes {
    fn encode(&self) -> String {
        let number = |n: Option<u64>| n.map_or_else(|| "-".to_owned(), |n| n.to_string());
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
        for (seq, bytes) in &self.outbox {
            out.push_str(&format!("outbox {seq} {}\n", bytes_field(bytes)));
        }
        for line in &self.reports {
            out.push_str(&format!(
                "report {} {} {} {} {} {} {}\n",
                line.phase,
                line.record,
                line.subkey,
                number(line.local),
                number(line.network),
                u8::from(line.pending),
                line.at_secs
            ));
        }
        for phase in &self.network_silent {
            out.push_str(&format!("network-silent {phase}\n"));
        }
        for subkey in &self.rewrote {
            out.push_str(&format!("rewrote {subkey}\n"));
        }
        for (seq, bytes) in &self.read_back {
            out.push_str(&format!("read-back {seq} {}\n", bytes_field(bytes)));
        }
        for (label, millis) in &self.timings {
            out.push_str(&format!("timing {label} {millis}\n"));
        }
        out
    }

    fn parse(text: &str) -> Result<Self, String> {
        let seq = |s: &str| s.parse::<u64>().ok();
        let subkey = |s: &str| s.parse::<u16>().ok();
        let flag = |s: &str| match s {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        };
        let record = |s: &str| {
            [CHANNEL, CONTROL_BEFORE, CONTROL_AFTER]
                .into_iter()
                .find(|known| *known == s)
        };
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
                ["outbox", s, h] => out
                    .outbox
                    .push((required(s, at, seq)?, required(h, at, parse_bytes)?)),
                ["report", phase, rec, sub, local, network, pending, at_secs] => {
                    out.reports.push(ReportLine {
                        phase: (*phase).to_owned(),
                        record: required(rec, at, record)?.to_owned(),
                        subkey: required(sub, at, subkey)?,
                        local: optional(local, at, seq)?,
                        network: optional(network, at, seq)?,
                        pending: required(pending, at, flag)?,
                        at_secs: required(at_secs, at, seq)?,
                    })
                }
                ["network-silent", phase] => out.network_silent.push((*phase).to_owned()),
                ["rewrote", sub] => out.rewrote.push(required(sub, at, subkey)?),
                ["read-back", s, h] => out
                    .read_back
                    .push((required(s, at, seq)?, required(h, at, parse_bytes)?)),
                ["timing", label, millis] => out
                    .timings
                    .push(((*label).to_owned(), required(millis, at, seq)?)),
                _ => return Err(format!("line {at}: unknown record {line:?}")),
            }
        }
        Ok(out)
    }

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

    /// The channel line for `subkey` in `phase`, if one was written.
    fn line_at(&self, phase: &str, subkey: u16) -> Option<&ReportLine> {
        self.reports
            .iter()
            .find(|line| line.phase == phase && line.record == CHANNEL && line.subkey == subkey)
    }
}

fn required<T>(field: &str, at: usize, parse: impl Fn(&str) -> Option<T>) -> Result<T, String> {
    parse(field).ok_or_else(|| format!("line {at}: {field:?} does not parse"))
}

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

// ── the loss rule and the end state ──────────────────────────────────────────

/// Whether a subkey only its owner writes has been lost: the network holds
/// nothing, or an older number than the owner's. A subkey still queued for the
/// flush has not been lost. This is § Eviction detection's rule for a channel.
fn behind(local: Option<u64>, network: Option<u64>, pending: bool) -> bool {
    if pending {
        return false;
    }
    match (local, network) {
        (_, None) => true,
        (Some(local), Some(network)) => network < local,
        (None, Some(_)) => false,
    }
}

/// Whether a report line shows its subkey on the network: a local number, not
/// queued, and a network number at or above it.
fn held(line: &ReportLine) -> bool {
    line.local.is_some() && !line.pending && !behind(line.local, line.network, line.pending)
}

/// The report for one subkey, or no numbers where the report did not reach it.
fn at(reports: &[SubkeyReport], subkey: u16) -> SubkeyReport {
    reports
        .get(usize::from(subkey))
        .copied()
        .unwrap_or_default()
}

/// Whether an inspect answered no network number for any subkey of a record
/// this node holds some of.
fn network_silent(reports: &[SubkeyReport]) -> bool {
    reports.iter().any(|r| r.local_seq.is_some()) && reports.iter().all(|r| r.network_seq.is_none())
}

/// The subkeys at stake: the control subkey and every outstanding slot.
fn tracked_subkeys(outbox: &[(u64, Vec<u8>)]) -> Vec<u16> {
    let mut subkeys = vec![channel::CONTROL_SUBKEY];
    subkeys.extend(outbox.iter().map(|(seq, _)| channel::slot_for(*seq)));
    subkeys.sort_unstable();
    subkeys.dedup();
    subkeys
}

/// One inspect's reports for `subkeys`, as notes lines.
fn lines_of(
    phase: &str,
    record: &str,
    reports: &[SubkeyReport],
    subkeys: &[u16],
    at_secs: u64,
) -> Vec<ReportLine> {
    subkeys
        .iter()
        .map(|&subkey| {
            let report = at(reports, subkey);
            ReportLine {
                phase: phase.to_owned(),
                record: record.to_owned(),
                subkey,
                local: report.local_seq,
                network: report.network_seq,
                pending: report.pending,
                at_secs,
            }
        })
        .collect()
}

/// Whether the look recorded under `phase` was answered: both its control
/// inspects show the control advert on the network. A look that fails this is
/// the network not answering.
fn look_answered(notes: &Notes, phase: &str) -> bool {
    [CONTROL_BEFORE, CONTROL_AFTER].iter().all(|record| {
        notes.reports.iter().any(|line| {
            line.phase == phase
                && line.record == *record
                && line.subkey == ADVERT_SUBKEY
                && held(line)
        })
    })
}

/// The advert subkey a control inspects.
const ADVERT_SUBKEY: u16 = 0;

/// What an answered control does not establish, carried into every verdict.
const CONTROL_LIMIT: &str = "the control is the looker's own advert, a different record from \
                             A's channel, so a look that reaches the advert's holders and none \
                             of the channel's still reads as a loss";

/// The first answered look that saw a tracked subkey lost against A's recorded
/// number: `(round, when, the lost subkeys)`.
fn first_loss(a: &Notes, o: &Notes) -> Option<(u32, u64, Vec<u16>)> {
    let mut rounds: Vec<u32> = o
        .reports
        .iter()
        .filter_map(|line| line.phase.strip_prefix("observed-")?.parse().ok())
        .collect();
    rounds.sort_unstable();
    rounds.dedup();
    for round in rounds {
        let phase = format!("observed-{round}");
        if !look_answered(o, &phase) {
            continue;
        }
        let mut lost = Vec::new();
        let mut when = None;
        for subkey in tracked_subkeys(&a.outbox) {
            let (Some(baseline), Some(seen)) =
                (a.line_at("established", subkey), o.line_at(&phase, subkey))
            else {
                continue;
            };
            when = Some(seen.at_secs);
            if behind(baseline.local, seen.network, false) {
                lost.push(subkey);
            }
        }
        if let (false, Some(when)) = (lost.is_empty(), when) {
            return Some((round, when, lost));
        }
    }
    None
}

/// The whole end state, from A's and the observer's notes.
///
/// A value so the tests at the foot of this file can show each clause fails on
/// the input it exists to refuse.
fn eviction_repaired(a: &Notes, o: &Notes) -> Result<(), String> {
    if a.outbox.is_empty() {
        return Err("A recorded no outstanding message, so nothing was at stake".into());
    }
    let subkeys = tracked_subkeys(&a.outbox);
    for &subkey in &subkeys {
        let baseline = a
            .line_at("established", subkey)
            .ok_or_else(|| format!("A recorded no baseline for subkey {subkey}"))?;
        if !held(baseline) {
            return Err(format!(
                "subkey {subkey} was not on the network when A established it: {baseline:?}"
            ));
        }
    }

    let (round, observed_at, lost) =
        first_loss(a, o).ok_or("no answered look reported a tracked subkey lost")?;

    if !look_answered(a, "inspected") {
        return Err(format!(
            "A's inspect was not answered: its control advert did not show on the network, so \
             the network was not answering and the inspect counts for nothing ({CONTROL_LIMIT})"
        ));
    }
    if !look_answered(o, "before-rewrite") {
        return Err(format!(
            "the observer's look before the rewrite was not answered, so nothing shows the loss \
             was still there when A's rewrite step began ({CONTROL_LIMIT})"
        ));
    }

    for &subkey in &lost {
        let established = a
            .line_at("established", subkey)
            .and_then(|line| line.local)
            .ok_or_else(|| format!("A recorded no established number for subkey {subkey}"))?;
        let seen = a
            .line_at("inspected", subkey)
            .ok_or_else(|| format!("A's inspect recorded nothing for subkey {subkey}"))?;
        if seen.pending {
            return Err(format!(
                "A's inspect found subkey {subkey} still queued for its flush: {seen:?}"
            ));
        }
        if !behind(seen.local, seen.network, seen.pending) {
            return Err(format!(
                "the look in round {round} saw subkey {subkey} lost, but A's inspect reported \
                 {seen:?}; opening a record held locally queues a rehydration that can repair \
                 the network before the inspect reads it"
            ));
        }
        if seen.at_secs < observed_at {
            return Err(format!(
                "A's inspect answered at {} before the look that saw the loss at {observed_at}",
                seen.at_secs
            ));
        }
        let turnaround = seen.at_secs - observed_at;
        if turnaround > POLL_INTERVAL_MIN.as_secs() {
            return Err(format!(
                "A's inspect reported subkey {subkey} lost {turnaround}s after the observer's \
                 look, more than POLL_INTERVAL_MIN ({}s)",
                POLL_INTERVAL_MIN.as_secs()
            ));
        }
        let before = o.line_at("before-rewrite", subkey).ok_or_else(|| {
            format!("the observer's look before the rewrite recorded nothing for subkey {subkey}")
        })?;
        if before.at_secs < seen.at_secs {
            return Err(format!(
                "the look before the rewrite answered at {} before A's inspect at {}",
                before.at_secs, seen.at_secs
            ));
        }
        if !behind(Some(established), before.network, false) {
            return Err(format!(
                "subkey {subkey} was repaired before the rewrite (rehydration): the observer's \
                 look before A's rewrite step shows network number {:?} against the established \
                 {established}",
                before.network
            ));
        }
        if !a.rewrote.contains(&subkey) {
            return Err(format!(
                "subkey {subkey} was lost but A did not rewrite it, so whatever restored it was \
                 not A's rewrite"
            ));
        }
    }

    for (seq, bytes) in &a.outbox {
        let (_, read) = o
            .read_back
            .iter()
            .find(|(s, _)| s == seq)
            .ok_or_else(|| format!("the observer read back nothing for sequence {seq}"))?;
        if read != bytes {
            return Err(format!(
                "the network copy of sequence {seq} is not the outbox entry: {} byte(s) read, \
                 {} in the outbox",
                read.len(),
                bytes.len()
            ));
        }
    }

    for &subkey in &subkeys {
        let restored = a
            .line_at("restored", subkey)
            .ok_or_else(|| format!("A recorded no report for subkey {subkey} after the rewrite"))?;
        if !held(restored) {
            return Err(format!(
                "after the rewrite subkey {subkey} is not on the network: {restored:?}"
            ));
        }
        let established = a
            .line_at("established", subkey)
            .and_then(|line| line.local)
            .ok_or_else(|| format!("A recorded no established number for subkey {subkey}"))?;
        if restored.network.is_none_or(|network| network < established) {
            return Err(format!(
                "after the rewrite subkey {subkey} is at network number {:?}, below the \
                 established {established}",
                restored.network
            ));
        }
        // A resealed control carries a fresh nonce, so only a rewrite moves its
        // number. A message slot's rewrite is byte-identical to the local copy and
        // keeps its number, so equal is what a slot's repair looks like.
        if subkey == channel::CONTROL_SUBKEY
            && lost.contains(&subkey)
            && restored
                .network
                .is_none_or(|network| network <= established)
        {
            return Err(format!(
                "the control subkey is back at network number {:?}, not above the established \
                 {established}: a resealed control carries a fresh nonce, so only a rewrite \
                 moves its number",
                restored.network
            ));
        }
    }
    Ok(())
}

/// The quiet period and round count, from their environment values.
fn quiet_schedule(
    quiet: Option<OsString>,
    rounds: Option<OsString>,
) -> Result<(Duration, u32), String> {
    let text = |name: &str, value: OsString| {
        value
            .into_string()
            .map_err(|value| format!("{name}={value:?} is not UTF-8"))
    };
    let quiet = match quiet {
        None => DEFAULT_QUIET,
        Some(value) => {
            let s = text(ENV_QUIET_SECS, value)?;
            let secs = s
                .parse::<u64>()
                .map_err(|_| format!("{ENV_QUIET_SECS}={s:?} is not a number of seconds"))?;
            Duration::from_secs(secs)
        }
    };
    if quiet < QUIET_FLOOR || quiet > QUIET_CEILING {
        return Err(format!(
            "{ENV_QUIET_SECS} must be between {} and {} seconds, not {}",
            QUIET_FLOOR.as_secs(),
            QUIET_CEILING.as_secs(),
            quiet.as_secs()
        ));
    }
    let rounds = match rounds {
        None => DEFAULT_ROUNDS,
        Some(value) => {
            let s = text(ENV_ROUNDS, value)?;
            s.parse::<u32>()
                .map_err(|_| format!("{ENV_ROUNDS}={s:?} is not a count"))?
        }
    };
    if rounds == 0 || rounds > ROUNDS_CEILING {
        return Err(format!(
            "{ENV_ROUNDS} must be between 1 and {ROUNDS_CEILING}, not {rounds}"
        ));
    }
    Ok((quiet, rounds))
}

// ── the harness ──────────────────────────────────────────────────────────────

struct Tracked {
    label: String,
    pid: u32,
    child: Child,
    status: Option<ExitStatus>,
    log: PathBuf,
}

/// Every step child this harness has started, and the one-process rule over
/// them, which is a value so a control can assert it fails.
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

    fn spawn(
        &mut self,
        label: &str,
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
            pid: child.id(),
            child,
            status: None,
            log,
        });
        Ok(self.tracked.len() - 1)
    }

    fn drain_log(&self, index: usize) -> String {
        let text = std::fs::read_to_string(&self.tracked[index].log).unwrap_or_default();
        let label = &self.tracked[index].label;
        eprintln!("harness: ---- {label} ----\n{text}harness: ---- end {label} ----");
        text
    }

    fn boundary_is_clear(&mut self) -> Result<(), String> {
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
        if alive.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "still running at the boundary: {}",
                alive.join(", ")
            ))
        }
    }

    fn wait_at(&mut self, index: usize, budget: Duration) -> Result<ExitStatus, String> {
        let started = Instant::now();
        loop {
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

    fn run_child(
        &mut self,
        label: &str,
        test_name: &str,
        env: &[(&str, &str)],
    ) -> Result<(), String> {
        self.boundary_is_clear()?;
        let index = self
            .spawn(label, test_name, env)
            .map_err(|e| format!("{label} did not spawn: {e}"))?;
        let waited = self.wait_at(index, STEP_BUDGET);
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
    fn run_to_exit(&mut self, step: Step, round: Option<u32>) {
        let state = self.state.to_string_lossy().into_owned();
        let round_text = round.map(|r| r.to_string()).unwrap_or_default();
        let mut env = vec![(ENV_STATE, state.as_str()), (ENV_ROLE, step.role().name())];
        if round.is_some() {
            env.push((ENV_ROUND, round_text.as_str()));
        }
        if let Err(e) = self.run_child(step.label(), step.test_name(), &env) {
            panic!("{e}");
        }
        let notes = Notes::load(&step.role().notes_path(&self.state));
        ran(step, round, &notes).unwrap_or_else(|e| panic!("{e}"));
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.kill_all();
    }
}

/// Whether a step's notes record that it ran — for a look, that it recorded
/// this round.
fn ran(step: Step, round: Option<u32>, notes: &Notes) -> Result<(), String> {
    let recorded = match (step, round) {
        (Step::ObserverLooks, Some(round)) => {
            let phase = format!("observed-{round}");
            notes.reports.iter().any(|line| line.phase == phase)
        }
        (Step::ObserverLooks, None) => false,
        _ => notes.done.iter().any(|d| d == step.label()),
    };
    if recorded {
        Ok(())
    } else {
        Err(format!(
            "{} (round {round:?}) left no record of having run; its notes name {:?}",
            step.label(),
            notes.done
        ))
    }
}

// ── the oracle ───────────────────────────────────────────────────────────────

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

/// The eviction probe on the live network.
#[test]
#[ignore = "attaches to the public Veilid network and waits for real eviction, one process per step; opt-in, run with --ignored"]
fn an_evicted_channel_slot_is_reported_and_rewritten_byte_identical() {
    let (quiet, rounds) = quiet_schedule(
        std::env::var_os(ENV_QUIET_SECS),
        std::env::var_os(ENV_ROUNDS),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let state = tempfile::tempdir().expect("a state directory");
    lay_out_state(state.path());
    let mut supervisor = Supervisor::new(state.path().to_path_buf());
    let notes_of = |role: Role| Notes::load(&role.notes_path(state.path()));

    supervisor.run_to_exit(Step::BPublishes, None);
    supervisor.run_to_exit(Step::AEstablishes, None);

    let mut observed = None;
    let mut unanswered = 0u32;
    for round in 1..=rounds {
        eprintln!(
            "harness: round {round}/{rounds}: {}s with no process touching the channel",
            quiet.as_secs()
        );
        std::thread::sleep(quiet);
        supervisor.run_to_exit(Step::ObserverLooks, Some(round));
        let o = notes_of(Role::O);
        if !look_answered(&o, &format!("observed-{round}")) {
            unanswered += 1;
            eprintln!("harness: round {round}: network not answering; not counted as a look");
            continue;
        }
        observed = first_loss(&notes_of(Role::A), &o);
        if observed.is_some() {
            break;
        }
    }
    let Some((round, _, lost)) = observed else {
        panic!(
            "no answered look in {rounds} round(s) of {}s saw the channel lost ({unanswered} \
             round(s) the network did not answer): eviction was not observed, so the claim was \
             not probed",
            quiet.as_secs()
        );
    };
    eprintln!("harness: round {round} saw subkey(s) {lost:?} lost; {CONTROL_LIMIT}");

    supervisor.run_to_exit(Step::AInspects, None);
    supervisor.run_to_exit(Step::ObserverLooksBeforeRewrite, None);
    supervisor.run_to_exit(Step::ARewrites, None);
    supervisor.run_to_exit(Step::ObserverReadsBack, None);

    let a = notes_of(Role::A);
    let o = notes_of(Role::O);
    let start = a.reports.first().map_or(0, |line| line.at_secs);
    let mut timeline: Vec<&ReportLine> = a.reports.iter().chain(o.reports.iter()).collect();
    timeline.sort_by_key(|line| line.at_secs);
    for line in timeline {
        eprintln!(
            "timeline: +{}s {} {} subkey {} local {:?} network {:?} pending {}",
            line.at_secs.saturating_sub(start),
            line.phase,
            line.record,
            line.subkey,
            line.local,
            line.network,
            line.pending
        );
    }
    for notes in [&a, &o] {
        for (label, millis) in &notes.timings {
            eprintln!("timing: {label} took {:.1}s", *millis as f64 / 1000.0);
        }
    }
    for phase in &a.network_silent {
        eprintln!("timeline: {phase}: the network answered no number for any channel subkey");
    }
    match eviction_repaired(&a, &o) {
        Ok(()) => eprintln!(
            "verdict: the loss was reported and the subkeys were restored after A's rewrite \
             step with the exact bytes; {CONTROL_LIMIT}"
        ),
        Err(e) => panic!("verdict: {e}"),
    }
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
fn publish_advert(
    store: &Store,
    records: &mut VeilidRecords,
    signer: &SignKeypair,
) -> Result<(), String> {
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
        .map_err(|e| format!("the advert did not publish: {e}"))
}

/// The lookup key of A's channel, from A's notes.
fn lookup_of(a: &Notes) -> [u8; 32] {
    a.lookup
        .as_deref()
        .and_then(|l| l.try_into().ok())
        .expect("A recorded its channel")
}

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

/// Whether every subkey in `subkeys` has a local number, is not queued, and the
/// network holds at least that number.
fn on_network(reports: &[SubkeyReport], subkeys: &[u16]) -> bool {
    subkeys.iter().all(|&subkey| {
        let report = at(reports, subkey);
        report.local_seq.is_some()
            && !report.pending
            && !behind(report.local_seq, report.network_seq, report.pending)
    })
}

/// One control inspect of this role's own advert, as a report line.
///
/// `publish` first writes the advert, so the record is live by construction,
/// and then retries the inspect for up to [`HOP`] until the advert shows on the
/// network. A control that never shows is written down as it last answered and
/// makes the look unanswered; it does not fail the step.
async fn control(
    store: &Store,
    records: &mut VeilidRecords,
    signer: &SignKeypair,
    phase: &str,
    record: &str,
    publish: bool,
) -> ReportLine {
    let owner = advert::derive_owner_seed(signer.public_key()).expect("the advert owner seed");
    let subkeys = [ADVERT_SUBKEY];
    let mut last = Vec::new();
    if publish {
        if let Err(e) = publish_advert(store, records, signer) {
            eprintln!("{phase} {record}: {e}");
        } else {
            let started = Instant::now();
            loop {
                if let Ok(reports) = records.inspect_advert(&owner, advert::ADVERT_SUBKEYS) {
                    let answered = on_network(&reports, &subkeys);
                    last = reports;
                    if answered {
                        break;
                    }
                }
                if started.elapsed() >= HOP {
                    break;
                }
                tokio::time::sleep(POLL).await;
            }
        }
    } else if let Ok(reports) = records.inspect_advert(&owner, advert::ADVERT_SUBKEYS) {
        last = reports;
    }
    let line = lines_of(phase, record, &last, &subkeys, now_secs())
        .pop()
        .expect("one line for one subkey");
    eprintln!("{phase} {record}: {line:?}");
    line
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
    let round = std::env::var(ENV_ROUND)
        .ok()
        .and_then(|r| r.parse::<u32>().ok());

    daemonseed_core::kats::initialize_module_unsigned_test_binary().expect("oxicrypt init");
    let started = Instant::now();

    let node_dir = role.dir(&state).join("node");
    if role == Role::O {
        // A fresh node on every run: one holding a local copy of A's channel
        // would rehydrate it on open.
        let _ = std::fs::remove_dir_all(&node_dir);
    }
    let (node, _events) = VeilidNet::start(node_config(role, &node_dir))
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
    let mut notes = Notes::load(&role.notes_path(&state));

    match step {
        Step::BPublishes => {
            let keys = identity_of(Role::B, &state);
            publish_advert(&store_of(Role::B, &state), &mut records, &keys.signing)
                .unwrap_or_else(|e| panic!("{e}"));
            notes.identity = Some(keys.signing.public_key().to_vec());
        }
        Step::AEstablishes => a_establishes(&mut records, &state, &mut notes).await,
        Step::ObserverLooks => {
            let round = round.expect("a look is spawned with its round");
            observer_looks(&mut records, &state, round, &mut notes).await
        }
        Step::AInspects => a_inspects(&mut records, &state, &mut notes).await,
        Step::ObserverLooksBeforeRewrite => {
            controlled_look(Role::O, &mut records, &state, "before-rewrite", &mut notes).await
        }
        Step::ARewrites => a_rewrites(&mut records, &state, &mut notes).await,
        Step::ObserverReadsBack => observer_reads_back(&mut records, &state, &mut notes).await,
    }

    notes.mark_done(step);
    notes.timings.push((
        step.label().to_owned(),
        started.elapsed().as_millis() as u64,
    ));
    notes.save(&role.notes_path(&state));
    node.shutdown(NODE_CLOSE).await;
}

/// A writes a first contact to B and waits until the channel is on the network.
async fn a_establishes(records: &mut VeilidRecords, state: &Path, notes: &mut Notes) {
    let keys = identity_of(Role::A, state);
    let me = Me {
        signer: &keys.signing,
        channel_root: &keys.dm_channel_root,
    };
    let store = store_of(Role::A, state);
    publish_advert(&store, records, &keys.signing).unwrap_or_else(|e| panic!("{e}"));
    let recipient: [u8; IDENTITY_PK_LEN] = Notes::load(&Role::B.notes_path(state))
        .identity
        .as_deref()
        .and_then(|b| b.try_into().ok())
        .expect("B recorded its identity");

    let lookup = until(
        "B's advert, and A's first contact",
        HOP,
        || match flows::first_contact(
            &store,
            records,
            &me,
            &recipient,
            MESSAGE_0.as_bytes(),
            fill,
            now_secs(),
        ) {
            Ok(FirstContact::Opened {
                outgoing_lookup_key,
                ..
            }) => Some(outgoing_lookup_key),
            Ok(other) => panic!("a first knock opens a conversation; it was {other:?}"),
            Err(FlowError::NoAdvert) => None,
            Err(e) => panic!("A's first contact failed: {e}"),
        },
    )
    .await;

    let loaded = store.load().expect("A's store reloads");
    assert_eq!(loaded.convs.len(), 1, "A has one correspondent");
    let outbox: Vec<(u64, Vec<u8>)> = loaded.convs[0]
        .outstanding_outbox
        .iter()
        .map(|entry| (entry.seq, entry.ciphertext.clone()))
        .collect();
    assert!(
        !outbox.is_empty(),
        "a first contact leaves message 0 outstanding"
    );
    let subkeys = tracked_subkeys(&outbox);

    let reports = until("A's channel is on the network", HOP, || {
        let reports = records.inspect_channel(&lookup).ok()?;
        on_network(&reports, &subkeys).then_some(reports)
    })
    .await;
    notes.identity = Some(keys.signing.public_key().to_vec());
    notes.lookup = Some(lookup.to_vec());
    notes.outbox = outbox;
    notes.reports.extend(lines_of(
        "established",
        CHANNEL,
        &reports,
        &subkeys,
        now_secs(),
    ));
}

/// One controlled look at A's channel, recorded under `phase`: the control
/// before, the channel, the control after.
async fn controlled_look(
    role: Role,
    records: &mut VeilidRecords,
    state: &Path,
    phase: &str,
    notes: &mut Notes,
) {
    let a = if role == Role::A {
        notes.clone()
    } else {
        Notes::load(&Role::A.notes_path(state))
    };
    let lookup = lookup_of(&a);
    let subkeys = tracked_subkeys(&a.outbox);
    let keys = identity_of(role, state);
    let store = store_of(role, state);

    let before = control(&store, records, &keys.signing, phase, CONTROL_BEFORE, true).await;
    notes.reports.push(before);

    let started = Instant::now();
    match records.inspect_channel(&lookup) {
        Ok(reports) => {
            eprintln!(
                "{phase}: channel inspect answered in {:.1}s",
                started.elapsed().as_secs_f64()
            );
            if network_silent(&reports) {
                notes.network_silent.push(phase.to_owned());
            }
            notes
                .reports
                .extend(lines_of(phase, CHANNEL, &reports, &subkeys, now_secs()));
        }
        Err(e) => eprintln!("{phase}: channel inspect failed: {e}"),
    }

    let after = control(&store, records, &keys.signing, phase, CONTROL_AFTER, false).await;
    notes.reports.push(after);
}

/// A fresh node looks at A's channel, controlled.
async fn observer_looks(records: &mut VeilidRecords, state: &Path, round: u32, notes: &mut Notes) {
    controlled_look(Role::O, records, state, &format!("observed-{round}"), notes).await;
}

/// A looks at its channel, controlled, before anything opens the channel
/// under its owner keypair.
async fn a_inspects(records: &mut VeilidRecords, state: &Path, notes: &mut Notes) {
    controlled_look(Role::A, records, state, "inspected", notes).await;
}

/// A reopens its channel, rewrites every lost subkey, and waits until the
/// network holds its numbers again.
async fn a_rewrites(records: &mut VeilidRecords, state: &Path, notes: &mut Notes) {
    let keys = identity_of(Role::A, state);
    let me = Me {
        signer: &keys.signing,
        channel_root: &keys.dm_channel_root,
    };
    let store = store_of(Role::A, state);
    let loaded = store.load().expect("A's store reloads");
    assert_eq!(loaded.convs.len(), 1, "A has one correspondent");
    let conv = &loaded.convs[0];
    let owner = channel::derive_owner_seed(
        me.channel_root,
        &conv.state.peer_identity_pk,
        conv.state.generation,
    )
    .expect("the channel owner seed");
    let lookup = records
        .open_channel(&owner, channel::CHANNEL_SUBKEYS)
        .expect("A reopens its channel");
    assert_eq!(
        lookup,
        lookup_of(notes),
        "the re-derived owner addresses A's channel"
    );

    let outbox: Vec<(u64, Vec<u8>)> = conv
        .outstanding_outbox
        .iter()
        .map(|entry| (entry.seq, entry.ciphertext.clone()))
        .collect();
    assert_eq!(
        outbox, notes.outbox,
        "the store's outbox is the one recorded at establishment"
    );
    let subkeys = tracked_subkeys(&outbox);

    let before = records
        .inspect_channel(&lookup)
        .expect("A's inspect answers");
    notes.reports.extend(lines_of(
        "a-before-rewrite",
        CHANNEL,
        &before,
        &subkeys,
        now_secs(),
    ));

    let control_report = at(&before, channel::CONTROL_SUBKEY);
    if behind(
        control_report.local_seq,
        control_report.network_seq,
        control_report.pending,
    ) {
        let opening = ChannelOpening::decode(
            conv.state
                .own_opening
                .as_deref()
                .expect("A's opening is persisted")
                .as_slice(),
        )
        .expect("A's opening decodes");
        let sealed = channel::seal_control_with_key(
            conv.state
                .own_control_key
                .as_ref()
                .expect("A's control key is persisted"),
            &Control {
                opening: Some(opening),
                collected_cursor: conv.state.my_collected,
                closed: false,
            },
        )
        .expect("the control reseals");
        records
            .write_channel(&lookup, channel::CONTROL_SUBKEY, &sealed)
            .expect("A rewrites its control subkey");
        notes.rewrote.push(channel::CONTROL_SUBKEY);
    }
    for (seq, bytes) in &outbox {
        let subkey = channel::slot_for(*seq);
        let report = at(&before, subkey);
        if behind(report.local_seq, report.network_seq, report.pending) {
            let written = Instant::now();
            records
                .write_channel(&lookup, subkey, bytes)
                .expect("A rewrites the slot from its outbox");
            eprintln!(
                "A: rewrote sequence {seq} in {:.1}s",
                written.elapsed().as_secs_f64()
            );
            notes.rewrote.push(subkey);
        }
    }

    let restored = until("A's channel is back on the network", HOP, || {
        let reports = records.inspect_channel(&lookup).ok()?;
        on_network(&reports, &subkeys).then_some(reports)
    })
    .await;
    notes.reports.extend(lines_of(
        "restored",
        CHANNEL,
        &restored,
        &subkeys,
        now_secs(),
    ));
}

/// A fresh node reads each outstanding slot back from the network.
async fn observer_reads_back(records: &mut VeilidRecords, state: &Path, notes: &mut Notes) {
    let a = Notes::load(&Role::A.notes_path(state));
    let lookup = lookup_of(&a);
    for (seq, _) in &a.outbox {
        let subkey = channel::slot_for(*seq);
        let bytes = until(&format!("sequence {seq} reads back"), HOP, || {
            records.read_channel(&lookup, subkey).ok().flatten()
        })
        .await;
        notes.read_back.push((*seq, bytes));
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
    async fn a_establishes_a_channel_with_an_outstanding_message() {
        run_step(Step::AEstablishes).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "one step of this file's driver test; it is spawned by it, with its state directory in the environment"]
    async fn o_looks_at_the_channel_from_a_fresh_node() {
        run_step(Step::ObserverLooks).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "one step of this file's driver test; it is spawned by it, with its state directory in the environment"]
    async fn a_inspects_its_channel_first() {
        run_step(Step::AInspects).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "one step of this file's driver test; it is spawned by it, with its state directory in the environment"]
    async fn o_looks_again_before_the_rewrite() {
        run_step(Step::ObserverLooksBeforeRewrite).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "one step of this file's driver test; it is spawned by it, with its state directory in the environment"]
    async fn a_rewrites_from_its_outbox() {
        run_step(Step::ARewrites).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "one step of this file's driver test; it is spawned by it, with its state directory in the environment"]
    async fn o_reads_the_rewritten_slot_back() {
        run_step(Step::ObserverReadsBack).await;
    }
}

fn node_config(role: Role, dir: &Path) -> VeilidNetConfig {
    let id = derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap();
    let mut cfg = VeilidNetConfig::new(id.veilid_node_seed, dir.to_string_lossy().into_owned());
    cfg.namespace = format!("two_node_dm_evict_{}", role.name());
    cfg.listen_address = Some(role.port().to_owned());
    cfg
}

// ── the harness's own tests, which need no network ───────────────────────────

const FIXTURE_HOLD: Duration = Duration::from_secs(30);

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

#[test]
fn a_step_that_outlives_its_boundary_fails_the_boundary_check() {
    let state = tempfile::tempdir().expect("a state directory");
    let dir = state.path().to_string_lossy().into_owned();
    let mut supervisor = Supervisor::new(state.path().to_path_buf());

    supervisor
        .spawn(
            "outlives",
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

#[test]
fn a_step_that_fails_is_reported_with_its_own_output() {
    let state = tempfile::tempdir().expect("a state directory");
    let dir = state.path().to_string_lossy().into_owned();
    let mut supervisor = Supervisor::new(state.path().to_path_buf());

    let failure = supervisor
        .run_child(
            "fails",
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

fn report(
    phase: &str,
    record: &str,
    subkey: u16,
    local: Option<u64>,
    network: Option<u64>,
    at_secs: u64,
) -> ReportLine {
    ReportLine {
        phase: phase.to_owned(),
        record: record.to_owned(),
        subkey,
        local,
        network,
        pending: false,
        at_secs,
    }
}

/// The two control lines of an answered look.
fn answered(phase: &str, at_secs: u64) -> [ReportLine; 2] {
    [
        report(
            phase,
            CONTROL_BEFORE,
            ADVERT_SUBKEY,
            Some(1),
            Some(1),
            at_secs,
        ),
        report(
            phase,
            CONTROL_AFTER,
            ADVERT_SUBKEY,
            Some(1),
            Some(1),
            at_secs,
        ),
    ]
}

#[test]
fn a_step_with_no_record_of_running_is_refused() {
    let mut notes = Notes::default();
    ran(Step::AInspects, None, &notes).expect_err("empty notes are not a step that ran");
    notes.mark_done(Step::AInspects);
    ran(Step::AInspects, None, &notes).expect("a recorded step ran");

    // A look is recorded per round: a record of round 1 is not round 2.
    let mut o = Notes::default();
    o.mark_done(Step::ObserverLooks);
    ran(Step::ObserverLooks, Some(1), &o).expect_err("a done label alone is not this round's look");
    o.reports.extend(answered("observed-1", 0));
    ran(Step::ObserverLooks, Some(1), &o).expect("round 1 was recorded");
    ran(Step::ObserverLooks, Some(2), &o).expect_err("round 2 was not");
    ran(Step::ObserverLooks, None, &o).expect_err("a look spawned without a round did not run");
}

#[test]
fn a_notes_file_round_trips_and_refuses_what_it_did_not_write() {
    let mut pending = report("observed-2", CONTROL_AFTER, 0, None, None, 200);
    pending.pending = true;
    let written = Notes {
        done: vec!["a-rewrites".to_owned()],
        identity: Some(vec![0xab; 8]),
        lookup: Some(vec![0x01; 32]),
        outbox: vec![(0, vec![0xde, 0xad]), (1, Vec::new())],
        reports: vec![
            report("established", CHANNEL, 1, Some(3), Some(3), 100),
            pending,
        ],
        network_silent: vec!["inspected".to_owned()],
        rewrote: vec![0, 1],
        read_back: vec![(0, vec![0xde, 0xad]), (1, Vec::new())],
        timings: vec![("a-rewrites".to_owned(), 42)],
    };
    assert_eq!(Notes::parse(&written.encode()).expect("parses"), written);
    assert!(
        written.encode().contains("outbox 1 ~\n"),
        "an empty byte field is written as ~"
    );

    let state = tempfile::tempdir().expect("a state directory");
    let path = Role::A.notes_path(state.path());
    written.save(&path);
    assert_eq!(Notes::load(&path), written);
    assert_eq!(
        Notes::load(&Role::O.notes_path(state.path())),
        Notes::default()
    );

    assert!(Notes::parse("nonsense").is_err());
    assert!(Notes::parse("outbox x ab").is_err());
    assert!(
        Notes::parse("outbox 1 ").is_err(),
        "an empty field is not an empty byte string"
    );
    assert!(Notes::parse("report inspected channel 1 - - 2 5").is_err());
    assert!(Notes::parse("report inspected elsewhere 1 - - 0 5").is_err());
    assert!(Notes::parse("report inspected channel 1 - -").is_err());
    assert!(Notes::parse("read-back 0 zz").is_err());
    assert!(Notes::parse("report inspected channel 1 - 4 0 5\nrewrote 1\n").is_ok());
}

/// § Eviction detection's channel rule, case by case.
#[test]
fn the_loss_rule_counts_only_an_absent_or_older_network_number() {
    assert!(
        behind(Some(3), None, false),
        "nothing on the network is a loss"
    );
    assert!(
        behind(Some(3), Some(2), false),
        "an older network number is a loss"
    );
    assert!(!behind(Some(3), Some(3), false), "the same number is not");
    assert!(
        !behind(Some(3), Some(4), false),
        "a newer number, as an owner-key overwrite leaves, is not"
    );
    assert!(
        !behind(Some(3), None, true),
        "a subkey still queued for its flush is not"
    );
    assert!(
        !behind(None, Some(1), false),
        "a number this node never wrote is not"
    );

    let silent = [SubkeyReport {
        local_seq: Some(1),
        network_seq: None,
        pending: false,
    }; 2];
    assert!(network_silent(&silent));
    let answered_reports = [
        SubkeyReport {
            local_seq: Some(1),
            network_seq: None,
            pending: false,
        },
        SubkeyReport {
            local_seq: Some(1),
            network_seq: Some(1),
            pending: false,
        },
    ];
    assert!(!network_silent(&answered_reports));
    assert!(
        !network_silent(&[SubkeyReport::default(); 2]),
        "a record this node holds none of"
    );

    assert_eq!(at(&answered_reports, 1).network_seq, Some(1));
    assert_eq!(
        at(&answered_reports, 9),
        SubkeyReport::default(),
        "past the report is no numbers"
    );
}

#[test]
fn a_look_counts_only_when_both_its_controls_answer() {
    let mut notes = Notes::default();
    notes.reports.extend(answered("observed-1", 10));
    assert!(look_answered(&notes, "observed-1"));
    assert!(
        !look_answered(&notes, "observed-2"),
        "another phase's controls"
    );

    let without = |record: &str| {
        let mut notes = notes.clone();
        notes.reports.retain(|line| line.record != record);
        notes
    };
    assert!(!look_answered(&without(CONTROL_BEFORE), "observed-1"));
    assert!(!look_answered(&without(CONTROL_AFTER), "observed-1"));

    let altered = |change: fn(&mut ReportLine)| {
        let mut notes = notes.clone();
        change(&mut notes.reports[1]);
        look_answered(&notes, "observed-1")
    };
    assert!(!altered(|line| line.network = None), "a silent control");
    assert!(
        !altered(|line| line.network = Some(0)),
        "a control behind its write"
    );
    assert!(
        !altered(|line| line.local = None),
        "a control never written"
    );
    assert!(
        !altered(|line| line.pending = true),
        "a control still queued"
    );
    assert!(
        !altered(|line| line.record = CHANNEL.to_owned()),
        "a channel line is no control"
    );
}

#[test]
fn the_tracked_subkeys_are_the_control_and_every_outstanding_slot() {
    assert_eq!(tracked_subkeys(&[]), vec![channel::CONTROL_SUBKEY]);
    let outbox = [(0, vec![1]), (1, vec![2])];
    assert_eq!(
        tracked_subkeys(&outbox),
        vec![
            channel::CONTROL_SUBKEY,
            channel::slot_for(0),
            channel::slot_for(1)
        ]
    );
    assert_ne!(channel::slot_for(0), channel::CONTROL_SUBKEY);

    let reports = vec![SubkeyReport::default(); 3];
    let lines = lines_of("inspected", CHANNEL, &reports, &tracked_subkeys(&outbox), 7);
    assert_eq!(lines.len(), 3, "one line per tracked subkey");
    assert!(lines
        .iter()
        .all(|line| line.phase == "inspected" && line.record == CHANNEL && line.at_secs == 7));
}

/// A run's notes that satisfy the end state: message 0 in slot 1, lost in
/// round 2, reported 60 s later, still lost in the observer's look before the
/// rewrite, rewritten, back at the established number 1, and read back.
fn repaired() -> (Notes, Notes) {
    let slot = channel::slot_for(0);
    let control = channel::CONTROL_SUBKEY;
    let mut a = Notes {
        outbox: vec![(0, vec![0xca, 0xfe])],
        reports: vec![
            report("established", CHANNEL, control, Some(1), Some(1), 1000),
            report("established", CHANNEL, slot, Some(1), Some(1), 1000),
            report("inspected", CHANNEL, control, Some(1), Some(1), 5060),
            report("inspected", CHANNEL, slot, Some(1), None, 5060),
            report("restored", CHANNEL, control, Some(1), Some(1), 5200),
            report("restored", CHANNEL, slot, Some(1), Some(1), 5200),
        ],
        rewrote: vec![slot],
        ..Notes::default()
    };
    a.reports.extend(answered("inspected", 5060));
    let mut o = Notes {
        reports: vec![
            report("observed-1", CHANNEL, control, None, Some(1), 3000),
            report("observed-1", CHANNEL, slot, None, Some(1), 3000),
            report("observed-2", CHANNEL, control, None, Some(1), 5000),
            report("observed-2", CHANNEL, slot, None, None, 5000),
            report("before-rewrite", CHANNEL, control, None, Some(1), 5100),
            report("before-rewrite", CHANNEL, slot, None, None, 5100),
        ],
        read_back: vec![(0, vec![0xca, 0xfe])],
        ..Notes::default()
    };
    o.reports.extend(answered("observed-1", 3000));
    o.reports.extend(answered("observed-2", 5000));
    o.reports.extend(answered("before-rewrite", 5100));
    (a, o)
}

/// [`repaired`] with the control subkey lost as well, rewritten under a fresh
/// nonce from number 1 to number 2.
fn control_also_lost() -> (Notes, Notes) {
    let control = channel::CONTROL_SUBKEY;
    let (mut a, mut o) = repaired();
    line_mut(&mut o, "observed-2", control).network = None;
    line_mut(&mut o, "before-rewrite", control).network = None;
    line_mut(&mut a, "inspected", control).network = None;
    let restored = line_mut(&mut a, "restored", control);
    restored.local = Some(2);
    restored.network = Some(2);
    a.rewrote.insert(0, control);
    (a, o)
}

/// The channel line for `subkey` in `phase`, for a fixture to change.
fn line_mut<'a>(notes: &'a mut Notes, phase: &str, subkey: u16) -> &'a mut ReportLine {
    notes
        .reports
        .iter_mut()
        .find(|line| line.phase == phase && line.record == CHANNEL && line.subkey == subkey)
        .expect("the fixture has this line")
}

#[test]
fn the_first_loss_is_the_first_answered_round_a_look_saw_one() {
    let (a, o) = repaired();
    let slot = channel::slot_for(0);
    assert_eq!(first_loss(&a, &o), Some((2, 5000, vec![slot])));

    let mut unlost = o.clone();
    unlost.reports.retain(|line| line.phase == "observed-1");
    assert_eq!(
        first_loss(&a, &unlost),
        None,
        "a look that saw the numbers intact is no loss"
    );

    // Silence with a control that did not answer is the network not answering.
    let mut silent = o.clone();
    silent
        .reports
        .retain(|line| !(line.phase == "observed-2" && line.record == CONTROL_AFTER));
    line_mut(&mut silent, "observed-2", channel::CONTROL_SUBKEY).network = None;
    assert_eq!(
        first_loss(&a, &silent),
        None,
        "a silent, uncontrolled look is not a loss"
    );

    // An unanswered round is skipped and a later answered one still counts.
    let mut later = silent.clone();
    later.reports.extend(answered("observed-3", 9000));
    later
        .reports
        .push(report("observed-3", CHANNEL, slot, None, None, 9000));
    assert_eq!(first_loss(&a, &later), Some((3, 9000, vec![slot])));

    let mut older = o.clone();
    for line in older
        .reports
        .iter_mut()
        .filter(|line| line.phase == "observed-2" && line.record == CHANNEL)
    {
        line.network = Some(0);
    }
    assert_eq!(
        first_loss(&a, &older).map(|(round, _, lost)| (round, lost.len())),
        Some((2, 2)),
        "an older network number on both subkeys is a loss of both"
    );

    let mut ahead = o.clone();
    for line in ahead
        .reports
        .iter_mut()
        .filter(|line| line.record == CHANNEL)
    {
        line.network = Some(9);
    }
    assert_eq!(
        first_loss(&a, &ahead),
        None,
        "a newer network number is not a loss"
    );
}

#[test]
fn the_end_state_check_catches_each_way_a_repair_can_fail() {
    let (a, o) = repaired();
    eviction_repaired(&a, &o).expect("a reported loss, rewritten and read back, passes");
    let slot = channel::slot_for(0);
    let control = channel::CONTROL_SUBKEY;
    let fails = |a: &Notes, o: &Notes, what: &str, needle: &str| {
        let failure = eviction_repaired(a, o).expect_err(what);
        assert!(failure.contains(needle), "{what}: {failure}");
    };

    // A message slot's rewrite is byte-identical to the local copy, so it comes
    // back at the established number, and that passes.
    let established = a.line_at("established", slot).and_then(|l| l.local);
    let restored = a.line_at("restored", slot).and_then(|l| l.network);
    assert_eq!((established, restored), (Some(1), Some(1)));

    let mut empty = a.clone();
    empty.outbox.clear();
    fails(&empty, &o, "nothing outstanding", "nothing was at stake");

    let mut never_written = a.clone();
    line_mut(&mut never_written, "established", slot).network = None;
    fails(
        &never_written,
        &o,
        "a baseline not on the network",
        "not on the network",
    );
    let mut baseline_pending = a.clone();
    line_mut(&mut baseline_pending, "established", slot).pending = true;
    fails(
        &baseline_pending,
        &o,
        "a baseline still queued",
        "not on the network",
    );
    let mut baseline_unwritten = a.clone();
    line_mut(&mut baseline_unwritten, "established", slot).local = None;
    fails(
        &baseline_unwritten,
        &o,
        "a baseline with no local number",
        "not on the network",
    );

    let mut no_loss = o.clone();
    no_loss.reports.retain(|line| line.phase == "observed-1");
    fails(&a, &no_loss, "no observed loss", "no answered look");

    let mut cold = a.clone();
    cold.reports.retain(|line| line.record == CHANNEL);
    fails(&cold, &o, "A's look with no controls", "not answered");

    let mut silent = a.clone();
    silent.reports.retain(|line| line.record == CHANNEL);
    silent.network_silent.push("inspected".to_owned());
    line_mut(&mut silent, "inspected", control).network = None;
    fails(&silent, &o, "A silent and uncontrolled", "not answering");

    let mut o_cold = o.clone();
    o_cold
        .reports
        .retain(|line| !(line.phase == "before-rewrite" && line.record == CONTROL_BEFORE));
    fails(
        &a,
        &o_cold,
        "an unanswered look before the rewrite",
        "not answered",
    );
    let mut o_missing = o.clone();
    o_missing
        .reports
        .retain(|line| !(line.phase == "before-rewrite" && line.record == CHANNEL));
    fails(
        &a,
        &o_missing,
        "no look before the rewrite",
        "recorded nothing",
    );
    let mut o_early = o.clone();
    line_mut(&mut o_early, "before-rewrite", slot).at_secs = 5059;
    fails(
        &a,
        &o_early,
        "a look before A's inspect",
        "before A's inspect",
    );
    let mut rehydrated_first = o.clone();
    line_mut(&mut rehydrated_first, "before-rewrite", slot).network = Some(1);
    fails(
        &a,
        &rehydrated_first,
        "a slot already restored before the rewrite",
        "repaired before the rewrite (rehydration)",
    );

    let (ca, co) = control_also_lost();
    eviction_repaired(&ca, &co).expect("a lost control rewritten to a higher number passes");
    let mut control_equal = ca.clone();
    let line = line_mut(&mut control_equal, "restored", control);
    line.local = Some(1);
    line.network = Some(1);
    fails(
        &control_equal,
        &co,
        "a lost control restored at the established number",
        "fresh nonce",
    );
    let mut control_unrewritten = ca.clone();
    control_unrewritten
        .rewrote
        .retain(|subkey| *subkey != control);
    fails(
        &control_unrewritten,
        &co,
        "a lost control not rewritten",
        "did not rewrite",
    );

    let mut inspected_missing = a.clone();
    inspected_missing.reports.retain(|line| {
        !(line.phase == "inspected" && line.record == CHANNEL && line.subkey == slot)
    });
    fails(
        &inspected_missing,
        &o,
        "no inspected line",
        "recorded nothing",
    );
    let mut inspected_pending = a.clone();
    line_mut(&mut inspected_pending, "inspected", slot).pending = true;
    fails(
        &inspected_pending,
        &o,
        "an inspected line still queued",
        "still queued",
    );

    let mut rehydrated = a.clone();
    line_mut(&mut rehydrated, "inspected", slot).network = Some(1);
    fails(
        &rehydrated,
        &o,
        "an inspect that shows no loss",
        "rehydration",
    );

    let mut out_of_order = a.clone();
    line_mut(&mut out_of_order, "inspected", slot).at_secs = 4999;
    fails(
        &out_of_order,
        &o,
        "an inspect before the look",
        "before the look",
    );

    let boundary = 5000 + POLL_INTERVAL_MIN.as_secs();
    let mut at_boundary = a.clone();
    line_mut(&mut at_boundary, "inspected", slot).at_secs = boundary;
    let mut o_after_boundary = o.clone();
    line_mut(&mut o_after_boundary, "before-rewrite", slot).at_secs = boundary;
    eviction_repaired(&at_boundary, &o_after_boundary)
        .expect("exactly POLL_INTERVAL_MIN after the look passes");
    let mut late = a.clone();
    line_mut(&mut late, "inspected", slot).at_secs = boundary + 1;
    fails(
        &late,
        &o,
        "one second past POLL_INTERVAL_MIN",
        "POLL_INTERVAL_MIN",
    );

    let mut unrewritten = a.clone();
    unrewritten.rewrote.clear();
    fails(
        &unrewritten,
        &o,
        "a loss restored without a rewrite",
        "did not rewrite",
    );

    let mut different = o.clone();
    different.read_back = vec![(0, vec![0xca, 0xff])];
    fails(
        &a,
        &different,
        "a network copy that is not the outbox",
        "not the outbox entry",
    );
    let mut unread = o.clone();
    unread.read_back.clear();
    fails(&a, &unread, "no read-back", "read back nothing");

    let mut restored_missing = a.clone();
    restored_missing
        .reports
        .retain(|line| !(line.phase == "restored" && line.subkey == slot));
    fails(&restored_missing, &o, "no restored line", "no report");
    let mut restored_pending = a.clone();
    line_mut(&mut restored_pending, "restored", slot).pending = true;
    fails(
        &restored_pending,
        &o,
        "a restored line still queued",
        "not on the network",
    );
    let mut still_behind = a.clone();
    line_mut(&mut still_behind, "restored", slot).network = Some(0);
    fails(
        &still_behind,
        &o,
        "a slot behind after the rewrite",
        "not on the network",
    );
    let mut below_established = a.clone();
    let line = line_mut(&mut below_established, "restored", slot);
    line.local = Some(0);
    line.network = Some(0);
    fails(
        &below_established,
        &o,
        "a slot restored below the established number",
        "below the",
    );
}

#[test]
fn the_quiet_schedule_reads_its_environment_and_refuses_nonsense() {
    use std::os::unix::ffi::OsStringExt;
    let os = |s: &str| Some(OsString::from(s));
    assert_eq!(
        quiet_schedule(None, None),
        Ok((DEFAULT_QUIET, DEFAULT_ROUNDS))
    );
    assert_eq!(
        quiet_schedule(os("90"), os("3")),
        Ok((Duration::from_secs(90), 3))
    );
    assert_eq!(
        quiet_schedule(os(&QUIET_FLOOR.as_secs().to_string()), os("1")),
        Ok((QUIET_FLOOR, 1)),
        "the floor itself is accepted"
    );
    assert!(quiet_schedule(os("six hours"), None).is_err());
    assert!(quiet_schedule(os("0"), None).is_err(), "no quiet at all");
    assert!(quiet_schedule(os(&(QUIET_FLOOR.as_secs() - 1).to_string()), None).is_err());
    assert!(quiet_schedule(os(&(QUIET_CEILING.as_secs() + 1).to_string()), None).is_err());
    assert!(quiet_schedule(os("99999999999999999999"), None).is_err());
    assert!(quiet_schedule(None, os("-1")).is_err());
    assert!(quiet_schedule(None, os("0")).is_err());
    assert!(quiet_schedule(None, os(&(ROUNDS_CEILING + 1).to_string())).is_err());
    let not_utf8 = Some(OsString::from_vec(vec![0x36, 0xff]));
    let failure = quiet_schedule(not_utf8.clone(), None).expect_err("a non-UTF-8 quiet period");
    assert!(failure.contains("UTF-8"), "{failure}");
    assert!(
        quiet_schedule(None, not_utf8).is_err(),
        "a non-UTF-8 round count"
    );
}

#[test]
fn every_step_names_its_own_function_and_role() {
    for (i, step) in STEPS.iter().enumerate() {
        for other in STEPS.iter().skip(i + 1) {
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
    assert_ne!(Role::B.port(), Role::O.port());
    assert_ne!(Role::A.port(), Role::O.port());
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
