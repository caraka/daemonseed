//! xtask — workspace task runner.
//!
//! Subcommands:
//! - `gen-proto` — regenerate the committed snapshot under
//!   `crates/daemonseed-proto/src/generated/` from the .proto files. Run after
//!   editing any .proto.
//! - `check-proto` — regenerate to a temporary directory and diff against the
//!   committed snapshot. Non-zero exit on drift. CI gate.
//! - `isc-coverage` — report the percentage of ISCs covered by registered
//!   tests in `daemonseed-integration-tests::isc_coverage`, against the
//!   registry's live total; `--min N` fails the run below N percent.
//! - `check-ui-strings` — refuse placeholder text in any string a user can
//!   read.
//! - `dm-size` — count the direct-messaging layer's lines, tests included, and
//!   refuse above its ceiling or on a module that names no founding claim.
//! - `install-hooks` — install the workspace's git pre-push hook into the
//!   active checkout's `.git/hooks/` (or into a `--target` directory).
//!   Idempotent; overwrites a previously-installed hook in-place.
//! - `check-manifests` — parse every `docs/llm-api-manifest/*.yaml` with
//!   duplicate-key detection at the event level and fail on any repeat. YAML
//!   discards a repeated mapping key silently, so nothing else in the repo
//!   would notice (#326).
//! - `gate` — run the Definition-of-Done gate, defined once as one table of
//!   steps in three groups: `preflight` (fmt, clippy, a release-profile
//!   type-check, rustdoc with warnings denied, and the xtask checks),
//!   `dev-suite` (the gui/desktop clippy pass and the dev-profile test suite)
//!   and `release-suite` (the release-profile test suite). `--group G` runs one
//!   group, `--list` prints the table and runs nothing, and no argument runs
//!   every group. A test step reporting zero passing tests is red whatever its
//!   exit code. Every run, whole or single-group, ends by deleting the binaries
//!   its steps linked into `target/` (see `remove_linked_bins`).
//! - `release-gate` — run every group of the gate and exit non-zero if any step
//!   is red, so a release tag is never cut on a red tree. Run before `git tag`.

mod dm_size;
mod manifests;
mod ui_strings;

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use walkdir::WalkDir;

#[derive(Parser)]
#[command(name = "xtask", about = "daemonseed workspace task runner")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Parse every `docs/llm-api-manifest/*.yaml` and fail on a duplicate
    /// mapping key, which YAML would otherwise discard silently (#326).
    CheckManifests,
    /// Regenerate `crates/daemonseed-proto/src/generated/` from .proto files.
    GenProto,
    /// Verify that the committed snapshot matches what tonic-build emits.
    CheckProto,
    /// Refuse placeholder text in any string a user can read (.slint, and the
    /// gui/tui Rust sources). A placeholder is not shippable by definition.
    CheckUiStrings,
    /// Count the direct-messaging layer's lines, tests included, and print them
    /// per module and in total. Exits non-zero above the ceiling read from
    /// `DM_SIZE_CEILING`, and on any module that names no founding claim and is
    /// not on the outside-layer list.
    DmSize,
    /// Report ISC coverage from `daemonseed-integration-tests`. Exits non-zero
    /// if the covered percentage is below `--min` (when supplied).
    IscCoverage {
        /// Minimum coverage percentage required for a zero exit code. CI gate
        /// will eventually set this to `95`. Omit at M0 to inspect the
        /// baseline without gating.
        #[arg(long)]
        min: Option<u8>,
    },
    /// Install the workspace's git pre-push hook into the active checkout.
    /// Idempotent — overwrites an existing hook in-place.
    InstallHooks {
        /// Target hook directory. Defaults to `<repo>/.git/hooks/` resolved
        /// via `git rev-parse --git-dir` so the install works inside worktrees.
        #[arg(long)]
        target: Option<PathBuf>,
    },
    /// Run the Definition-of-Done gate: the `preflight`, `dev-suite` and
    /// `release-suite` groups of `RELEASE_GATE_STEPS`, or one group of them.
    /// Exits non-zero naming any red step.
    Gate {
        /// Run only this group. Omit to run every group.
        #[arg(long)]
        group: Option<GateGroup>,
        /// Print one `<group>\t<step>` line per step, narrowed by `--group` where it
        /// is given, and run nothing.
        #[arg(long)]
        list: bool,
    },
    /// Run every group of the Definition-of-Done gate and refuse (non-zero
    /// exit) if any step is red — so a release tag is never cut on a red tree
    /// (#62). Run before `git tag`.
    ReleaseGate,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::CheckManifests => manifests::check_manifests(&workspace_root_from_xtask()?),
        Cmd::GenProto => gen_proto(),
        Cmd::CheckProto => check_proto(),
        Cmd::CheckUiStrings => ui_strings::check_ui_strings(&workspace_root_from_xtask()?),
        Cmd::DmSize => dm_size::check(
            &workspace_root_from_xtask()?,
            dm_size::LAYER_DIRS,
            dm_size::OUTSIDE_LAYER,
            dm_size::ceiling_from_env()?,
        ),
        Cmd::IscCoverage { min } => isc_coverage(min),
        Cmd::InstallHooks { target } => install_hooks(target),
        Cmd::Gate { group, list } => {
            if list {
                list_gate_steps(group);
                Ok(())
            } else {
                run_gate(group)
            }
        }
        Cmd::ReleaseGate => run_gate(None),
    }
}

/// Reports ISC coverage from the single-source registry.
///
/// Both the denominator [`daemonseed_isc::TOTAL`] (built, non-deferred ISCs)
/// and the numerator [`daemonseed_isc::COVERED`] (distinct ISCs with a
/// registered integration test) are read live from the zero-dependency
/// `daemonseed-isc` leaf crate — there is no longer a hand-maintained mirror in
/// xtask (the old `TOTAL_ISCS` / `COVERED_ISCS` constants drifted from the
/// registry, the bug M15 E fixed). The per-milestone provenance of COVERED and
/// its drift guards (`covered_sum_matches`, `covered_within_total`) live in
/// `daemonseed_isc`. A future fully-live numerator (running the suite and
/// tallying actual `Coverage::register` calls) would replace the COVERED
/// constant; the `covered_sum_matches` test keeps it honest until then.
fn isc_coverage(min: Option<u8>) -> Result<()> {
    let covered = daemonseed_isc::COVERED as u32;
    let total = daemonseed_isc::TOTAL as u32;
    let pct = if total == 0 {
        0.0
    } else {
        (covered as f64) * 100.0 / (total as f64)
    };
    println!("ISC coverage: {covered}/{total} = {pct:.1}% (built ISC surface)");
    if let Some(m) = min
        && (pct as u32) < (m as u32)
    {
        bail!(
            "ISC coverage {pct:.1}% below required minimum {m}%. \
             Register tests against entries in daemonseed-isc::ISCS."
        );
    }
    Ok(())
}

fn install_hooks(target: Option<PathBuf>) -> Result<()> {
    let xtask_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = xtask_dir
        .parent()
        .context("xtask manifest dir has no parent")?;
    let src = repo_root.join("scripts").join("git-hooks").join("pre-push");
    if !src.exists() {
        bail!("source hook missing at {}", src.display());
    }

    let target_dir = match target {
        Some(p) => p,
        None => resolve_git_hooks_dir(repo_root)?,
    };
    fs::create_dir_all(&target_dir).with_context(|| format!("create {}", target_dir.display()))?;
    let dst = target_dir.join("pre-push");

    fs::copy(&src, &dst).with_context(|| format!("copy {} -> {}", src.display(), dst.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&dst)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&dst, perms).with_context(|| format!("chmod +x {}", dst.display()))?;
    }

    println!("install-hooks: installed pre-push -> {}", dst.display());
    Ok(())
}

/// Resolve the directory git runs hooks from for this checkout.
///
/// `git rev-parse --git-path hooks` answers with the directory git itself
/// consults: `core.hooksPath` when it is set, otherwise the `hooks/` of the
/// common `.git` directory. Hooks are shared by every worktree of a repository;
/// a worktree's own `.git/worktrees/<name>/` holds no hooks directory git reads,
/// so a hook written there never runs.
fn resolve_git_hooks_dir(repo_root: &Path) -> Result<PathBuf> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("rev-parse")
        .arg("--git-path")
        .arg("hooks")
        .output()
        .context("invoke git rev-parse --git-path hooks")?;
    if !out.status.success() {
        bail!(
            "git rev-parse --git-path hooks failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let hooks_dir = String::from_utf8(out.stdout)
        .context("git output is not utf-8")?
        .trim()
        .to_string();
    let hooks_path = if Path::new(&hooks_dir).is_absolute() {
        PathBuf::from(hooks_dir)
    } else {
        repo_root.join(hooks_dir)
    };
    Ok(hooks_path)
}

/// Resolve `<repo>/crates/daemonseed-proto`.
fn proto_crate_dir() -> Result<PathBuf> {
    let xtask_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = xtask_dir
        .parent()
        .context("xtask manifest dir has no parent")?;
    Ok(repo_root.join("crates").join("daemonseed-proto"))
}

fn collect_protos(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !root.exists() {
        return Ok(out);
    }
    for entry in WalkDir::new(root) {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().is_some_and(|e| e == "proto") {
            out.push(path.to_path_buf());
        }
    }
    out.sort();
    Ok(out)
}

/// Run tonic-build against `proto/` and emit into `out_dir`. Must stay aligned
/// with `crates/daemonseed-proto/build.rs::main` so OUT_DIR and snapshot stay
/// byte-identical.
fn compile_protos(proto_crate: &Path, out_dir: &Path) -> Result<()> {
    let proto_root = proto_crate.join("proto");
    let protos = collect_protos(&proto_root)?;
    if protos.is_empty() {
        bail!(
            "no .proto files found under {} — nothing to generate",
            proto_root.display()
        );
    }
    fs::create_dir_all(out_dir).with_context(|| format!("create out_dir {}", out_dir.display()))?;
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .out_dir(out_dir)
        // Suppress `cargo:rerun-if-changed=...` lines that tonic-build emits
        // on stdout. They're meaningful in a build script (where cargo reads
        // them) but noise when xtask runs from the command line. build.rs in
        // daemonseed-proto keeps the default (emit) behavior.
        .emit_rerun_if_changed(false)
        .compile_protos(&protos, &[proto_root])
        .context("tonic-build codegen failed")?;
    Ok(())
}

fn gen_proto() -> Result<()> {
    let proto_crate = proto_crate_dir()?;
    let snapshot_dir = proto_crate.join("src").join("generated");

    let preserved = preserve_non_generated(&snapshot_dir)?;
    clear_generated(&snapshot_dir)?;
    compile_protos(&proto_crate, &snapshot_dir)?;
    restore_non_generated(&snapshot_dir, preserved)?;

    println!("gen-proto: wrote snapshot to {}", snapshot_dir.display());
    Ok(())
}

fn check_proto() -> Result<()> {
    let proto_crate = proto_crate_dir()?;
    let snapshot_dir = proto_crate.join("src").join("generated");

    let tmp = tempdir_in(&proto_crate)?;
    let tmp_out = tmp.join("generated");
    compile_protos(&proto_crate, &tmp_out)?;

    let diffs = diff_generated_dirs(&snapshot_dir, &tmp_out)?;
    let _ = fs::remove_dir_all(&tmp);

    if diffs.is_empty() {
        println!("check-proto: snapshot matches .proto sources");
        Ok(())
    } else {
        for d in &diffs {
            eprintln!("drift: {d}");
        }
        bail!(
            "check-proto: {} file(s) differ from committed snapshot. \
             Run `cargo xtask gen-proto` and commit the result.",
            diffs.len()
        )
    }
}

/// Files inside `src/generated/` that are not codegen output — README, etc.
/// gen-proto preserves them across regeneration.
fn is_non_generated(name: &str) -> bool {
    name == "README.md" || name == ".gitkeep"
}

fn preserve_non_generated(snapshot_dir: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let mut preserved = Vec::new();
    if !snapshot_dir.exists() {
        return Ok(preserved);
    }
    for entry in fs::read_dir(snapshot_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.path().is_file() && is_non_generated(&name) {
            let bytes = fs::read(entry.path())?;
            preserved.push((name, bytes));
        }
    }
    Ok(preserved)
}

fn restore_non_generated(snapshot_dir: &Path, files: Vec<(String, Vec<u8>)>) -> Result<()> {
    for (name, bytes) in files {
        fs::write(snapshot_dir.join(name), bytes)?;
    }
    Ok(())
}

fn clear_generated(snapshot_dir: &Path) -> Result<()> {
    if !snapshot_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(snapshot_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_non_generated(&name) {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
    }
    Ok(())
}

fn tempdir_in(parent: &Path) -> Result<PathBuf> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let tmp = parent.join(format!(".xtask-tmp-{pid}-{nanos}"));
    fs::create_dir_all(&tmp).with_context(|| format!("create tempdir {}", tmp.display()))?;
    Ok(tmp)
}

/// List generated-output files (everything not in `is_non_generated`) in
/// `dir`, returning paths relative to `dir`.
fn list_generated_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in WalkDir::new(dir) {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if is_non_generated(&name) {
            continue;
        }
        let rel = path
            .strip_prefix(dir)
            .with_context(|| format!("strip_prefix {} from {}", dir.display(), path.display()))?
            .to_path_buf();
        out.push(rel);
    }
    out.sort();
    Ok(out)
}

fn diff_generated_dirs(snapshot: &Path, fresh: &Path) -> Result<Vec<String>> {
    let snapshot_files = list_generated_files(snapshot)?;
    let fresh_files = list_generated_files(fresh)?;

    use std::collections::BTreeSet;
    let snap_set: BTreeSet<_> = snapshot_files.iter().cloned().collect();
    let fresh_set: BTreeSet<_> = fresh_files.iter().cloned().collect();

    let mut diffs = Vec::new();

    for missing in fresh_set.difference(&snap_set) {
        diffs.push(format!("missing from snapshot: {}", missing.display()));
    }
    for extra in snap_set.difference(&fresh_set) {
        diffs.push(format!(
            "stale in snapshot (no longer generated): {}",
            extra.display()
        ));
    }
    for shared in snap_set.intersection(&fresh_set) {
        let a = fs::read(snapshot.join(shared))?;
        let b = fs::read(fresh.join(shared))?;
        if a != b {
            diffs.push(format!("content differs: {}", shared.display()));
        }
    }
    Ok(diffs)
}

// ── gate helpers ─────────────────────────────────────────────────────

/// Locate the workspace root from xtask's own manifest dir. xtask lives
/// at `<repo>/xtask/`, so the repo root is `parent()` — kept local
/// rather than going through `cargo metadata` to keep xtask deps minimal.
fn workspace_root_from_xtask() -> Result<PathBuf> {
    let xtask_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    xtask_dir
        .parent()
        .map(Path::to_path_buf)
        .context("xtask manifest dir has no parent")
}

/// Runnable binaries this workspace links, relative to a profile directory under
/// `target/`. Kept as a list rather than globbed so a new bin target is a deliberate
/// addition here.
const WORKSPACE_BINS: &[&str] = &["daemonseed-tui", "daemonseed-gui", "xtask"];

/// The directory cargo writes artifacts to: `CARGO_TARGET_DIR` where it is set —
/// taken as given when absolute, resolved against the workspace root when relative
/// — and `<repo>/target` otherwise.
fn target_dir(repo: &Path) -> PathBuf {
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(dir) => repo.join(PathBuf::from(dir)),
        None => repo.join("target"),
    }
}

/// Delete the binaries the gate's `cargo test`/`clippy --all-targets` steps linked into
/// the profile directories under the cargo target directory.
///
/// **This is not tidiness — it prevents a cross-machine miscompile.** Where a
/// `target/` directory is shared between two machines whose glibc versions differ,
/// a binary linked on the newer host fails to load on the older one
/// (`version 'GLIBC_2.xx' not found`), and because the artifact's timestamp then looks
/// fresh, that machine's own `cargo build` no-ops instead of relinking — so it keeps
/// running the unusable binary with nothing to say why. Removing the linked bins forces
/// a genuine relink wherever they are next built. Missing files are not an error: most
/// gate runs never link most of these.
fn remove_linked_bins(repo: &Path) -> Result<()> {
    let target = target_dir(repo);
    for profile in ["debug", "release"] {
        for bin in WORKSPACE_BINS {
            let path = target.join(profile).join(bin);
            match fs::remove_file(&path) {
                Ok(()) => println!("gate: removed linked binary {}", path.display()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(e).with_context(|| format!("remove {}", path.display()));
                }
            }
        }
    }
    Ok(())
}

/// Cargo binary the operator's `cargo xtask` invocation ran through. Cargo
/// sets `CARGO` for subcommands; falling back to plain `"cargo"` keeps the
/// path manual-invoke-friendly.
fn cargo_bin() -> std::ffi::OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

// ── gate ─────────────────────────────────────────────────────────────

/// The groups the Definition-of-Done gate is split into. Every gate step belongs
/// to exactly one group, and the groups run in this order: `preflight` is the
/// compile-and-check half, `dev-suite` and `release-suite` are the test suites in
/// the two profiles.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum GateGroup {
    Preflight,
    DevSuite,
    ReleaseSuite,
}

impl GateGroup {
    /// The group's name on the command line and in `--list` output.
    fn as_str(self) -> &'static str {
        match self {
            GateGroup::Preflight => "preflight",
            GateGroup::DevSuite => "dev-suite",
            GateGroup::ReleaseSuite => "release-suite",
        }
    }
}

/// One Definition-of-Done step, run as `cargo <args>` with `env` set in the
/// child's environment. Mirrors `AGENTS.md` § Definition of done.
struct GateStep {
    name: &'static str,
    group: GateGroup,
    args: &'static [&'static str],
    env: &'static [(&'static str, &'static str)],
}

/// The Definition-of-Done gate: one table, read by every caller. The pre-push hook
/// runs the `preflight` group; CI runs all three; a release tag-cut runs the whole
/// table through `release-gate` (#62).
const RELEASE_GATE_STEPS: &[GateStep] = &[
    GateStep {
        name: "fmt --all --check",
        group: GateGroup::Preflight,
        args: &["fmt", "--all", "--check"],
        env: &[],
    },
    GateStep {
        name: "clippy --workspace -D warnings",
        group: GateGroup::Preflight,
        args: &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
        env: &[],
    },
    // #381: a type-check of the workspace in the profile that ships. `debug_assert!`
    // expands its arguments in every profile, so a binding introduced under
    // `#[cfg(debug_assertions)]` and read only by a `debug_assert_eq!` compiles in dev
    // and fails to compile in release (E0425). `check` rather than `build`: it does not
    // link, and reuses the release cache the release-profile test step fills.
    GateStep {
        name: "check --workspace --release",
        group: GateGroup::Preflight,
        args: &["check", "--workspace", "--release"],
        env: &[],
    },
    // `cargo doc` exits 0 with warnings present, so `-D warnings` is what gives this
    // step a red state at all. The class it covers is public documentation linking to
    // deliberately private items.
    GateStep {
        name: "doc --workspace --no-deps (warnings denied)",
        group: GateGroup::Preflight,
        args: &["doc", "--workspace", "--no-deps"],
        env: &[("RUSTDOCFLAGS", "-D warnings")],
    },
    GateStep {
        name: "xtask check-proto",
        group: GateGroup::Preflight,
        args: &["xtask", "check-proto"],
        env: &[],
    },
    GateStep {
        name: "xtask isc-coverage",
        group: GateGroup::Preflight,
        args: &["xtask", "isc-coverage"],
        env: &[],
    },
    // #326: a parse of seven small files, cheap enough to sit alongside the compile
    // steps rather than form a step set of its own.
    GateStep {
        name: "xtask check-manifests",
        group: GateGroup::Preflight,
        args: &["xtask", "check-manifests"],
        env: &[],
    },
    // No other step reads a user-visible string. Cheap: a scan of the .slint
    // files and the two front-end src trees.
    GateStep {
        name: "xtask check-ui-strings",
        group: GateGroup::Preflight,
        args: &["xtask", "check-ui-strings"],
        env: &[],
    },
    // The direct-messaging layer's ceiling and its founding-claim headers are
    // properties of the tree as a whole: a module added to one crate crosses the
    // total no per-crate step reads. Cheap: a line count of two directories.
    GateStep {
        name: "xtask dm-size",
        group: GateGroup::Preflight,
        args: &["xtask", "dm-size"],
        env: &[],
    },
    // `--all-targets` skips targets whose `required-features` are unsatisfied, so the
    // windowed GUI is linted only by an invocation that opts into `desktop`.
    GateStep {
        name: "clippy -p daemonseed-gui --features desktop -D warnings",
        group: GateGroup::DevSuite,
        args: &[
            "clippy",
            "-p",
            "daemonseed-gui",
            "--features",
            "desktop",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
        env: &[],
    },
    GateStep {
        name: "test --workspace",
        group: GateGroup::DevSuite,
        args: &["test", "--workspace"],
        env: &[],
    },
    // #274: the release profile sets `overflow-checks = true` (#258), so the two
    // profiles differ in behaviour and not only in optimization level — a green dev
    // suite is not evidence about the artifact that ships.
    GateStep {
        name: "test --workspace --release",
        group: GateGroup::ReleaseSuite,
        args: &["test", "--workspace", "--release"],
        env: &[],
    },
];

/// Total tests reported passing across every `test result:` line in a cargo test
/// run's output.
///
/// A test binary that contains no tests exits 0 and prints `0 passed`, which is
/// indistinguishable from a suite of thousands by exit code alone. Summing the
/// reported counts is what tells the two apart, so the gate reads this in addition to
/// the status of a `test` step (#62).
fn passed_count(output: &str) -> usize {
    output
        .lines()
        .filter(|line| line.contains("test result:"))
        .filter_map(|line| {
            let head = &line[..line.find(" passed")?];
            let reversed: String = head
                .chars()
                .rev()
                .take_while(char::is_ascii_digit)
                .collect();
            reversed
                .chars()
                .rev()
                .collect::<String>()
                .parse::<usize>()
                .ok()
        })
        .sum()
}

/// Pure verdict: GREEN iff every step passed, else RED naming the failed steps in
/// order. Separated from the subprocess runner so the refuse-on-red logic is
/// unit-tested without shelling out (#62).
fn release_gate_verdict(
    results: &[(&'static str, bool)],
) -> std::result::Result<(), Vec<&'static str>> {
    let failed: Vec<&'static str> = results
        .iter()
        .filter(|(_, ok)| !ok)
        .map(|(name, _)| *name)
        .collect();
    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed)
    }
}

/// Run one gate step and report whether it was green.
///
/// A `test` step has its stdout piped so the reported pass count can be read, and
/// every line is echoed as it arrives so the step's progress is still visible. Such
/// a step is red when it reports zero passing tests, whatever its exit code.
fn run_gate_step(cargo: &std::ffi::OsStr, repo: &Path, step: &GateStep) -> Result<bool> {
    let mut cmd = Command::new(cargo);
    cmd.current_dir(repo).args(step.args);
    for (key, value) in step.env {
        cmd.env(key, value);
    }
    if step.args.first() != Some(&"test") {
        let status = cmd
            .status()
            .with_context(|| format!("spawn cargo {}", step.name))?;
        return Ok(status.success());
    }

    cmd.stdout(Stdio::piped());
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn cargo {}", step.name))?;
    let stdout = child
        .stdout
        .take()
        .context("a child spawned with a piped stdout has one")?;
    let mut captured = String::new();
    for line in BufReader::new(stdout).lines() {
        let line = line.with_context(|| format!("read the output of cargo {}", step.name))?;
        println!("{line}");
        captured.push_str(&line);
        captured.push('\n');
    }
    let status = child
        .wait()
        .with_context(|| format!("wait for cargo {}", step.name))?;
    if !status.success() {
        return Ok(false);
    }

    let passed = passed_count(&captured);
    if passed == 0 {
        println!(
            "gate: {} reported {passed} passing tests — a test step that runs no tests is red.",
            step.name
        );
        return Ok(false);
    }
    println!("gate: {} — {passed} tests passed.", step.name);
    Ok(true)
}

/// Print the gate table — every step, or only `group`'s — one `<group>\t<name>` line
/// each, and run nothing.
fn list_gate_steps(group: Option<GateGroup>) {
    for step in RELEASE_GATE_STEPS
        .iter()
        .filter(|step| group.is_none_or(|g| step.group == g))
    {
        println!("{}\t{}", step.group.as_str(), step.name);
    }
}

/// Run the gate — every group, or only `group` — and exit non-zero naming any red
/// step. With no group this is the full Definition-of-Done gate a release tag-cut
/// must pass, so a tag is never created on a red tree (#62).
fn run_gate(group: Option<GateGroup>) -> Result<()> {
    let repo = workspace_root_from_xtask()?;
    let cargo = cargo_bin();
    let steps = RELEASE_GATE_STEPS
        .iter()
        .filter(|step| group.is_none_or(|g| step.group == g));
    let mut results: Vec<(&'static str, bool)> = Vec::with_capacity(RELEASE_GATE_STEPS.len());
    let mut step_error = None;
    for step in steps {
        println!("gate [{}]: {} …", step.group.as_str(), step.name);
        match run_gate_step(&cargo, &repo, step) {
            Ok(ok) => results.push((step.name, ok)),
            // A step that could not be run at all — the spawn, the read of its output or
            // the wait failed — ends the run, but only after the sweep below.
            Err(e) => {
                step_error = Some(e);
                break;
            }
        }
    }
    // After every step, green, red or errored: the paths below all leave the run, and
    // the linked binaries must not survive any of them. Where both the sweep and a step
    // failed, the step's error is what started it and is carried as the sweep's context.
    let swept = remove_linked_bins(&repo);
    match (step_error, swept) {
        (Some(step), Err(sweep)) => {
            return Err(sweep.context(format!("after the gate step failed: {step}")));
        }
        (Some(step), Ok(())) => return Err(step),
        (None, Err(sweep)) => return Err(sweep),
        (None, Ok(())) => {}
    }
    match release_gate_verdict(&results) {
        Ok(()) => {
            match group {
                Some(g) => println!("gate: GREEN — every step in {} passed.", g.as_str()),
                None => println!(
                    "gate: GREEN — every Definition-of-Done step passed; safe to cut the signed tag."
                ),
            }
            Ok(())
        }
        Err(failed) => bail!(
            "gate: RED — failed: {}. Fix and re-run before pushing or cutting a tag.",
            failed.join(", ")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn green_only_when_every_step_passes() {
        let all_green = [("fmt", true), ("clippy", true), ("test --workspace", true)];
        assert!(release_gate_verdict(&all_green).is_ok());
    }

    #[test]
    fn the_v0290_slip_red_test_workspace_refuses_the_tag() {
        // The v0.29.0 slip: a red `test --workspace` while every other step is
        // green must still produce a RED verdict that names it.
        let results = [
            ("fmt", true),
            ("clippy", true),
            ("test --workspace", false),
            ("xtask check-proto", true),
        ];
        assert_eq!(
            release_gate_verdict(&results),
            Err(vec!["test --workspace"])
        );
    }

    /// #274: the gate must run the suite in the RELEASE profile, not only dev. Three
    /// `daemonseed-gui` tests were red in release and this gate never saw them. Asserted
    /// on the step table so deleting the step is a test failure, not a silent
    /// regression back to dev-only coverage.
    #[test]
    fn the_gate_runs_the_suite_in_the_release_profile() {
        let release_step = RELEASE_GATE_STEPS
            .iter()
            .find(|s| s.args.first() == Some(&"test") && s.args.contains(&"--release"))
            .expect("the release-profile test step must be in the gate");
        assert!(release_step.args.contains(&"--workspace"));
        // …and the dev step is still there: release must be an ADDITION, since dev is
        // what every contributor runs locally and what `debug_assertions` covers.
        assert!(
            RELEASE_GATE_STEPS
                .iter()
                .any(|s| s.args == ["test", "--workspace"]),
            "the dev-profile test step must not be replaced"
        );
    }

    /// #381: the gate must type-check the workspace in the release profile. Every other
    /// compile step runs with `debug_assertions` on, and `debug_assert!` expands its
    /// arguments in every profile, so a binding under `#[cfg(debug_assertions)]` read
    /// only by a `debug_assert_eq!` compiles in dev and fails in release. Asserted on
    /// the step table so deleting the step is a test failure.
    #[test]
    fn the_gate_type_checks_the_workspace_in_the_release_profile() {
        let step = RELEASE_GATE_STEPS
            .iter()
            .find(|s| s.args.first() == Some(&"check"))
            .expect("the release-profile check step must be in the gate");
        assert_eq!(step.args, ["check", "--workspace", "--release"]);
    }

    /// The linked-binary sweep removes what a `cargo test`/`clippy --all-targets` step
    /// left in `target/{debug,release}/`, and tolerates the (usual) case where a bin was
    /// never linked at all. Planted files stand in for real binaries — the sweep is pure
    /// filesystem work with nothing cargo-specific about it.
    #[test]
    fn the_linked_binary_sweep_removes_what_a_gate_step_linked() {
        let repo = std::env::temp_dir().join(format!(
            "ds-xtask-bin-sweep-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let debug = repo.join("target/debug");
        let release = repo.join("target/release");
        fs::create_dir_all(&debug).unwrap();
        fs::create_dir_all(&release).unwrap();
        // Plant one bin per profile; deliberately leave the others absent so the
        // NotFound arm is exercised on the same run.
        let planted = [debug.join("daemonseed-gui"), release.join("daemonseed-tui")];
        for f in &planted {
            fs::write(f, b"not really an elf").unwrap();
            assert!(f.exists(), "positive control: the plant must exist first");
        }
        // A non-binary sibling must survive — the sweep is a named list, not a wipe.
        let bystander = release.join("libdaemonseed_core.rlib");
        fs::write(&bystander, b"keep me").unwrap();

        remove_linked_bins(&repo).expect("the sweep must tolerate absent binaries");

        for f in &planted {
            assert!(!f.exists(), "{} must be gone", f.display());
        }
        assert!(
            bystander.exists(),
            "the sweep must not touch non-bin artifacts"
        );
        fs::remove_dir_all(&repo).ok();
    }

    /// Every group in the enum names at least one step, so a caller asking for a
    /// group never gets a silently empty run that reads as a pass.
    #[test]
    fn every_group_has_at_least_one_step() {
        for group in GateGroup::value_variants() {
            assert!(
                RELEASE_GATE_STEPS.iter().any(|s| s.group == *group),
                "group {} has no steps",
                group.as_str()
            );
        }
    }

    /// The rustdoc step is part of the gate and denies warnings. `cargo doc` exits 0
    /// with warnings present, so without `RUSTDOCFLAGS` the step can never be red and
    /// reads exactly like one that passes.
    #[test]
    fn the_gate_documents_the_workspace_with_warnings_denied() {
        let step = RELEASE_GATE_STEPS
            .iter()
            .find(|s| s.args.first() == Some(&"doc"))
            .expect("the rustdoc step must be in the gate");
        assert_eq!(step.args, ["doc", "--workspace", "--no-deps"]);
        assert_eq!(step.group, GateGroup::Preflight);
        assert!(step.env.contains(&("RUSTDOCFLAGS", "-D warnings")));
    }

    /// The direct-messaging layer's line ceiling is checked by the gate, in the group
    /// the pre-push hook runs. Asserted on the step table so deleting the step is a
    /// test failure rather than a ceiling that silently stops being enforced.
    #[test]
    fn the_gate_checks_the_direct_messaging_layers_size() {
        let step = RELEASE_GATE_STEPS
            .iter()
            .find(|s| s.args == ["xtask", "dm-size"])
            .expect("the dm-size step must be in the gate");
        assert_eq!(step.name, "xtask dm-size");
        assert_eq!(step.group, GateGroup::Preflight);
    }

    /// The `release-suite` group is exactly the release-profile test suite: it is the
    /// longest group, and anything else landing in it lengthens the gate's slowest leg.
    #[test]
    fn the_release_suite_group_is_the_release_profile_test_step() {
        let steps: Vec<&GateStep> = RELEASE_GATE_STEPS
            .iter()
            .filter(|s| s.group == GateGroup::ReleaseSuite)
            .collect();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].args, ["test", "--workspace", "--release"]);
    }

    /// A suite that compiled to no tests exits 0 and prints `0 passed`, so the sum of
    /// the reported counts is what separates it from a suite that ran thousands.
    #[test]
    fn a_run_reporting_only_zero_passed_counts_zero() {
        let output = "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n\
                      test result: ok. 0 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out\n";
        assert_eq!(passed_count(output), 0);
    }

    #[test]
    fn a_run_mixing_empty_binaries_with_one_real_suite_counts_its_tests() {
        let output = "   Running unittests src/lib.rs\n\
                      test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n\
                      test result: ok. 3 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out\n";
        assert_eq!(passed_count(output), 3);
    }

    #[test]
    fn a_run_that_printed_nothing_counts_zero() {
        assert_eq!(passed_count(""), 0);
    }

    /// A failing suite still ran its passing tests, and the count is read off the
    /// same line whether the verdict is `ok.` or `FAILED.`.
    #[test]
    fn a_failed_run_still_counts_the_tests_that_passed() {
        let output =
            "test result: FAILED. 5 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n";
        assert_eq!(passed_count(output), 5);
    }

    #[test]
    fn a_count_of_more_than_one_digit_is_read_whole() {
        let output =
            "test result: ok. 1234 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n";
        assert_eq!(passed_count(output), 1234);
    }

    /// Only a `test result:` line carries a count. A test whose NAME contains the word
    /// is not a summary and contributes nothing.
    #[test]
    fn a_test_name_containing_the_word_is_not_a_summary_line() {
        assert_eq!(passed_count("test tests::passed_count_works ... ok\n"), 0);
    }

    /// Every string in a parsed YAML document, in document order.
    fn yaml_strings(node: &yaml_rust2::Yaml, out: &mut Vec<String>) {
        match node {
            yaml_rust2::Yaml::String(text) => out.push(text.clone()),
            yaml_rust2::Yaml::Array(items) => {
                for item in items {
                    yaml_strings(item, out);
                }
            }
            yaml_rust2::Yaml::Hash(map) => {
                for (key, value) in map {
                    yaml_strings(key, out);
                    yaml_strings(value, out);
                }
            }
            _ => {}
        }
    }

    /// Parse a YAML file under the workspace root, panicking with its path on either
    /// a read or a parse failure.
    fn parse_yaml(relative: &str) -> yaml_rust2::Yaml {
        let path = workspace_root_from_xtask().unwrap().join(relative);
        let text =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let docs = yaml_rust2::yaml::YamlLoader::load_from_str(&text)
            .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
        docs.into_iter()
            .next()
            .unwrap_or(yaml_rust2::Yaml::BadValue)
    }

    /// The workflow and the gate table are one definition with two callers, so
    /// every group has exactly one job invoking it. `preflight` and `dev-suite` run
    /// unconditionally; `release-suite` runs on every event except a pull request,
    /// and that exact condition is pinned so a broader one — which would silently
    /// stop the release profile being tested on `main` — fails here. The live-network
    /// tests stay behind their `#[ignore]` attribute, so nothing in the workflow or
    /// in the action it calls opts back into ignored tests.
    ///
    /// Parsed rather than grepped: a commented-out job, or one held behind an `if:`
    /// at the step, is not a job that runs its group, and raw text cannot tell the
    /// difference.
    #[test]
    fn the_workflow_runs_every_gate_group_once() {
        let workflow = parse_yaml(".github/workflows/ci.yml");
        let jobs = workflow["jobs"]
            .as_hash()
            .expect("the workflow defines jobs");
        assert!(
            !jobs.is_empty(),
            "positive control: there must be jobs to examine"
        );

        // Exactly the three gate jobs and nothing beside them: a job that calls a
        // reusable workflow has no `steps` and would otherwise be invisible below.
        assert_eq!(
            jobs.len(),
            GateGroup::value_variants().len(),
            "the workflow has one job per gate group and no other"
        );

        // One entry per job: the job-level `if:` (absent, a string, or something
        // else — a YAML `false` is not a string and must not read as absent) and the
        // `run` strings of its unconditional steps. A step carrying an `if:` is
        // conditional.
        let per_job: Vec<(Option<&str>, Vec<&str>)> = jobs
            .iter()
            .map(|(name, job)| {
                let condition = &job["if"];
                assert!(
                    condition.is_badvalue() || condition.as_str().is_some(),
                    "job {name:?}: an `if:` must be a string expression, never a bare value"
                );
                let runs = job["steps"]
                    .as_vec()
                    .map(|steps| {
                        steps
                            .iter()
                            .filter(|step| step["if"].is_badvalue())
                            .filter_map(|step| step["run"].as_str())
                            .collect()
                    })
                    .unwrap_or_default();
                (condition.as_str(), runs)
            })
            .collect();

        const NOT_ON_PULL_REQUESTS: &str = "github.event_name != 'pull_request'";
        for group in GateGroup::value_variants() {
            let invocation = format!("cargo xtask gate --group {}", group.as_str());
            let conditions: Vec<Option<&str>> = per_job
                .iter()
                .filter(|(_, runs)| runs.iter().any(|run| run.trim() == invocation))
                .map(|(condition, _)| *condition)
                .collect();
            assert_eq!(
                conditions.len(),
                1,
                "exactly one job must run `{invocation}`"
            );
            let expected = match group {
                GateGroup::Preflight | GateGroup::DevSuite => None,
                GateGroup::ReleaseSuite => Some(NOT_ON_PULL_REQUESTS),
            };
            assert_eq!(
                conditions[0], expected,
                "the job running `{invocation}` carries the wrong condition"
            );
        }

        // Every string of both files, not only the gate lines: an opt-in to the ignored
        // tests would work as well from an `env:` value or a step's `with:` as from a
        // `run:`.
        let mut strings = Vec::new();
        yaml_strings(&workflow, &mut strings);
        yaml_strings(
            &parse_yaml(".github/actions/setup/action.yml"),
            &mut strings,
        );
        assert!(
            strings.iter().any(|s| s.contains("cargo xtask gate")),
            "positive control: the scan must reach the gate invocations"
        );
        assert!(
            !strings.iter().any(|s| s.contains("--include-ignored")),
            "the live-network tests are excluded by their attribute"
        );
    }

    /// The workflow's jobs share their setup through a local composite action, which
    /// nothing else checks: a composite step that omits `shell` fails only at run time,
    /// and a `uses: ./…` naming a directory with no `action.yml` fails the same way.
    #[test]
    fn the_local_composite_action_is_well_formed_and_reachable() {
        let action = parse_yaml(".github/actions/setup/action.yml");
        assert_eq!(action["runs"]["using"].as_str(), Some("composite"));
        let steps = action["runs"]["steps"]
            .as_vec()
            .expect("the action defines steps");
        assert!(!steps.is_empty(), "positive control: there must be steps");
        for step in steps {
            if step["run"].as_str().is_some() {
                assert!(
                    step["shell"].as_str().is_some(),
                    "a composite `run` step must name its shell"
                );
            }
        }

        let workflow = parse_yaml(".github/workflows/ci.yml");
        let mut strings = Vec::new();
        yaml_strings(&workflow, &mut strings);
        let local: Vec<&String> = strings.iter().filter(|s| s.starts_with("./")).collect();
        assert!(
            !local.is_empty(),
            "positive control: a local `uses:` exists"
        );
        let root = workspace_root_from_xtask().unwrap();
        for path in local {
            let manifest = root.join(path.trim_start_matches("./")).join("action.yml");
            assert!(
                manifest.exists(),
                "`uses: {path}` names no {}",
                manifest.display()
            );
        }
    }

    /// The CLI spelling of a group and the spelling `--list` prints come from two
    /// places — clap's `ValueEnum` derive and `as_str` — so a rename of one without
    /// the other would leave `--group <what --list printed>` unparseable. Matched
    /// case-sensitively: a case-only divergence is a divergence.
    #[test]
    fn every_group_parses_back_from_the_name_it_prints() {
        for group in GateGroup::value_variants() {
            assert_eq!(
                GateGroup::from_str(group.as_str(), false).unwrap(),
                *group,
                "`{}` must parse back to itself",
                group.as_str()
            );
        }
    }

    #[test]
    fn every_red_step_is_named_in_order() {
        let results = [
            ("fmt", false),
            ("clippy", true),
            ("test --workspace", false),
        ];
        assert_eq!(
            release_gate_verdict(&results),
            Err(vec!["fmt", "test --workspace"])
        );
    }
}
