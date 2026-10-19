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
//! - `install-hooks` — install the workspace's git pre-push hook into the
//!   active checkout's `.git/hooks/` (or into a `--target` directory).
//!   Idempotent; overwrites a previously-installed hook in-place.
//! - `check-manifests` — parse every `docs/llm-api-manifest/*.yaml` with
//!   duplicate-key detection at the event level and fail on any repeat. YAML
//!   discards a repeated mapping key silently, so nothing else in the repo
//!   would notice (#326).
//! - `check-versions` — fail when a workspace package does not inherit the
//!   workspace version in `Cargo.toml`, or `lama.yaml` or a manifest under
//!   `docs/llm-api-manifest/` disagrees with it, or the `README.md` `## Status`
//!   release line is newer than it: the README may lag but never lead (see
//!   `versions`). `--release` also requires the README line and any `v*` tag on
//!   `HEAD` to equal it, and a clean working tree.
//! - `gate` — run the Definition-of-Done gate, defined once as one table of
//!   steps in three groups: `preflight` (fmt, clippy, a release-profile
//!   type-check, rustdoc with warnings denied, and the xtask checks),
//!   `dev-suite` (the gui/desktop clippy pass and the dev-profile test suite)
//!   and `release-suite` (the release-profile test suite). `--group G` runs one
//!   group, `--list` prints the table and runs nothing, and no argument runs
//!   every group. A test step reporting zero passing tests is red whatever its
//!   exit code. Every run, whole or single-group, ends by deleting the binaries
//!   its steps linked into `target/` (see `remove_linked_bins`).
//! - `release-gate` — run `check-versions --release`, then every group of the
//!   gate, and exit non-zero naming any red step. It is the fallback for a
//!   release: run it before `git tag` when CI cannot run.

mod manifests;
mod ui_strings;
#[cfg(test)]
mod version_fixture;
mod versions;

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
    /// Fail when a workspace package does not inherit the workspace version, or
    /// `lama.yaml` or a manifest under `docs/llm-api-manifest/` disagrees with it, or
    /// the README's current-release line is newer than it. The README may lag but
    /// never lead.
    CheckVersions {
        /// Release rules: the README line must equal the workspace version, which
        /// must be final, any `v*` tag on `HEAD` must be `v` plus that version, and the
        /// working tree must be clean.
        #[arg(long)]
        release: bool,
        /// Check this tree instead of the workspace xtask was built from.
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Regenerate `crates/daemonseed-proto/src/generated/` from .proto files.
    GenProto,
    /// Verify that the committed snapshot matches what tonic-build emits.
    CheckProto,
    /// Refuse placeholder text in any string a user can read (.slint, and the
    /// gui/tui Rust sources). A placeholder is not shippable by definition.
    CheckUiStrings,
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
    /// Run `check-versions --release`, then every group of the Definition-of-Done
    /// gate, and exit non-zero naming any red step (#62). Run before `git tag`
    /// when CI cannot run.
    ReleaseGate,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::CheckManifests => manifests::check_manifests(&workspace_root_from_xtask()?),
        Cmd::CheckVersions { release, root } => {
            let root = match root {
                Some(root) => root,
                None => workspace_root_from_xtask()?,
            };
            let mode = if release {
                versions::Mode::Release
            } else {
                versions::Mode::Preflight
            };
            versions::check_versions(&root, mode)
        }
        Cmd::GenProto => gen_proto(),
        Cmd::CheckProto => check_proto(),
        Cmd::CheckUiStrings => ui_strings::check_ui_strings(&workspace_root_from_xtask()?),
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
        Cmd::ReleaseGate => {
            versions::check_versions(&workspace_root_from_xtask()?, versions::Mode::Release)?;
            run_gate(None)
        }
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
    resolve_target_dir(repo, std::env::var_os("CARGO_TARGET_DIR").as_deref())
}

/// [`target_dir`]'s rule over an explicit `CARGO_TARGET_DIR` value.
fn resolve_target_dir(repo: &Path, cargo_target_dir: Option<&std::ffi::OsStr>) -> PathBuf {
    match cargo_target_dir {
        Some(dir) => repo.join(dir),
        None => repo.join("target"),
    }
}

/// Delete the binaries the gate's `cargo test`/`clippy --all-targets` steps linked into
/// the profile directories under `target`, the cargo target directory (see
/// [`target_dir`]).
///
/// **This is not tidiness — it prevents a cross-machine miscompile.** Where a
/// `target/` directory is shared between two machines whose glibc versions differ,
/// a binary linked on the newer host fails to load on the older one
/// (`version 'GLIBC_2.xx' not found`), and because the artifact's timestamp then looks
/// fresh, that machine's own `cargo build` no-ops instead of relinking — so it keeps
/// running the unusable binary with nothing to say why. Removing the linked bins forces
/// a genuine relink wherever they are next built. Missing files are not an error: most
/// gate runs never link most of these.
fn remove_linked_bins(target: &Path) -> Result<()> {
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
/// runs the `preflight` group; CI runs each group in its own job, and on `main` does
/// not run a group again when the newest pull-request run of the pushed commit
/// already passed it on the same tree; `release-gate` runs the whole table
/// locally, before `git tag` when CI cannot run (#62).
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
    // The version stated in the hand-edited manifests and README drifts silently from
    // the workspace version otherwise. A read of the same small files as `xtask check-manifests`.
    GateStep {
        name: "xtask check-versions",
        group: GateGroup::Preflight,
        args: &["xtask", "check-versions"],
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
/// step. With no group this is the full Definition-of-Done gate, which
/// `release-gate` runs (#62).
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
    let swept = remove_linked_bins(&target_dir(&repo));
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

        remove_linked_bins(&repo.join("target")).expect("the sweep must tolerate absent binaries");

        for f in &planted {
            assert!(!f.exists(), "{} must be gone", f.display());
        }
        assert!(
            bystander.exists(),
            "the sweep must not touch non-bin artifacts"
        );
        fs::remove_dir_all(&repo).ok();
    }

    /// The target directory is `<repo>/target` when `CARGO_TARGET_DIR` is unset, the
    /// value as given when it is absolute, and the value under the repository when it
    /// is relative.
    #[test]
    fn the_target_directory_follows_cargo_target_dir() {
        let repo = std::path::Path::new("/work/repo");
        assert_eq!(resolve_target_dir(repo, None), repo.join("target"));
        assert_eq!(
            resolve_target_dir(repo, Some(std::ffi::OsStr::new("/elsewhere/build"))),
            std::path::PathBuf::from("/elsewhere/build")
        );
        assert_eq!(
            resolve_target_dir(repo, Some(std::ffi::OsStr::new("out/build"))),
            repo.join("out/build")
        );
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

    /// The version-agreement check runs in `preflight`, the group the pre-push hook runs.
    #[test]
    fn the_gate_checks_versions_in_preflight() {
        let step = RELEASE_GATE_STEPS
            .iter()
            .find(|s| s.args == ["xtask", "check-versions"])
            .expect("the version check must be in the gate");
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
    /// every group has exactly one job invoking it, and no other job exists.
    ///
    /// Each gate job runs `scripts/ci/already-passed.sh` on a push that is not a
    /// force-push, and its setup and gate steps run unless that check reported that
    /// the pushed tree already passed the same job in a pull-request run. On a pull
    /// request, after the gate passes, the job uploads the artifact that records the
    /// tree it tested, which is the evidence the check looks for. Every condition is
    /// pinned exactly: any other expression could skip the gate on a pull request,
    /// or on a tree no run has tested. The check is pinned to its exact command and
    /// environment, because a command that only mentions the script, or asks about
    /// another job, would answer for the wrong thing. No job has a `name:`, because
    /// the script matches the API's job name against `github.job`, and no job or
    /// step has `continue-on-error`, which would report a red gate as green. The
    /// triggers are pinned too: the conditions assume pull requests run the gate
    /// and pushes run only on `main`.
    ///
    /// `preflight` and `dev-suite` carry no job-level `if:`, so they always report
    /// a result. `release-suite` runs on every event except a pull
    /// request, and on a pull request from a `release/` branch; that exact condition
    /// is pinned so a broader one, which would run the release profile on every pull
    /// request, or a narrower one, which would stop it being tested on `main`, fails
    /// here. The live-network tests stay behind their `#[ignore]` attribute, so
    /// nothing in the workflow or in the action it calls opts back into ignored
    /// tests.
    ///
    /// Parsed rather than grepped: a commented-out job, or a step held behind some
    /// other `if:`, is not a job that runs its group, and raw text cannot tell the
    /// difference.
    #[test]
    fn the_workflow_runs_every_gate_group_once() {
        const CHECK_ID: &str = "prior";
        const CHECK_SCRIPT: &str = "scripts/ci/already-passed.sh";
        const CHECK_RUN: &str = r#"scripts/ci/already-passed.sh "${{ github.job }}""#;
        const CHECK_TOKEN: &str = "${{ github.token }}";
        const CHECK_ONLY_ON_PUSH: &str =
            "github.event_name == 'push' && github.event.forced != true";
        const UNLESS_ALREADY_PASSED: &str = "steps.prior.outputs.passed != 'true'";
        const ONLY_ON_PULL_REQUESTS: &str = "github.event_name == 'pull_request'";
        const TREE_ID: &str = "tree";
        const TREE_RUN: &str = concat!(
            "git rev-parse 'HEAD^{tree}' > \"$RUNNER_TEMP/tested-tree\"\n",
            "echo \"sha=$(cat \"$RUNNER_TEMP/tested-tree\")\" >> \"$GITHUB_OUTPUT\"\n",
        );
        const UPLOAD_ACTION: &str = "actions/upload-artifact@v4";
        const ARTIFACT_NAME: &str = "tested-${{ github.job }}-${{ steps.tree.outputs.sha }}";
        const RELEASE_SUITE_CONDITION: &str =
            "github.event_name != 'pull_request' || startsWith(github.head_ref, 'release/')";

        let workflow = parse_yaml(".github/workflows/ci.yml");
        let triggers = &workflow["on"];
        let pull_request = &triggers["pull_request"];
        assert!(
            !pull_request.is_badvalue(),
            "every pull request must run the gate"
        );
        for filter in [
            "branches",
            "branches-ignore",
            "paths",
            "paths-ignore",
            "types",
        ] {
            assert!(
                pull_request[filter].is_badvalue(),
                "the `pull_request` trigger takes no `{filter}` filter: every pull request runs the gate"
            );
        }
        let push = triggers["push"].as_hash();
        assert_eq!(
            push.map(|keys| keys.len()),
            Some(1),
            "the `push` trigger carries its branch filter and nothing else"
        );
        let push_branches: Option<Vec<Option<&str>>> = triggers["push"]["branches"]
            .as_vec()
            .map(|branches| branches.iter().map(|b| b.as_str()).collect());
        assert_eq!(
            push_branches,
            Some(vec![Some("main")]),
            "pushes run the workflow on `main` and on no other branch"
        );
        assert!(
            !triggers["workflow_dispatch"].is_badvalue(),
            "the workflow can be run by hand"
        );
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

        for group in GateGroup::value_variants() {
            let invocation = format!("cargo xtask gate --group {}", group.as_str());
            let is_gate = |step: &yaml_rust2::Yaml| {
                step["run"].as_str().map(str::trim) == Some(invocation.as_str())
            };
            let running: Vec<(&yaml_rust2::Yaml, &yaml_rust2::Yaml, &[yaml_rust2::Yaml])> = jobs
                .iter()
                .filter_map(|(name, job)| {
                    job["steps"]
                        .as_vec()
                        .map(|steps| (name, job, steps.as_slice()))
                })
                .filter(|(_, _, steps)| steps.iter().any(is_gate))
                .collect();
            assert_eq!(running.len(), 1, "exactly one job must run `{invocation}`");
            let (name, job, steps) = running[0];

            // The job-level `if:` is absent or a string: a YAML `false` is not a
            // string and must not read as absent.
            let condition = &job["if"];
            assert!(
                condition.is_badvalue() || condition.as_str().is_some(),
                "job {name:?}: an `if:` must be a string expression, never a bare value"
            );
            let expected = match group {
                GateGroup::Preflight | GateGroup::DevSuite => None,
                GateGroup::ReleaseSuite => Some(RELEASE_SUITE_CONDITION),
            };
            assert_eq!(
                condition.as_str(),
                expected,
                "the job running `{invocation}` carries the wrong condition"
            );
            assert_eq!(
                job["permissions"]["actions"].as_str(),
                Some("read"),
                "job {name:?} must be able to read earlier runs of the workflow"
            );
            assert!(
                job["name"].is_badvalue(),
                "job {name:?}: the API must report the job by its id, which the check matches"
            );
            assert!(
                job["continue-on-error"].is_badvalue(),
                "job {name:?}: a failing gate must fail the job"
            );
            for (at, step) in steps.iter().enumerate() {
                assert!(
                    step["continue-on-error"].is_badvalue(),
                    "job {name:?}: step {at} must fail the job when it fails"
                );
            }

            let checks: Vec<usize> = steps
                .iter()
                .enumerate()
                .filter(|(_, step)| {
                    step["run"]
                        .as_str()
                        .is_some_and(|run| run.contains(CHECK_SCRIPT))
                })
                .map(|(at, _)| at)
                .collect();
            assert_eq!(
                checks.len(),
                1,
                "job {name:?} must run `{CHECK_SCRIPT}` exactly once"
            );
            let check_at = checks[0];
            assert_eq!(
                steps[check_at]["id"].as_str(),
                Some(CHECK_ID),
                "job {name:?}: the gate conditions read the check's output by this id"
            );
            assert_eq!(
                steps[check_at]["if"].as_str(),
                Some(CHECK_ONLY_ON_PUSH),
                "job {name:?}: the check is consulted on a push that is not a force-push, and on nothing else"
            );
            assert_eq!(
                steps[check_at]["run"].as_str().map(str::trim),
                Some(CHECK_RUN),
                "job {name:?}: the check must run the script, asking about this job"
            );
            let check_env = steps[check_at]["env"].as_hash();
            assert_eq!(
                check_env.map(|env| env.len()),
                Some(1),
                "job {name:?}: the check's environment holds the token and nothing else"
            );
            assert_eq!(
                steps[check_at]["env"]["GH_TOKEN"].as_str(),
                Some(CHECK_TOKEN),
                "job {name:?}: the check authenticates with the job's token"
            );
            assert_eq!(
                steps.iter().filter(|step| is_gate(step)).count(),
                1,
                "job {name:?} must run `{invocation}` exactly once"
            );
            let gate_at = steps
                .iter()
                .position(is_gate)
                .expect("the job runs its gate");
            assert!(
                gate_at > check_at,
                "job {name:?}: the gate must come after the check that can skip it"
            );

            // Before the check, nothing is conditional. From the check to the gate,
            // every step is skipped exactly when the check reported the tree already
            // passed. After the gate come exactly the two steps that record the tested
            // tree, on a pull request only, and only once the gate has passed.
            assert_eq!(
                steps.len(),
                gate_at + 3,
                "job {name:?}: the gate is followed by the tree record and its upload, and nothing else"
            );
            for (at, step) in steps.iter().enumerate() {
                if at < check_at {
                    assert!(
                        step["if"].is_badvalue(),
                        "job {name:?}: step {at} runs before the check and must be unconditional"
                    );
                } else if at > check_at && at <= gate_at {
                    assert_eq!(
                        step["if"].as_str(),
                        Some(UNLESS_ALREADY_PASSED),
                        "job {name:?}: step {at} must run unless the tree already passed"
                    );
                } else if at > gate_at {
                    assert_eq!(
                        step["if"].as_str(),
                        Some(ONLY_ON_PULL_REQUESTS),
                        "job {name:?}: step {at} records the tested tree on a pull request, after the gate passed"
                    );
                }
            }
            let tree = &steps[gate_at + 1];
            assert_eq!(
                tree["id"].as_str(),
                Some(TREE_ID),
                "job {name:?}: the artifact name reads the tree by this id"
            );
            assert_eq!(
                tree["run"].as_str(),
                Some(TREE_RUN),
                "job {name:?}: the record names the tree of the checked-out commit"
            );
            let upload = &steps[gate_at + 2];
            assert_eq!(upload["uses"].as_str(), Some(UPLOAD_ACTION));
            assert_eq!(
                upload["with"]["name"].as_str(),
                Some(ARTIFACT_NAME),
                "job {name:?}: the artifact name is what the check looks for"
            );
            assert_eq!(
                upload["with"]["retention-days"].as_i64(),
                Some(30),
                "job {name:?}: the record is kept for 30 days"
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

    /// A canned GitHub API for `scripts/ci/already-passed.sh`. A stub `gh`, first on
    /// `PATH`, serves each request from a JSON file and applies the script's `--jq`
    /// filter with `jq`, as `gh` would. The commit is real, in a scratch repository,
    /// so the script computes its tree with `git` exactly as it does in CI.
    struct ApiFixture {
        dir: PathBuf,
        sha: String,
        tree: String,
    }

    const STUB_GH: &str = r#"#!/usr/bin/env bash
# Serves `gh api` requests from canned files in $STUB_GH_DIR.
set -euo pipefail
if [[ -n "${STUB_GH_FAIL:-}" ]]; then
    echo "gh: HTTP 500" >&2
    exit 1
fi
filter="." url=""
while (($#)); do
    case "$1" in
        --jq) filter="$2"; shift 2 ;;
        repos/*) url="$1"; shift ;;
        *) shift ;;
    esac
done
echo "$url" >> "$STUB_GH_DIR/requests.log"
path="${url%%\?*}"
case "$path" in
    */actions/workflows/*/runs) file="runs.json" ;;
    */actions/runs/*/jobs) id="${path%/jobs}"; file="jobs-${id##*/}.json" ;;
    */actions/runs/*/artifacts) id="${path%/artifacts}"; file="artifacts-${id##*/}.json" ;;
    *) echo "gh: unexpected request $url" >&2; exit 1 ;;
esac
if [[ ! -f "$STUB_GH_DIR/$file" ]]; then
    echo "gh: Not Found (HTTP 404)" >&2
    exit 1
fi
jq -r "$filter" "$STUB_GH_DIR/$file"
"#;

    impl ApiFixture {
        fn new(label: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let jq = Command::new("jq").arg("--version").output();
            assert!(
                jq.is_ok_and(|out| out.status.success()),
                "these tests need `jq` on PATH to stand in for the filter `gh` applies"
            );
            let dir =
                std::env::temp_dir().join(format!("already-passed-{label}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            for sub in ["bin", "api", "repo"] {
                fs::create_dir_all(dir.join(sub)).unwrap();
            }
            let repo = dir.join("repo");
            let git = |args: &[&str]| {
                let out = Command::new("git")
                    .env("GIT_CONFIG_GLOBAL", "/dev/null")
                    .env("GIT_CONFIG_NOSYSTEM", "1")
                    .args([
                        "-c",
                        "user.name=fixture",
                        "-c",
                        "user.email=fixture@example.invalid",
                    ])
                    .args(args)
                    .current_dir(&repo)
                    .output()
                    .unwrap();
                assert!(out.status.success(), "git {args:?}: {out:?}");
                String::from_utf8(out.stdout).unwrap().trim().to_owned()
            };
            git(&["init", "-q"]);
            fs::write(repo.join("file"), "fixture\n").unwrap();
            git(&["add", "file"]);
            git(&["commit", "-q", "-m", "fixture"]);
            let sha = git(&["rev-parse", "HEAD"]);
            let tree = git(&["rev-parse", "HEAD^{tree}"]);
            assert_ne!(sha, tree, "positive control: a commit and its tree differ");

            let gh = dir.join("bin/gh");
            fs::write(&gh, STUB_GH).unwrap();
            fs::set_permissions(&gh, fs::Permissions::from_mode(0o755)).unwrap();
            Self { dir, sha, tree }
        }

        fn serve(&self, file: &str, json: &str) {
            fs::write(self.dir.join("api").join(file), json).unwrap();
        }

        /// Completed runs of the workflow for this commit, as `(id, created_at,
        /// event)`, with no `run_started_at`, so the script falls back to
        /// `created_at`.
        fn serve_runs(&self, runs: &[(u64, &str, &str)]) {
            let full: Vec<(u64, &str, Option<&str>, &str, &str)> = runs
                .iter()
                .map(|(id, created, event)| (*id, *created, None, *event, "completed"))
                .collect();
            self.serve_runs_full(&full);
        }

        /// Runs as `(id, created_at, run_started_at, event, status)`.
        fn serve_runs_full(&self, runs: &[(u64, &str, Option<&str>, &str, &str)]) {
            let entries: Vec<String> = runs
                .iter()
                .map(|(id, created, started, event, status)| {
                    let started = started
                        .map(|at| format!(r#","run_started_at":"{at}""#))
                        .unwrap_or_default();
                    format!(
                        r#"{{"id":{id},"head_sha":"{}","event":"{event}","status":"{status}","created_at":"{created}"{started}}}"#,
                        self.sha
                    )
                })
                .collect();
            self.serve(
                "runs.json",
                &format!(r#"{{"workflow_runs":[{}]}}"#, entries.join(",")),
            );
        }

        fn serve_job(&self, run: u64, job: &str, conclusion: &str) {
            self.serve(
                &format!("jobs-{run}.json"),
                &format!(r#"{{"jobs":[{{"name":"{job}","status":"completed","conclusion":"{conclusion}"}}]}}"#),
            );
        }

        /// A job that has started and not finished: the API reports no conclusion.
        fn serve_job_in_progress(&self, run: u64, job: &str) {
            self.serve(
                &format!("jobs-{run}.json"),
                &format!(
                    r#"{{"jobs":[{{"name":"{job}","status":"in_progress","conclusion":null}}]}}"#
                ),
            );
        }

        /// A run whose jobs list is empty, as it is before its jobs are created.
        fn serve_no_jobs(&self, run: u64) {
            self.serve(&format!("jobs-{run}.json"), r#"{"jobs":[]}"#);
        }

        fn serve_artifacts(&self, run: u64, names: &[String]) {
            let entries: Vec<(String, bool)> =
                names.iter().map(|name| (name.clone(), false)).collect();
            self.serve_artifacts_full(run, &entries);
        }

        /// Artifacts as `(name, expired)`.
        fn serve_artifacts_full(&self, run: u64, artifacts: &[(String, bool)]) {
            let entries: Vec<String> = artifacts
                .iter()
                .map(|(name, expired)| format!(r#"{{"name":"{name}","expired":{expired}}}"#))
                .collect();
            self.serve(
                &format!("artifacts-{run}.json"),
                &format!(r#"{{"artifacts":[{}]}}"#, entries.join(",")),
            );
        }

        fn tested(&self, job: &str) -> String {
            format!("tested-{job}-{}", self.tree)
        }

        /// Run the script for `dev-suite`, with `overrides` replacing the default
        /// environment, and return its stdout and what it wrote to `GITHUB_OUTPUT`.
        /// The script answers every case with exit 0.
        fn ask(&self, overrides: &[(&str, &str)]) -> (String, String) {
            let output = self.dir.join("github-output");
            let _ = fs::remove_file(&output);
            let path = format!(
                "{}:{}",
                self.dir.join("bin").display(),
                std::env::var("PATH").unwrap_or_default()
            );
            let script = workspace_root_from_xtask()
                .unwrap()
                .join("scripts/ci/already-passed.sh");
            let mut command = Command::new(script);
            command
                .arg("dev-suite")
                .current_dir(self.dir.join("repo"))
                .env("PATH", path)
                .env("STUB_GH_DIR", self.dir.join("api"))
                .env("GITHUB_OUTPUT", &output)
                .env("GITHUB_REPOSITORY", "owner/repo")
                .env("GITHUB_SHA", &self.sha)
                .env(
                    "GITHUB_WORKFLOW_REF",
                    "owner/repo/.github/workflows/ci.yml@refs/heads/main",
                )
                .env_remove("STUB_GH_FAIL");
            for (key, value) in overrides {
                command.env(key, value);
            }
            let out = command.output().unwrap();
            assert!(
                out.status.success(),
                "the script must always exit 0: {out:?}"
            );
            (
                String::from_utf8(out.stdout).unwrap(),
                fs::read_to_string(&output).unwrap_or_default(),
            )
        }

        fn requests(&self) -> String {
            fs::read_to_string(self.dir.join("api/requests.log")).unwrap_or_default()
        }
    }

    impl Drop for ApiFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn assert_runs_gate((stdout, output): (String, String)) {
        assert!(
            stdout.starts_with("run: "),
            "expected `run:`, got {stdout:?}"
        );
        assert_eq!(output, "passed=false\n");
    }

    /// The one case that skips the gate: the newest pull-request run that ran the
    /// job passed it, and recorded the pushed commit's tree. It is also the positive
    /// control for every `run:` case below, each of which changes one thing.
    #[test]
    fn a_newest_passing_run_that_recorded_this_tree_skips_the_gate() {
        let api = ApiFixture::new("pass");
        api.serve_runs(&[(11, "2026-10-01T10:00:00Z", "pull_request")]);
        api.serve_job(11, "dev-suite", "success");
        api.serve_artifacts(11, &[api.tested("dev-suite")]);
        let (stdout, output) = api.ask(&[]);
        assert!(
            stdout.starts_with("already-passed: "),
            "expected `already-passed:`, got {stdout:?}"
        );
        assert_eq!(output, "passed=true\n");
        assert!(
            api.requests()
                .contains("repos/owner/repo/actions/workflows/ci.yml/runs?"),
            "the workflow file comes from GITHUB_WORKFLOW_REF: {}",
            api.requests()
        );
    }

    #[test]
    fn an_older_pass_behind_a_newer_failure_runs_the_gate() {
        let api = ApiFixture::new("newer-failure");
        // Listed oldest first, so only ordering by start time finds the failure.
        api.serve_runs(&[
            (11, "2026-10-01T10:00:00Z", "pull_request"),
            (12, "2026-10-01T11:00:00Z", "pull_request"),
        ]);
        api.serve_job(11, "dev-suite", "success");
        api.serve_artifacts(11, &[api.tested("dev-suite")]);
        api.serve_job(12, "dev-suite", "failure");
        api.serve_artifacts(12, &[]);
        assert_runs_gate(api.ask(&[]));
    }

    /// A job whose `if:` was false is listed as `skipped`: that run did not test the
    /// job, so the decision falls to the newest run that did.
    #[test]
    fn a_newer_run_that_skipped_the_job_defers_to_the_one_that_ran_it() {
        let api = ApiFixture::new("newer-skipped");
        api.serve_runs(&[
            (11, "2026-10-01T10:00:00Z", "pull_request"),
            (12, "2026-10-01T11:00:00Z", "pull_request"),
        ]);
        api.serve_job(11, "dev-suite", "success");
        api.serve_artifacts(11, &[api.tested("dev-suite")]);
        api.serve_job(12, "dev-suite", "skipped");
        let (stdout, output) = api.ask(&[]);
        assert!(stdout.starts_with("already-passed: "), "{stdout:?}");
        assert_eq!(output, "passed=true\n");
    }

    /// A newer run that has not reported this job yet may still fail it, so it
    /// decides, and the gate runs. Queued, its jobs list is empty.
    #[test]
    fn a_newer_queued_run_runs_the_gate() {
        let api = ApiFixture::new("newer-queued");
        api.serve_runs_full(&[
            (
                11,
                "2026-10-01T10:00:00Z",
                None,
                "pull_request",
                "completed",
            ),
            (12, "2026-10-01T11:00:00Z", None, "pull_request", "queued"),
        ]);
        api.serve_job(11, "dev-suite", "success");
        api.serve_artifacts(11, &[api.tested("dev-suite")]);
        api.serve_no_jobs(12);
        assert_runs_gate(api.ask(&[]));
    }

    /// In progress, with this job not yet listed.
    #[test]
    fn a_newer_run_in_progress_without_the_job_runs_the_gate() {
        let api = ApiFixture::new("newer-in-progress");
        api.serve_runs_full(&[
            (
                11,
                "2026-10-01T10:00:00Z",
                None,
                "pull_request",
                "completed",
            ),
            (
                12,
                "2026-10-01T11:00:00Z",
                None,
                "pull_request",
                "in_progress",
            ),
        ]);
        api.serve_job(11, "dev-suite", "success");
        api.serve_artifacts(11, &[api.tested("dev-suite")]);
        api.serve_job(12, "preflight", "success");
        assert_runs_gate(api.ask(&[]));
    }

    /// A completed newer run that has no entry for the job did not test it, so the
    /// decision falls to the older run.
    #[test]
    fn a_completed_newer_run_without_the_job_defers_to_the_one_that_ran_it() {
        let api = ApiFixture::new("newer-absent");
        api.serve_runs(&[
            (11, "2026-10-01T10:00:00Z", "pull_request"),
            (12, "2026-10-01T11:00:00Z", "pull_request"),
        ]);
        api.serve_job(11, "dev-suite", "success");
        api.serve_artifacts(11, &[api.tested("dev-suite")]);
        api.serve_no_jobs(12);
        let (stdout, output) = api.ask(&[]);
        assert!(stdout.starts_with("already-passed: "), "{stdout:?}");
        assert_eq!(output, "passed=true\n");
    }

    /// A re-run keeps its run's `created_at` and moves its `run_started_at`, so an
    /// older run re-run after a newer pass is the newest evidence.
    #[test]
    fn an_older_run_re_run_later_and_failed_runs_the_gate() {
        let api = ApiFixture::new("re-run-failed");
        api.serve_runs_full(&[
            (
                11,
                "2026-10-01T10:00:00Z",
                Some("2026-10-01T12:00:00Z"),
                "pull_request",
                "completed",
            ),
            (
                12,
                "2026-10-01T11:00:00Z",
                Some("2026-10-01T11:00:05Z"),
                "pull_request",
                "completed",
            ),
        ]);
        api.serve_job(11, "dev-suite", "failure");
        api.serve_artifacts(11, &[api.tested("dev-suite")]);
        api.serve_job(12, "dev-suite", "success");
        api.serve_artifacts(12, &[api.tested("dev-suite")]);
        assert_runs_gate(api.ask(&[]));
    }

    /// Two runs that started at the same second cannot be ordered, so neither may
    /// stand in for the other. The passing run has the larger id, so breaking the
    /// tie by id would pick it and skip the gate.
    #[test]
    fn runs_tied_on_start_time_run_the_gate() {
        let api = ApiFixture::new("tied");
        api.serve_runs_full(&[
            (
                11,
                "2026-10-01T10:00:00Z",
                Some("2026-10-01T11:00:00Z"),
                "pull_request",
                "completed",
            ),
            (
                12,
                "2026-10-01T10:30:00Z",
                Some("2026-10-01T11:00:00Z"),
                "pull_request",
                "completed",
            ),
        ]);
        api.serve_job(11, "dev-suite", "failure");
        api.serve_artifacts(11, &[]);
        api.serve_job(12, "dev-suite", "success");
        api.serve_artifacts(12, &[api.tested("dev-suite")]);
        assert_runs_gate(api.ask(&[]));
    }

    /// A run whose start time is not a fixed-width UTC timestamp cannot be ordered
    /// against the others. Here the malformed one is the pass, and as text it sorts
    /// above the failure in any locale, so ordering it at all would skip the gate.
    #[test]
    fn a_run_with_a_malformed_start_time_runs_the_gate() {
        let api = ApiFixture::new("bad-time");
        api.serve_runs_full(&[
            (
                11,
                "2026-10-01T10:00:00Z",
                Some("2026-10-01T11:00:00Z"),
                "pull_request",
                "completed",
            ),
            (
                12,
                "2026-10-01T09:00:00Z",
                Some("soon"),
                "pull_request",
                "completed",
            ),
        ]);
        api.serve_job(11, "dev-suite", "failure");
        api.serve_artifacts(11, &[]);
        api.serve_job(12, "dev-suite", "success");
        api.serve_artifacts(12, &[api.tested("dev-suite")]);
        assert_runs_gate(api.ask(&[]));
    }

    /// Only the fixed-width form GitHub returns is accepted, so that byte order is
    /// time order. A fractional second sorts after the whole second it follows, and
    /// an offset is a different clock, so either answers run.
    #[test]
    fn a_start_time_with_fractional_seconds_runs_the_gate() {
        assert_runs_gate(odd_start_time("frac", "2026-10-01T10:00:00.1Z"));
    }

    #[test]
    fn a_start_time_with_an_offset_runs_the_gate() {
        assert_runs_gate(odd_start_time("offset", "2026-10-01T10:00:00+00:00"));
    }

    /// One passing run, with the tree recorded, whose start time is `started`.
    fn odd_start_time(label: &str, started: &str) -> (String, String) {
        let api = ApiFixture::new(label);
        api.serve_runs_full(&[(
            11,
            "2026-10-01T09:00:00Z",
            Some(started),
            "pull_request",
            "completed",
        )]);
        api.serve_job(11, "dev-suite", "success");
        api.serve_artifacts(11, &[api.tested("dev-suite")]);
        api.ask(&[])
    }

    /// A run still in progress whose job has already concluded is judged on that
    /// job: its result is final for the attempt, and a re-run of the job would
    /// replace it in the latest-attempt listing.
    #[test]
    fn a_running_newest_run_that_already_passed_the_job_skips_the_gate() {
        let api = ApiFixture::new("running-passed");
        api.serve_runs_full(&[
            (
                11,
                "2026-10-01T10:00:00Z",
                None,
                "pull_request",
                "completed",
            ),
            (
                12,
                "2026-10-01T11:00:00Z",
                None,
                "pull_request",
                "in_progress",
            ),
        ]);
        api.serve_job(11, "dev-suite", "failure");
        api.serve_artifacts(11, &[]);
        api.serve_job(12, "dev-suite", "success");
        api.serve_artifacts(12, &[api.tested("dev-suite")]);
        let (stdout, output) = api.ask(&[]);
        assert!(stdout.starts_with("already-passed: "), "{stdout:?}");
        assert_eq!(output, "passed=true\n");
    }

    /// The newest run's job has started and has no conclusion yet.
    #[test]
    fn a_job_still_running_in_the_newest_run_runs_the_gate() {
        let api = ApiFixture::new("job-in-progress");
        api.serve_runs_full(&[
            (
                11,
                "2026-10-01T10:00:00Z",
                None,
                "pull_request",
                "completed",
            ),
            (
                12,
                "2026-10-01T11:00:00Z",
                None,
                "pull_request",
                "in_progress",
            ),
        ]);
        api.serve_job(11, "dev-suite", "success");
        api.serve_artifacts(11, &[api.tested("dev-suite")]);
        api.serve_job_in_progress(12, "dev-suite");
        assert_runs_gate(api.ask(&[]));
    }

    #[test]
    fn an_expired_record_of_the_tree_runs_the_gate() {
        let api = ApiFixture::new("expired");
        api.serve_runs(&[(11, "2026-10-01T10:00:00Z", "pull_request")]);
        api.serve_job(11, "dev-suite", "success");
        api.serve_artifacts_full(11, &[(api.tested("dev-suite"), true)]);
        assert_runs_gate(api.ask(&[]));
    }

    #[test]
    fn a_pass_that_recorded_no_tree_runs_the_gate() {
        let api = ApiFixture::new("no-artifact");
        api.serve_runs(&[(11, "2026-10-01T10:00:00Z", "pull_request")]);
        api.serve_job(11, "dev-suite", "success");
        api.serve_artifacts(11, &[]);
        assert_runs_gate(api.ask(&[]));
    }

    /// A pull request whose base was not the branch the commit landed on tested the
    /// merge with that base, which is a different tree.
    #[test]
    fn a_pass_that_recorded_a_different_tree_runs_the_gate() {
        let api = ApiFixture::new("other-tree");
        api.serve_runs(&[(11, "2026-10-01T10:00:00Z", "pull_request")]);
        api.serve_job(11, "dev-suite", "success");
        api.serve_artifacts(
            11,
            &[
                format!("tested-dev-suite-{}", "0".repeat(40)),
                format!("tested-preflight-{}", api.tree),
            ],
        );
        assert_runs_gate(api.ask(&[]));
    }

    #[test]
    fn a_run_that_was_not_a_pull_request_runs_the_gate() {
        let api = ApiFixture::new("not-pr");
        api.serve_runs(&[(11, "2026-10-01T10:00:00Z", "push")]);
        api.serve_job(11, "dev-suite", "success");
        api.serve_artifacts(11, &[api.tested("dev-suite")]);
        assert_runs_gate(api.ask(&[]));
    }

    #[test]
    fn an_api_error_runs_the_gate() {
        let api = ApiFixture::new("gh-error");
        api.serve_runs(&[(11, "2026-10-01T10:00:00Z", "pull_request")]);
        api.serve_job(11, "dev-suite", "success");
        api.serve_artifacts(11, &[api.tested("dev-suite")]);
        assert_runs_gate(api.ask(&[("STUB_GH_FAIL", "1")]));
    }

    #[test]
    fn a_malformed_commit_id_runs_the_gate() {
        let api = ApiFixture::new("bad-sha");
        api.serve_runs(&[(11, "2026-10-01T10:00:00Z", "pull_request")]);
        api.serve_job(11, "dev-suite", "success");
        api.serve_artifacts(11, &[api.tested("dev-suite")]);
        let short = api.sha[..7].to_owned();
        assert_runs_gate(api.ask(&[("GITHUB_SHA", &short)]));
    }

    #[test]
    fn an_unparseable_workflow_ref_runs_the_gate() {
        let api = ApiFixture::new("bad-ref");
        api.serve_runs(&[(11, "2026-10-01T10:00:00Z", "pull_request")]);
        api.serve_job(11, "dev-suite", "success");
        api.serve_artifacts(11, &[api.tested("dev-suite")]);
        assert_runs_gate(api.ask(&[("GITHUB_WORKFLOW_REF", "ci.yml")]));
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
