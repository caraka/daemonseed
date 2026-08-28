//! xtask — workspace task runner.
//!
//! Subcommands:
//! - `gen-proto` — regenerate the committed snapshot under
//!   `crates/daemonseed-proto/src/generated/` from the .proto files. Run after
//!   editing any .proto.
//! - `check-proto` — regenerate to a temporary directory and diff against the
//!   committed snapshot. Non-zero exit on drift. CI gate.
//! - `isc-coverage` — report the percentage of ISCs covered by registered
//!   tests in `daemonseed-integration-tests::isc_coverage`. M0 reports the
//!   0/93 baseline; later milestones surface the live registry count and
//!   gate CI at `--min 95`.
//! - `findings-resolved` — grep-assert that the M0 cross-ISC findings
//!   (F14 / F18 / F19 / F21) are still resolved in `ds-isc-draft.md`. Closes
//!   redteam reservation R4: the text fixes have a runtime gate, not just
//!   a memory.
//! - `install-hooks` — install the workspace's git pre-push hook into the
//!   active checkout's `.git/hooks/` (or into a `--target` directory).
//!   Idempotent; overwrites a previously-installed hook in-place.
//! - `check-manifests` — parse every `docs/llm-api-manifest/*.yaml` with
//!   duplicate-key detection at the event level and fail on any repeat. YAML
//!   discards a repeated mapping key silently, so nothing else in the repo
//!   would notice (#326).
//! - `release-gate` — run the full Definition-of-Done gate and refuse a
//!   non-zero exit if any check is red, so a release tag is never cut on a
//!   red tree. Runs the test suite in BOTH the dev and release profiles (#274),
//!   then deletes the binaries those steps linked into `target/` (see
//!   `remove_linked_bins`). Run before `git tag`.

mod manifests;
mod ui_strings;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
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
    /// Report ISC coverage from `daemonseed-integration-tests`. Exits non-zero
    /// if the covered percentage is below `--min` (when supplied).
    IscCoverage {
        /// Minimum coverage percentage required for a zero exit code. CI gate
        /// will eventually set this to `95`. Omit at M0 to inspect the
        /// baseline without gating.
        #[arg(long)]
        min: Option<u8>,
    },
    /// Grep-assert that the M0 cross-ISC findings (F14 / F18 / F19 / F21) are
    /// still resolved in `ds-isc-draft.md`. Exits non-zero on the first
    /// missing marker. Closes redteam reservation R4.
    FindingsResolved {
        /// Path to the working ISC draft. Required: the draft is kept outside
        /// this repository, so there is no default that would resolve here.
        #[arg(long)]
        draft: Option<PathBuf>,
    },
    /// Install the workspace's git pre-push hook into the active checkout.
    /// Idempotent — overwrites an existing hook in-place.
    InstallHooks {
        /// Target hook directory. Defaults to `<repo>/.git/hooks/` resolved
        /// via `git rev-parse --git-dir` so the install works inside worktrees.
        #[arg(long)]
        target: Option<PathBuf>,
    },
    /// Run the full Definition-of-Done gate (fmt, clippy workspace +
    /// gui/desktop, test --workspace, check-proto, isc-coverage) and refuse
    /// (non-zero exit) if any check is red — so a release tag is never cut on a
    /// red tree (#62). Run before `git tag`.
    ReleaseGate,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::CheckManifests => manifests::check_manifests(&workspace_root_from_xtask()?),
        Cmd::GenProto => gen_proto(),
        Cmd::CheckProto => check_proto(),
        Cmd::CheckUiStrings => ui_strings::check_ui_strings(&workspace_root_from_xtask()?),
        Cmd::IscCoverage { min } => isc_coverage(min),
        Cmd::FindingsResolved { draft } => findings_resolved(draft),
        Cmd::InstallHooks { target } => install_hooks(target),
        Cmd::ReleaseGate => release_gate(),
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

/// M0 cross-ISC findings whose ISC-draft text fixes are runtime-asserted by
/// `findings-resolved`. Each marker is the literal substring that must appear
/// in `ds-isc-draft.md`; the in-draft edit phrases the marker so re-wording
/// the surrounding prose doesn't accidentally trip the gate.
const FINDING_MARKERS: &[&str] = &["per F14", "per F18", "per F19", "per F21"];

fn findings_resolved(draft: Option<PathBuf>) -> Result<()> {
    // The ISC draft is a working document kept outside this repository, so there
    // is no default path that would mean anything to a reader: `--draft` names it.
    let path = draft.context(
        "findings-resolved needs `--draft <path>`: the ISC draft is kept outside this repository",
    )?;
    let body = fs::read_to_string(&path)
        .with_context(|| format!("read ISC draft at {}", path.display()))?;

    let mut missing = Vec::new();
    for marker in FINDING_MARKERS {
        let n = body.matches(marker).count();
        if n == 0 {
            missing.push(*marker);
        } else {
            println!("findings-resolved: `{marker}` ✓  ({n} occurrence(s))");
        }
    }
    if missing.is_empty() {
        println!(
            "findings-resolved: all 4 markers present in {}",
            path.display()
        );
        Ok(())
    } else {
        bail!(
            "findings-resolved: {} marker(s) missing in {}: {}",
            missing.len(),
            path.display(),
            missing.join(", ")
        )
    }
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

/// Resolve `.git/hooks/` for a checkout. Works inside worktrees: `git
/// rev-parse --git-dir` returns the worktree's hooks dir, not the common
/// `.git/` of the source repo (where the hook would be shared with all
/// worktrees — which is usually the wrong sharing default).
fn resolve_git_hooks_dir(repo_root: &Path) -> Result<PathBuf> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("rev-parse")
        .arg("--git-dir")
        .output()
        .context("invoke git rev-parse --git-dir")?;
    if !out.status.success() {
        bail!(
            "git rev-parse --git-dir failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let git_dir = String::from_utf8(out.stdout)
        .context("git output is not utf-8")?
        .trim()
        .to_string();
    let git_dir_path = if Path::new(&git_dir).is_absolute() {
        PathBuf::from(git_dir)
    } else {
        repo_root.join(git_dir)
    };
    Ok(git_dir_path.join("hooks"))
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

// ── release-gate helpers ─────────────────────────────────────────────

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

/// Delete the binaries the gate's `cargo test`/`clippy --all-targets` steps linked into
/// `target/{debug,release}/`.
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
    for profile in ["debug", "release"] {
        for bin in WORKSPACE_BINS {
            let path = repo.join("target").join(profile).join(bin);
            match fs::remove_file(&path) {
                Ok(()) => println!("release-gate: removed linked binary {}", path.display()),
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

// ── release-gate ─────────────────────────────────────────────────────

/// One Definition-of-Done step the release gate runs, in order. `args` go to
/// `cargo`. Mirrors `AGENTS.md` § Definition of done.
struct GateStep {
    name: &'static str,
    args: &'static [&'static str],
}

/// The full DoD gate a release tag-cut must pass green (#62).
const RELEASE_GATE_STEPS: &[GateStep] = &[
    GateStep {
        name: "fmt --all --check",
        args: &["fmt", "--all", "--check"],
    },
    GateStep {
        name: "clippy --workspace -D warnings",
        args: &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    },
    GateStep {
        name: "clippy -p daemonseed-gui --features desktop -D warnings",
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
    },
    GateStep {
        name: "test --workspace",
        args: &["test", "--workspace"],
    },
    // #274: the suite in the RELEASE profile as well as dev. Three `daemonseed-gui`
    // tests were red in release for as long as the release profile existed, and this
    // gate never saw them because it only ever ran dev. Since #258 put
    // `overflow-checks = true` on the release profile, the two profiles differ in
    // BEHAVIOUR and not merely in optimization level, so a green dev suite is no longer
    // evidence about the artifact that actually ships.
    GateStep {
        name: "test --workspace --release",
        args: &["test", "--workspace", "--release"],
    },
    GateStep {
        name: "xtask check-proto",
        args: &["xtask", "check-proto"],
    },
    GateStep {
        name: "xtask isc-coverage",
        args: &["xtask", "isc-coverage"],
    },
    // #326: a parse of seven small files, so it joins the gate that already runs
    // rather than becoming a push-time cost of its own.
    GateStep {
        name: "xtask check-manifests",
        args: &["xtask", "check-manifests"],
    },
    // No other step reads a user-visible string. Cheap: a scan of the .slint
    // files and the two front-end src trees.
    GateStep {
        name: "xtask check-ui-strings",
        args: &["xtask", "check-ui-strings"],
    },
];

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

/// Run every DoD step and refuse the tag-cut (non-zero exit) if any is red, so a
/// release tag is never created on a red tree — the v0.29.0 slip, where a tag was
/// cut while `test --workspace` was red (#62). Run before `git tag`.
fn release_gate() -> Result<()> {
    let repo = workspace_root_from_xtask()?;
    let cargo = cargo_bin();
    let mut results: Vec<(&'static str, bool)> = Vec::with_capacity(RELEASE_GATE_STEPS.len());
    for step in RELEASE_GATE_STEPS {
        println!("release-gate: {} …", step.name);
        let status = Command::new(&cargo)
            .current_dir(&repo)
            .args(step.args)
            .status()
            .with_context(|| format!("spawn cargo {}", step.name))?;
        results.push((step.name, status.success()));
    }
    // After every step, red or green: the verdict below can `bail!`, and the linked
    // binaries must not survive that path either.
    remove_linked_bins(&repo)?;
    match release_gate_verdict(&results) {
        Ok(()) => {
            println!("release-gate: GREEN — every DoD check passed; safe to cut the signed tag.");
            Ok(())
        }
        Err(failed) => bail!(
            "release-gate: RED — refusing the tag-cut; failed: {}. Fix and re-run before `git tag`.",
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
