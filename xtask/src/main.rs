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

use std::fs;
use std::path::{Path, PathBuf};

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
    /// Regenerate `crates/daemonseed-proto/src/generated/` from .proto files.
    GenProto,
    /// Verify that the committed snapshot matches what tonic-build emits.
    CheckProto,
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
        /// Path to the working ISC draft. Defaults to the vault location used
        /// during the private phase. Override for CI on a forked checkout or
        /// after the draft is promoted in-repo.
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
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::GenProto => gen_proto(),
        Cmd::CheckProto => check_proto(),
        Cmd::IscCoverage { min } => isc_coverage(min),
        Cmd::FindingsResolved { draft } => findings_resolved(draft),
        Cmd::InstallHooks { target } => install_hooks(target),
    }
}

/// Total ISC count, kept in sync with `daemonseed-integration-tests::isc_coverage::TOTAL`.
/// Source of truth for the count check is the integration-tests crate's own
/// unit tests (`registry_count_matches_total`); xtask only needs the constant
/// to report the M0 baseline without taking a heavy path-dep on core+proto
/// transitively. Bump both when the ISC list changes.
const TOTAL_ISCS: u32 = 93;

/// M0 baseline coverage. M1+ replaces this with a real query against the live
/// registry — either by linking `daemonseed-integration-tests` directly or by
/// shelling out to `cargo test -p daemonseed-integration-tests --
/// --report-coverage` and parsing the output. Today's purpose is to give CI a
/// gate command that prints a real number.
fn isc_coverage(min: Option<u8>) -> Result<()> {
    let covered: u32 = 0; // M0 baseline — no tests registered yet
    let pct = if TOTAL_ISCS == 0 {
        0.0
    } else {
        (covered as f64) * 100.0 / (TOTAL_ISCS as f64)
    };
    println!("ISC coverage (M0 baseline): {covered}/{TOTAL_ISCS} = {pct:.1}%");
    if let Some(m) = min
        && (pct as u32) < (m as u32)
    {
        bail!(
            "ISC coverage {pct:.1}% below required minimum {m}%. \
             Register tests against entries in daemonseed-integration-tests::isc_coverage."
        );
    }
    Ok(())
}

/// M0 cross-ISC findings whose ISC-draft text fixes are runtime-asserted by
/// `findings-resolved`. Each marker is the literal substring that must appear
/// in `ds-isc-draft.md`; the in-draft edit phrases the marker so re-wording
/// the surrounding prose doesn't accidentally trip the gate.
const FINDING_MARKERS: &[&str] = &["per F14", "per F18", "per F19", "per F21"];

/// Default path to the working ISC draft during the private phase. Outside
/// the repo (`~/carakastan/Projects/DaemonSeed/`). Override via `--draft`.
fn default_draft_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home)
            .join("carakastan")
            .join("Projects")
            .join("DaemonSeed")
            .join("ds-isc-draft.md")
    } else {
        PathBuf::from("ds-isc-draft.md")
    }
}

fn findings_resolved(draft: Option<PathBuf>) -> Result<()> {
    let path = draft.unwrap_or_else(default_draft_path);
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
