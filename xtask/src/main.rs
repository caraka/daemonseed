//! xtask — workspace task runner.
//!
//! Subcommands:
//! - `gen-proto` — regenerate the committed snapshot under
//!   `crates/daemonseed-proto/src/generated/` from the .proto files. Run after
//!   editing any .proto.
//! - `check-proto` — regenerate to a temporary directory and diff against the
//!   committed snapshot. Non-zero exit on drift. CI gate.

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
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::GenProto => gen_proto(),
        Cmd::CheckProto => check_proto(),
    }
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
