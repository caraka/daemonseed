//! Gate checks for the crypto dependency and the release scripts.
//!
//! - `check-crypto-deps` fails unless `Cargo.lock` holds exactly one package
//!   whose name starts with `oxicrypt`, and that package is the `oxicrypt`
//!   binding crate. A module crate (`oxicrypt-module`, `oxicrypt-aes`, …) in the
//!   graph would compile an unsigned copy of module code into daemonseed beside
//!   the signed library the binding links.
//! - `release-scripts` runs `scripts/test-release-scripts.sh`, the fixture tests
//!   of the release workflow's scripts, and fails when it does.

use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

/// The `oxicrypt*` package names a `Cargo.lock` text lists, in file order.
pub fn oxicrypt_packages(lock: &str) -> Vec<String> {
    lock.lines()
        .filter_map(|line| line.strip_prefix("name = \""))
        .filter_map(|rest| rest.strip_suffix('"'))
        .filter(|name| name.starts_with("oxicrypt"))
        .map(str::to_owned)
        .collect()
}

/// Fails unless `lock` lists the `oxicrypt` binding crate and no other
/// `oxicrypt*` package.
pub fn check_lock(lock: &str) -> Result<()> {
    let found = oxicrypt_packages(lock);
    if found != ["oxicrypt"] {
        bail!(
            "check-crypto-deps: Cargo.lock must hold the `oxicrypt` crate and no other \
             oxicrypt package; it holds {found:?}"
        );
    }
    Ok(())
}

pub fn check_crypto_deps(repo_root: &Path) -> Result<()> {
    let path = repo_root.join("Cargo.lock");
    let lock = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    check_lock(&lock)?;
    println!("check-crypto-deps: Cargo.lock holds the oxicrypt binding crate and no module crate");
    Ok(())
}

/// The command that runs the release scripts' fixture tests, without git's
/// repository-local environment: the fixtures create and tag repositories of
/// their own, and a git hook that runs this step exports `GIT_DIR`.
pub fn release_scripts_command(repo_root: &Path) -> Command {
    let mut cmd = Command::new("bash");
    crate::git_env::without_repo_env(&mut cmd);
    cmd.arg(repo_root.join("scripts/test-release-scripts.sh"))
        .current_dir(repo_root);
    cmd
}

pub fn release_scripts(repo_root: &Path) -> Result<()> {
    let script = repo_root.join("scripts/test-release-scripts.sh");
    let status = release_scripts_command(repo_root)
        .status()
        .with_context(|| format!("run {}", script.display()))?;
    if !status.success() {
        bail!("release-scripts: {} failed ({status})", script.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BINDING: &str = "[[package]]\nname = \"oxicrypt\"\nversion = \"0.26.0\"\n";

    #[test]
    fn the_binding_crate_alone_passes() {
        let lock = format!("[[package]]\nname = \"anyhow\"\n\n{BINDING}");
        check_lock(&lock).expect("the binding alone is the intended graph");
    }

    #[test]
    fn a_module_crate_beside_the_binding_fails() {
        let lock =
            format!("{BINDING}\n[[package]]\nname = \"oxicrypt-module\"\nversion = \"0.24.0\"\n");
        let err = check_lock(&lock).expect_err("a module crate must fail the check");
        assert!(err.to_string().contains("oxicrypt-module"), "{err}");
    }

    #[test]
    fn a_lock_without_the_binding_fails() {
        check_lock("[[package]]\nname = \"anyhow\"\n").expect_err("no binding crate must fail");
    }

    /// `git -C <repo> <args>`, started without git's repository-local
    /// environment, returning stdout; panics on failure.
    fn git_out(repo: &Path, args: &[&str]) -> Vec<u8> {
        let mut cmd = Command::new("git");
        crate::git_env::without_repo_env(&mut cmd);
        let out = cmd
            .arg("-C")
            .arg(repo)
            .args([
                "-c",
                "user.name=sentinel",
                "-c",
                "user.email=sentinel@example.invalid",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .output()
            .expect("spawn git");
        assert!(out.status.success(), "git {args:?}: {out:?}");
        out.stdout
    }

    /// The release scripts' fixture tests leave the repository a git hook runs
    /// them for untouched. A hook exports `GIT_DIR`; here it names a sentinel
    /// repository, whose refs and configuration must be byte-identical after
    /// the run.
    #[test]
    fn the_release_script_tests_leave_an_inherited_git_dir_untouched() {
        let sentinel = tempfile::tempdir().expect("sentinel dir");
        git_out(sentinel.path(), &["init", "-q"]);
        git_out(
            sentinel.path(),
            &["commit", "-q", "--allow-empty", "-m", "sentinel"],
        );
        let snapshot = || {
            let text =
                |args: &[&str]| String::from_utf8(git_out(sentinel.path(), args)).expect("utf-8");
            (text(&["for-each-ref"]), text(&["config", "--list"]))
        };
        let before = snapshot();
        assert!(
            !before.0.is_empty(),
            "positive control: the sentinel has a ref"
        );

        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root");
        let mut run = Command::new("bash");
        crate::git_env::without_repo_env(&mut run);
        let out = run
            .arg(root.join("scripts/test-release-scripts.sh"))
            .current_dir(root)
            .env("GIT_DIR", sentinel.path().join(".git"))
            .output()
            .expect("run the release script tests");

        assert_eq!(
            snapshot(),
            before,
            "the release script tests changed the repository GIT_DIR named"
        );
        assert!(
            out.status.success(),
            "the release script tests fail under an inherited GIT_DIR: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn the_gate_step_starts_the_script_without_git_dir() {
        let cmd = release_scripts_command(Path::new("."));
        assert!(
            cmd.get_envs()
                .any(|(key, value)| key == "GIT_DIR" && value.is_none()),
            "the step must remove GIT_DIR from the script's environment"
        );
    }

    #[test]
    fn the_workspace_lock_passes() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root");
        check_crypto_deps(root).expect("the workspace graph holds only the binding crate");
    }
}
