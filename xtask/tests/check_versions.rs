//! The built `xtask check-versions` exits non-zero on a drifted tree and zero on a
//! clean one, so the gate step that runs it can be red.

#[path = "../src/git_env.rs"]
mod git_env;
#[path = "../src/version_fixture.rs"]
mod version_fixture;

use std::process::Command;

use version_fixture::Tree;

fn check_versions(tree: &Tree, extra: &[&str]) -> std::process::ExitStatus {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("check-versions")
        .arg("--root")
        .arg(tree.root())
        .args(extra)
        .status()
        .expect("run xtask check-versions")
}

#[test]
fn the_binary_exits_non_zero_on_a_drifted_tree() {
    let clean = Tree::new("0.37.2");
    assert!(check_versions(&clean, &[]).success(), "a clean tree passes");

    let drifted = Tree::new("0.37.2");
    drifted.set_manifest(Tree::MANIFESTS[0], "0.1.0");
    assert!(!check_versions(&drifted, &[]).success());
}

#[test]
fn the_binary_applies_release_mode_on_request() {
    let lagging = Tree::new("0.37.2");
    lagging.set_readme("0.37.1");
    lagging.git_tag("v0.37.2");
    assert!(check_versions(&lagging, &[]).success());
    assert!(!check_versions(&lagging, &["--release"]).success());
}
