//! A throwaway workspace tree for driving `check-versions` end to end: a root
//! `Cargo.toml`, one member package, `lama.yaml`, `README.md` and three manifests,
//! every surface at one version until a test changes one.
//!
//! Used by the unit tests in `versions` and by the binary test in
//! `tests/check_versions.rs`, which includes this file by path.

#![allow(dead_code)]

use std::fs;
use std::path::Path;
use std::process::Command;

/// A temporary workspace tree, deleted on drop.
pub struct Tree {
    dir: tempfile::TempDir,
}

impl Tree {
    /// The manifest files the tree carries, in sorted order.
    pub const MANIFESTS: [&'static str; 3] = [
        "a-first-api.yaml",
        "m-middle-api.yaml",
        "z-last-protocol.yaml",
    ];

    /// A tree where every surface carries `version`.
    pub fn new(version: &str) -> Tree {
        let tree = Tree {
            dir: tempfile::tempdir().expect("create a temporary directory"),
        };
        tree.write(
            "Cargo.toml",
            &format!(
                "[workspace]\nmembers = [\"member\"]\nresolver = \"2\"\n\n\
                 [workspace.package]\nversion = \"{version}\"\n"
            ),
        );
        tree.write(
            "member/Cargo.toml",
            "[package]\nname = \"fixture-member\"\nversion.workspace = true\nedition = \"2021\"\n",
        );
        tree.write("member/src/lib.rs", "");
        tree.write("lama.yaml", &manifest("fixture", version));
        for name in Self::MANIFESTS {
            tree.set_manifest(name, version);
        }
        tree.set_readme(version);
        tree
    }

    pub fn root(&self) -> &Path {
        self.dir.path()
    }

    fn write(&self, relative: &str, text: &str) {
        let path = self.root().join(relative);
        fs::create_dir_all(path.parent().expect("a file path has a parent"))
            .expect("create the parent directory");
        fs::write(&path, text).expect("write a fixture file");
    }

    pub fn set_manifest(&self, name: &str, version: &str) {
        self.write(
            &format!("docs/llm-api-manifest/{name}"),
            &manifest(name, version),
        );
    }

    pub fn remove_manifests(&self) {
        for name in Self::MANIFESTS {
            fs::remove_file(self.root().join("docs/llm-api-manifest").join(name))
                .expect("remove a fixture manifest");
        }
    }

    pub fn set_readme(&self, version: &str) {
        self.write(
            "README.md",
            &format!(
                "# fixture\n\n## Status\n\nCurrent release: **v{version}** — beta.\n\n## Get it\n\nText.\n"
            ),
        );
    }

    /// Give the member package its own version instead of the workspace one.
    pub fn set_member_version(&self, version: &str) {
        self.write(
            "member/Cargo.toml",
            &format!(
                "[package]\nname = \"fixture-member\"\nversion = \"{version}\"\nedition = \"2021\"\n"
            ),
        );
    }

    /// Make the tree a git repository with every file in one commit, and tag that
    /// commit.
    pub fn git_tag(&self, tag: &str) {
        let git = |args: &[&str]| {
            let status = Command::new("git")
                .arg("-C")
                .arg(self.root())
                .args([
                    "-c",
                    "user.name=fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "-c",
                    "tag.gpgsign=false",
                ])
                .args(args)
                .env_remove("GIT_DIR")
                .env_remove("GIT_WORK_TREE")
                .env_remove("GIT_INDEX_FILE")
                .status()
                .expect("spawn git");
            assert!(status.success(), "git {args:?} failed");
        };
        git(&["init", "-q"]);
        git(&["add", "-A"]);
        git(&["commit", "-q", "-m", "fixture"]);
        git(&["tag", tag]);
    }
}

fn manifest(name: &str, version: &str) -> String {
    format!("lama: \"0.1\"\nlibrary:\n  name: {name}\n  version: \"{version}\"\n")
}
