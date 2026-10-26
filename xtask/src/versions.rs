//! Check that every package and every file recording the version agrees with the
//! workspace.
//!
//! The workspace `[workspace.package] version` in the root `Cargo.toml` is the one
//! source of the version. Every package must inherit it with
//! `version.workspace = true`, and the desktop app reads its in-app label from it at
//! compile time. The check reads the package list from `cargo metadata` and each
//! package's own `Cargo.toml`, so a package that sets a literal `version` is
//! reported even when the literal matches. Three
//! kinds of hand-edited text also state the version, and nothing else notices when
//! they drift:
//!
//! - `lama.yaml` `library.version`,
//! - each manifest under `docs/llm-api-manifest/` (`library.version`),
//! - the `README.md` `## Status` line `Current release: **vX.Y.Z**`.
//!
//! The manifests must equal the workspace version exactly, pre-release suffix
//! included: they describe the code in the tree, whatever version that is.
//!
//! **The README rule depends on the mode.** The README names the newest
//! *published* release, which a reader can download. On a release branch the
//! workspace already carries the version being prepared, and the README keeps
//! naming the previous release until the new one is published. Requiring equality
//! on every push would make the gate red for that whole period, or push the README
//! into announcing a release that does not exist yet. So in the default mode, run by
//! the `preflight` gate group, the README line must name a final release (no
//! pre-release suffix) that is not newer than the workspace version: it may lag
//! but never lead.
//!
//! The lag ends when the release is cut, so release mode (`--release`, run by
//! `cargo xtask release-gate` before the tag is created) removes it. The workspace
//! version must be final, the README line must equal it, and any `v*` tag already on
//! `HEAD` must be `v` followed by the workspace version. The working tree must also
//! be clean, so the files checked are the files in the commit the tag will name.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use yaml_rust2::YamlLoader;

use crate::manifests::MANIFEST_DIR;

/// Which rules apply.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Every push: the README may lag but never lead the workspace version.
    Preflight,
    /// Before a release tag: the README and any tag on `HEAD` must equal it, and
    /// the working tree must be clean.
    Release,
}

/// A `MAJOR.MINOR.PATCH` version with an optional pre-release suffix, from a strict
/// subset of SemVer 2.0: no build metadata, and each numeric part fits in a `u64`.
#[derive(Debug, PartialEq, Eq)]
pub struct Version {
    core: (u64, u64, u64),
    pre: Option<String>,
}

/// A SemVer numeric identifier: ASCII digits, and no leading zero unless it is `0`.
fn numeric_identifier(id: &str) -> Option<u64> {
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if id.len() > 1 && id.starts_with('0') {
        return None;
    }
    id.parse().ok()
}

/// A SemVer pre-release identifier: non-empty, `[0-9A-Za-z-]` only, and no leading
/// zero when it is all digits.
fn valid_pre_release_identifier(id: &str) -> bool {
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return false;
    }
    !(id.bytes().all(|b| b.is_ascii_digit()) && id.len() > 1 && id.starts_with('0'))
}

impl Version {
    /// Parse `MAJOR.MINOR.PATCH` or `MAJOR.MINOR.PATCH-PRE` under a strict subset of
    /// the SemVer 2.0 grammar. Build metadata (`+…`) is not used in this workspace and
    /// is refused: `+` is outside the alphabet of both numeric and pre-release
    /// identifiers. A numeric part too large for a `u64` is refused too.
    pub fn parse(text: &str) -> Option<Version> {
        let (core, pre) = match text.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (text, None),
        };
        let mut parts = core.split('.');
        let core = (
            numeric_identifier(parts.next()?)?,
            numeric_identifier(parts.next()?)?,
            numeric_identifier(parts.next()?)?,
        );
        if parts.next().is_some() {
            return None;
        }
        if let Some(pre) = pre
            && !pre.split('.').all(valid_pre_release_identifier)
        {
            return None;
        }
        Some(Version {
            core,
            pre: pre.map(str::to_owned),
        })
    }

    /// Whether a final release `self` comes after `other` in release order. A
    /// pre-release precedes the final release of the same `MAJOR.MINOR.PATCH`, so a
    /// final `0.37.2` is after `0.37.2-rc.1`.
    fn release_is_after(&self, other: &Version) -> bool {
        match self.core.cmp(&other.core) {
            Ordering::Greater => true,
            Ordering::Less => false,
            Ordering::Equal => other.pre.is_some(),
        }
    }
}

/// The `[workspace.package] version` value of a root `Cargo.toml`.
pub fn workspace_version(cargo_toml: &str) -> Result<String> {
    let section = cargo_toml
        .split("\n[workspace.package]")
        .nth(1)
        .context("Cargo.toml has no [workspace.package] table")?;
    section
        .lines()
        .take_while(|line| !line.starts_with('['))
        .find_map(|line| line.strip_prefix("version = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .map(str::to_owned)
        .context("[workspace.package] sets no version")
}

/// The `library.version` value of a LAMA manifest.
///
/// A file with any repeated mapping key, or with more than one YAML document, is
/// refused: the loader keeps only one of the repeats, so the version read might not
/// be the one a reader sees.
pub fn library_version(yaml: &str) -> Result<String> {
    if let Some(dup) = crate::manifests::duplicate_keys(yaml)?.first() {
        bail!(
            "duplicate key {:?} on line {}, so the version read may not be the one written",
            dup.key,
            dup.line
        );
    }
    let docs =
        YamlLoader::load_from_str(yaml).map_err(|e| anyhow::anyhow!("YAML parse failed: {e}"))?;
    if docs.len() != 1 {
        bail!("{} YAML documents, expected exactly one", docs.len());
    }
    let doc = docs.first().context("the file holds no YAML document")?;
    doc["library"]["version"]
        .as_str()
        .map(str::to_owned)
        .context("no string `library.version`")
}

/// The version in every `Current release: **vX.Y.Z**` line of the README's
/// `## Status` section. A line without the closing `**` yields the rest of the line,
/// which then fails to parse as a version.
pub fn readme_releases(readme: &str) -> Vec<String> {
    let Some(status) = readme.split("\n## Status\n").nth(1) else {
        return Vec::new();
    };
    let status = status.split("\n## ").next().unwrap_or_default();
    status
        .lines()
        .filter_map(|line| line.strip_prefix("Current release: **v"))
        .map(|rest| rest.split_once("**").map_or(rest, |(v, _)| v).to_owned())
        .collect()
}

/// The `(name, version)` of every package in `cargo metadata --no-deps` output.
pub fn package_versions(metadata_json: &str) -> Result<Vec<(String, String)>> {
    let metadata: serde_json::Value =
        serde_json::from_str(metadata_json).context("parsing cargo metadata output")?;
    let packages = metadata["packages"]
        .as_array()
        .context("cargo metadata output has no `packages` array")?;
    packages
        .iter()
        .map(|p| {
            let name = p["name"].as_str().context("a package without a name")?;
            let version = p["version"]
                .as_str()
                .with_context(|| format!("package {name} has no version"))?;
            Ok((name.to_owned(), version.to_owned()))
        })
        .collect()
}

/// Whether a package `Cargo.toml` takes its version from the workspace: parsed as
/// TOML, `package.version` must be the table `{ workspace = true }`, however it is
/// written. A file that does not parse does not inherit.
pub fn inherits_workspace_version(cargo_toml: &str) -> bool {
    let Ok(manifest) = cargo_toml.parse::<toml::Table>() else {
        return false;
    };
    manifest
        .get("package")
        .and_then(|package| package.get("version"))
        .and_then(toml::Value::as_table)
        .is_some_and(|version| {
            version.len() == 1 && version.get("workspace") == Some(&toml::Value::Boolean(true))
        })
}

/// Everything the version is compared against, read from one tree.
pub struct Surfaces<'a> {
    /// `(name, version)` of every workspace package.
    pub packages: &'a [(String, String)],
    /// The names of the packages whose `Cargo.toml` does not inherit the version.
    pub literal_versions: &'a [String],
    /// The text of `lama.yaml`.
    pub lama: &'a str,
    /// `(display name, text)` of every manifest under `docs/llm-api-manifest/`.
    pub manifests: &'a [(String, String)],
    /// The text of `README.md`.
    pub readme: &'a str,
    /// The `v*` tags on `HEAD`. Compared only in [`Mode::Release`].
    pub head_tags: &'a [String],
    /// `git status --porcelain` lines. Compared only in [`Mode::Release`].
    pub dirty: &'a [String],
}

/// Every disagreement between the workspace version and `surfaces`, one message
/// each.
///
/// Factored out of the file and subprocess reads so fixtures can drive every
/// branch: a check that only ever reads a tree expected to be clean cannot be shown
/// to fire.
pub fn version_problems(workspace: &str, surfaces: &Surfaces, mode: Mode) -> Result<Vec<String>> {
    let ws = Version::parse(workspace).with_context(|| {
        format!("workspace version {workspace:?} is not a SemVer MAJOR.MINOR.PATCH[-PRE] version")
    })?;
    let mut problems = Vec::new();

    for (name, version) in surfaces.packages {
        if version != workspace {
            problems.push(format!(
                "package {name}: version is {version:?}, the workspace version is {workspace:?}"
            ));
        }
    }
    for name in surfaces.literal_versions {
        problems.push(format!(
            "package {name}: Cargo.toml sets its own version, not `version.workspace = true`"
        ));
    }

    let named = std::iter::once(("lama.yaml", surfaces.lama)).chain(
        surfaces
            .manifests
            .iter()
            .map(|(name, text)| (name.as_str(), text.as_str())),
    );
    for (name, text) in named {
        match library_version(text) {
            Ok(v) if v == workspace => {}
            Ok(v) => problems.push(format!(
                "{name}: library.version is {v:?}, the workspace version is {workspace:?}"
            )),
            Err(e) => problems.push(format!("{name}: {e:#}")),
        }
    }

    let status_sections = surfaces.readme.matches("\n## Status\n").count();
    if status_sections > 1 {
        problems.push(format!(
            "README.md: {status_sections} `## Status` sections, expected one"
        ));
    }

    match readme_releases(surfaces.readme).as_slice() {
        [] => problems
            .push("README.md: no `Current release: **vX.Y.Z**` line under `## Status`".to_owned()),
        [text] => match Version::parse(text) {
            Some(readme) if readme.pre.is_none() => match mode {
                Mode::Preflight => {
                    if readme.release_is_after(&ws) {
                        problems.push(format!(
                            "README.md: the current release v{text} is newer than the workspace version {workspace}"
                        ));
                    }
                }
                Mode::Release => {
                    if text != workspace {
                        problems.push(format!(
                            "README.md: the current release is v{text}, a release of the workspace version names v{workspace}"
                        ));
                    }
                }
            },
            _ => problems.push(format!(
                "README.md: the current release v{text} is not a final MAJOR.MINOR.PATCH release"
            )),
        },
        many => problems.push(format!(
            "README.md: {} `Current release:` lines under `## Status`, expected one",
            many.len()
        )),
    }

    if mode == Mode::Release {
        if ws.pre.is_some() {
            problems.push(format!(
                "Cargo.toml: a release needs a final workspace version, not the pre-release {workspace}"
            ));
        }
        let expected = format!("v{workspace}");
        for tag in surfaces.head_tags {
            if *tag != expected {
                problems.push(format!(
                    "git: HEAD carries the tag {tag}, the workspace version names {expected}"
                ));
            }
        }
        if let Some(first) = surfaces.dirty.first() {
            problems.push(format!(
                "git: the working tree has {} uncommitted change(s), the first `{first}`",
                surfaces.dirty.len()
            ));
        }
    }

    Ok(problems)
}

/// The workspace packages, as `cargo metadata` and their own manifests report them.
struct Packages {
    /// `(name, version)` of every package.
    versions: Vec<(String, String)>,
    /// The names of the packages whose `Cargo.toml` does not inherit the version.
    literal: Vec<String>,
}

/// Run `cargo metadata --no-deps` on the workspace at `repo_root`, and read each
/// package's `Cargo.toml`.
fn read_packages(repo_root: &Path) -> Result<Packages> {
    let output = Command::new(crate::cargo_bin())
        .args([
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(repo_root.join("Cargo.toml"))
        .output()
        .context("spawn cargo metadata")?;
    if !output.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let metadata = String::from_utf8_lossy(&output.stdout);
    let packages = package_versions(&metadata)?;
    // No packages would compare nothing and report clean.
    if packages.is_empty() {
        bail!("cargo metadata listed no packages — the check examined nothing");
    }
    let mut literal = Vec::new();
    for (name, manifest) in package_manifest_paths(&metadata)? {
        let text = std::fs::read_to_string(&manifest)
            .with_context(|| format!("reading {}", manifest.display()))?;
        if !inherits_workspace_version(&text) {
            literal.push(name);
        }
    }
    Ok(Packages {
        versions: packages,
        literal,
    })
}

/// The `(name, manifest_path)` of every package in `cargo metadata --no-deps` output.
pub fn package_manifest_paths(metadata_json: &str) -> Result<Vec<(String, PathBuf)>> {
    let metadata: serde_json::Value =
        serde_json::from_str(metadata_json).context("parsing cargo metadata output")?;
    let packages = metadata["packages"]
        .as_array()
        .context("cargo metadata output has no `packages` array")?;
    packages
        .iter()
        .map(|p| {
            let name = p["name"].as_str().context("a package without a name")?;
            let path = p["manifest_path"]
                .as_str()
                .with_context(|| format!("package {name} has no manifest_path"))?;
            Ok((name.to_owned(), PathBuf::from(path)))
        })
        .collect()
}

/// Run `git` at `repo_root` and return its stdout lines.
fn git_lines(repo_root: &Path, args: &[&str]) -> Result<Vec<String>> {
    let mut cmd = Command::new("git");
    // Read the repository at `repo_root`, not one an enclosing git process
    // named in the environment.
    crate::git_env::without_repo_env(&mut cmd);
    let output = cmd
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .with_context(|| format!("spawn git {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "git {} failed (release mode needs a git checkout): {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .collect())
}

/// Read the workspace version and every surface that states it, and fail naming
/// each disagreement.
pub fn check_versions(repo_root: &Path, mode: Mode) -> Result<()> {
    let read = |path: &Path| {
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
    };
    let workspace = workspace_version(&read(&repo_root.join("Cargo.toml"))?)?;

    let dir = repo_root.join(MANIFEST_DIR);
    let paths = yaml_paths(
        std::fs::read_dir(&dir)
            .with_context(|| format!("reading {}", dir.display()))?
            .map(|entry| entry.map(|e| e.path())),
    )?;
    // An empty directory would compare nothing and report clean.
    if paths.is_empty() {
        bail!(
            "no manifests found under {} — the check examined nothing",
            dir.display()
        );
    }
    let manifests = paths
        .iter()
        .map(|p| Ok((format!("{MANIFEST_DIR}/{}", file_name(p)), read(p)?)))
        .collect::<Result<Vec<_>>>()?;

    let Packages {
        versions: packages,
        literal: literal_versions,
    } = read_packages(repo_root)?;
    let (head_tags, dirty) = match mode {
        Mode::Preflight => (Vec::new(), Vec::new()),
        Mode::Release => (
            git_lines(repo_root, &["tag", "--points-at", "HEAD", "--list", "v*"])?,
            git_lines(repo_root, &["status", "--porcelain"])?,
        ),
    };
    let lama = read(&repo_root.join("lama.yaml"))?;
    let readme = read(&repo_root.join("README.md"))?;
    let surfaces = Surfaces {
        packages: &packages,
        literal_versions: &literal_versions,
        lama: &lama,
        manifests: &manifests,
        readme: &readme,
        head_tags: &head_tags,
        dirty: &dirty,
    };

    let problems = version_problems(&workspace, &surfaces, mode)?;
    if !problems.is_empty() {
        for p in &problems {
            eprintln!("{p}");
        }
        bail!(
            "check-versions: {} surface(s) disagree with the workspace version {workspace}",
            problems.len()
        );
    }
    println!(
        "check-versions{}: {} package(s), lama.yaml, {} manifest(s) and README.md agree with {workspace}",
        if mode == Mode::Release {
            " --release"
        } else {
            ""
        },
        packages.len(),
        manifests.len()
    );
    Ok(())
}

/// The `.yaml`/`.yml` paths among directory `entries`, sorted. An entry that could
/// not be read is an error, since skipping it could leave a manifest unchecked.
fn yaml_paths(entries: impl Iterator<Item = std::io::Result<PathBuf>>) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in entries {
        let path = entry.context("reading a manifest directory entry")?;
        if path.extension().is_some_and(|x| x == "yaml" || x == "yml") {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version_fixture::Tree;

    fn manifest(version: &str) -> String {
        format!("lama: \"0.1\"\nlibrary:\n  name: crate\n  version: \"{version}\"\n")
    }

    fn readme(version: &str) -> String {
        format!(
            "# daemonseed\n\nIntro.\n\n## Status\n\nCurrent release: **v{version}** — beta.\n\n## Get it\n\nText.\n"
        )
    }

    /// Problems for a tree whose surfaces carry the given versions, with three
    /// manifests in the order `first`, `middle`, `last`.
    struct Case<'a> {
        ws: &'a str,
        package: &'a str,
        lama: &'a str,
        api: [&'a str; 3],
        readme: &'a str,
        tags: &'a [&'a str],
    }

    impl<'a> Case<'a> {
        fn clean(ws: &'a str) -> Self {
            Case {
                ws,
                package: ws,
                lama: ws,
                api: [ws; 3],
                readme: ws,
                tags: &[],
            }
        }

        fn problems(&self, mode: Mode) -> Vec<String> {
            let packages = [
                ("pkg-a".to_owned(), self.ws.to_owned()),
                ("pkg-b".to_owned(), self.package.to_owned()),
            ];
            let manifests: Vec<(String, String)> = ["first", "middle", "last"]
                .iter()
                .zip(self.api)
                .map(|(name, v)| (format!("{name}-api.yaml"), manifest(v)))
                .collect();
            let tags: Vec<String> = self.tags.iter().map(|t| (*t).to_owned()).collect();
            let lama = manifest(self.lama);
            let readme = readme(self.readme);
            version_problems(
                self.ws,
                &Surfaces {
                    packages: &packages,
                    literal_versions: &[],
                    lama: &lama,
                    manifests: &manifests,
                    readme: &readme,
                    head_tags: &tags,
                    dirty: &[],
                },
                mode,
            )
            .expect("the workspace version parses")
        }
    }

    /// Exactly one problem, and it starts with `prefix`.
    fn one(found: Vec<String>, prefix: &str) {
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].starts_with(prefix), "{found:?}");
    }

    #[test]
    fn every_surface_agreeing_is_clean() {
        assert!(Case::clean("0.37.2").problems(Mode::Preflight).is_empty());
        assert!(Case::clean("0.37.2").problems(Mode::Release).is_empty());
    }

    #[test]
    fn a_package_with_its_own_version_is_reported() {
        let case = Case {
            package: "0.1.0",
            ..Case::clean("0.37.2")
        };
        one(case.problems(Mode::Preflight), "package pkg-b:");
    }

    /// A package whose `Cargo.toml` sets a literal version is reported even when the
    /// literal equals the workspace version.
    #[test]
    fn a_package_with_a_matching_literal_version_is_reported() {
        let found = version_problems(
            "0.37.2",
            &Surfaces {
                packages: &[("pkg-a".to_owned(), "0.37.2".to_owned())],
                literal_versions: &["pkg-a".to_owned()],
                lama: &manifest("0.37.2"),
                manifests: &[],
                readme: &readme("0.37.2"),
                head_tags: &[],
                dirty: &[],
            },
            Mode::Preflight,
        )
        .unwrap();
        one(found, "package pkg-a:");
    }

    #[test]
    fn inheritance_is_read_from_the_package_table() {
        for inherits in [
            "[package]\nname = \"a\"\nversion.workspace = true\n",
            "[package]\nname = \"a\"\nversion = { workspace = true }\n",
        ] {
            assert!(inherits_workspace_version(inherits), "{inherits:?}");
        }
        for literal in [
            "[package]\nname = \"a\"\nversion = \"0.37.2\"\n",
            "[package]\nname = \"a\"\n\n[dependencies]\nversion.workspace = true\n",
            "[package]\nname = \"a\"\nedition.workspace = true\n",
            "[package]\nname = \"a\"\nversion = { workspace = false }\n",
        ] {
            assert!(!inherits_workspace_version(literal), "{literal:?}");
        }
    }

    /// The text `version.workspace = true` inside a string value is not the key.
    #[test]
    fn inheritance_text_inside_a_description_is_not_inheritance() {
        let manifest = "[package]\nname = \"a\"\nversion = \"0.37.2\"\n\
                        description = \"\"\"\nA crate.\nversion.workspace = true\n\"\"\"\n";
        assert!(!inherits_workspace_version(manifest));
    }

    #[test]
    fn a_second_status_section_is_reported() {
        let readme = "# d\n\n## Status\n\nCurrent release: **v0.37.2**\n\n\
                      ## Status\n\nCurrent release: **v0.37.2**\n";
        let found = version_problems(
            "0.37.2",
            &Surfaces {
                packages: &[],
                literal_versions: &[],
                lama: &manifest("0.37.2"),
                manifests: &[],
                readme,
                head_tags: &[],
                dirty: &[],
            },
            Mode::Preflight,
        )
        .unwrap();
        one(found, "README.md: 2 `## Status` sections");
    }

    /// In release mode the working tree must be clean; preflight does not look.
    #[test]
    fn a_dirty_tree_is_reported_in_release_mode_only() {
        let dirty = ["?? notes.txt".to_owned()];
        let packages = [("pkg-a".to_owned(), "0.37.2".to_owned())];
        let lama = manifest("0.37.2");
        let readme = readme("0.37.2");
        let surfaces = Surfaces {
            packages: &packages,
            literal_versions: &[],
            lama: &lama,
            manifests: &[],
            readme: &readme,
            head_tags: &[],
            dirty: &dirty,
        };
        one(
            version_problems("0.37.2", &surfaces, Mode::Release).unwrap(),
            "git:",
        );
        assert!(
            version_problems("0.37.2", &surfaces, Mode::Preflight)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_disagreeing_lama_yaml_is_reported() {
        let case = Case {
            lama: "0.37.1",
            ..Case::clean("0.37.2")
        };
        one(case.problems(Mode::Preflight), "lama.yaml:");
    }

    #[test]
    fn a_disagreement_in_any_manifest_position_is_reported() {
        for (i, name) in ["first", "middle", "last"].iter().enumerate() {
            let mut api = ["0.37.2"; 3];
            api[i] = "0.1.0";
            let case = Case {
                api,
                ..Case::clean("0.37.2")
            };
            one(case.problems(Mode::Preflight), &format!("{name}-api.yaml:"));
        }
    }

    /// The manifests describe the tree, so a pre-release workspace needs the suffix
    /// in them too.
    #[test]
    fn a_manifest_missing_the_pre_release_suffix_is_reported() {
        let case = Case {
            api: ["0.37.2-rc.1", "0.37.2-rc.1", "0.37.2"],
            readme: "0.37.1",
            ..Case::clean("0.37.2-rc.1")
        };
        one(case.problems(Mode::Preflight), "last-api.yaml:");
    }

    #[test]
    fn a_readme_a_minor_release_ahead_is_reported() {
        let case = Case {
            readme: "0.38.0",
            ..Case::clean("0.37.2")
        };
        one(case.problems(Mode::Preflight), "README.md:");
    }

    #[test]
    fn a_readme_a_patch_release_ahead_is_reported() {
        let case = Case {
            readme: "0.37.3",
            ..Case::clean("0.37.2")
        };
        one(case.problems(Mode::Preflight), "README.md:");
    }

    /// A pre-release precedes its final release, so a README already naming the
    /// final version is ahead of an rc workspace.
    #[test]
    fn a_readme_naming_the_final_release_of_an_rc_workspace_is_reported() {
        let case = Case {
            readme: "0.37.2",
            ..Case::clean("0.37.2-rc.1")
        };
        one(case.problems(Mode::Preflight), "README.md:");
    }

    #[test]
    fn a_readme_naming_a_pre_release_is_reported() {
        let case = Case {
            readme: "0.37.2-rc.1",
            ..Case::clean("0.37.2")
        };
        one(case.problems(Mode::Preflight), "README.md:");
    }

    /// On a release branch the README still names the previous published release.
    #[test]
    fn a_readme_lagging_the_workspace_is_accepted_in_preflight() {
        let lagging = Case {
            readme: "0.37.1",
            ..Case::clean("0.37.2")
        };
        assert!(lagging.problems(Mode::Preflight).is_empty());
        let rc = Case {
            readme: "0.37.1",
            ..Case::clean("0.37.2-rc.1")
        };
        assert!(rc.problems(Mode::Preflight).is_empty());
    }

    /// A release is cut once the README names it.
    #[test]
    fn a_readme_lagging_the_workspace_is_reported_in_release_mode() {
        let case = Case {
            readme: "0.37.1",
            ..Case::clean("0.37.2")
        };
        one(case.problems(Mode::Release), "README.md:");
    }

    #[test]
    fn a_pre_release_workspace_is_reported_in_release_mode() {
        let case = Case {
            readme: "0.37.1",
            ..Case::clean("0.37.2-rc.1")
        };
        let found = case.problems(Mode::Release);
        assert!(
            found.iter().any(|p| p.starts_with("Cargo.toml:")),
            "{found:?}"
        );
    }

    #[test]
    fn a_head_tag_naming_another_version_is_reported_in_release_mode() {
        let case = Case {
            tags: &["v0.37.3"],
            ..Case::clean("0.37.2")
        };
        one(case.problems(Mode::Release), "git:");
        let matching = Case {
            tags: &["v0.37.2"],
            ..Case::clean("0.37.2")
        };
        assert!(matching.problems(Mode::Release).is_empty());
    }

    /// Tags are a release-time property; a tag on an earlier commit checked out for a
    /// preflight run is not this check's business.
    #[test]
    fn head_tags_are_not_compared_in_preflight() {
        let case = Case {
            tags: &["v0.1.0"],
            ..Case::clean("0.37.2")
        };
        assert!(case.problems(Mode::Preflight).is_empty());
    }

    #[test]
    fn a_readme_without_a_status_line_is_reported() {
        let found = version_problems(
            "0.37.2",
            &Surfaces {
                packages: &[],
                literal_versions: &[],
                lama: &manifest("0.37.2"),
                manifests: &[],
                readme: "# daemonseed\n\n## Status\n\nBeta.\n",
                head_tags: &[],
                dirty: &[],
            },
            Mode::Preflight,
        )
        .unwrap();
        one(found, "README.md:");
    }

    /// A release line under another heading is not the Status line.
    #[test]
    fn a_release_line_outside_status_is_not_read() {
        let readme = "# d\n\n## Status\n\nBeta.\n\n## History\n\nCurrent release: **v0.37.2**\n";
        assert!(readme_releases(readme).is_empty());
        let before = "# d\n\nCurrent release: **v0.37.2**\n\n## Status\n\nBeta.\n";
        assert!(readme_releases(before).is_empty());
    }

    /// A second release line, even one that agrees, is ambiguous for a reader.
    #[test]
    fn two_release_lines_in_status_are_reported_in_both_modes() {
        for second in ["0.37.2", "0.38.0"] {
            let readme = format!(
                "# d\n\n## Status\n\nCurrent release: **v0.37.2** — beta.\n\
                 Current release: **v{second}**\n\n## Get it\n"
            );
            for mode in [Mode::Preflight, Mode::Release] {
                let found = version_problems(
                    "0.37.2",
                    &Surfaces {
                        packages: &[],
                        literal_versions: &[],
                        lama: &manifest("0.37.2"),
                        manifests: &[],
                        readme: &readme,
                        head_tags: &[],
                        dirty: &[],
                    },
                    mode,
                )
                .unwrap();
                one(found, "README.md:");
            }
        }
    }

    #[test]
    fn a_second_yaml_document_is_refused() {
        let yaml = format!("{}---\n{}", manifest("0.37.2"), manifest("0.1.0"));
        let err = library_version(&yaml).unwrap_err();
        assert!(err.to_string().contains("2 YAML documents"), "{err:#}");
    }

    #[test]
    fn a_duplicate_version_key_is_refused() {
        let yaml = "library:\n  name: d\n  version: \"0.37.2\"\n  version: \"0.1.0\"\n";
        let err = library_version(yaml).unwrap_err();
        assert!(
            err.to_string().contains("duplicate key \"version\""),
            "{err:#}"
        );
        let yaml = "library:\n  version: \"0.37.2\"\nlibrary:\n  version: \"0.1.0\"\n";
        assert!(library_version(yaml).is_err());
    }

    #[test]
    fn an_unreadable_directory_entry_is_an_error() {
        let entries = vec![
            Ok(PathBuf::from("a-api.yaml")),
            Err(std::io::Error::other("entry unreadable")),
            Ok(PathBuf::from("b-api.yaml")),
        ];
        assert!(yaml_paths(entries.into_iter()).is_err());
        let clean = vec![
            Ok(PathBuf::from("z.yaml")),
            Ok(PathBuf::from("notes.txt")),
            Ok(PathBuf::from("a.yml")),
        ];
        assert_eq!(
            yaml_paths(clean.into_iter()).unwrap(),
            [PathBuf::from("a.yml"), PathBuf::from("z.yaml")]
        );
    }

    #[test]
    fn a_manifest_without_a_library_version_is_reported() {
        let found = version_problems(
            "0.37.2",
            &Surfaces {
                packages: &[],
                literal_versions: &[],
                lama: "lama: \"0.1\"\nlibrary:\n  name: daemonseed\n",
                manifests: &[],
                readme: &readme("0.37.2"),
                head_tags: &[],
                dirty: &[],
            },
            Mode::Preflight,
        )
        .unwrap();
        one(found, "lama.yaml:");
    }

    #[test]
    fn the_workspace_version_is_read_from_its_own_table() {
        let toml = "[workspace]\nmembers = []\n\n[package]\nversion = \"9.9.9\"\n\n\
                    [workspace.package]\nversion = \"0.37.2\"\nedition = \"2024\"\n";
        assert_eq!(workspace_version(toml).unwrap(), "0.37.2");
    }

    /// A `version` key in a later table is not the workspace version.
    #[test]
    fn a_version_in_a_later_table_is_not_the_workspace_version() {
        let toml = "[workspace]\n\n[workspace.package]\nedition = \"2024\"\n\n\
                    [workspace.dependencies]\nversion = \"1.0.0\"\n";
        assert!(workspace_version(toml).is_err());
    }

    #[test]
    fn package_versions_are_read_from_cargo_metadata() {
        let json = r#"{"packages":[{"name":"a","version":"0.37.2"},{"name":"b","version":"0.1.0"}],"workspace_root":"/w"}"#;
        assert_eq!(
            package_versions(json).unwrap(),
            [
                ("a".to_owned(), "0.37.2".to_owned()),
                ("b".to_owned(), "0.1.0".to_owned())
            ]
        );
        assert!(package_versions(r#"{"workspace_root":"/w"}"#).is_err());
    }

    #[test]
    fn releases_and_pre_releases_parse() {
        for good in [
            "0.37.2",
            "0.37.2-rc.1",
            "0.37.2-rc.0",
            "0.37.2-0a",
            "1.0.0-x-y.7",
        ] {
            assert!(Version::parse(good).is_some(), "{good:?} must parse");
        }
    }

    #[test]
    fn malformed_cores_are_refused() {
        for bad in ["0.37", "0.37.2.1", "v0.37.2", "0.x.2", "", "0.37.2-"] {
            assert!(Version::parse(bad).is_none(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn build_metadata_is_refused() {
        for bad in ["0.37.2+build.1", "0.37.2-rc.1+build"] {
            assert!(Version::parse(bad).is_none(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn leading_zeros_in_the_core_are_refused() {
        for bad in ["01.37.2", "0.037.2", "0.37.02"] {
            assert!(Version::parse(bad).is_none(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn empty_pre_release_identifiers_are_refused() {
        for bad in ["0.37.2-rc..1", "0.37.2-rc.", "0.37.2-.rc"] {
            assert!(Version::parse(bad).is_none(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn pre_release_identifiers_outside_the_alphabet_are_refused() {
        for bad in ["0.37.2-rc_1", "0.37.2-rc 1", "0.37.2-rc.é"] {
            assert!(Version::parse(bad).is_none(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn numeric_pre_release_identifiers_with_a_leading_zero_are_refused() {
        assert!(Version::parse("0.37.2-rc.01").is_none());
    }

    // ── whole-tree checks ────────────────────────────────────────────

    #[test]
    fn a_clean_tree_passes() {
        let tree = Tree::new("0.37.2");
        check_versions(tree.root(), Mode::Preflight).expect("a clean tree passes");
    }

    /// Each manifest position in turn, including the first and the last in sorted
    /// order, so a walk that drops either end is caught.
    #[test]
    fn a_tree_with_any_one_manifest_drifted_fails() {
        for name in Tree::MANIFESTS {
            let tree = Tree::new("0.37.2");
            tree.set_manifest(name, "0.1.0");
            let err = check_versions(tree.root(), Mode::Preflight)
                .expect_err(&format!("{name} drifted must fail"));
            assert!(err.to_string().contains("1 surface(s)"), "{name}: {err:#}");
        }
    }

    #[test]
    fn a_tree_with_a_package_off_the_workspace_version_fails() {
        let tree = Tree::new("0.37.2");
        tree.set_member_version("0.1.0");
        let err = check_versions(tree.root(), Mode::Preflight).unwrap_err();
        // The version differs, and it is a literal rather than inherited.
        assert!(err.to_string().contains("2 surface(s)"), "{err:#}");
    }

    #[test]
    fn an_empty_manifest_directory_fails() {
        let tree = Tree::new("0.37.2");
        tree.remove_manifests();
        let err = check_versions(tree.root(), Mode::Preflight).unwrap_err();
        assert!(err.to_string().contains("examined nothing"), "{err:#}");
    }

    #[test]
    fn release_mode_on_a_tree_requires_the_readme_and_tag_to_match() {
        let tree = Tree::new("0.37.2");
        tree.git_tag("v0.37.2");
        check_versions(tree.root(), Mode::Release).expect("readme and tag match");

        let lagging = Tree::new("0.37.2");
        lagging.set_readme("0.37.1");
        lagging.git_tag("v0.37.2");
        check_versions(lagging.root(), Mode::Preflight).expect("preflight allows the lag");
        assert!(check_versions(lagging.root(), Mode::Release).is_err());

        let mistagged = Tree::new("0.37.2");
        mistagged.git_tag("v0.37.3");
        assert!(check_versions(mistagged.root(), Mode::Release).is_err());
    }

    #[test]
    fn release_mode_on_a_tree_refuses_uncommitted_changes() {
        let tree = Tree::new("0.37.2");
        tree.git_tag("v0.37.2");
        check_versions(tree.root(), Mode::Release).expect("a clean tagged tree passes");
        std::fs::write(tree.root().join("notes.txt"), "uncommitted").unwrap();
        let err = check_versions(tree.root(), Mode::Release).unwrap_err();
        assert!(err.to_string().contains("1 surface(s)"), "{err:#}");
    }

    #[test]
    fn a_tree_with_a_matching_literal_member_version_fails() {
        let tree = Tree::new("0.37.2");
        tree.set_member_version("0.37.2");
        let err = check_versions(tree.root(), Mode::Preflight).unwrap_err();
        assert!(err.to_string().contains("1 surface(s)"), "{err:#}");
    }
}
