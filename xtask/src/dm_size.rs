//! Hold the direct-messaging layer under its line ceiling, and require every
//! module in it to name the founding claim it serves.
//!
//! `docs/design/direct-messaging.md` § Size rule sets two conditions on the
//! layer: it is at most [`DEFAULT_CEILING`] lines of Rust including tests, and
//! every component names the founding claim it serves. Both are properties of
//! the tree as a whole, which no per-crate lint or test can see — a module is
//! added to one crate, the total is read from neither, and the ceiling is
//! crossed without any step going red.
//!
//! A module belongs to the layer when its leading `//!` doc block carries a
//! line naming a founding claim in the form `Serves FC<n>`, one or more of
//! them. The header is the whole of the test: it is written by whoever adds
//! the module, in the file the module lives in, and it states which claim the
//! code exists to serve.
//!
//! Modules named in [`OUTSIDE_LAYER`] are counted and printed as a separate
//! total, so the layer figure measures the layer and the run still reports
//! every line under the two directories.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use walkdir::WalkDir;

/// The directories the layer is built from, relative to the repository root.
pub const LAYER_DIRS: &[&str] = &[
    "crates/daemonseed-core/src/dm",
    "crates/daemonseed-veilid-net/src/dm",
];

/// The layer's line ceiling, from `docs/design/direct-messaging.md` § Size
/// rule. [`CEILING_ENV`] overrides it for a single run.
pub const DEFAULT_CEILING: usize = 6000;

/// The environment variable a run reads its ceiling from.
pub const CEILING_ENV: &str = "DM_SIZE_CEILING";

/// The modules under [`LAYER_DIRS`] counted outside the layer, as paths
/// relative to the repository root.
///
/// An entry is removed when that module gains a founding-claim header or is
/// deleted. An entry naming no file is an error.
pub const OUTSIDE_LAYER: &[&str] = &[
    "crates/daemonseed-core/src/dm/ack.rs",
    "crates/daemonseed-core/src/dm/ack_budget.rs",
    "crates/daemonseed-core/src/dm/ack_cadence.rs",
    "crates/daemonseed-core/src/dm/ack_record.rs",
    "crates/daemonseed-core/src/dm/admission.rs",
    "crates/daemonseed-core/src/dm/block_list.rs",
    "crates/daemonseed-core/src/dm/collect.rs",
    "crates/daemonseed-core/src/dm/contact_cache.rs",
    "crates/daemonseed-core/src/dm/domain.rs",
    "crates/daemonseed-core/src/dm/doorbell.rs",
    "crates/daemonseed-core/src/dm/firstcontact.rs",
    "crates/daemonseed-core/src/dm/frame.rs",
    "crates/daemonseed-core/src/dm/keyrec.rs",
    "crates/daemonseed-core/src/dm/mod.rs",
    "crates/daemonseed-core/src/dm/outbox.rs",
    "crates/daemonseed-core/src/dm/paging.rs",
    "crates/daemonseed-core/src/dm/persist.rs",
    "crates/daemonseed-core/src/dm/pow.rs",
    "crates/daemonseed-core/src/dm/provisional.rs",
    "crates/daemonseed-core/src/dm/ratchet.rs",
    "crates/daemonseed-core/src/dm/reest.rs",
    "crates/daemonseed-core/src/dm/resume.rs",
    "crates/daemonseed-core/src/dm/spent_store.rs",
    "crates/daemonseed-core/src/dm/token.rs",
    "crates/daemonseed-veilid-net/src/dm/driver.rs",
    "crates/daemonseed-veilid-net/src/dm/machine.rs",
    "crates/daemonseed-veilid-net/src/dm/mock.rs",
    "crates/daemonseed-veilid-net/src/dm/mod.rs",
    "crates/daemonseed-veilid-net/src/dm/seam.rs",
    "crates/daemonseed-veilid-net/src/dm/types.rs",
];

/// Which of the two totals a module's lines are added to.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Set {
    /// The module carries a founding-claim header and counts against the
    /// ceiling.
    Layer,
    /// The module is named in the outside list and counts against neither.
    Outside,
}

impl Set {
    /// The set's word in the per-module output line.
    pub fn as_str(self) -> &'static str {
        match self {
            Set::Layer => "layer",
            Set::Outside => "outside",
        }
    }
}

/// One counted module: its path relative to the repository root, its line
/// count, and the set it is in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Module {
    pub path: String,
    pub lines: usize,
    pub set: Set,
}

/// What one run measured: every module in path order, and the two totals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub modules: Vec<Module>,
    pub layer_total: usize,
    pub outside_total: usize,
}

/// The ceiling this run gates on: [`CEILING_ENV`] where it is set,
/// [`DEFAULT_CEILING`] where it is not.
///
/// A value that is set but is not a line count is an error, whether it is not
/// a number or not valid UTF-8. Falling back to the default on either would
/// gate on a figure the caller did not ask for.
pub fn ceiling_from_env() -> Result<usize> {
    ceiling_from(std::env::var_os(CEILING_ENV).as_deref())
}

/// [`ceiling_from_env`] over a supplied value, so every case it must reject can
/// be driven from a fixture rather than from the process environment.
pub fn ceiling_from(value: Option<&OsStr>) -> Result<usize> {
    let Some(raw) = value else {
        return Ok(DEFAULT_CEILING);
    };
    let text = raw
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("{CEILING_ENV}={raw:?} is not valid UTF-8"))?;
    text.trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("{CEILING_ENV}={text:?} is not a line count: {e}"))
}

/// Whether a source file's leading `//!` doc block names a founding claim.
///
/// Only the leading block counts: a `Serves FC1` further down the file is
/// prose about some other item, not the module's own statement of what it
/// serves.
pub fn serves_founding_claim(content: &str) -> bool {
    let mut header = String::new();
    for line in content.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("//!") {
            header.push_str(rest);
            header.push('\n');
        } else if trimmed.is_empty() {
            continue;
        } else {
            break;
        }
    }
    header.match_indices("Serves FC").any(|(at, found)| {
        header[at + found.len()..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit())
    })
}

/// A module's line count: every line of the file, tests included.
pub fn line_count(content: &str) -> usize {
    content.lines().count()
}

/// Every `.rs` file under `dirs`, in path order, as paths relative to `repo`.
///
/// A directory that is not there, and one that holds no module, are both
/// failures rather than an empty result: the paths have moved and every figure
/// the check would then report is a figure about nothing. Checked per entry of
/// `dirs`, so one directory's modules cannot cover for another's absence.
fn modules_under(repo: &Path, dirs: &[&str]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for dir in dirs {
        let root = repo.join(dir);
        if !root.is_dir() {
            bail!(
                "dm-size: {} is not a directory — the paths have moved and this check \
                 would pass on nothing. That is a failure, not a clean result.",
                root.display()
            );
        }
        let before = out.len();
        for entry in WalkDir::new(&root) {
            let entry =
                entry.map_err(|e| anyhow::anyhow!("dm-size: walk {}: {e}", root.display()))?;
            let path = entry.path();
            if !path.is_file() || path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            out.push(path.strip_prefix(repo).unwrap_or(path).to_path_buf());
        }
        if out.len() == before {
            bail!(
                "dm-size: found no .rs file under {} — the paths have moved and this check \
                 would pass on nothing. That is a failure, not a clean result.",
                root.display()
            );
        }
    }
    out.sort();
    Ok(out)
}

/// Count every module under `dirs`, splitting them by header and `outside`.
///
/// Refuses on any shape defect rather than reporting a figure built on it: an
/// `outside` entry that names no file, a module on neither the list nor the
/// headered side, which would leave lines counted in no total at all, and a
/// listed module that names a founding claim, whose entry is now stale.
pub fn measure(repo: &Path, dirs: &[&str], outside: &[&str]) -> Result<Report> {
    let missing: Vec<&str> = outside
        .iter()
        .copied()
        .filter(|entry| !repo.join(entry).is_file())
        .collect();
    if !missing.is_empty() {
        bail!(
            "dm-size: the outside-layer list names {} file(s) that do not exist:\n  {}\n\
             An entry is removed when its module gains a founding-claim header or is deleted.",
            missing.len(),
            missing.join("\n  ")
        );
    }

    let mut modules = Vec::new();
    let mut unheadered: Vec<String> = Vec::new();
    let mut stale: Vec<String> = Vec::new();
    let mut layer_total = 0;
    let mut outside_total = 0;
    for rel in modules_under(repo, dirs)? {
        let path = rel.to_string_lossy().replace('\\', "/");
        let content = std::fs::read_to_string(repo.join(&rel))
            .map_err(|e| anyhow::anyhow!("dm-size: read {path}: {e}"))?;
        let lines = line_count(&content);
        let headered = serves_founding_claim(&content);
        let set = if outside.contains(&path.as_str()) {
            if headered {
                stale.push(path.clone());
                continue;
            }
            outside_total += lines;
            Set::Outside
        } else if headered {
            layer_total += lines;
            Set::Layer
        } else {
            unheadered.push(path.clone());
            continue;
        };
        modules.push(Module { path, lines, set });
    }

    if !stale.is_empty() {
        bail!(
            "dm-size: {} module(s) name a founding claim and are still on the outside-layer list:\n  {}\n\
             Remove the list entry so the module counts in the layer.",
            stale.len(),
            stale.join("\n  ")
        );
    }

    if !unheadered.is_empty() {
        bail!(
            "dm-size: {} module(s) name no founding claim and are not on the outside-layer list:\n  {}\n\
             Add a `Serves FC<n>` line to the module's leading `//!` block naming the claim it serves.",
            unheadered.len(),
            unheadered.join("\n  ")
        );
    }

    Ok(Report {
        modules,
        layer_total,
        outside_total,
    })
}

/// Measure the layer, print what it found, and refuse above `ceiling`.
pub fn check(repo: &Path, dirs: &[&str], outside: &[&str], ceiling: usize) -> Result<()> {
    let report = measure(repo, dirs, outside)?;
    for module in &report.modules {
        println!(
            "{:>6}  {}  {}",
            module.lines,
            module.set.as_str(),
            module.path
        );
    }
    println!(
        "dm-size: layer {} line(s), outside {} line(s), ceiling {}",
        report.layer_total, report.outside_total, ceiling
    );
    if report.layer_total > ceiling {
        bail!(
            "dm-size: the layer is {} line(s), above its ceiling of {}. \
             Remove lines from the layer or move a component out of it.",
            report.layer_total,
            ceiling
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixture tree under the system temp directory, unique per test, removed
    /// when the test ends.
    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "ds-dm-size-{name}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::remove_dir_all(&root).ok();
            std::fs::create_dir_all(root.join("layer")).unwrap();
            Fixture { root }
        }

        /// Write `content` to `layer/<name>` and return the relative path the
        /// report and the outside list use.
        fn write(&self, name: &str, content: &str) -> String {
            self.write_in("layer", name, content)
        }

        /// Write `content` to `<dir>/<name>`, creating `dir`, and return the
        /// relative path the report and the outside list use.
        fn write_in(&self, dir: &str, name: &str, content: &str) -> String {
            let at = self.root.join(dir);
            std::fs::create_dir_all(&at).unwrap();
            std::fs::write(at.join(name), content).unwrap();
            format!("{dir}/{name}")
        }

        /// Create `dir` and leave it empty.
        fn mkdir(&self, dir: &str) {
            std::fs::create_dir_all(self.root.join(dir)).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).ok();
        }
    }

    const DIRS: &[&str] = &["layer"];

    const HEADERED: &str =
        "//! A component of the layer.\n//!\n//! Serves FC1, FC5.\n\npub fn a() {}\n";
    const BARE: &str = "//! A component with no claim named.\n\npub fn b() {}\n";

    #[test]
    fn a_headered_module_counts_in_the_layer_and_a_listed_one_outside() {
        let fx = Fixture::new("split");
        let headered = fx.write("headered.rs", HEADERED);
        let listed = fx.write("listed.rs", BARE);
        // Only Rust is counted, so a neighbouring document is not a module and
        // is not subject to the header rule either.
        let ignored = fx.write("notes.md", "# Serves FC1.\n");
        let report = measure(&fx.root, DIRS, &[listed.as_str()]).unwrap();

        assert_eq!(report.modules.len(), 2, "both modules must be reported");
        assert!(
            !report.modules.iter().any(|m| m.path == ignored),
            "a non-Rust file must not be in the report"
        );
        let by_path = |p: &str| {
            report
                .modules
                .iter()
                .find(|m| m.path == p)
                .unwrap_or_else(|| panic!("{p} must be in the report"))
        };
        assert_eq!(by_path(&headered).set, Set::Layer);
        assert_eq!(by_path(&listed).set, Set::Outside);
        assert_eq!(report.layer_total, line_count(HEADERED));
        assert_eq!(report.outside_total, line_count(BARE));
    }

    #[test]
    fn an_unlisted_module_naming_no_claim_is_refused_by_name() {
        let fx = Fixture::new("unlisted");
        fx.write("headered.rs", HEADERED);
        let stray = fx.write("stray.rs", BARE);
        let err = measure(&fx.root, DIRS, &[]).unwrap_err().to_string();
        assert!(
            err.contains(&stray),
            "the refusal must name the module, got: {err}"
        );
    }

    #[test]
    fn a_ceiling_below_the_layer_total_is_refused() {
        let fx = Fixture::new("ceiling");
        fx.write("headered.rs", HEADERED);
        let total = line_count(HEADERED);
        // The mirror control: the same tree passes at its own total, so the
        // refusal below is the ceiling and not some other defect.
        check(&fx.root, DIRS, &[], total).expect("a ceiling at the total must pass");
        let err = check(&fx.root, DIRS, &[], total - 1)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("above its ceiling"),
            "a ceiling below the total must refuse, got: {err}"
        );

        // The ceiling is on the layer, so a listed module's lines do not move
        // it: the ceiling that passed above still passes with one added.
        let listed = fx.write("listed.rs", BARE);
        check(&fx.root, DIRS, &[listed.as_str()], total)
            .expect("an outside-listed module must not count against the ceiling");
    }

    #[test]
    fn a_listed_module_that_names_a_claim_is_refused_by_name() {
        let fx = Fixture::new("stale");
        let listed = fx.write("listed.rs", HEADERED);
        let err = measure(&fx.root, DIRS, &[listed.as_str()])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(&listed) && err.contains("Remove the list entry"),
            "the refusal must name the module and say to prune it, got: {err}"
        );
    }

    #[test]
    fn a_dirs_entry_naming_no_directory_is_refused() {
        let fx = Fixture::new("nodir");
        fx.write("headered.rs", HEADERED);
        // The mirror control: the same tree measures cleanly under the real
        // directory, so the refusal below is the absent one and nothing else.
        measure(&fx.root, DIRS, &[]).expect("the present directory must measure");
        let err = measure(&fx.root, &["layer", "gone"], &[])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("gone") && err.contains("would pass on nothing"),
            "an absent directory must refuse, got: {err}"
        );
    }

    #[test]
    fn a_walk_finding_no_module_is_refused() {
        let fx = Fixture::new("empty");
        let err = measure(&fx.root, DIRS, &[]).unwrap_err().to_string();
        assert!(
            err.contains("found no .rs file"),
            "an empty walk must refuse, got: {err}"
        );
    }

    #[test]
    fn a_list_entry_naming_no_file_is_refused() {
        let fx = Fixture::new("absent");
        fx.write("headered.rs", HEADERED);
        let err = measure(&fx.root, DIRS, &["layer/deleted.rs"])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("layer/deleted.rs"),
            "the refusal must name the entry, got: {err}"
        );
    }

    #[test]
    fn a_modules_count_is_its_line_count() {
        let fx = Fixture::new("lines");
        let body = "//! Serves FC2.\n\npub fn c() {}\n\n#[cfg(test)]\nmod t {}\n";
        let path = fx.write("counted.rs", body);
        let report = measure(&fx.root, DIRS, &[]).unwrap();
        assert_eq!(report.modules.len(), 1);
        assert_eq!(report.modules[0].path, path);
        assert_eq!(report.modules[0].lines, 6);
        assert_eq!(report.modules[0].lines, body.lines().count());
    }

    #[test]
    fn a_claim_named_below_the_leading_block_does_not_count() {
        assert!(serves_founding_claim("//! Serves FC1.\n\npub fn a() {}\n"));
        assert!(!serves_founding_claim(
            "//! A component.\n\n/// Serves FC1.\npub fn a() {}\n"
        ));
        assert!(
            !serves_founding_claim("//! Serves FCn, whatever that is.\n"),
            "the form is `Serves FC` followed by a number"
        );
    }

    #[test]
    fn one_empty_directory_is_refused_even_beside_a_populated_one() {
        let fx = Fixture::new("perdir");
        fx.write_in("first", "headered.rs", HEADERED);
        fx.mkdir("second");
        // The mirror control: the populated directory alone measures cleanly,
        // so the refusal below is the empty one and not the pair.
        measure(&fx.root, &["first"], &[]).expect("the populated directory must measure");
        let err = measure(&fx.root, &["first", "second"], &[])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("second") && err.contains("found no .rs file"),
            "the empty directory must be named, got: {err}"
        );
    }

    /// The ceiling in `docs/design/direct-messaging.md` § Size rule.
    #[test]
    fn the_default_ceiling_is_the_figure_the_design_sets() {
        assert_eq!(DEFAULT_CEILING, 6000);
    }

    #[test]
    fn an_absent_ceiling_is_the_default_and_a_number_is_read_whole() {
        assert_eq!(ceiling_from(None).unwrap(), DEFAULT_CEILING);
        assert_eq!(ceiling_from(Some(OsStr::new("42"))).unwrap(), 42);
        assert_eq!(ceiling_from(Some(OsStr::new(" 42 "))).unwrap(), 42);
    }

    #[test]
    fn a_ceiling_that_is_not_a_line_count_is_refused() {
        for value in ["", "x", "-1"] {
            let err = ceiling_from(Some(OsStr::new(value)))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("is not a line count"),
                "{value:?} must be refused, got: {err}"
            );
        }
        // Not every rejected value is even a string: an environment variable
        // carries bytes, and bytes that are not UTF-8 must not read as absent.
        let raw: &OsStr = std::os::unix::ffi::OsStrExt::from_bytes(&[0xff][..]);
        let err = ceiling_from(Some(raw)).unwrap_err().to_string();
        assert!(
            err.contains("UTF-8"),
            "a non-UTF-8 value must be refused for what it is, got: {err}"
        );
    }

    /// The shipped configuration measures the whole of the layer: both
    /// directories are walked, and every module under them lands in one of the
    /// two totals. Walked independently here, so a renamed or dropped
    /// [`LAYER_DIRS`] entry — and a module dropped from [`OUTSIDE_LAYER`] —
    /// fails rather than shrinking the figures silently.
    #[test]
    fn the_shipped_configuration_measures_the_whole_layer() {
        assert_eq!(
            LAYER_DIRS,
            [
                "crates/daemonseed-core/src/dm",
                "crates/daemonseed-veilid-net/src/dm",
            ]
            .as_slice()
        );
        let repo = crate::workspace_root_from_xtask().unwrap();
        let report = measure(&repo, LAYER_DIRS, OUTSIDE_LAYER)
            .expect("the shipped configuration must measure the tree");

        let mut files = Vec::new();
        for dir in LAYER_DIRS {
            for entry in WalkDir::new(repo.join(dir))
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                if path.is_file() && path.extension().is_some_and(|e| e == "rs") {
                    files.push(path.to_path_buf());
                }
            }
        }
        assert!(
            !files.is_empty(),
            "positive control: the two directories hold modules"
        );
        assert_eq!(
            report.modules.len(),
            files.len(),
            "every module under the two directories must be in one of the two sets"
        );
        let lines: usize = files
            .iter()
            .map(|p| line_count(&std::fs::read_to_string(p).unwrap()))
            .sum();
        assert_eq!(
            report.layer_total + report.outside_total,
            lines,
            "the two totals must account for every line under the two directories"
        );
    }

    /// Every entry of the shipped list names a file in the tree the check runs
    /// on, which is the condition [`measure`] refuses without.
    #[test]
    fn the_shipped_outside_list_names_files_that_exist() {
        let repo = crate::workspace_root_from_xtask().unwrap();
        assert!(
            !OUTSIDE_LAYER.is_empty(),
            "positive control: there are entries to check"
        );
        for entry in OUTSIDE_LAYER {
            assert!(
                repo.join(entry).is_file(),
                "the outside-layer list names {entry}, which does not exist"
            );
        }
    }
}
