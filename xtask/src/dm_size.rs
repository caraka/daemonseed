//! Measure the direct-messaging layer against its line ceiling, and require
//! every module in it to name the founding claim it serves.
//!
//! `docs/design/direct-messaging.md` § Size rule sets two conditions on the
//! layer: it is at most [`DEFAULT_CEILING`] lines of production code, and
//! every component names the founding claim it serves. Both are properties of
//! the tree as a whole, which no per-crate lint or test can see — a module is
//! added to one crate, the total is read from neither, and the ceiling is
//! crossed without any step noticing.
//!
//! The two conditions have different consequences. A module naming no claim
//! fails the run. A layer above its ceiling does not: the run prints a
//! warning naming the figures and exits 0, because the ceiling exists so the
//! maintainer is told when the layer has grown and can look for scope creep,
//! not so a commit is refused.
//!
//! A line of production code is a line that is not blank, is not a comment,
//! and is not part of an item marked `#[cfg(test)]`. Tests, documentation and
//! whitespace are what make a layer readable, and a ceiling that counted them
//! would push the layer toward fewer of each. See [`code_lines`] for the
//! exact rule.
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
/// An entry is removed when that module gains a founding-claim header, is
/// declared under `#[cfg(test)]` by its parent, or is deleted. An entry naming
/// no file is an error.
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
    /// The module is declared under `#[cfg(test)]` by its parent, so it is
    /// compiled only for tests: it counts zero, against neither total, and
    /// needs no header.
    TestOnly,
}

impl Set {
    /// The set's word in the per-module output line.
    pub fn as_str(self) -> &'static str {
        match self {
            Set::Layer => "layer",
            Set::Outside => "outside",
            Set::TestOnly => "test-only",
        }
    }
}

/// One counted module: its path relative to the repository root, its count of
/// production code lines, and the set it is in.
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

/// A module's count of production code lines.
///
/// A line counts unless it is blank, is a comment (`//`, `///` or `//!`, or
/// inside a `/* */` block), or belongs to an item marked `#[cfg(test)]`. The
/// attribute is recognised on its own line. The item it marks runs through
/// any further attributes and then its own lines: a line that opens a brace
/// it does not close begins a body that runs to the closing brace at the
/// attribute's own indentation; a line with balanced braces, or ending in
/// `;`, ends the item; the item's first line ending in `,` (a field or a
/// variant) ends it too; any other line is a signature or an expression that
/// continues, until a `}` at or above the attribute's indentation closes the
/// enclosing block. This is the layout `rustfmt` produces, and the gate's
/// `cargo fmt --all --check` step holds every module to it. A line that ends
/// an item early, such as a `}` at the item's indentation inside a raw string
/// in a test, makes the count larger. One shape makes it smaller: a marked
/// multi-line match arm followed by sibling arms, whose lines are swallowed
/// until the enclosing `}`; the layer has none.
///
/// A file that is itself compiled only for tests, because its parent declares
/// it under `#[cfg(test)]`, is not the concern of this function: see
/// [`test_only_mod_declarations`] and [`measure`].
pub fn code_lines(content: &str) -> usize {
    let mut count = 0;
    let mut in_block_comment = false;
    // The indentation of a `#[cfg(test)]` whose item's signature is still
    // being read, and whether the item's first line has been seen.
    let mut pending_test_attr: Option<(usize, bool)> = None;
    // The indentation of the `#[cfg(test)]` whose multi-line item is being
    // skipped.
    let mut skipping_to_indent: Option<usize> = None;
    for line in content.lines() {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if in_block_comment {
            if line.contains("*/") {
                in_block_comment = false;
            }
            continue;
        }
        if let Some(at) = skipping_to_indent {
            if indent == at && trimmed.starts_with('}') {
                skipping_to_indent = None;
            }
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        if trimmed.starts_with("/*") {
            if !trimmed.contains("*/") {
                in_block_comment = true;
            }
            continue;
        }
        if trimmed == "#[cfg(test)]" {
            pending_test_attr = Some((indent, false));
            continue;
        }
        if let Some((at, started)) = pending_test_attr {
            if !started && trimmed.starts_with('#') {
                // A further attribute on the same item.
                continue;
            }
            let opens = trimmed.matches('{').count();
            let closes = trimmed.matches('}').count();
            let ended = trimmed.trim_end();
            if started && indent <= at && trimmed.starts_with('}') {
                // The enclosing block closed before the item ended: the
                // item is over and this brace belongs to the code.
                pending_test_attr = None;
            } else if opens > closes {
                skipping_to_indent = Some(at);
                pending_test_attr = None;
                continue;
            } else if opens > 0 || ended.ends_with(';') || (!started && ended.ends_with(',')) {
                pending_test_attr = None;
                continue;
            } else {
                // A signature or an expression continuing on the next line.
                pending_test_attr = Some((at, true));
                continue;
            }
        }
        count += 1;
    }
    count
}

/// The names of the out-of-line modules a file declares under `#[cfg(test)]`:
/// each `mod name;` whose attributes include the marker, in order.
///
/// Such a module is compiled only for tests, and its file holds no production
/// code however it reads.
pub fn test_only_mod_declarations(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut pending = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "#[cfg(test)]" {
            pending = true;
            continue;
        }
        if !pending {
            continue;
        }
        if trimmed.starts_with('#') || trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        pending = false;
        let Some(rest) = trimmed.strip_suffix(';') else {
            continue;
        };
        let mut rest = rest.trim();
        if let Some(after) = rest.strip_prefix("pub") {
            rest = match after.strip_prefix('(') {
                Some(inner) => inner.split_once(')').map(|(_, r)| r).unwrap_or(""),
                None => after,
            }
            .trim_start();
        }
        let Some(name) = rest.strip_prefix("mod ") else {
            continue;
        };
        let name = name.trim();
        if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            out.push(name.to_string());
        }
    }
    out
}

/// The files, relative to `repo`, a `mod name;` in `declaring` can name: the
/// sibling `name.rs` and the child `name/mod.rs`, resolved against the
/// directory the declaring file's own modules live in.
fn declared_module_paths(declaring: &Path, name: &str) -> [PathBuf; 2] {
    let dir = declaring.parent().unwrap_or(Path::new(""));
    let stem = declaring.file_stem().and_then(OsStr::to_str).unwrap_or("");
    let base = if matches!(stem, "mod" | "lib" | "main") {
        dir.to_path_buf()
    } else {
        dir.join(stem)
    };
    [
        base.join(format!("{name}.rs")),
        base.join(name).join("mod.rs"),
    ]
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
/// A module some other module under `dirs` declares under `#[cfg(test)]` is
/// test-only: reported at zero, in neither total, and exempt from the header
/// rule.
///
/// Refuses on any shape defect rather than reporting a figure built on it: an
/// `outside` entry that names no file, a module on neither the list nor the
/// headered side, which would leave lines counted in no total at all, a
/// listed module that names a founding claim, whose entry is now stale, and a
/// listed module that is test-only, whose entry counts nothing.
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

    let found = modules_under(repo, dirs)?;
    let mut sources = Vec::with_capacity(found.len());
    for rel in &found {
        let path = rel.to_string_lossy().replace('\\', "/");
        let content = std::fs::read_to_string(repo.join(rel))
            .map_err(|e| anyhow::anyhow!("dm-size: read {path}: {e}"))?;
        sources.push((rel.clone(), path, content));
    }
    let mut test_only: Vec<PathBuf> = Vec::new();
    for (rel, _, content) in &sources {
        for name in test_only_mod_declarations(content) {
            test_only.extend(declared_module_paths(rel, &name));
        }
    }

    let mut modules = Vec::new();
    let mut unheadered: Vec<String> = Vec::new();
    let mut stale: Vec<String> = Vec::new();
    let mut listed_test_only: Vec<String> = Vec::new();
    let mut layer_total = 0;
    let mut outside_total = 0;
    for (rel, path, content) in &sources {
        let path = path.clone();
        let lines = code_lines(content);
        let headered = serves_founding_claim(content);
        let listed = outside.contains(&path.as_str());
        let set = if test_only.contains(rel) {
            if listed {
                listed_test_only.push(path.clone());
                continue;
            }
            modules.push(Module {
                path,
                lines: 0,
                set: Set::TestOnly,
            });
            continue;
        } else if listed {
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

    if !listed_test_only.is_empty() {
        bail!(
            "dm-size: {} module(s) are declared under `#[cfg(test)]` and are on the outside-layer list:\n  {}\n\
             Remove the list entry; a test-only module counts nothing.",
            listed_test_only.len(),
            listed_test_only.join("\n  ")
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

/// The warning a run prints when the layer is above `ceiling`, and `None`
/// when it is not.
pub fn ceiling_warning(report: &Report, ceiling: usize) -> Option<String> {
    (report.layer_total > ceiling).then(|| {
        format!(
            "dm-size: WARNING the layer is {} code line(s), above its ceiling of {}. \
             Tell the maintainer, who reviews the layer for scope creep.",
            report.layer_total, ceiling
        )
    })
}

/// Measure the layer and print what it found, with a warning above `ceiling`.
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
        "dm-size: layer {} code line(s), outside {} code line(s), ceiling {}",
        report.layer_total, report.outside_total, ceiling
    );
    if let Some(warning) = ceiling_warning(&report, ceiling) {
        println!("{warning}");
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
        assert_eq!(report.layer_total, code_lines(HEADERED));
        assert_eq!(report.outside_total, code_lines(BARE));
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
    fn a_ceiling_below_the_layer_total_warns_and_does_not_refuse() {
        let fx = Fixture::new("ceiling");
        fx.write("headered.rs", HEADERED);
        let total = code_lines(HEADERED);
        let report = measure(&fx.root, DIRS, &[]).unwrap();
        // The mirror control: no warning at the total, so the one below is
        // the ceiling and not some other defect.
        assert_eq!(ceiling_warning(&report, total), None);
        let warning = ceiling_warning(&report, total - 1).expect("a ceiling below the total warns");
        assert!(
            warning.contains("WARNING") && warning.contains("above its ceiling"),
            "the warning names the condition, got: {warning}"
        );
        // A run above the ceiling still exits 0: the warning is the whole
        // consequence.
        check(&fx.root, DIRS, &[], total - 1).expect("a layer above its ceiling is not refused");

        // The ceiling is on the layer, so a listed module's lines do not move
        // it: the report that had no warning at the total still has none
        // with one added.
        let listed = fx.write("listed.rs", BARE);
        let report = measure(&fx.root, DIRS, &[listed.as_str()]).unwrap();
        assert_eq!(report.layer_total, total);
        assert_eq!(ceiling_warning(&report, total), None);
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
    fn a_modules_count_is_its_production_code_lines() {
        let fx = Fixture::new("lines");
        let body = "//! Serves FC2.\n\npub fn c() {}\n\n#[cfg(test)]\nmod t {\n    fn d() {}\n}\n";
        let path = fx.write("counted.rs", body);
        let report = measure(&fx.root, DIRS, &[]).unwrap();
        assert_eq!(report.modules.len(), 1);
        assert_eq!(report.modules[0].path, path);
        assert_eq!(report.modules[0].lines, 1, "only `pub fn c() {{}}` is code");
        assert_eq!(
            body.lines().count(),
            8,
            "positive control: the file has more lines than that"
        );
    }

    #[test]
    fn blank_and_comment_lines_are_not_code() {
        // The mirror control: two code lines with nothing between them.
        assert_eq!(code_lines("pub fn a() {}\npub fn b() {}\n"), 2);
        assert_eq!(code_lines("pub fn a() {}\n\n\n   \npub fn b() {}\n"), 2);
        assert_eq!(
            code_lines(
                "//! Module doc.\n/// Item doc.\n// Note.\npub fn a() {}\n    // Indented.\npub fn b() {}\n"
            ),
            2
        );
        assert_eq!(
            code_lines("/* one line */\npub fn a() {}\n/* two\n   lines */\npub fn b() {}\n"),
            2
        );
        // A trailing comment does not stop a line being code.
        assert_eq!(code_lines("pub fn a() {} // trailing\n"), 1);
    }

    #[test]
    fn an_item_marked_cfg_test_is_not_code_and_the_item_after_it_is() {
        // The mirror control: the same text with the attribute removed counts
        // every line.
        let module = "mod t {\n    use super::*;\n    fn d() {}\n}\n";
        assert_eq!(code_lines(module), 4);
        assert_eq!(
            code_lines(&format!("#[cfg(test)]\n{module}pub fn after() {{}}\n")),
            1
        );

        // A nested item inside an impl block, ended by the brace at its own
        // indentation and not by the impl's.
        let nested = "impl A {\n    pub fn a() {}\n    #[cfg(test)]\n    pub fn t() {\n        if x {\n        }\n    }\n    pub fn b() {}\n}\n";
        assert_eq!(code_lines(nested), 4, "impl, a, b and the closing brace");

        // Further attributes on the marked item belong to it.
        let derived =
            "#[cfg(test)]\n#[derive(Clone)]\nstruct K {\n    x: u8,\n}\npub fn after() {}\n";
        assert_eq!(code_lines(derived), 1);

        // A single-line marked item ends on that line, so the next line counts.
        assert_eq!(
            code_lines("#[cfg(test)]\nuse std::cell::Cell;\npub fn after() {}\n"),
            1
        );
        assert_eq!(code_lines("#[cfg(test)]\nmod t;\npub fn after() {}\n"), 1);
        assert_eq!(
            code_lines("#[cfg(test)]\nfn t() {}\npub fn after() {}\n"),
            1
        );

        // A macro invocation with a brace body is an item like any other.
        let tl = "#[cfg(test)]\nthread_local! {\n    static S: u8 = 0;\n}\npub fn after() {}\n";
        assert_eq!(code_lines(tl), 1);

        // A signature that wraps across lines, with a `where` clause, is
        // still one item: the body opens on a later line.
        let wrapped = "#[cfg(test)]\npub(crate) fn t<F>(\n    f: F,\n) -> u8\nwhere\n    F: Fn(),\n{\n    1\n}\npub fn after() {}\n";
        assert_eq!(code_lines(wrapped), 1);

        // A marked struct field or enum variant ends at its comma, and a
        // marked statement at its semicolon.
        assert_eq!(
            code_lines("struct S {\n    #[cfg(test)]\n    t: u8,\n    u: u8,\n}\n"),
            3
        );
        assert_eq!(
            code_lines(
                "fn f() {\n    #[cfg(test)]\n    let t = g(\n        1,\n    );\n    h();\n}\n"
            ),
            3
        );

        // A marked multi-line match arm that is the last arm: the enclosing
        // `}` ends it and is itself code.
        assert_eq!(
            code_lines(
                "fn f(x: u8) -> u8 {\n    match x {\n        #[cfg(test)]\n        0 => g(\n            1,\n        ),\n    }\n}\npub fn after() {}\n"
            ),
            5
        );

        // A blank line at the attribute's indentation inside the marked item
        // does not end it: only the closing brace does.
        assert_eq!(
            code_lines(
                "#[cfg(test)]\nmod t {\n    fn a() {}\n\n    fn b() {}\n}\npub fn after() {}\n"
            ),
            1
        );

        // A `}` shallower than the attribute, inside a string, does not end
        // the item either.
        assert_eq!(
            code_lines(
                "impl A {\n    #[cfg(test)]\n    fn t() {\n        let s = \"\n}\n\";\n    }\n    pub fn b() {}\n}\n"
            ),
            3
        );
    }

    #[test]
    fn a_module_declared_under_cfg_test_counts_zero_and_needs_no_header() {
        let fx = Fixture::new("testonly");
        let parent = fx.write(
            "mod.rs",
            "//! Serves FC1.\n\n#[cfg(test)]\npub(crate) mod mock;\npub mod seam;\n",
        );
        let mock = fx.write("mock.rs", "pub fn m() {}\npub fn n() {}\n");
        let seam = fx.write("seam.rs", "//! Serves FC1.\n\npub fn s() {}\n");
        let report = measure(&fx.root, DIRS, &[]).unwrap();
        let by_path = |p: &str| {
            report
                .modules
                .iter()
                .find(|m| m.path == p)
                .unwrap_or_else(|| panic!("{p} must be in the report"))
        };
        assert_eq!(by_path(&mock).set, Set::TestOnly);
        assert_eq!(by_path(&mock).lines, 0);
        assert_eq!(by_path(&parent).set, Set::Layer);
        assert_eq!(by_path(&seam).set, Set::Layer);
        assert_eq!(
            report.layer_total, 2,
            "mod.rs's `pub mod seam;` and seam.rs's one line"
        );

        // The mirror control: the same tree with the attribute removed refuses
        // the unheadered module by name.
        fx.write(
            "mod.rs",
            "//! Serves FC1.\n\npub(crate) mod mock;\npub mod seam;\n",
        );
        let err = measure(&fx.root, DIRS, &[]).unwrap_err().to_string();
        assert!(err.contains(&mock), "got: {err}");

        // A test-only module on the outside list is a stale entry.
        fx.write(
            "mod.rs",
            "//! Serves FC1.\n\n#[cfg(test)]\npub(crate) mod mock;\npub mod seam;\n",
        );
        let err = measure(&fx.root, DIRS, &[mock.as_str()])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(&mock) && err.contains("test-only module counts nothing"),
            "got: {err}"
        );
    }

    #[test]
    fn test_only_declarations_are_read_from_a_parent_and_resolve_to_both_paths() {
        assert_eq!(
            test_only_mod_declarations(
                "#[cfg(test)]\npub(crate) mod mock;\npub mod seam;\n#[cfg(test)]\n#[allow(dead_code)]\nmod fixtures;\n#[cfg(test)]\nmod inline {\n}\n"
            ),
            ["mock", "fixtures"]
        );
        assert_eq!(
            declared_module_paths(Path::new("a/dm/mod.rs"), "mock"),
            [
                PathBuf::from("a/dm/mock.rs"),
                PathBuf::from("a/dm/mock/mod.rs")
            ]
        );
        assert_eq!(
            declared_module_paths(Path::new("a/dm.rs"), "mock"),
            [
                PathBuf::from("a/dm/mock.rs"),
                PathBuf::from("a/dm/mock/mod.rs")
            ]
        );
    }

    #[test]
    fn a_cfg_that_is_not_test_alone_is_code() {
        assert_eq!(code_lines("#[cfg(feature = \"x\")]\nfn f() {}\n"), 2);
        assert_eq!(
            code_lines("#[cfg(any(test, feature = \"x\"))]\nfn f() {}\n"),
            2
        );
        assert_eq!(
            code_lines("#[cfg_attr(test, derive(Debug))]\nstruct S;\n"),
            2
        );
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
        let test_only: Vec<PathBuf> = report
            .modules
            .iter()
            .filter(|m| m.set == Set::TestOnly)
            .map(|m| repo.join(&m.path))
            .collect();
        assert!(
            test_only.iter().any(|p| p.ends_with("dm/mock.rs")),
            "positive control: the transport's mock is declared test-only"
        );
        let lines: usize = files
            .iter()
            .filter(|p| !test_only.contains(p))
            .map(|p| code_lines(&std::fs::read_to_string(p).unwrap()))
            .sum();
        assert_eq!(
            report.layer_total + report.outside_total,
            lines,
            "the two totals must account for every code line under the two directories"
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
