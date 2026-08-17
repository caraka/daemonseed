//! Well-formedness checks for `docs/llm-api-manifest/*.yaml` (#326).
//!
//! These files are hand-edited YAML and are the surface a reader-LLM trusts to
//! discover the project. YAML has no duplicate-key semantics: a repeated mapping
//! key is silently discarded on parse, by every ordinary loader, by design. #264
//! was one instance — `IndexKey` carried `security:` twice — and it was found by
//! eye while verifying an unrelated commit, not by anything that runs.
//!
//! **The strictness has to be explicit or this check cannot fail.** Loading these
//! files with a normal loader and reporting success is a gate that passes forever
//! while testing nothing — the same shape as plain `cargo doc`, which exits 0 with
//! warnings present until `-D warnings` is added. So the duplicate detection is
//! done at the *event* level, where both occurrences of a repeated key are still
//! visible, rather than over a parsed map where the first has already been
//! overwritten. `tests::a_duplicate_key_is_detected` drives it — named rather than
//! linked, because a `#[cfg(test)]` item does not exist in the build rustdoc sees.
//!
//! **What this does NOT check**, stated so the gate is not read as more than it
//! is: whether the manifests are *true*. #307 is a live example — `lama.yaml`
//! advertises two `xtask` subcommands that do not exist and omits one that does,
//! in an entry that is perfectly well-formed. Structural validity and factual
//! accuracy are different lenses, and only the first is mechanical.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
use yaml_rust2::scanner::Marker;

/// One repeated mapping key, with the line the repeat appeared on.
#[derive(Debug, PartialEq, Eq)]
pub struct DuplicateKey {
    pub key: String,
    pub line: usize,
}

/// A frame of the document being walked.
enum Frame {
    /// Inside a mapping: the keys seen so far, and whether the next scalar is a
    /// key rather than a value.
    Mapping {
        seen: HashSet<String>,
        expecting_key: bool,
    },
    /// Inside a sequence. Tracked only so a mapping nested in one restores the
    /// right frame when it ends.
    Sequence,
}

#[derive(Default)]
struct DuplicateFinder {
    stack: Vec<Frame>,
    found: Vec<DuplicateKey>,
}

impl DuplicateFinder {
    /// A value has just been consumed, so the next scalar in an enclosing mapping
    /// is a key again.
    fn value_done(&mut self) {
        if let Some(Frame::Mapping { expecting_key, .. }) = self.stack.last_mut() {
            *expecting_key = true;
        }
    }
}

impl MarkedEventReceiver for DuplicateFinder {
    fn on_event(&mut self, ev: Event, mark: Marker) {
        match ev {
            Event::MappingStart(..) => {
                // The mapping is itself a value of whatever encloses it; the flag
                // is restored when it ends.
                self.stack.push(Frame::Mapping {
                    seen: HashSet::new(),
                    expecting_key: true,
                });
            }
            Event::MappingEnd => {
                self.stack.pop();
                self.value_done();
            }
            Event::SequenceStart(..) => self.stack.push(Frame::Sequence),
            Event::SequenceEnd => {
                self.stack.pop();
                self.value_done();
            }
            Event::Scalar(text, ..) => {
                let is_key = matches!(
                    self.stack.last(),
                    Some(Frame::Mapping {
                        expecting_key: true,
                        ..
                    })
                );
                if is_key {
                    if let Some(Frame::Mapping {
                        seen,
                        expecting_key,
                    }) = self.stack.last_mut()
                    {
                        if !seen.insert(text.clone()) {
                            self.found.push(DuplicateKey {
                                key: text,
                                line: mark.line(),
                            });
                        }
                        *expecting_key = false;
                    }
                } else {
                    self.value_done();
                }
            }
            _ => {}
        }
    }
}

/// Every repeated mapping key in one YAML document, innermost mapping scope.
///
/// Factored out of the file walk so it can be driven by fixtures rather than only
/// by the real manifests — a check that reads only files it expects to be clean
/// can never be shown to fire.
pub fn duplicate_keys(yaml: &str) -> Result<Vec<DuplicateKey>> {
    let mut finder = DuplicateFinder::default();
    let mut parser = Parser::new_from_str(yaml);
    parser
        .load(&mut finder, true)
        .map_err(|e| anyhow::anyhow!("YAML parse failed: {e}"))?;
    Ok(finder.found)
}

/// The manifest directory, relative to the workspace root.
pub const MANIFEST_DIR: &str = "docs/llm-api-manifest";

/// Check every manifest, failing on the first file with repeated keys.
pub fn check_manifests(repo_root: &Path) -> Result<()> {
    let dir = repo_root.join(MANIFEST_DIR);
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "yaml" || x == "yml"))
        .collect();
    files.sort();

    // The root manifest is the same kind of artifact, hand-edited by the same
    // doc-sync step, and #307 is a live drift finding against it — so it is
    // checked too rather than left outside the only gate these files have.
    let root = repo_root.join("lama.yaml");
    if root.is_file() {
        files.push(root);
    }

    // A directory that matched nothing would report clean, which is the vacuous
    // pass this check exists to avoid.
    if files.is_empty() {
        bail!(
            "no manifests found under {} — the check examined nothing",
            dir.display()
        );
    }

    let mut failures = 0usize;
    for path in &files {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let dups = duplicate_keys(&text).with_context(|| format!("parsing {}", path.display()))?;
        for d in &dups {
            eprintln!(
                "{}:{}: duplicate key {:?} — YAML discards the earlier one silently",
                path.display(),
                d.line,
                d.key
            );
            failures += 1;
        }
    }

    if failures > 0 {
        bail!(
            "check-manifests: {failures} duplicate key(s) across {} file(s)",
            files.len()
        );
    }
    println!(
        "check-manifests: {} manifest(s) clean, no duplicate keys",
        files.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The check catches a repeat, and reports where the *second* one is.
    #[test]
    fn a_duplicate_key_is_detected() {
        let dups = duplicate_keys("a: 1\nb: 2\na: 3\n").expect("parses");
        assert_eq!(
            dups,
            vec![DuplicateKey {
                key: "a".to_owned(),
                line: 3
            }]
        );
    }

    /// The shape #264 actually had: a repeat inside a nested mapping, itself
    /// inside a sequence entry.
    #[test]
    fn a_duplicate_nested_under_a_sequence_entry_is_detected() {
        let yaml = "\
items:
  - name: IndexKey
    security:
      contains_secret: true
    security:
      zeroize_on_drop: true
";
        let dups = duplicate_keys(yaml).expect("parses");
        assert_eq!(dups.len(), 1, "got {dups:?}");
        assert_eq!(dups[0].key, "security");
    }

    /// **The mirror control.** Without it the check could pass by firing on
    /// everything, and the same key legitimately appears once per sibling entry —
    /// which is not a duplicate, because each entry is its own mapping scope.
    #[test]
    fn the_same_key_in_sibling_entries_is_not_a_duplicate() {
        let yaml = "\
items:
  - name: One
    kind: struct
  - name: Two
    kind: struct
";
        assert!(duplicate_keys(yaml).expect("parses").is_empty());
    }

    /// A key repeated at two different depths is two scopes, not one repeat.
    #[test]
    fn the_same_key_at_different_depths_is_not_a_duplicate() {
        let yaml = "name: outer\nchild:\n  name: inner\n";
        assert!(duplicate_keys(yaml).expect("parses").is_empty());
    }

    /// Malformed YAML is an error, not a silent clean pass.
    #[test]
    fn a_parse_failure_is_reported_rather_than_swallowed() {
        assert!(duplicate_keys("a: [1, 2\n").is_err());
    }
}
