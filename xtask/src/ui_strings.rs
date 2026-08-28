//! Refuse to ship a placeholder inside text a user can read.
//!
//! A user interface is often built ahead of the behaviour it describes, which
//! leaves stand-in strings where copy cannot yet be written. No other gate step
//! reads a user-visible string, so such a string is invisible to every one of
//! them and reaches the screen intact. The discipline that marks an unfinished
//! test has no equivalent for unfinished copy.
//!
//! This needs no judgement: a placeholder is by definition not shippable, so
//! finding one is a refusal rather than a warning.
//!
//! # Scope, and what it deliberately does not cover
//!
//! Two surfaces, with different token sets, because their false-positive risk
//! differs:
//!
//! - **`.slint` files** — every quoted string is display text or a style token,
//!   and there is no test code in them. The full token set applies.
//! - **`daemonseed-{gui,tui}` Rust sources** — a string literal there may be a
//!   test name, a key, an error or a log line, so only the tokens that cannot
//!   be innocent apply. `TODO` in a Rust string is not flagged.
//!
//! **Comments are never flagged, on either surface.** A `// TODO` is ordinary
//! engineering; a `"TODO"` a user can read is not. The check is on string
//! literals alone, which is what makes it precise enough to keep switched on.
//!
//! Not covered, and named so a clean run is not read as more than it is: text
//! composed at runtime from fragments, text loaded from a file, and any string
//! reaching the screen through a crate this check does not walk.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use walkdir::WalkDir;

/// Tokens that may not appear in a `.slint` string. Every quoted span in a
/// `.slint` file is display text or a style token, so all of these are wrong.
pub const SLINT_TOKENS: &[&str] = &[
    "PLACEHOLDER",
    "PENDING SECURITY REVIEW",
    "TODO",
    "FIXME",
    "TBD",
    "XXX",
];

/// Tokens that may not appear in a Rust string literal in a front-end crate.
/// Deliberately shorter than [`SLINT_TOKENS`]: a Rust literal can legitimately
/// be a test fixture or an error string, and a gate that fires on those is a
/// gate somebody switches off.
pub const RUST_TOKENS: &[&str] = &["PLACEHOLDER", "PENDING SECURITY REVIEW"];

/// One offending literal: 1-indexed line, the token that matched, and the
/// literal itself, truncated for reporting.
#[derive(Debug, PartialEq, Eq)]
pub struct Hit {
    pub line: usize,
    pub token: String,
    pub literal: String,
}

/// The double-quoted spans on one line, with `\"` treated as an escape rather
/// than a terminator. Returns the span contents without their quotes.
fn string_literals(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    let mut escaped = false;
    for ch in line.chars() {
        match &mut cur {
            None => {
                if ch == '"' {
                    cur = Some(String::new());
                }
            }
            Some(buf) => {
                if escaped {
                    buf.push(ch);
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    out.push(std::mem::take(buf));
                    cur = None;
                } else {
                    buf.push(ch);
                }
            }
        }
    }
    out
}

/// Every offending literal in `content`, matched case-insensitively.
///
/// Pure and fixture-driven on purpose: a check that can only be exercised by
/// planting a string in the real tree cannot be shown to fire, and a guard that
/// has never been seen to fire reads exactly like one that passes.
pub fn placeholder_hits(content: &str, tokens: &[&str]) -> Vec<Hit> {
    let mut hits = Vec::new();
    for (i, line) in content.lines().enumerate() {
        for literal in string_literals(line) {
            let upper = literal.to_uppercase();
            for token in tokens {
                if upper.contains(&token.to_uppercase()) {
                    hits.push(Hit {
                        line: i + 1,
                        token: (*token).to_string(),
                        literal: literal.chars().take(90).collect(),
                    });
                    break;
                }
            }
        }
    }
    hits
}

/// Files this check walks, paired with the token set that governs each.
fn targets(repo: &Path) -> Vec<(PathBuf, &'static [&'static str])> {
    let mut out: Vec<(PathBuf, &'static [&'static str])> = Vec::new();
    let push_tree = |dir: PathBuf, ext: &str, tokens: &'static [&'static str], out: &mut Vec<_>| {
        if !dir.is_dir() {
            return;
        }
        for entry in WalkDir::new(&dir).into_iter().filter_map(|e| e.ok()) {
            let p = entry.path();
            if p.is_file() && p.extension().is_some_and(|e| e == ext) {
                out.push((p.to_path_buf(), tokens));
            }
        }
    };
    push_tree(
        repo.join("crates/daemonseed-gui/ui"),
        "slint",
        SLINT_TOKENS,
        &mut out,
    );
    for crate_dir in ["crates/daemonseed-gui/src", "crates/daemonseed-tui/src"] {
        push_tree(repo.join(crate_dir), "rs", RUST_TOKENS, &mut out);
    }
    out
}

/// Walk the UI surfaces and refuse if any placeholder is present.
///
/// Finding no files is a failure, not a pass: it means the paths moved and the
/// check has been silently inspecting nothing.
pub fn check_ui_strings(repo: &Path) -> Result<()> {
    let files = targets(repo);
    if files.is_empty() {
        bail!(
            "check-ui-strings: found no UI files under {} — the paths have moved and this \
             check is inspecting nothing. That is a failure, not a clean result.",
            repo.display()
        );
    }

    let mut findings: Vec<String> = Vec::new();
    for (path, tokens) in &files {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => bail!("check-ui-strings: read {}: {e}", path.display()),
        };
        for hit in placeholder_hits(&content, tokens) {
            let rel = path.strip_prefix(repo).unwrap_or(path);
            findings.push(format!(
                "  {}:{} [{}] \"{}\"",
                rel.display(),
                hit.line,
                hit.token,
                hit.literal
            ));
        }
    }

    if findings.is_empty() {
        println!("check-ui-strings: {} file(s) clean", files.len());
        return Ok(());
    }

    eprintln!("check-ui-strings: placeholder text in strings a user can read:\n");
    for f in &findings {
        eprintln!("{f}");
    }
    eprintln!(
        "\nA placeholder is not shippable by definition. Write the real text, or \
         remove the element until the text can be written."
    );
    bail!(
        "{} placeholder string(s) in the user interface",
        findings.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_placeholder_in_a_slint_string_is_found() {
        let src = r#"Text { text: "[PLACEHOLDER - relay sentence]"; color: #5b6472; }"#;
        let hits = placeholder_hits(src, SLINT_TOKENS);
        assert_eq!(hits.len(), 1, "the shipped defect must be caught");
        assert_eq!(hits[0].token, "PLACEHOLDER");
        assert_eq!(hits[0].line, 1);
    }

    #[test]
    fn two_placeholders_on_consecutive_lines_are_both_caught() {
        let src = concat!(
            "Text { text: \"[PENDING SECURITY REVIEW - relay-exposure sentence]\"; }\n",
            "Text { text: \"[PENDING SECURITY REVIEW - \\\"N others\\\" only on a trusted relay]\"; }\n",
        );
        let hits = placeholder_hits(src, SLINT_TOKENS);
        assert_eq!(
            hits.len(),
            2,
            "both lines must be caught, not just the first"
        );
        assert_eq!(hits[0].line, 1);
        assert_eq!(hits[1].line, 2);
    }

    #[test]
    fn honest_display_text_is_not_flagged() {
        // The mirror control. Without it this suite passes with every token
        // deleted, because a clean fixture is clean under any token set.
        let src = concat!(
            "Text { text: \"End-to-end encrypted · only people with this phrase can read it.\"; }\n",
            "Text { text: \"Join a circle\"; }\n",
            "Text { text: \"Scan QR · soon\"; }\n",
        );
        assert!(
            placeholder_hits(src, SLINT_TOKENS).is_empty(),
            "ordinary copy must not be refused"
        );
    }

    #[test]
    fn a_comment_is_never_flagged_but_a_string_on_the_same_line_is() {
        let only_comment = "// TODO: revisit this once the ratchet lands";
        assert!(
            placeholder_hits(only_comment, SLINT_TOKENS).is_empty(),
            "engineering comments are not user-visible"
        );
        let both = r#"Text { text: "TODO write this"; } // TODO: and a comment"#;
        assert_eq!(
            placeholder_hits(both, SLINT_TOKENS).len(),
            1,
            "the literal counts, the comment does not"
        );
    }

    #[test]
    fn rust_tokens_are_narrower_than_slint_tokens() {
        // A Rust string literal may legitimately be a test name or a key, so
        // TODO is not a Rust token. Both halves asserted: without the first the
        // narrowing is untested, without the second it is indistinguishable
        // from the check being switched off for Rust entirely.
        let todo = r#"let name = "TODO";"#;
        assert!(placeholder_hits(todo, RUST_TOKENS).is_empty());
        let placeholder = r#"let s = "PLACEHOLDER - not written yet";"#;
        assert_eq!(placeholder_hits(placeholder, RUST_TOKENS).len(), 1);
    }

    #[test]
    fn matching_is_case_insensitive_and_substring() {
        let src = r#"Text { text: "some placeholder copy"; }"#;
        assert_eq!(placeholder_hits(src, SLINT_TOKENS).len(), 1);
    }

    #[test]
    fn an_escaped_quote_does_not_end_the_literal() {
        // A parser that treated the escape as a terminator would split the
        // literal and could miss the token, so this pins escape handling.
        let src = r#"Text { text: "a \"quoted\" PLACEHOLDER inside"; }"#;
        let hits = placeholder_hits(src, SLINT_TOKENS);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].literal.contains("N") || hits[0].literal.contains("quoted"));
    }

    #[test]
    fn an_empty_tree_is_a_failure_not_a_pass() {
        let dir = std::env::temp_dir().join("ds-ui-strings-empty-probe");
        std::fs::create_dir_all(&dir).unwrap();
        let err = check_ui_strings(&dir).unwrap_err().to_string();
        assert!(
            err.contains("inspecting nothing"),
            "an empty walk must refuse, got: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
