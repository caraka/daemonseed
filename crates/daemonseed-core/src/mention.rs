//! @-mention recognition (ISC-C17) and resolution (ISC-C18).
//!
//! Both are **pure, client-side** functions over already-decrypted chat
//! plaintext and a locally-known scope of handles. They generate no new
//! server-visible traffic: recognition runs after decrypt, resolution runs
//! before send and only rewrites the local composition into the full wire
//! handle the message would already carry. The server cannot distinguish a
//! mention-bearing message from any other chat message (ISC-A-C4).
//!
//! ## Recognition (ISC-C17)
//!
//! Recognition keys on the recipient's **full wire handle** (`<name>#<prefix>`
//! or floor `#<prefix>`), never the display name alone — so a daemon sharing
//! only a display name with the recipient cannot trip a false notification by
//! spelling the name. The wire form of a mention always carries the full
//! handle (ISC-C18), so scanning for `@<full-handle>` is exact.
//!
//! ## Resolution (ISC-C18)
//!
//! A typed token is resolved against the in-scope handles: a fully-qualified
//! `@<name>#<prefix>` (or floor `@#<prefix>`) bypasses autocomplete and
//! resolves directly (power-user path); a bare `@<name>` resolves by exact
//! display-name match — one match resolves silently, several return the
//! candidates (the UI renders prefixes to disambiguate), none is not-found.

use core::ops::Range;

use crate::handle::Handle;

/// Byte range in the scanned plaintext covering one `@<full-handle>` mention.
pub type MentionSpan = Range<usize>;

/// Find every mention of `own_handle` in already-decrypted chat `plaintext`
/// (ISC-C17). Returns the byte range of each `@<full-handle>` occurrence, in
/// left-to-right order.
///
/// A match requires the `@` to sit at a word boundary (not preceded by an
/// alphanumeric, so `user@name#hex` email-style text is not a mention) and the
/// 12-hex prefix to terminate cleanly (the following character, if any, is not
/// a hex digit — otherwise the text names a *different*, longer prefix).
pub fn find_self_mentions(plaintext: &str, own_handle: &Handle) -> Vec<MentionSpan> {
    let needle = format!("@{own_handle}");
    plaintext
        .match_indices(&needle)
        .filter_map(|(start, m)| {
            let end = start + m.len();
            // Leading boundary: the char before '@' must not be alphanumeric,
            // so `user@name#hex` email-style text is not treated as a mention.
            let leading_ok = plaintext[..start]
                .chars()
                .next_back()
                .is_none_or(|c| !c.is_alphanumeric());
            // Trailing boundary: the char after the 12-hex prefix must not be a
            // hex digit, else the text names a different (longer) prefix.
            let trailing_ok = plaintext[end..]
                .chars()
                .next()
                .is_none_or(|c| !c.is_ascii_hexdigit());
            (leading_ok && trailing_ok).then_some(start..end)
        })
        .collect()
}

/// Outcome of resolving a typed `@…` token against in-scope handles (ISC-C18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MentionResolution {
    /// Exactly one match (or an explicitly-typed full handle): resolved.
    Resolved(Handle),
    /// Several display-name matches; the UI must disambiguate by prefix.
    Ambiguous(Vec<Handle>),
    /// No match in scope.
    NotFound,
}

/// Resolve a typed mention token (`typed` = the text after `@`) against the
/// `scope` of currently-reachable handles (ISC-C18).
pub fn resolve_mention(typed: &str, scope: &[Handle]) -> MentionResolution {
    // Explicit path: a fully-qualified handle bypasses autocomplete entirely.
    if let Ok(handle) = typed.parse::<Handle>() {
        return MentionResolution::Resolved(handle);
    }
    // Autocomplete path: exact display-name match against the in-scope handles.
    let matches: Vec<Handle> = scope
        .iter()
        .filter(|h| h.display_name() == Some(typed))
        .cloned()
        .collect();
    match matches.len() {
        0 => MentionResolution::NotFound,
        1 => MentionResolution::Resolved(matches.into_iter().next().unwrap()),
        _ => MentionResolution::Ambiguous(matches),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Handle {
        s.parse().expect("valid test handle")
    }

    // ── recognition (ISC-C17) ──────────────────────────────────────────────

    #[test]
    fn recognizes_full_handle_mention() {
        let own = h("alice#aabbccddeeff");
        let text = "hey @alice#aabbccddeeff how are you";
        let spans = find_self_mentions(text, &own);
        assert_eq!(spans.len(), 1);
        assert_eq!(&text[spans[0].clone()], "@alice#aabbccddeeff");
    }

    #[test]
    fn recognizes_floor_handle_mention() {
        let own = h("#001122334455");
        let text = "ping @#001122334455 please";
        let spans = find_self_mentions(text, &own);
        assert_eq!(spans.len(), 1);
        assert_eq!(&text[spans[0].clone()], "@#001122334455");
    }

    #[test]
    fn recognition_keys_on_full_handle_not_display_name() {
        let own = h("alice#aabbccddeeff");
        // Same display name, different prefix → NOT me.
        assert!(find_self_mentions("@alice#ffffffffffff hi", &own).is_empty());
        // Display name only, no prefix → NOT a full-handle mention.
        assert!(find_self_mentions("@alice hi", &own).is_empty());
    }

    #[test]
    fn recognition_ignores_email_like_at() {
        let own = h("alice#aabbccddeeff");
        // '@' preceded by an alphanumeric is not a mention boundary.
        assert!(find_self_mentions("write bob@alice#aabbccddeeff", &own).is_empty());
    }

    #[test]
    fn recognition_rejects_trailing_hex_digit() {
        let own = h("alice#aabbccddeeff");
        // A trailing hex digit means the real handle has a longer prefix.
        assert!(find_self_mentions("@alice#aabbccddeeffab here", &own).is_empty());
    }

    #[test]
    fn recognition_allows_trailing_punctuation() {
        let own = h("alice#aabbccddeeff");
        let spans = find_self_mentions("thanks @alice#aabbccddeeff!", &own);
        assert_eq!(spans.len(), 1);
    }

    #[test]
    fn recognizes_multiple_mentions() {
        let own = h("alice#aabbccddeeff");
        let text = "@alice#aabbccddeeff and again @alice#aabbccddeeff";
        assert_eq!(find_self_mentions(text, &own).len(), 2);
    }

    // ── resolution (ISC-C18) ───────────────────────────────────────────────

    #[test]
    fn resolve_single_display_name_match() {
        let scope = [h("alice#aabbccddeeff"), h("bob#ccddeeff0011")];
        assert_eq!(
            resolve_mention("alice", &scope),
            MentionResolution::Resolved(h("alice#aabbccddeeff"))
        );
    }

    #[test]
    fn resolve_ambiguous_display_name_returns_candidates() {
        let scope = [h("alice#aabbccddeeff"), h("alice#ccddeeff0011")];
        match resolve_mention("alice", &scope) {
            MentionResolution::Ambiguous(cands) => assert_eq!(cands.len(), 2),
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn resolve_not_found() {
        let scope = [h("alice#aabbccddeeff")];
        assert_eq!(
            resolve_mention("carol", &scope),
            MentionResolution::NotFound
        );
    }

    #[test]
    fn resolve_explicit_full_handle_bypasses_autocomplete() {
        // Power user typed the full handle directly — resolves even with an
        // empty scope.
        assert_eq!(
            resolve_mention("alice#aabbccddeeff", &[]),
            MentionResolution::Resolved(h("alice#aabbccddeeff"))
        );
    }

    #[test]
    fn resolve_explicit_floor_handle_bypasses_autocomplete() {
        assert_eq!(
            resolve_mention("#001122334455", &[]),
            MentionResolution::Resolved(h("#001122334455"))
        );
    }
}
