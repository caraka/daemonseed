//! Client-side public-space data handling (M6).
//!
//! The transport — opening a `PublicSpaceClient` over the post-Authenticated
//! connection — is the thin layer the server's own round-trip test already
//! validates end-to-end. This module holds the client's *data* plumbing that
//! is independent of transport and is the M6 "plumbing only" scope (D-M6-1):
//!
//! - [`render_motd`] — render a signed MOTD as inert plaintext (ISC-25): no
//!   markup is interpreted and terminal control sequences are stripped, so a
//!   (legitimately-signed) MOTD cannot smuggle ANSI escapes into the client's
//!   terminal.
//! - [`select_rating`] — choose a rating from the *active server's* taxonomy
//!   (ISC-30); a choice outside that taxonomy is rejected, which is the
//!   public-space half of active-server scoping (ISC-31 / F20 — the active
//!   server is the connected host).
//! - [`filter_shares_by_rating`] — the rating filter predicate (ISC-32 /
//!   ISC-A-C5), applied both when rendering a listing and when fetching it
//!   (same predicate, two call sites). Share *content* arrives at M8; M6 wires
//!   the selection/filter surface only.

use daemonseed_proto::v1 as wire;
use prost::Message;

/// Render a signed MOTD as inert plaintext for a terminal client (ISC-25).
///
/// The text is shown verbatim except that terminal control sequences are
/// stripped (ESC and other C0/C1 control chars, keeping `\n` and `\t`), so a
/// signed MOTD cannot inject ANSI escapes — a signature proves *who wrote it*,
/// not that the bytes are safe to feed a terminal. No markdown/HTML/link
/// interpretation happens; the client never makes the text clickable.
///
/// A payload that fails to decode renders as empty (the server already
/// validated it as a `MotdPayload` at load time; this is belt-and-suspenders).
pub fn render_motd(motd: &wire::SignedArtifact) -> String {
    let text = wire::MotdPayload::decode(motd.signed_payload.as_slice())
        .map(|p| p.text)
        .unwrap_or_default();
    sanitize_plaintext(&text)
}

/// Strip terminal-unsafe control characters, keeping newlines and tabs.
fn sanitize_plaintext(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

/// Errors selecting a rating from the active taxonomy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RatingError {
    /// The chosen label is not in the active server's taxonomy.
    NotInTaxonomy,
}

/// Choose `choice` as a rating, but only if it is one the active server's
/// taxonomy defines (ISC-30 / ISC-31). Rejecting an out-of-taxonomy choice is
/// the public-space half of active-server scoping: a client cannot tag with a
/// rating the host you are connected to does not publish.
pub fn select_rating(taxonomy: &[String], choice: &str) -> Result<String, RatingError> {
    if taxonomy.iter().any(|label| label == choice) {
        Ok(choice.to_owned())
    } else {
        Err(RatingError::NotInTaxonomy)
    }
}

/// Filter a public-share listing by rating (ISC-32 / ISC-A-C5). `None` returns
/// everything; `Some(label)` keeps only shares carrying that advisory rating.
///
/// The server never filters by rating (ISC-A-S5b); this same predicate is the
/// client's filter at BOTH render time (the displayed subset) and fetch time
/// (which results to keep). Share content/transfer is M8 — in M6 this operates
/// on the (currently empty) listing surface.
pub fn filter_shares_by_rating<'a>(
    shares: &'a [wire::PublicShareListing],
    rating: Option<&str>,
) -> Vec<&'a wire::PublicShareListing> {
    shares
        .iter()
        .filter(|s| rating.is_none_or(|r| s.rating == r))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn motd(text: &str) -> wire::SignedArtifact {
        let payload = wire::MotdPayload {
            text: text.to_owned(),
            signed_timestamp_ms: 1,
        };
        wire::SignedArtifact {
            signed_payload: payload.encode_to_vec(),
            signer_pubkey: vec![],
            signature: vec![],
        }
    }

    fn share(id: &str, rating: &str) -> wire::PublicShareListing {
        wire::PublicShareListing {
            share_id: id.to_owned(),
            name: format!("share-{id}"),
            rating: rating.to_owned(),
        }
    }

    // ── render_motd (ISC-25) ─────────────────────────────────────────────

    #[test]
    fn render_motd_returns_text() {
        assert_eq!(
            render_motd(&motd("welcome to the relay")),
            "welcome to the relay"
        );
    }

    #[test]
    fn render_motd_strips_terminal_escapes() {
        // A signed MOTD must not be able to inject ANSI escape sequences.
        let rendered = render_motd(&motd("safe\x1b[31mRED\x1b[0mtext"));
        assert!(!rendered.contains('\x1b'), "ESC stripped: {rendered:?}");
        assert_eq!(rendered, "safe[31mRED[0mtext");
    }

    #[test]
    fn render_motd_keeps_newlines_and_tabs() {
        assert_eq!(render_motd(&motd("line1\nline2\tcol")), "line1\nline2\tcol");
    }

    // ── select_rating (ISC-30 / ISC-31) ──────────────────────────────────

    #[test]
    fn select_rating_accepts_in_taxonomy() {
        let taxonomy = vec!["PG13".to_owned(), "R".to_owned()];
        assert_eq!(select_rating(&taxonomy, "R"), Ok("R".to_owned()));
    }

    #[test]
    fn select_rating_rejects_out_of_taxonomy() {
        // Active-server scoping: can't pick a rating the host doesn't publish.
        let taxonomy = vec!["PG13".to_owned()];
        assert_eq!(
            select_rating(&taxonomy, "X"),
            Err(RatingError::NotInTaxonomy)
        );
    }

    // ── filter_shares_by_rating (ISC-32) ─────────────────────────────────

    #[test]
    fn filter_shares_none_returns_all() {
        let shares = vec![share("a", "PG13"), share("b", "R")];
        assert_eq!(filter_shares_by_rating(&shares, None).len(), 2);
    }

    #[test]
    fn filter_shares_keeps_only_matching_rating() {
        let shares = vec![share("a", "PG13"), share("b", "R"), share("c", "PG13")];
        let filtered = filter_shares_by_rating(&shares, Some("PG13"));
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|s| s.rating == "PG13"));
    }
}
