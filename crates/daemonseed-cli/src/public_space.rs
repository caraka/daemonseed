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
//! - [`verify_served_post`] / [`verify_served_motd`] — the client half of
//!   verify-and-serve (ISC-A-S3): re-run the *same* `verify_artifact` the
//!   server did against the published whitelist ([`whitelist_from_wire`]) and
//!   re-derive the content address, trusting nothing the server asserts. The
//!   live fetch loop that calls these lands with the CLI's gRPC transport;
//!   the verification itself is wired and tested here.

use core::str::FromStr;

use daemonseed_core::handle::{Handle, HandleParseError};
use daemonseed_core::public_space::{
    ArtifactError, Whitelist, WhitelistEntry, WhitelistParseError, verify_artifact,
};
use daemonseed_core::share_catalog::ShareListing;
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
    shares: &'a [ShareListing],
    rating: Option<&str>,
) -> Vec<&'a ShareListing> {
    shares
        .iter()
        .filter(|s| rating.is_none_or(|r| s.rating == r))
        .collect()
}

/// Drop any [`ShareListing`] whose sharer wire handle is in
/// `hidden` (ISC-C16 / ISC-A-C3).
///
/// Pairs with [`filter_shares_by_rating`]: the rating filter is operator-
/// taxonomy-scoped, this one is recipient-private-scoped. Both are applied
/// client-side; neither leaves the client (no wire field carries either set —
/// the relay must not know who a recipient hides). `hidden` is the
/// [`Seeds::hidden_shares`] set or a clone of it.
///
/// A listing with an empty `sharer_handle` is always kept: legacy /
/// operator-pinned listings predate the additive-MINOR field, and an empty
/// handle cannot meaningfully match any concrete hidden-handle entry. This
/// behaviour mirrors `is_share_hidden`'s point-query semantics, just lifted
/// to a list-filter shape.
///
/// [`Seeds::hidden_shares`]: daemonseed_core::storage::seeds::Seeds::hidden_shares
pub fn filter_shares_excluding_hidden<'a>(
    shares: &'a [ShareListing],
    hidden: &std::collections::BTreeSet<String>,
) -> Vec<&'a ShareListing> {
    shares
        .iter()
        .filter(|s| s.sharer_handle.is_empty() || !hidden.contains(&s.sharer_handle))
        .collect()
}

// ── Client re-verification (ISC-A-S3 client half) ────────────────────────

/// Why converting the published wire whitelist failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhitelistConvertError {
    /// A `SignerWhitelistEntry` had no `entry` oneof set.
    EmptyEntry,
    /// A full-key entry was the wrong length.
    BadKey(WhitelistParseError),
    /// A handle entry didn't parse as `<name>#<hash>`.
    BadHandle(HandleParseError),
}

/// Build a [`Whitelist`] from the wire entries a client fetched via
/// `GetSignerWhitelist` (ISC-S8 / ISC-6), optionally augmented with the
/// server's own key for MOTD verification (ISC-26 — pass the server pubkey the
/// client authenticated during identity-proof; `None` for the post whitelist).
pub fn whitelist_from_wire(
    entries: &[wire::SignerWhitelistEntry],
    server_pubkey: Option<&[u8]>,
) -> Result<Whitelist, WhitelistConvertError> {
    use wire::signer_whitelist_entry::Entry;
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        match e.entry.as_ref() {
            Some(Entry::FullPubkey(bytes)) => {
                out.push(
                    WhitelistEntry::from_full_key_bytes(bytes)
                        .map_err(WhitelistConvertError::BadKey)?,
                );
            }
            Some(Entry::Handle(h)) => {
                out.push(WhitelistEntry::Handle(
                    Handle::from_str(h).map_err(WhitelistConvertError::BadHandle)?,
                ));
            }
            None => return Err(WhitelistConvertError::EmptyEntry),
        }
    }
    if let Some(pk) = server_pubkey {
        out.push(WhitelistEntry::from_full_key_bytes(pk).map_err(WhitelistConvertError::BadKey)?);
    }
    Ok(Whitelist::from_entries(out))
}

/// Decode a served post's inner payload into `(topic, body, signed_timestamp_ms)`
/// for client rendering (ISC-S7). A payload that fails to decode renders as
/// empty — the server validated it as a `PostPayload` at upload time
/// (ISC-A-S3); this is belt-and-suspenders so a malformed post can never panic
/// a rendering client. Provenance is a separate concern: pair this with
/// [`verify_served_post`] to learn whether the post is whitelist-authorized.
pub fn post_render_fields(post: &wire::Post) -> (String, String, i64) {
    post.artifact
        .as_ref()
        .and_then(|a| wire::PostPayload::decode(a.signed_payload.as_slice()).ok())
        .map(|p| (p.topic, p.body, p.signed_timestamp_ms))
        .unwrap_or_default()
}

/// Why a server-served artifact failed client re-verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServedVerifyError {
    /// A `Post` carried no `artifact`.
    Missing,
    /// Signature / whitelist verification failed.
    Verify(ArtifactError),
    /// The server-asserted content address didn't match the client-derived one.
    AddressMismatch,
}

/// Re-verify a post the server served (ISC-A-S3 client half): the client
/// trusts NOTHING the server asserts. It re-runs the same `verify_artifact` the
/// server did AND re-derives the content address, rejecting any mismatch — so a
/// server that substitutes or mutates a post is detected client-side.
pub fn verify_served_post(
    post: &wire::Post,
    whitelist: &Whitelist,
) -> Result<(), ServedVerifyError> {
    let artifact = post.artifact.as_ref().ok_or(ServedVerifyError::Missing)?;
    let derived = verify_artifact(
        &artifact.signed_payload,
        &artifact.signer_pubkey,
        &artifact.signature,
        whitelist,
    )
    .map_err(ServedVerifyError::Verify)?;
    if derived.as_bytes().as_slice() != post.content_address.as_slice() {
        return Err(ServedVerifyError::AddressMismatch);
    }
    Ok(())
}

/// Re-verify a server-served MOTD (ISC-A-S3 client half / ISC-26). `whitelist`
/// must include the server's own key (build it via [`whitelist_from_wire`] with
/// `server_pubkey = Some(..)`), since a MOTD may be server-signed.
pub fn verify_served_motd(
    motd: &wire::SignedArtifact,
    whitelist: &Whitelist,
) -> Result<(), ServedVerifyError> {
    verify_artifact(
        &motd.signed_payload,
        &motd.signer_pubkey,
        &motd.signature,
        whitelist,
    )
    .map(|_| ())
    .map_err(ServedVerifyError::Verify)
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

    fn share(id: &str, rating: &str) -> ShareListing {
        share_with_handle(id, rating, "")
    }

    fn share_with_handle(id: &str, rating: &str, sharer_handle: &str) -> ShareListing {
        ShareListing {
            share_id: id.to_owned(),
            name: format!("share-{id}"),
            rating: rating.to_owned(),
            sharer_handle: sharer_handle.to_owned(),
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

    // ── filter_shares_excluding_hidden (ISC-C16 / ISC-A-C3) ──────────────

    #[test]
    fn filter_hidden_empty_set_returns_all() {
        let shares = vec![
            share_with_handle("a", "PG13", "alice#aabbccddeeff"),
            share_with_handle("b", "R", "bob#001122334455"),
        ];
        let hidden = std::collections::BTreeSet::new();
        assert_eq!(
            filter_shares_excluding_hidden(&shares, &hidden).len(),
            2,
            "empty hide set: nothing filtered"
        );
    }

    #[test]
    fn filter_hidden_drops_listed_sharer() {
        let shares = vec![
            share_with_handle("a", "PG13", "alice#aabbccddeeff"),
            share_with_handle("b", "R", "bob#001122334455"),
            share_with_handle("c", "PG13", "alice#aabbccddeeff"),
        ];
        let mut hidden = std::collections::BTreeSet::new();
        hidden.insert("alice#aabbccddeeff".to_owned());
        let filtered = filter_shares_excluding_hidden(&shares, &hidden);
        assert_eq!(filtered.len(), 1, "only Bob's listing survives");
        assert_eq!(filtered[0].sharer_handle, "bob#001122334455");
    }

    #[test]
    fn filter_hidden_keeps_empty_sharer_handle() {
        // Legacy / operator-pinned listings predate the additive-MINOR
        // sharer_handle field. An empty handle can't match a concrete entry
        // in the hide set and must always render.
        let shares = vec![
            share_with_handle("operator-pin", "", ""),
            share_with_handle("alice-1", "PG13", "alice#aabbccddeeff"),
        ];
        let mut hidden = std::collections::BTreeSet::new();
        hidden.insert("alice#aabbccddeeff".to_owned());
        let filtered = filter_shares_excluding_hidden(&shares, &hidden);
        assert_eq!(filtered.len(), 1, "operator-pinned listing kept");
        assert_eq!(filtered[0].share_id, "operator-pin");
    }

    #[test]
    fn filter_hidden_composes_with_rating_filter() {
        // Both filters are client-side, neither leaves the client; they
        // compose as set-intersections regardless of order.
        let shares = vec![
            share_with_handle("a", "PG13", "alice#aabbccddeeff"),
            share_with_handle("b", "R", "alice#aabbccddeeff"),
            share_with_handle("c", "PG13", "bob#001122334455"),
        ];
        let mut hidden = std::collections::BTreeSet::new();
        hidden.insert("alice#aabbccddeeff".to_owned());
        let after_hide = filter_shares_excluding_hidden(&shares, &hidden);
        assert_eq!(after_hide.len(), 1);
        // Re-collect references through the rating predicate on the same
        // borrowed slice — establishes the order-independence.
        let after_hide_owned: Vec<ShareListing> = after_hide.into_iter().cloned().collect();
        let after_both = filter_shares_by_rating(&after_hide_owned, Some("PG13"));
        assert_eq!(after_both.len(), 1);
        assert_eq!(after_both[0].share_id, "c");
    }

    // ── Client re-verification (ISC-A-S3 client half) ────────────────────

    use daemonseed_core::identity::keys::SignKeypair;

    fn keypair(seed: u8) -> SignKeypair {
        let _ = oxicrypt_module::initialize();
        SignKeypair::from_ml_dsa_seed(&[seed; 32]).unwrap()
    }

    fn wire_full_key(signer: &SignKeypair) -> wire::SignerWhitelistEntry {
        wire::SignerWhitelistEntry {
            entry: Some(wire::signer_whitelist_entry::Entry::FullPubkey(
                signer.public_key().to_vec(),
            )),
        }
    }

    /// A signed Post with a correctly-derived server-asserted content address.
    fn served_post(signer: &SignKeypair, body: &str) -> wire::Post {
        let payload = wire::PostPayload {
            topic: "announcements".to_owned(),
            body: body.to_owned(),
            signed_timestamp_ms: 1,
        };
        let signed_payload = payload.encode_to_vec();
        let signature = signer.sign(&signed_payload).unwrap().to_vec();
        let address = daemonseed_core::public_space::content_address(&signed_payload).unwrap();
        wire::Post {
            artifact: Some(wire::SignedArtifact {
                signed_payload,
                signer_pubkey: signer.public_key().to_vec(),
                signature,
            }),
            content_address: address.as_bytes().to_vec(),
        }
    }

    #[test]
    fn whitelist_from_wire_handles_full_key_and_handle() {
        let signer = keypair(70);
        let handle_entry = wire::SignerWhitelistEntry {
            entry: Some(wire::signer_whitelist_entry::Entry::Handle(
                "relay-bear#aabbccddeeff".to_owned(),
            )),
        };
        let wl = whitelist_from_wire(&[wire_full_key(&signer), handle_entry], None).unwrap();
        assert!(wl.authorizes(signer.public_key()).unwrap());
    }

    #[test]
    fn verify_served_post_accepts_correct_artifact() {
        let signer = keypair(71);
        let wl = whitelist_from_wire(&[wire_full_key(&signer)], None).unwrap();
        let post = served_post(&signer, "hello");
        assert_eq!(verify_served_post(&post, &wl), Ok(()));
    }

    #[test]
    fn verify_served_post_rejects_address_mismatch() {
        // A server that serves a real post under a lying content address.
        let signer = keypair(72);
        let wl = whitelist_from_wire(&[wire_full_key(&signer)], None).unwrap();
        let mut post = served_post(&signer, "hello");
        post.content_address = vec![0u8; 48];
        assert_eq!(
            verify_served_post(&post, &wl),
            Err(ServedVerifyError::AddressMismatch)
        );
    }

    #[test]
    fn verify_served_post_rejects_unknown_signer() {
        let signer = keypair(73);
        let stranger = keypair(74);
        let wl = whitelist_from_wire(&[wire_full_key(&stranger)], None).unwrap();
        let post = served_post(&signer, "forged-by-relay");
        assert_eq!(
            verify_served_post(&post, &wl),
            Err(ServedVerifyError::Verify(ArtifactError::UnknownSigner))
        );
    }

    #[test]
    fn verify_served_motd_accepts_server_signed() {
        // MOTD signed by the server key, which is NOT an operator whitelist
        // entry — the client adds it via server_pubkey (ISC-26).
        let server = keypair(75);
        let wl = whitelist_from_wire(&[], Some(server.public_key())).unwrap();
        let payload = wire::MotdPayload {
            text: "welcome".to_owned(),
            signed_timestamp_ms: 1,
        };
        let signed_payload = payload.encode_to_vec();
        let signature = server.sign(&signed_payload).unwrap().to_vec();
        let motd = wire::SignedArtifact {
            signed_payload,
            signer_pubkey: server.public_key().to_vec(),
            signature,
        };
        assert_eq!(verify_served_motd(&motd, &wl), Ok(()));
    }
}
