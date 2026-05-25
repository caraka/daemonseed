//! Introducer-response construction (ISC-S6 / ISC-S13 / ISC-A-S7).
//!
//! [`introducer_response`] turns the operator's configured `[[peer]]` table
//! into an [`IntroducerResponse`] for a requesting client OR a peering server —
//! the same function serves both, because the no-keys + suppression rules are
//! identical on each path (ISC-S6, ISC-S12 introductions).
//!
//! Three invariants are enforced here, and the test suite is project-lifetime
//! regression surface:
//!
//! - **No keys (ISC-S6).** The response never carries a public key. This is
//!   structural — [`PeerTriple`] has no key field — so this module physically
//!   cannot leak one; the tests assert the shape stays that way.
//! - **Introduce-to-clients suppression (ISC-S13).** A peer with
//!   `introduce_to_clients = false` is omitted from every response.
//! - **Don't-introduce indistinguishability (ISC-A-S7).** A by-id query for a
//!   suppressed peer returns the *same* empty response as a query for a
//!   genuinely-unknown peer, so an active attacker cannot confirm a suspected
//!   peer's existence by asking for it.

use daemonseed_proto::v1::{IntroducerQuery, IntroducerResponse, PeerTriple};

use crate::config::PeerConfig;

/// Build the introducer response for `query` from the configured `peers`.
///
/// An empty / unset `target_server_id` returns the full list of
/// introduce-to-clients peers; a populated one returns just that peer's triple
/// if it is both known and introducible, otherwise an empty list (ISC-A-S7).
pub fn introducer_response(peers: &[PeerConfig], query: &IntroducerQuery) -> IntroducerResponse {
    let target = query.target_server_id.as_deref().filter(|t| !t.is_empty());

    let triples = peers
        .iter()
        // ISC-S13: never reveal a don't-introduce peer.
        .filter(|p| p.introduce_to_clients)
        // ISC-S6-11: a by-id query narrows to the exact match; no target
        // returns the whole (already-filtered) list.
        .filter(|p| target.is_none_or(|t| p.server_id == t))
        .map(to_triple)
        .collect();

    IntroducerResponse { peers: triples }
}

/// Project a configured peer to a wire triple. `last_known_availability` is
/// left unset: the RAM-only availability producer is deferred past MVP (finding
/// F15). The full key is deliberately absent (ISC-S6) — `PeerTriple` has no
/// field for it.
fn to_triple(p: &PeerConfig) -> PeerTriple {
    PeerTriple {
        server_id: p.server_id.clone(),
        address: p.address.clone(),
        last_known_availability_unix_ms: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemonseed_core::federation::trust::TrustMode;

    fn peer(server_id: &str, introduce: bool) -> PeerConfig {
        PeerConfig {
            server_id: server_id.to_owned(),
            address: format!("{server_id}.example:443"),
            trust_mode: TrustMode::Trusted,
            introduce_to_clients: introduce,
            key_hex: None,
        }
    }

    fn list_query() -> IntroducerQuery {
        IntroducerQuery {
            target_server_id: None,
        }
    }

    fn by_id(id: &str) -> IntroducerQuery {
        IntroducerQuery {
            target_server_id: Some(id.to_owned()),
        }
    }

    #[test]
    fn full_list_returns_all_introducible_peers() {
        let peers = vec![peer("a#0123456789ab", true), peer("b#0123456789ab", true)];
        let resp = introducer_response(&peers, &list_query());
        assert_eq!(resp.peers.len(), 2);
    }

    #[test]
    fn full_list_excludes_dont_introduce_peers() {
        let peers = vec![
            peer("a#0123456789ab", true),
            peer("secret#0123456789ab", false),
        ];
        let resp = introducer_response(&peers, &list_query());
        assert_eq!(resp.peers.len(), 1);
        assert_eq!(resp.peers[0].server_id, "a#0123456789ab");
    }

    #[test]
    fn by_id_known_introducible_returns_one_triple() {
        let peers = vec![peer("a#0123456789ab", true), peer("b#0123456789ab", true)];
        let resp = introducer_response(&peers, &by_id("b#0123456789ab"));
        assert_eq!(resp.peers.len(), 1);
        assert_eq!(resp.peers[0].server_id, "b#0123456789ab");
    }

    #[test]
    fn by_id_dont_introduce_peer_returns_empty() {
        // ISC-A-S7: a suppressed peer must look identical to an absent one.
        let peers = vec![peer("secret#0123456789ab", false)];
        let resp = introducer_response(&peers, &by_id("secret#0123456789ab"));
        assert!(resp.peers.is_empty());
    }

    #[test]
    fn by_id_unknown_peer_returns_empty() {
        let peers = vec![peer("a#0123456789ab", true)];
        let resp = introducer_response(&peers, &by_id("nobody#000000000000"));
        assert!(resp.peers.is_empty());
    }

    #[test]
    fn dont_introduce_and_unknown_responses_are_identical() {
        // The CVE-class assertion: an active enumerator querying a suspected
        // suppressed peer gets a byte-identical response to querying a name
        // that was never configured.
        let peers = vec![peer("secret#0123456789ab", false)];
        let suppressed = introducer_response(&peers, &by_id("secret#0123456789ab"));
        let unknown = introducer_response(&peers, &by_id("phantom#0123456789ab"));
        assert_eq!(suppressed, unknown);
    }

    #[test]
    fn triple_omits_availability_at_mvp() {
        // F15: no availability producer yet → field stays None on the wire.
        let peers = vec![peer("a#0123456789ab", true)];
        let resp = introducer_response(&peers, &list_query());
        assert_eq!(resp.peers[0].last_known_availability_unix_ms, None);
    }
}
