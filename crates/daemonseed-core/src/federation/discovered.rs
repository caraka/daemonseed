//! Introducer-discovered peers (M12, gate step 6 — client side).
//!
//! A relay's introducer answer is **discovery only**: it carries
//! `(server-id, address)` pairs, never keys (ISC-S6). Recording one here is a
//! no-op against trust — the peer becomes a *candidate* the user may later
//! promote (ISC-C22: "treated identically to manual entry — never auto-trusted
//! from the introduction"). Promotion is an explicit user action that chooses
//! the trust mode; the key is established only then, by the client's own trust
//! machinery on first contact ([`super::store::apply_trust`]).
//!
//! This separation is the structural guard the precautionary design buys: a
//! relay you connect to can *suggest* addresses, but cannot push anything into
//! your active [`TrustStore`] — so it can never get a key it controls silently
//! trusted by populating your server set. It mirrors ISC-A-C19's refusal to do
//! introducer auto-discovery at first-start, extended to the post-bootstrap
//! refresh: discovery never auto-trusts, at any point in the client lifecycle.

use std::collections::BTreeMap;

use daemonseed_proto::v1::IntroducerResponse;

use crate::federation::store::{ServerEntry, TrustStore};
use crate::handle::Handle;

/// A peer learned from an introducer but NOT in the active federation set — a
/// candidate only, known-of but never trusted or connected to until promoted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredPeer {
    /// The discovered server-id (`<name>#<12hex>`). The 12-hex suffix is a hash
    /// fingerprint, NOT a key (ISC-S6) — the key is established only on promote.
    pub server_id: Handle,
    /// The reachable address the introducer reported (hostname or IP literal,
    /// optional `:port`).
    pub address: String,
}

/// Per-merge tally: what a single refresh actually did, for the refresh UX and
/// the gate assertion. Re-discovering an already-known or already-candidate
/// peer is intentionally a no-op, so a repeated refresh converges (idempotent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MergeOutcome {
    /// Genuinely-new candidates recorded this merge.
    pub added: usize,
    /// Skipped: the server is already in the active [`TrustStore`] (including
    /// the relay we are currently connected to — re-learning it is a no-op).
    pub skipped_known: usize,
    /// Skipped: already a pending candidate from an earlier refresh.
    pub skipped_duplicate: usize,
    /// Dropped: the server-id did not parse as `<name>#<12hex>`.
    pub malformed: usize,
}

/// The client's RAM-only cache of introducer-discovered peer candidates, keyed
/// by canonical server-id string. Deliberately distinct from the active
/// [`TrustStore`]: nothing here is trusted or connectable until promoted.
/// RAM-only, mirroring the M5 trust-store persistence deferral.
#[derive(Debug, Default, Clone)]
pub struct DiscoveredPeers {
    peers: BTreeMap<String, DiscoveredPeer>,
}

impl DiscoveredPeers {
    /// An empty candidate cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of pending candidates.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether there are no pending candidates.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// The candidates, in canonical server-id order.
    pub fn iter(&self) -> impl Iterator<Item = &DiscoveredPeer> {
        self.peers.values()
    }

    /// The candidate for `server_id`, if discovered and not yet promoted.
    pub fn get(&self, server_id: &Handle) -> Option<&DiscoveredPeer> {
        self.peers.get(&server_id.to_string())
    }

    /// Merge an introducer response into the candidate cache — the refresh.
    ///
    /// Precautionary (ISC-C22 / ISC-A-C19): records candidates ONLY and never
    /// mutates `known` — discovery is decoupled from trust. A triple is recorded
    /// iff its server-id parses, is not already in the active `known` store, and
    /// is not already a candidate. Server-side filtering already excluded every
    /// `introduce_to_clients=false` peer (ISC-S13), so suppressed peers never
    /// reach this merge. Returns a per-merge tally.
    pub fn merge(&mut self, response: &IntroducerResponse, known: &dyn TrustStore) -> MergeOutcome {
        let mut out = MergeOutcome::default();
        for triple in &response.peers {
            let Ok(server_id) = triple.server_id.parse::<Handle>() else {
                out.malformed += 1;
                continue;
            };
            if known.get(&server_id).is_some() {
                out.skipped_known += 1;
                continue;
            }
            let key = server_id.to_string();
            if self.peers.contains_key(&key) {
                out.skipped_duplicate += 1;
                continue;
            }
            self.peers.insert(
                key,
                DiscoveredPeer {
                    server_id,
                    address: triple.address.clone(),
                },
            );
            out.added += 1;
        }
        out
    }

    /// Promote a candidate into the active federation set in TRUSTED mode —
    /// identical to a manual trusted add (ISC-C22): no pin yet, the key is
    /// verified by the first-contact hash check on the next connection. Removes
    /// the candidate and returns the new entry; `None` if `server_id` is not a
    /// pending candidate.
    pub fn promote_trusted(
        &mut self,
        server_id: &Handle,
        store: &mut dyn TrustStore,
    ) -> Option<ServerEntry> {
        let peer = self.peers.remove(&server_id.to_string())?;
        let entry = ServerEntry::new_trusted(peer.server_id, peer.address);
        store.upsert(entry.clone());
        Some(entry)
    }

    /// Promote a candidate in UNTRUSTED mode with the out-of-band `configured_key`
    /// the user supplies — identical to a manual untrusted add (ISC-C22): the key
    /// must match byte-for-byte on connect. Removes the candidate and returns the
    /// new entry; `None` if `server_id` is not a pending candidate.
    pub fn promote_untrusted(
        &mut self,
        server_id: &Handle,
        configured_key: Vec<u8>,
        store: &mut dyn TrustStore,
    ) -> Option<ServerEntry> {
        let peer = self.peers.remove(&server_id.to_string())?;
        let entry = ServerEntry::new_untrusted(peer.server_id, peer.address, configured_key);
        store.upsert(entry.clone());
        Some(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::store::InMemoryTrustStore;
    use crate::federation::trust::TrustMode;
    use daemonseed_proto::v1::PeerTriple;

    fn ensure_module() {
        let _ = oxicrypt_module::initialize();
    }

    /// A server-id Handle from a fake key, plus its canonical string form.
    fn server(name: &str, key: &[u8]) -> Handle {
        ensure_module();
        Handle::from_pubkey(Some(name.to_owned()), key).unwrap()
    }

    fn triple(server_id: &Handle, address: &str) -> PeerTriple {
        PeerTriple {
            server_id: server_id.to_string(),
            address: address.to_owned(),
            last_known_availability_unix_ms: None,
        }
    }

    fn response(triples: Vec<PeerTriple>) -> IntroducerResponse {
        IntroducerResponse { peers: triples }
    }

    #[test]
    fn merge_records_new_candidates() {
        let a = server("a", &[1u8; 32]);
        let b = server("b", &[2u8; 32]);
        let known = InMemoryTrustStore::new();
        let mut disc = DiscoveredPeers::new();

        let out = disc.merge(
            &response(vec![triple(&a, "a.example:443"), triple(&b, "b.example")]),
            &known,
        );
        assert_eq!(out.added, 2);
        assert_eq!(disc.len(), 2);
        assert_eq!(disc.get(&a).unwrap().address, "a.example:443");
    }

    #[test]
    fn merge_never_touches_the_trust_store() {
        // The precautionary invariant: discovery records candidates only and
        // never writes the active set (ISC-C22 / ISC-A-C19).
        let a = server("a", &[1u8; 32]);
        let known = InMemoryTrustStore::new();
        let mut disc = DiscoveredPeers::new();
        disc.merge(&response(vec![triple(&a, "a.example:443")]), &known);
        assert!(
            known.get(&a).is_none(),
            "discovery must not add to the trust store"
        );
    }

    #[test]
    fn merge_skips_already_known_servers() {
        let a = server("a", &[1u8; 32]);
        let mut known = InMemoryTrustStore::new();
        known.upsert(ServerEntry::new_trusted(a.clone(), "a.example:443".into()));
        let mut disc = DiscoveredPeers::new();

        let out = disc.merge(&response(vec![triple(&a, "a.example:443")]), &known);
        assert_eq!(out.added, 0);
        assert_eq!(out.skipped_known, 1);
        assert!(disc.is_empty());
    }

    #[test]
    fn merge_is_idempotent_on_repeat() {
        let a = server("a", &[1u8; 32]);
        let known = InMemoryTrustStore::new();
        let mut disc = DiscoveredPeers::new();
        let resp = response(vec![triple(&a, "a.example:443")]);

        assert_eq!(disc.merge(&resp, &known).added, 1);
        let second = disc.merge(&resp, &known);
        assert_eq!(second.added, 0);
        assert_eq!(second.skipped_duplicate, 1);
        assert_eq!(disc.len(), 1, "a repeated refresh does not duplicate");
    }

    #[test]
    fn merge_drops_malformed_server_ids() {
        let known = InMemoryTrustStore::new();
        let mut disc = DiscoveredPeers::new();
        let bad = PeerTriple {
            server_id: "no-hash-separator".to_owned(),
            address: "x:443".to_owned(),
            last_known_availability_unix_ms: None,
        };
        let out = disc.merge(&response(vec![bad]), &known);
        assert_eq!(out.malformed, 1);
        assert_eq!(out.added, 0);
        assert!(disc.is_empty());
    }

    #[test]
    fn promote_trusted_moves_candidate_to_active_store_no_pin() {
        let a = server("a", &[1u8; 32]);
        let known = InMemoryTrustStore::new();
        let mut disc = DiscoveredPeers::new();
        disc.merge(&response(vec![triple(&a, "a.example:443")]), &known);

        let mut store = InMemoryTrustStore::new();
        let entry = disc
            .promote_trusted(&a, &mut store)
            .expect("candidate promotes");
        assert_eq!(entry.mode, TrustMode::Trusted);
        assert_eq!(
            entry.pinned_key, None,
            "trusted promote has no pin yet (first-contact verifies)"
        );
        assert_eq!(store.get(&a).unwrap().address, "a.example:443");
        assert!(disc.is_empty(), "promotion removes the candidate");
    }

    #[test]
    fn promote_untrusted_carries_the_oob_key() {
        let a = server("a", &[1u8; 32]);
        let known = InMemoryTrustStore::new();
        let mut disc = DiscoveredPeers::new();
        disc.merge(&response(vec![triple(&a, "a.example:443")]), &known);

        let mut store = InMemoryTrustStore::new();
        let key = vec![9u8; 32];
        let entry = disc
            .promote_untrusted(&a, key.clone(), &mut store)
            .expect("candidate promotes");
        assert_eq!(entry.mode, TrustMode::Untrusted);
        assert_eq!(entry.configured_key.as_deref(), Some(&key[..]));
        assert!(disc.is_empty());
    }

    #[test]
    fn promote_unknown_candidate_returns_none() {
        let a = server("a", &[1u8; 32]);
        let mut disc = DiscoveredPeers::new();
        let mut store = InMemoryTrustStore::new();
        assert!(disc.promote_trusted(&a, &mut store).is_none());
        assert!(store.get(&a).is_none());
    }
}
