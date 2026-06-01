//! RAM-only published-share registry (M12, gate step 5 — user-publish file
//! sharing).
//!
//! A connected daemon publishes a public-space share via `PublishShare`; the
//! relay holds it in RAM ONLY, tied to the publishing connection, and lists it
//! in `ListPublicShares` until the sharer unpublishes it or disconnects.
//! NOTHING is persisted (ISC-A-S1): a published share is user data, not an
//! operator carve-out, so it lives in process memory and vanishes on disconnect
//! — mirroring the circle-of-trust live relay's RAM-only, reaped-on-disconnect
//! model (ISC-A-S5).
//!
//! The relay is a blind forwarder: the sharer's self-asserted name / rating /
//! handle are relayed verbatim and never policed (ISC-A-S5b / ISC-C19), and the
//! `sharer_handle` is NOT bound to the connection's authenticated identity.
//!
//! **Ownership, not id-secrecy, is the access control.** Each connection is
//! issued an opaque [`OwnerId`]; a share remembers its owner so `UnpublishShare`
//! is owner-scoped and a single connection-close reaps exactly that
//! connection's shares ([`ShareReapGuard`]). `share_id`s are server-assigned and
//! opaque; an other-owned unpublish is a silent no-op so the relay never reveals
//! another connection's share ownership (ISC-A-S1).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use daemonseed_proto::v1::PublicShareListing;

/// An opaque per-connection publisher token. Distinct connections get distinct
/// values within a process run; never reused.
pub type OwnerId = u64;

struct OwnedShare {
    owner: OwnerId,
    listing: PublicShareListing,
}

struct Inner {
    /// share_id -> owned share.
    shares: BTreeMap<String, OwnedShare>,
    next_owner: OwnerId,
    next_share: u64,
}

/// The relay's RAM-only published-share table, shared (`Arc`) across every
/// connection so one daemon's published share is visible to others'
/// `ListPublicShares`. Cloning shares the inner table.
#[derive(Clone)]
pub struct SharePublishRegistry {
    inner: Arc<Mutex<Inner>>,
}

impl Default for SharePublishRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SharePublishRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                shares: BTreeMap::new(),
                next_owner: 0,
                next_share: 0,
            })),
        }
    }

    /// Issue a fresh per-connection owner token.
    pub fn new_owner(&self) -> OwnerId {
        let mut g = self.lock();
        let id = g.next_owner;
        g.next_owner += 1;
        id
    }

    /// Publish `listing` under `owner`; assign and return an opaque `share_id`.
    /// Any `listing.share_id` set by the caller is overwritten — the id is
    /// server-scoped (ISC-C19 / F25).
    pub fn publish(&self, owner: OwnerId, mut listing: PublicShareListing) -> String {
        let mut g = self.lock();
        let n = g.next_share;
        g.next_share += 1;
        let share_id = format!("{n:016x}");
        listing.share_id = share_id.clone();
        g.shares
            .insert(share_id.clone(), OwnedShare { owner, listing });
        share_id
    }

    /// Unpublish `share_id` iff it is owned by `owner`. Returns whether a share
    /// was removed; an unknown or other-owned id removes nothing (silent no-op,
    /// ISC-A-S1).
    pub fn unpublish(&self, owner: OwnerId, share_id: &str) -> bool {
        let mut g = self.lock();
        match g.shares.get(share_id) {
            Some(s) if s.owner == owner => {
                g.shares.remove(share_id);
                true
            }
            _ => false,
        }
    }

    /// Reap every share owned by `owner` — called once on connection close via
    /// [`ShareReapGuard`].
    pub fn reap_owner(&self, owner: OwnerId) {
        self.lock().shares.retain(|_, s| s.owner != owner);
    }

    /// The live listings in `share_id` order, each carrying its assigned id.
    pub fn list(&self) -> Vec<PublicShareListing> {
        self.lock()
            .shares
            .values()
            .map(|s| s.listing.clone())
            .collect()
    }

    /// Number of live shares — for metrics/tests.
    pub fn live_count(&self) -> usize {
        self.lock().shares.len()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("share registry mutex poisoned")
    }
}

/// Reaps a connection's published shares when dropped — the single place a
/// disconnect releases share state, so no path leaks a share past connection
/// close (ISC-A-S1 ephemerality). Held for the connection's lifetime alongside
/// the served application stream; mirrors the CoT `ReleaseGuard`.
pub struct ShareReapGuard {
    registry: SharePublishRegistry,
    owner: OwnerId,
}

impl ShareReapGuard {
    /// Guard `owner`'s shares in `registry`; reaps them on drop.
    pub fn new(registry: SharePublishRegistry, owner: OwnerId) -> Self {
        Self { registry, owner }
    }
}

impl Drop for ShareReapGuard {
    fn drop(&mut self) {
        self.registry.reap_owner(self.owner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listing(name: &str, handle: &str) -> PublicShareListing {
        PublicShareListing {
            share_id: String::new(),
            name: name.to_owned(),
            rating: "PG".to_owned(),
            sharer_handle: handle.to_owned(),
        }
    }

    #[test]
    fn publish_assigns_id_and_lists() {
        let reg = SharePublishRegistry::new();
        let owner = reg.new_owner();
        let id = reg.publish(owner, listing("docs", "a#0123456789ab"));
        assert!(!id.is_empty());

        let shares = reg.list();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].share_id, id, "the assigned id rides the listing");
        assert_eq!(shares[0].name, "docs");
        assert_eq!(
            shares[0].sharer_handle, "a#0123456789ab",
            "self-asserted handle verbatim"
        );
    }

    #[test]
    fn publish_overwrites_caller_supplied_share_id() {
        let reg = SharePublishRegistry::new();
        let owner = reg.new_owner();
        let mut l = listing("docs", "a#0123456789ab");
        l.share_id = "client-tried-to-pick-this".to_owned();
        let id = reg.publish(owner, l);
        assert_ne!(id, "client-tried-to-pick-this", "share_id is server-scoped");
        assert_eq!(reg.list()[0].share_id, id);
    }

    #[test]
    fn unpublish_by_owner_removes_the_share() {
        let reg = SharePublishRegistry::new();
        let owner = reg.new_owner();
        let id = reg.publish(owner, listing("docs", "a#0123456789ab"));
        assert!(reg.unpublish(owner, &id));
        assert_eq!(reg.live_count(), 0);
    }

    #[test]
    fn unpublish_by_another_owner_is_a_silent_noop() {
        // ISC-A-S1: ownership is the access control; another connection cannot
        // unpublish your share, and learns nothing by trying.
        let reg = SharePublishRegistry::new();
        let alice = reg.new_owner();
        let bob = reg.new_owner();
        let id = reg.publish(alice, listing("docs", "alice#0123456789ab"));
        assert!(!reg.unpublish(bob, &id), "other owner cannot unpublish");
        assert_eq!(reg.live_count(), 1, "share survives the foreign unpublish");
        assert!(reg.unpublish(alice, &id), "the owner still can");
    }

    #[test]
    fn unpublish_unknown_id_is_a_silent_noop() {
        let reg = SharePublishRegistry::new();
        let owner = reg.new_owner();
        assert!(!reg.unpublish(owner, "deadbeef"));
    }

    #[test]
    fn reap_owner_drops_only_that_owners_shares() {
        let reg = SharePublishRegistry::new();
        let alice = reg.new_owner();
        let bob = reg.new_owner();
        reg.publish(alice, listing("a1", "alice#0123456789ab"));
        reg.publish(alice, listing("a2", "alice#0123456789ab"));
        let bob_share = reg.publish(bob, listing("b1", "bob#0123456789ab"));

        reg.reap_owner(alice);
        let remaining = reg.list();
        assert_eq!(
            remaining.len(),
            1,
            "alice's two shares reaped, bob's survives"
        );
        assert_eq!(remaining[0].share_id, bob_share);
    }

    #[test]
    fn guard_reaps_on_drop() {
        // The disconnect path: dropping the guard reaps exactly the connection's
        // shares (ISC-A-S1 ephemerality).
        let reg = SharePublishRegistry::new();
        let owner = reg.new_owner();
        reg.publish(owner, listing("docs", "a#0123456789ab"));
        assert_eq!(reg.live_count(), 1);
        {
            let _guard = ShareReapGuard::new(reg.clone(), owner);
            assert_eq!(reg.live_count(), 1, "share live while connection open");
        }
        assert_eq!(reg.live_count(), 0, "connection close reaped the share");
    }
}
