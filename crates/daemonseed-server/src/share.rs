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
//!
//! **Share ids are drawn from the OS CSPRNG, not a counter (ISC-S21 /
//! ISC-A-S15).** Each `share_id` is 128 bits of OS entropy, lowercase-hex
//! encoded. A sequential or otherwise order-derived id would let any peer
//! enumerate the published-share space (`0000…`, `0001…`, …) and undercut the
//! blind-relay privacy posture — the CoT fetch-asset for a share derives from
//! its id, so a guessable id is a guessable rendezvous address.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use daemonseed_proto::v1::PublicShareListing;

/// An opaque per-connection publisher token. Distinct connections get distinct
/// values within a process run; never reused.
pub type OwnerId = u64;

/// Draw an opaque, unpredictable `share_id`: 128 bits from the OS CSPRNG,
/// lowercase-hex encoded (32 chars). Drawn from `getrandom` — the same OS
/// entropy source the rest of daemonseed uses — so ids are not order-derived and
/// the published-share space is not enumerable (ISC-S21 / ISC-A-S15).
///
/// An OS-entropy failure is unrecoverable for the server (the same posture as
/// every other key/nonce draw in the process), so this panics rather than
/// silently degrading to a predictable id.
fn random_share_id() -> String {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("OS CSPRNG entropy for share_id");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

struct OwnedShare {
    owner: OwnerId,
    listing: PublicShareListing,
}

struct Inner {
    /// share_id -> owned share.
    shares: BTreeMap<String, OwnedShare>,
    next_owner: OwnerId,
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
    /// server-scoped (ISC-C19 / F25) and CSPRNG-drawn, not order-derived
    /// (ISC-S21 / ISC-A-S15). On the astronomically-unlikely collision the draw
    /// retries, so the returned id is always unique in the live registry.
    pub fn publish(&self, owner: OwnerId, mut listing: PublicShareListing) -> String {
        let mut g = self.lock();
        let share_id = loop {
            let candidate = random_share_id();
            if !g.shares.contains_key(&candidate) {
                break candidate;
            }
        };
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
    fn share_id_is_opaque_128bit_lowercase_hex() {
        // ISC-S21: the id is 16 bytes (128 bit) of OS entropy, lowercase-hex
        // encoded — exactly 32 hex chars, never an order-derived counter.
        let reg = SharePublishRegistry::new();
        let owner = reg.new_owner();
        let id = reg.publish(owner, listing("docs", "a#0123456789ab"));
        assert_eq!(id.len(), 32, "128-bit id is 32 hex chars");
        assert!(
            id.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "id is lowercase hex only, got {id:?}"
        );
    }

    #[test]
    fn share_ids_are_not_sequential_or_order_derived() {
        // ISC-A-S15: the first id must NOT be the old enumerable counter value
        // (`0000000000000000`), and successive ids must not be adjacent — a peer
        // cannot walk the published-share space.
        let reg = SharePublishRegistry::new();
        let owner = reg.new_owner();
        let first = reg.publish(owner, listing("a", "a#0123456789ab"));
        let second = reg.publish(owner, listing("b", "a#0123456789ab"));
        assert_ne!(first, "0000000000000000", "id is not the counter origin");
        assert_ne!(first, second, "distinct shares get distinct ids");
        // Adjacent-counter check: the two ids, parsed as integers, are not n / n+1.
        let a = u128::from_str_radix(&first, 16).expect("hex");
        let b = u128::from_str_radix(&second, 16).expect("hex");
        assert_ne!(b, a.wrapping_add(1), "ids are not a +1 sequence");
    }

    #[test]
    fn many_share_ids_are_unique_and_well_formed() {
        // ISC-S21 / ISC-A-S15: across many draws every id is unique (the
        // unique-in-registry retry holds) and every id is valid 32-char hex.
        let reg = SharePublishRegistry::new();
        let owner = reg.new_owner();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1_000 {
            let id = reg.publish(owner, listing("docs", "a#0123456789ab"));
            assert_eq!(id.len(), 32);
            assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
            assert!(seen.insert(id), "every assigned id is unique");
        }
        assert_eq!(reg.live_count(), 1_000);
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
