//! Per-server federation trust state: the [`TrustStore`] trait, an in-memory
//! implementation, and [`apply_trust`] — the evaluate-then-record step the
//! client runs after the identity-proof yields the server's presented key.
//!
//! Persistence is deliberately out of scope for M5 (decision: mirror M4b's D8
//! deferral of replay-counter persistence). [`InMemoryTrustStore`] is the
//! state machine the federation test matrix exercises; sealing it to disk
//! (alongside the client's seeds blob) is a later client-identity commit.

use std::collections::HashMap;

use crate::federation::trust::{TrustDecision, TrustMode, TrustQuery, evaluate_trust};
use crate::handle::{HASH_PREFIX_BYTES, Handle};

/// One configured federation server and its accumulated trust state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerEntry {
    /// The configured server-id (`<name>#<12hex>`), the trust anchor.
    pub server_id: Handle,
    /// Reachable address (hostname or IP literal, optional `:port`).
    pub address: String,
    /// Trusted or untrusted slider position (ISC-C22).
    pub mode: TrustMode,
    /// The TOFU-pinned full key (trusted mode, set on first contact). `None`
    /// means trusted-mode first contact hasn't happened yet.
    pub pinned_key: Option<Vec<u8>>,
    /// The out-of-band pre-configured full key (untrusted mode).
    pub configured_key: Option<Vec<u8>>,
    /// Whether the user dismissed rotation notices for this server.
    pub rotation_dismissed: bool,
}

impl ServerEntry {
    /// A trusted-mode entry with no pin yet — the common "user just added a
    /// public community server" case (ISC-C22 default).
    pub fn new_trusted(server_id: Handle, address: String) -> Self {
        Self {
            server_id,
            address,
            mode: TrustMode::Trusted,
            pinned_key: None,
            configured_key: None,
            rotation_dismissed: false,
        }
    }

    /// An untrusted-mode entry carrying the out-of-band pre-configured key
    /// (ISC-C22 untrusted).
    pub fn new_untrusted(server_id: Handle, address: String, configured_key: Vec<u8>) -> Self {
        Self {
            server_id,
            address,
            mode: TrustMode::Untrusted,
            pinned_key: None,
            configured_key: Some(configured_key),
            rotation_dismissed: false,
        }
    }
}

/// Storage for per-server federation trust state. Implemented in-memory for
/// M5; a disk-backed implementation lands with persisted client identity.
pub trait TrustStore {
    /// The entry for `server_id`, if configured.
    fn get(&self, server_id: &Handle) -> Option<&ServerEntry>;
    /// Insert or replace an entry.
    fn upsert(&mut self, entry: ServerEntry);
    /// Set/update the TOFU pin for `server_id` (no-op if unknown).
    fn set_pin(&mut self, server_id: &Handle, key: Vec<u8>);
    /// Mark rotation notices dismissed for `server_id` (no-op if unknown).
    ///
    /// **Contract:** call this ONLY in response to a rotation notice that was
    /// actually surfaced to the user (ISC-C22 "the first rotation always
    /// surfaces"). Once set, the dismissal makes every subsequent key change
    /// for this server accept silently, so setting it without a surfaced notice
    /// — or carrying it across rotations as a sticky flag — would turn the
    /// trusted-mode pin into "accept any A-C18-passing key" permanently.
    fn dismiss_rotation(&mut self, server_id: &Handle);
}

/// In-memory [`TrustStore`], keyed by the server-id's canonical string form.
#[derive(Debug, Default, Clone)]
pub struct InMemoryTrustStore {
    entries: HashMap<String, ServerEntry>,
}

impl InMemoryTrustStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl TrustStore for InMemoryTrustStore {
    fn get(&self, server_id: &Handle) -> Option<&ServerEntry> {
        self.entries.get(&server_id.to_string())
    }

    fn upsert(&mut self, entry: ServerEntry) {
        self.entries.insert(entry.server_id.to_string(), entry);
    }

    fn set_pin(&mut self, server_id: &Handle, key: Vec<u8>) {
        if let Some(e) = self.entries.get_mut(&server_id.to_string()) {
            e.pinned_key = Some(key);
        }
    }

    fn dismiss_rotation(&mut self, server_id: &Handle) {
        if let Some(e) = self.entries.get_mut(&server_id.to_string()) {
            e.rotation_dismissed = true;
        }
    }
}

/// Evaluate trust for a server presenting `presented_pubkey` and record the
/// result: on a trusted-mode accept (first contact or rotation) the pin is
/// updated to the presented key. Returns the [`TrustDecision`] for the caller
/// to act on (refuse → close; rotation → surface the notice).
///
/// `presented_prefix` is `SHA-384(presented_pubkey)[:12]`, computed once by the
/// caller via [`Handle::from_pubkey`]. An unknown server refuses (fail closed).
pub fn apply_trust(
    store: &mut dyn TrustStore,
    server_id: &Handle,
    presented_pubkey: &[u8],
    presented_prefix: &[u8; HASH_PREFIX_BYTES],
) -> TrustDecision {
    // Snapshot the entry's trust inputs so the immutable borrow ends before the
    // mutable set_pin below. An unknown server fails closed.
    let Some(entry) = store.get(server_id) else {
        return TrustDecision::Refuse;
    };
    let mode = entry.mode;
    let expected_prefix = *entry.server_id.hash_prefix();
    let pinned = entry.pinned_key.clone();
    let configured = entry.configured_key.clone();
    let dismissed = entry.rotation_dismissed;

    let decision = evaluate_trust(&TrustQuery {
        mode,
        expected_prefix: &expected_prefix,
        presented_pubkey,
        presented_prefix,
        pinned_key: pinned.as_deref(),
        configured_key: configured.as_deref(),
        rotation_dismissed: dismissed,
    });

    // Trusted mode pins the presented key on any accept (first contact, silent
    // re-pin, or rotation). Untrusted mode anchors on configured_key and never
    // pins. Refuse writes nothing.
    if mode == TrustMode::Trusted
        && matches!(
            decision,
            TrustDecision::Accept | TrustDecision::AcceptWithRotation { .. }
        )
    {
        store.set_pin(server_id, presented_pubkey.to_vec());
    }

    decision
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ensure_module() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
    }

    /// Build a real server-id Handle and the matching presented prefix from a
    /// fake key (Handle::from_pubkey hashes arbitrary bytes).
    fn server_for(key: &[u8], name: &str) -> (Handle, [u8; HASH_PREFIX_BYTES]) {
        ensure_module();
        let h = Handle::from_pubkey(Some(name.to_owned()), key).unwrap();
        let prefix = *h.hash_prefix();
        (h, prefix)
    }

    #[test]
    fn upsert_then_get_round_trips() {
        let (id, _) = server_for(&[1u8; 32], "relay");
        let mut store = InMemoryTrustStore::new();
        store.upsert(ServerEntry::new_trusted(
            id.clone(),
            "relay.example:443".into(),
        ));
        assert_eq!(store.get(&id).unwrap().address, "relay.example:443");
    }

    #[test]
    fn dismiss_rotation_sets_flag() {
        let (id, _) = server_for(&[1u8; 32], "relay");
        let mut store = InMemoryTrustStore::new();
        store.upsert(ServerEntry::new_trusted(id.clone(), "a:443".into()));
        store.dismiss_rotation(&id);
        assert!(store.get(&id).unwrap().rotation_dismissed);
    }

    #[test]
    fn apply_unknown_server_refuses() {
        let (id, prefix) = server_for(&[1u8; 32], "relay");
        let mut store = InMemoryTrustStore::new();
        assert_eq!(
            apply_trust(&mut store, &id, &[1u8; 32], &prefix),
            TrustDecision::Refuse
        );
    }

    #[test]
    fn apply_trusted_first_contact_pins_presented_key() {
        let key = [7u8; 32];
        let (id, prefix) = server_for(&key, "relay");
        let mut store = InMemoryTrustStore::new();
        store.upsert(ServerEntry::new_trusted(id.clone(), "a:443".into()));
        let d = apply_trust(&mut store, &id, &key, &prefix);
        assert_eq!(d, TrustDecision::Accept);
        assert_eq!(
            store.get(&id).unwrap().pinned_key.as_deref(),
            Some(&key[..])
        );
    }

    #[test]
    fn apply_trusted_rotation_updates_pin_and_surfaces() {
        let key_old = [7u8; 32];
        let key_new = [9u8; 32];
        let (id, _) = server_for(&key_old, "relay");
        let new_prefix = *Handle::from_pubkey(None, &key_new).unwrap().hash_prefix();
        let mut store = InMemoryTrustStore::new();
        let mut entry = ServerEntry::new_trusted(id.clone(), "a:443".into());
        entry.pinned_key = Some(key_old.to_vec());
        store.upsert(entry);

        let d = apply_trust(&mut store, &id, &key_new, &new_prefix);
        assert!(matches!(d, TrustDecision::AcceptWithRotation { .. }));
        assert_eq!(
            store.get(&id).unwrap().pinned_key.as_deref(),
            Some(&key_new[..]),
            "pin updates to the rotated key"
        );
    }

    #[test]
    fn apply_untrusted_match_accepts_without_writing_pin() {
        let key = [7u8; 32];
        let (id, prefix) = server_for(&key, "relay");
        let mut store = InMemoryTrustStore::new();
        store.upsert(ServerEntry::new_untrusted(
            id.clone(),
            "a:443".into(),
            key.to_vec(),
        ));
        let d = apply_trust(&mut store, &id, &key, &prefix);
        assert_eq!(d, TrustDecision::Accept);
        assert_eq!(
            store.get(&id).unwrap().pinned_key,
            None,
            "untrusted mode anchors on configured_key, never pins"
        );
    }
}
