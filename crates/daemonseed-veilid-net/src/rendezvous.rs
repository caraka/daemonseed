//! The shared-owner DFLT DHT **rendezvous engine** — one generic primitive
//! underneath circles, the lobby / public rooms, share discovery, and (later)
//! presence and announcements. It is parameterized by exactly two things: a
//! deterministically-derivable **owner keypair** and the opaque **sealed bytes**
//! a participant publishes; the engine never knows which feature it is serving.
//!
//! Design (`docs/design/veilid-migration.md`): an owner keypair is derived
//! deterministically from shared inputs — a circle's entropy (a sibling of the
//! content `cot_key`), or a public room's name+family (a sibling of the room
//! key) — so every participant computes the SAME DFLT record key, the relay-free
//! rendezvous address (the DHT analog of the relay-era `SHA-384(key ‖ server_id)`).
//! Every participant holds the owner secret, so all write owner-signed subkeys
//! with no pre-known member list (which is what an `SMPL` baked-in member set
//! could not give for open membership). Each participant writes a small
//! append-ring within its own region (region = hash of its node pubkey), so a
//! connecting participant finds a bounded backlog of recent items with no relay
//! and no roster. Content stays sealed under the feature's key (circle key /
//! `PublicRoomKey`) — this layer moves opaque bytes only.
//!
//! The owner-derivation is the *only* thing that distinguishes the consumers:
//! member-secret (circle) → confidential; world-derivable (lobby/public room,
//! share discovery) → open; operator-only owner (announcements/MOTD) → the
//! non-derivable owner keypair is the write-gate.

use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::mpsc;
use veilid_core::{
    DHTSchema, KeyPair, RecordKey, RoutingContext, SetDHTValueOptions, VeilidAPI, CRYPTO_KIND_VLD0,
};

use crate::actor::APP_MESSAGE_CAP;
use crate::error::{Result, VeilidNetError};
use crate::event::VeilidNetEvent;

/// Total subkeys in a rendezvous DFLT record. Fixed — it is part of the
/// deterministic record key, so every participant MUST agree. Kept small so a
/// connecting participant can sweep the whole record for backlog cheaply.
/// `= MEMBER_REGIONS * RING_DEPTH`.
pub const SUBKEY_COUNT: u16 = 64;

/// Distinct member regions; a member maps to one by hashing its node pubkey.
/// Collision (two members → same region) degrades to slot-sharing, not a crash;
/// a roster (Phase 4) removes the blind hash. Sized for small circles.
pub const MEMBER_REGIONS: u32 = 32;

/// Append-ring depth per member — the bounded recent backlog surfaced on login.
/// "A couple of recent messages", deliberately not durable scrollback.
pub const RING_DEPTH: u32 = 2;

/// The fixed DFLT schema shared by every rendezvous record.
fn schema() -> Result<DHTSchema> {
    DHTSchema::dflt(SUBKEY_COUNT).map_err(|e| VeilidNetError::Routing(e.to_string()))
}

/// Compute a rendezvous record's deterministic record key from its owner
/// keypair. Local crypto only — no network round-trip.
pub async fn rendezvous_key(api: &VeilidAPI, owner: &KeyPair) -> Result<RecordKey> {
    api.get_dht_record_key(schema()?, owner.key(), None)
        .await
        .map_err(|e| VeilidNetError::Routing(e.to_string()))
}

/// Open the circle's rendezvous record, creating it deterministically if it is
/// not yet on the network. Every member holds the owner secret, so any member
/// can do either. Returns the (deterministic) record key.
///
/// **Single encryption layer.** The record key is derived with NO Veilid
/// encryption key ([`rendezvous_key`] passes `None`), so Veilid stores values
/// verbatim — our cot-sealed (AES-256-GCM, post-quantum) bytes are the ONLY
/// encryption, and the DHT sees ciphertext exactly as the relay did (ISC-A-S2).
/// `create_dht_record` force-assigns a *random* per-record encryption key to
/// the local handle (`create_record.rs`), which other members cannot derive; we
/// reopen with our no-encryption-key record key, which resets the handle's
/// encryption to none (`open_record.rs`: `crypto_with_key` defaults to `None`),
/// so writes are stored verbatim and any member who derives the same address
/// reads them back byte-identical. This also keeps content crypto fully
/// decoupled from Veilid's (classical) transport crypto — so adopting a future
/// Veilid PQC suite is a free, content-independent change.
pub async fn open_or_create(
    api: &VeilidAPI,
    rc: &RoutingContext,
    owner: &KeyPair,
) -> Result<RecordKey> {
    let key = rendezvous_key(api, owner).await?;
    crate::vtrace!("open_or_create: rendezvous key={key:?}; trying open#1");
    match rc.open_dht_record(key.clone(), Some(owner.clone())).await {
        Ok(_) => {
            crate::vtrace!("open_or_create: open#1 ok (record already on net) -> Ok");
            return Ok(key);
        }
        Err(e) => crate::vtrace!("open_or_create: open#1 failed ({e}); creating record"),
    }
    // Not present — create the network record. Ignore the result: on success
    // the handle carries create's random encryption key; on a lost create race
    // a peer already created it. Either way the reopen below (with our
    // no-encryption-key record key) resets the handle to verbatim storage.
    match rc
        .create_dht_record(CRYPTO_KIND_VLD0, schema()?, Some(owner.clone()))
        .await
    {
        Ok(_) => crate::vtrace!("open_or_create: create ok"),
        Err(e) => crate::vtrace!("open_or_create: create failed ({e}) (lost race? reopen anyway)"),
    }
    let r = rc
        .open_dht_record(key.clone(), Some(owner.clone()))
        .await
        .map(|_| key)
        .map_err(|e| VeilidNetError::Routing(e.to_string()));
    crate::vtrace!(
        "open_or_create: reopen {}",
        if r.is_ok() { "ok -> Ok" } else { "ERR" }
    );
    r
}

/// A session cache of rendezvous records already opened, keyed by owner seed →
/// the post-reopen [`RecordKey`]. [`open_or_create`] pays a fresh open (~6–10 s
/// live-measured) on every publish/subscribe; once a key is cached, callers reuse
/// the open handle and skip the round-trip. The cached key is the reopen result,
/// so it carries the verbatim-storage (no-encryption) handle semantics — never a
/// raw `create` handle with a random encryption key.
pub type OpenCache = Mutex<HashMap<[u8; 32], RecordKey>>;

/// Return the cached open key for `owner_seed`, else run `open` once, cache its
/// result, and return it. Generic over the key type so the caching logic is
/// unit-testable without veilid types. `open` is a lazy future built by the
/// caller: on a cache hit it is dropped un-awaited (an `async fn` future runs no
/// body until polled), so a hit costs nothing beyond the map lookup.
///
/// The record is opened once per session and never closed, so the cached key
/// stays valid — there is deliberately no error-path invalidation. A `set`/`get`
/// failure is a transient network condition the caller surfaces (and may retry),
/// not a dead local handle; dropping the entry would only force a redundant
/// re-open, and on the shared lobby record (every share advert + the lobby
/// subscription derive the SAME `owner_seed`) it would evict an entry other
/// callers are actively using. See ISA Decisions (2026-07-06, #128 D-0a).
pub async fn open_cached<K: Clone>(
    cache: &Mutex<HashMap<[u8; 32], K>>,
    owner_seed: &[u8; 32],
    open: impl std::future::Future<Output = Result<K>>,
) -> Result<K> {
    if let Some(k) = cache.lock().unwrap().get(owner_seed).cloned() {
        return Ok(k);
    }
    let k = open.await?;
    cache.lock().unwrap().insert(*owner_seed, k.clone());
    Ok(k)
}

/// The base subkey of this member's append-ring region, from its node pubkey.
pub fn member_base_subkey(node_pub: &[u8; 32]) -> u32 {
    let region =
        u32::from_le_bytes([node_pub[0], node_pub[1], node_pub[2], node_pub[3]]) % MEMBER_REGIONS;
    region * RING_DEPTH
}

/// Write a sealed message into this member's ring at `base + (seq % RING_DEPTH)`,
/// signed with the shared owner key (DFLT: all subkeys are owner-written).
pub async fn publish(
    rc: &RoutingContext,
    key: &RecordKey,
    owner: &KeyPair,
    base: u32,
    seq: u32,
    sealed: Vec<u8>,
) -> Result<()> {
    publish_at_subkey(rc, key, owner, base + (seq % RING_DEPTH), sealed).await
}

/// Map a stable logical identity (a `share_id`; later a presence member id) to a
/// fixed subkey — the **current-state** placement (Shape B,
/// `docs/design/unified-room-model.md`). Unlike [`member_base_subkey`], the slot is a
/// pure function of the item's stable identity, NOT the ephemeral node pubkey, so a
/// republish (even under a fresh node identity after a restart) overwrites the SAME
/// slot — last-writer-wins — and a withdraw cancels it in place. This is what stops
/// dead-route share announcements from orphaning across restarts (#118). Collision
/// (two ids → same slot) degrades to slot-sharing, bounded by [`SUBKEY_COUNT`]; a
/// larger dedicated schema lifts the ceiling if it ever bites.
pub fn current_state_subkey(stable_id: &str) -> u32 {
    // FNV-1a — dep-free and well-distributed over the input bytes.
    let mut h: u32 = 0x811c_9dc5;
    for b in stable_id.as_bytes() {
        h ^= u32::from(*b);
        h = h.wrapping_mul(0x0100_0193);
    }
    h % u32::from(SUBKEY_COUNT)
}

/// Write `sealed` to a SPECIFIC subkey (owner-signed), last-writer-wins — the
/// current-state counterpart to [`publish`]'s append-ring write. The caller picks the
/// slot from a stable identity via [`current_state_subkey`], so re-publishing the same
/// item overwrites in place instead of orphaning a stale copy.
pub async fn publish_at_subkey(
    rc: &RoutingContext,
    key: &RecordKey,
    owner: &KeyPair,
    subkey: u32,
    sealed: Vec<u8>,
) -> Result<()> {
    if sealed.len() > APP_MESSAGE_CAP {
        return Err(VeilidNetError::Send(format!(
            "sealed {} bytes exceeds the {APP_MESSAGE_CAP}-byte subkey cap (re-chunk)",
            sealed.len()
        )));
    }
    rc.set_dht_value(
        key.clone(),
        subkey,
        sealed,
        Some(SetDHTValueOptions {
            writer: Some(owner.clone()),
            allow_offline: None,
        }),
    )
    .await
    .map(|_| ())
    .map_err(|e| VeilidNetError::Send(e.to_string()))
}

/// Sweep every subkey once for the login backlog, emitting an [`VeilidNetEvent::Inbound`]
/// per populated slot. `force_refresh` pulls from the network (DHT reads are
/// eventually consistent). Bounded by [`SUBKEY_COUNT`]; runs as a background task.
pub async fn sweep(
    rc: RoutingContext,
    key: RecordKey,
    ev_tx: mpsc::UnboundedSender<VeilidNetEvent>,
) {
    let mut found = 0u32;
    for subkey in 0..u32::from(SUBKEY_COUNT) {
        if let Ok(Some(v)) = rc.get_dht_value(key.clone(), subkey, true).await {
            found += 1;
            if ev_tx
                .send(VeilidNetEvent::Inbound {
                    bytes: v.data().to_vec(),
                })
                .is_err()
            {
                return; // receiver dropped — stop sweeping
            }
        }
    }
    crate::vtrace!("sweep: done, {found} backlog slot(s) emitted");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Counting stand-in for [`open_or_create`]'s network round-trip: increments on
    /// every actual open, so a test can assert the cache collapsed N calls to one.
    /// `u32` avoids constructing a veilid `RecordKey` — no network types in a unit test.
    async fn counting_open(opens: &AtomicU32, ret: u32) -> Result<u32> {
        opens.fetch_add(1, Ordering::SeqCst);
        Ok(ret)
    }

    #[test]
    fn current_state_subkey_is_stable_and_in_range() {
        // A share's slot must be identical across calls — last-writer-wins on
        // re-publish (the #118 fix) depends on it.
        let id = "3cbac166afc8088bc30cb1dd256c754d";
        assert_eq!(current_state_subkey(id), current_state_subkey(id));
        assert!(current_state_subkey(id) < u32::from(SUBKEY_COUNT));
    }

    #[test]
    fn current_state_subkey_ignores_node_identity_and_distributes() {
        // The slot is a pure function of the stable id — by construction it cannot
        // depend on the ephemeral per-launch node pubkey, so a restart can never
        // orphan a share into a new slot. Distinct ids spread across many slots.
        let slots: HashSet<u32> = (0..200)
            .map(|i| current_state_subkey(&format!("share-{i:032x}")))
            .collect();
        assert!(slots.len() > 1, "ids spread across slots, not all into one");
        assert!(slots.iter().all(|s| *s < u32::from(SUBKEY_COUNT)));
    }

    #[tokio::test]
    async fn open_cached_opens_once_across_repeated_publishes_to_same_key() {
        // The D-0a invariant: five publishes to one owner seed trigger exactly ONE
        // open. On a cache hit the counting_open future is built but dropped un-awaited,
        // so it never increments.
        let cache: Mutex<HashMap<[u8; 32], u32>> = Mutex::new(HashMap::new());
        let opens = AtomicU32::new(0);
        let seed = [7u8; 32];
        for _ in 0..5 {
            let k = open_cached(&cache, &seed, counting_open(&opens, 42))
                .await
                .unwrap();
            assert_eq!(k, 42);
        }
        assert_eq!(
            opens.load(Ordering::SeqCst),
            1,
            "one open across five publishes to the same key"
        );
    }

    #[tokio::test]
    async fn distinct_seeds_each_open_once_and_a_hit_returns_the_cached_key() {
        let cache: Mutex<HashMap<[u8; 32], u32>> = Mutex::new(HashMap::new());
        let opens = AtomicU32::new(0);
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert_eq!(
            open_cached(&cache, &a, counting_open(&opens, 10))
                .await
                .unwrap(),
            10
        );
        // Cache hit on the same seed: returns the CACHED key (10), and the
        // counting_open(…, 99) future is dropped un-awaited (no open, no 99).
        assert_eq!(
            open_cached(&cache, &a, counting_open(&opens, 99))
                .await
                .unwrap(),
            10
        );
        // A distinct seed is a separate open.
        assert_eq!(
            open_cached(&cache, &b, counting_open(&opens, 20))
                .await
                .unwrap(),
            20
        );
        assert_eq!(
            opens.load(Ordering::SeqCst),
            2,
            "one open per distinct seed; hits reuse the cached key"
        );
    }
}
