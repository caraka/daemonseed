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
use std::future::Future;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use veilid_core::{
    DHTSchema, KeyPair, RecordKey, RoutingContext, SetDHTValueOptions, VeilidAPI, CRYPTO_KIND_VLD0,
};

use crate::actor::APP_MESSAGE_CAP;
use crate::dht_gate::DhtGate;
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
    gate: &Arc<DhtGate>,
    api: &VeilidAPI,
    rc: &RoutingContext,
    owner: &KeyPair,
) -> Result<RecordKey> {
    let key = rendezvous_key(api, owner).await?;
    crate::vtrace!("open_or_create: rendezvous key={key:?}; trying open#1");
    // §RS-2 margin limiter: each raw `open_dht_record` is an un-gated DHT op, so it
    // holds an un-gated-op permit across the call — peak open concurrency ≤ margin(2)
    // by construction (CRSH-ISC-14), never a census argument. Acquired at raw-call
    // granularity (not spanning the whole fn) so the margin is occupied only for the
    // open RPC, and `create_dht_record` between the two opens runs without it.
    // CRSH-ISC-17: `open_or_create` issues no gated GET, so no read-pool permit is ever
    // held while this limiter permit is acquired (the single-permit rule is respected).
    let open1 = {
        let _ungated = gate.acquire_ungated().await;
        rc.open_dht_record(key.clone(), Some(owner.clone())).await
    };
    match open1 {
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
    let r = {
        let _ungated = gate.acquire_ungated().await;
        rc.open_dht_record(key.clone(), Some(owner.clone())).await
    }
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
    // Poison-recovery idiom (WB-5.1 / I5″.8, mirroring `ring_seq`): the guarded state
    // is a plain key→key cache whose per-entry invariants survive an unwind, so a
    // panic elsewhere while holding this brief map guard must NOT poison-cascade and
    // wedge every subsequent record open (#168 failure class). Recover the inner map.
    if let Some(k) = cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(owner_seed)
        .cloned()
    {
        return Ok(k);
    }
    let k = open.await?;
    cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(*owner_seed, k.clone());
    Ok(k)
}

/// Per-rendezvous-record serialization lock: one async mutex per record, keyed by
/// owner seed. Two operations on the SAME record must not run concurrently —
/// spawned append-ring [`publish`]es (the off-loop publish path) would otherwise
/// race into the shared `base + (seq % RING_DEPTH)` slot, and an older write landing
/// after a newer one silently DROPS the newer message (not merely reorders it — the
/// receiver's `sent_unix_ms` sort cannot recover a value that was never stored); and
/// two cold-cache callers would both run [`open_or_create`] on the same record.
/// Holding this lock across the open+write of one record serializes both, while
/// DISTINCT records take DISTINCT locks and stay fully concurrent — so a slow write
/// to one record never blocks another's traffic or the actor command loop. See ISA
/// Decisions (2026-07-07, #128 xhigh review).
pub type RecordLocks = Mutex<HashMap<[u8; 32], Arc<tokio::sync::Mutex<()>>>>;

/// The serialization lock for `owner_seed`, creating it on first use. The returned
/// `Arc` is `.lock().await`-ed by the caller; the brief `std::sync::Mutex` guard on
/// the map itself is never held across an await.
pub fn record_lock(locks: &RecordLocks, owner_seed: &[u8; 32]) -> Arc<tokio::sync::Mutex<()>> {
    // Poison-recovery idiom (WB-5.1 / I5″.8, mirroring `ring_seq`): the guarded state
    // is a map of per-record lock handles whose invariants survive an unwind; a
    // poisoned-mutex cascade wedging every subsequent record open is the #168 failure
    // class with a different door, so recover the inner map rather than propagate.
    locks
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(*owner_seed)
        .or_default()
        .clone()
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

/// Per-sweep GET accounting. `attempted` counts every subkey GET issued; `failed`
/// counts GETs that errored (distinct from an empty slot — the observability the old
/// `.ok().flatten()` swallowed); `found` counts populated slots handed to `on_bytes`.
/// Surfacing `failed` separately from empty/`found` is the enabling signal for
/// consumer-side session-health tracking (CRSH-ISC-1): an erroring record session
/// produces `failed > 0` sweeps instead of silent zero-yield ones.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepOutcome {
    pub attempted: u32,
    pub failed: u32,
    pub found: u32,
}

/// Sweep every subkey once for the login backlog, emitting an [`VeilidNetEvent::Inbound`]
/// per populated slot. Each `get_dht_value` `force_refresh`es from the network (DHT
/// reads are eventually consistent) under a **per-GET** read permit from the shared
/// [`DhtGate`] (WB-5.1 / I5″.2): the permit is held around ONE GET and released before
/// the next, so read occupancy never exceeds the read partition no matter how many
/// sweeps run concurrently (WB-ISC-21/22) — the fix for the first WB-5 build, whose
/// whole-sweep permit let ≥13 cold-start sweeps drain the pool and starve writes.
/// Bounded by [`SUBKEY_COUNT`]; runs as a background task. Produces a [`SweepOutcome`]
/// and traces its counts (CRSH-ISC-1); the session-health tracker that consumes them
/// is a later build step.
pub async fn sweep(
    gate: Arc<DhtGate>,
    rc: RoutingContext,
    key: RecordKey,
    ev_tx: mpsc::UnboundedSender<VeilidNetEvent>,
) {
    let outcome = sweep_gated(
        &gate,
        SUBKEY_COUNT,
        |bytes| ev_tx.send(VeilidNetEvent::Inbound { bytes }).is_ok(),
        |subkey| {
            let rc = rc.clone();
            let key = key.clone();
            async move {
                match rc.get_dht_value(key, subkey, true).await {
                    Ok(Some(v)) => Ok(Some(v.data().to_vec())),
                    Ok(None) => Ok(None),
                    Err(e) => {
                        // The GET errored — distinct from an empty slot. Keep the error
                        // string visible in traces (the old `.ok().flatten()` dropped it
                        // silently, the primary observability gap per §RS-1.1) and report
                        // it up as a per-record failure rather than an empty slot.
                        crate::vtrace!("sweep: get_dht_value error on subkey {subkey}: {e}");
                        Err(())
                    }
                }
            }
        },
    )
    .await;
    crate::vtrace!(
        "sweep: done, {} backlog slot(s) emitted ({} attempted, {} failed)",
        outcome.found,
        outcome.attempted,
        outcome.failed
    );
}

/// The testable per-GET sweep core (WB-5.1 / I5″.2). For each subkey it acquires ONE
/// read permit from `gate`, runs `get` (one DHT GET), releases the permit, then hands
/// any populated slot's bytes to `on_bytes`. The permit is held across the GET only —
/// never across the whole sweep and never across `on_bytes` (the emit is not a DHT op)
/// — so `gate`'s read pool bounds instantaneous read concurrency regardless of live
/// sweep count. `on_bytes` returns `false` to stop early (the receiver dropped).
/// Generic over `get` so the per-GET permit discipline is unit-testable without veilid
/// types (WB-ISC-21/22).
///
/// `get` returns `Result<Option<Vec<u8>>, ()>`: `Err(())` is a failed GET, `Ok(None)`
/// an empty slot, `Ok(Some(bytes))` a populated one — the three cases the old
/// `Option`-only surface conflated (CRSH-ISC-1). A per-subkey GET error increments
/// `failed` and the sweep continues (a GET error is per-record health signal, not a
/// reason to abort the sweep); the receiver-dropped early return still applies only via
/// `on_bytes` returning `false`. Returns a [`SweepOutcome`] with `attempted`/`failed`/
/// `found` counts.
pub async fn sweep_gated<Fut>(
    gate: &Arc<DhtGate>,
    subkey_count: u16,
    mut on_bytes: impl FnMut(Vec<u8>) -> bool,
    get: impl Fn(u32) -> Fut,
) -> SweepOutcome
where
    // `std::result::Result` (not the crate's one-param `Result` alias): `Err(())` is a
    // failed GET, distinct from `Ok(None)` (empty slot) and `Ok(Some(_))` (populated).
    Fut: Future<Output = std::result::Result<Option<Vec<u8>>, ()>>,
{
    let mut outcome = SweepOutcome::default();
    for subkey in 0..u32::from(subkey_count) {
        let got = {
            // The read permit is scoped to THIS GET: acquired here, dropped at the end
            // of the block before the next iteration (RAII — releases even on unwind,
            // #168). This is the per-GET granularity that bounds read occupancy.
            let _read_permit = gate.acquire_read().await;
            get(subkey).await
        };
        outcome.attempted += 1;
        match got {
            Ok(Some(bytes)) => {
                outcome.found += 1;
                if !on_bytes(bytes) {
                    return outcome; // receiver dropped — stop sweeping
                }
            }
            Ok(None) => {}
            Err(()) => outcome.failed += 1, // failed GET: per-record health signal, keep sweeping
        }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

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

    #[test]
    fn record_lock_is_per_seed_same_shares_distinct_separate() {
        // Same owner seed → the SAME lock (same-record ops serialize); distinct
        // seeds → distinct locks (different records run concurrently).
        let locks: RecordLocks = Mutex::new(HashMap::new());
        let a = record_lock(&locks, &[1u8; 32]);
        let a2 = record_lock(&locks, &[1u8; 32]);
        let b = record_lock(&locks, &[2u8; 32]);
        assert!(Arc::ptr_eq(&a, &a2), "same seed reuses one lock");
        assert!(!Arc::ptr_eq(&a, &b), "distinct seeds get distinct locks");
    }

    #[tokio::test]
    async fn same_record_critical_sections_do_not_interleave_across_await() {
        // The regression fix: writes to one record must not interleave even across
        // an await (the DHT open/set). Eight tasks contend on one seed's lock, each
        // logging start/end around a yield; with the lock held every (start,end) is
        // an unbroken pair. Without it a yield would let another task's start slip
        // between — the exact race that lets an older ring write land after a newer.
        let locks: Arc<RecordLocks> = Arc::new(Mutex::new(HashMap::new()));
        let log: Arc<Mutex<Vec<(u32, char)>>> = Arc::new(Mutex::new(Vec::new()));
        let seed = [9u8; 32];
        let mut handles = Vec::new();
        for i in 0..8u32 {
            let locks = locks.clone();
            let log = log.clone();
            handles.push(tokio::spawn(async move {
                let lock = record_lock(&locks, &seed);
                let _guard = lock.lock().await;
                log.lock().unwrap().push((i, 's'));
                tokio::task::yield_now().await;
                log.lock().unwrap().push((i, 'e'));
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let log = log.lock().unwrap();
        assert_eq!(log.len(), 16);
        for pair in log.chunks(2) {
            assert_eq!(pair[0].1, 's');
            assert_eq!(pair[1].1, 'e');
            assert_eq!(
                pair[0].0, pair[1].0,
                "one record's critical section stays atomic across the await"
            );
        }
    }

    // ── WB-ISC-21: per-GET read-permit granularity ────────────────────────────
    /// A read permit is held across ONE `get_dht_value` and released before the next,
    /// so a *different* acquirer obtains the shared permit BETWEEN two GETs of one
    /// active sweep — impossible if the sweep held the permit across its whole run.
    /// With a 1-permit read pool and FIFO fairness the permit ping-pongs, so a
    /// competitor's acquisition interleaves before the sweep finishes.
    #[tokio::test]
    async fn wb_isc_21_read_permit_is_per_get_not_per_sweep() {
        let gate = DhtGate::with_pools(2, 1, 2, 1); // read pool = 1 (the contended permit)
        let log: Arc<Mutex<Vec<char>>> = Arc::new(Mutex::new(Vec::new()));

        // Competitor: two acquisitions of the single read permit, yielding while held.
        let comp = {
            let gate = gate.clone();
            let log = log.clone();
            tokio::spawn(async move {
                for _ in 0..2 {
                    let _p = gate.acquire_read().await;
                    log.lock().unwrap().push('c');
                    tokio::task::yield_now().await;
                    drop(_p);
                    tokio::task::yield_now().await;
                }
            })
        };

        // Sweep: three GETs, each records 's' while holding the read permit, yielding
        // so the FIFO-queued competitor can take the permit once it is released.
        let outcome = sweep_gated(
            &gate,
            3,
            |_bytes| true,
            |_subkey| {
                let log = log.clone();
                async move {
                    log.lock().unwrap().push('s');
                    tokio::task::yield_now().await;
                    Ok(Some(vec![1u8]))
                }
            },
        )
        .await;
        comp.await.unwrap();
        assert_eq!(outcome.found, 3, "all three slots populated");

        let log = log.lock().unwrap();
        let first_c = log.iter().position(|&c| c == 'c');
        let last_s = log.iter().rposition(|&c| c == 's');
        assert!(
            log.contains(&'c') && log.contains(&'s'),
            "both the sweep and the competitor made progress"
        );
        assert!(
            first_c.unwrap() < last_s.unwrap(),
            "a competitor acquired the shared read permit BETWEEN sweep GETs \
             (per-GET release), not only after the whole sweep finished: {log:?}"
        );
    }

    // ── WB-ISC-22: read-lane occupancy is N-independent ───────────────────────
    /// Read-lane occupancy never exceeds the read partition regardless of how many
    /// sweeps run concurrently, and every sweep completes. `2 × partition` concurrent
    /// sweeps against a 2-permit read pool: max observed read-in-flight stays ≤ 2, and
    /// all four sweeps finish (a whole-sweep hold would let record-count growth erode
    /// the budget — this closes it at the read layer).
    #[tokio::test]
    async fn wb_isc_22_read_occupancy_bounded_by_partition() {
        const READ_POOL: usize = 2;
        let gate = DhtGate::with_pools(2, 1, 2, READ_POOL);
        let max_in_flight = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..(2 * READ_POOL) {
            let gate = gate.clone();
            let max_in_flight = max_in_flight.clone();
            handles.push(tokio::spawn(async move {
                sweep_gated(
                    &gate,
                    8,
                    |_bytes| true,
                    |_subkey| {
                        let gate = gate.clone();
                        let max_in_flight = max_in_flight.clone();
                        async move {
                            let in_flight = READ_POOL - gate.available_read();
                            max_in_flight.fetch_max(in_flight, Ordering::SeqCst);
                            tokio::task::yield_now().await;
                            Ok(Some(vec![1u8]))
                        }
                    },
                )
                .await
            }));
        }
        let mut total_found = 0u32;
        for h in handles {
            total_found += h.await.unwrap().found; // every sweep completes (no deadlock/hang)
        }
        assert_eq!(
            total_found,
            8 * (2 * READ_POOL) as u32,
            "all sweeps swept all slots"
        );
        assert!(
            max_in_flight.load(Ordering::SeqCst) <= READ_POOL,
            "read occupancy never exceeds the read partition regardless of live sweep count"
        );
    }

    // ── CRSH-ISC-1: sweep GET accounting distinguishes failed / empty / found ──
    /// A `get` closure that errors on some subkeys, returns empty on others, and
    /// populates the rest must surface the three cases separately in [`SweepOutcome`]:
    /// `failed` counts the `Err(())` GETs (no longer swallowed into the empty-slot path
    /// by the old `.ok().flatten()`), `found` counts `Ok(Some)`, and `attempted` counts
    /// every subkey. This is the enabling observability for consumer-side session-health
    /// tracking (§RS-1.1).
    #[tokio::test]
    async fn crsh_isc_1_sweep_outcome_accounts_failed_empty_and_found_separately() {
        let gate = DhtGate::with_pools(2, 1, 2, 4);
        // 9 subkeys by `subkey % 3`: 0,3,6 error; 1,4,7 populated; 2,5,8 empty.
        let outcome = sweep_gated(
            &gate,
            9,
            |_bytes| true,
            |subkey| async move {
                match subkey % 3 {
                    0 => Err(()),
                    1 => Ok(Some(vec![1u8])),
                    _ => Ok(None),
                }
            },
        )
        .await;
        assert_eq!(outcome.attempted, 9, "every subkey is attempted");
        assert_eq!(
            outcome.failed, 3,
            "subkeys 0,3,6 errored (not counted as empty)"
        );
        assert_eq!(outcome.found, 3, "subkeys 1,4,7 populated");
    }
}
