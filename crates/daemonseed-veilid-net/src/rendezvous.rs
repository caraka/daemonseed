//! The shared-owner DFLT DHT **rendezvous engine** — one generic primitive
//! underneath circles, the lobby / public rooms, share discovery, direct
//! messaging, and (later) presence and announcements. It is parameterized by
//! exactly three things: a deterministically-derivable **owner keypair**, the
//! record's **[`RecordShape`]** (its `o_cnt`, which is part of the derived
//! address and fixes the per-subkey write cap), and the opaque **sealed bytes** a
//! participant publishes; the engine never knows which feature it is serving.
//! The owner keypair and the shape are returned bound together as a
//! [`RendezvousHandle`], so a write or sweep can never disagree with the
//! derivation about which record it is addressing.
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
    DHTSchema, KeyPair, PublicKey, RecordKey, RoutingContext, SetDHTValueOptions, VeilidAPI,
    CRYPTO_KIND_VLD0,
};

use crate::dht_gate::DhtGate;
use crate::error::{Result, VeilidNetError};
use crate::event::VeilidNetEvent;

/// Total subkeys in a rendezvous DFLT record. Fixed — it is part of the
/// deterministic record key, so every participant MUST agree. Kept small so a
/// connecting participant can sweep the whole record for backlog cheaply.
/// `= MEMBER_REGIONS * RING_DEPTH`.
pub const SUBKEY_COUNT: u16 = 64;

/// Veilid's hard per-subkey value ceiling
/// (`veilid-core-0.5.7 src/storage_manager/types/mod.rs:14`, which defines it as
/// `EncryptedValueData::MAX_LEN` — `types/encrypted_value_data.rs:13`).
///
/// Mirrored rather than imported: it lives in veilid-core's private
/// `storage_manager` module and is not re-exported, so a version bump must be
/// caught by re-auditing this citation. (Contrast [`MAX_SUBKEY_COUNT`], which IS
/// public and is cross-checked by a test.)
pub const MAX_SUBKEY_SIZE: usize = 32768;

/// Veilid's per-record total data ceiling (`MAX_RECORD_DATA_SIZE`,
/// `veilid-core-0.5.7 src/storage_manager/types/mod.rs:16`). Divided by the
/// schema's `o_cnt`, it is the *other* half of the per-subkey cap. Mirrored for
/// the same reason as [`MAX_SUBKEY_SIZE`] — private module, not re-exported.
pub const MAX_RECORD_DATA_SIZE: usize = 1_048_576;

/// The largest `o_cnt` a DFLT schema accepts (`DHTSchema::MAX_SUBKEY_COUNT`,
/// `veilid-core-0.5.7 src/veilid_api/types/dht/schema/mod.rs:24`).
pub const MAX_SUBKEY_COUNT: u16 = 1024;

/// A DFLT record's **shape**: its subkey count (`o_cnt`) and the per-subkey value
/// cap that count implies.
///
/// `o_cnt` is part of the record's deterministic address (it feeds both
/// `get_dht_record_key` and `create_dht_record`), so a record's shape is fixed at
/// derivation and every participant MUST agree on it. Different surfaces want
/// different shapes — the chat/discovery rendezvous record is `dflt(64)`, while
/// direct messaging's key record, doorbell, and channel pages are `dflt(1)`,
/// `dflt(32)`, and `dflt(16)` respectively (`docs/design/direct-messaging.md`
/// DRAFT v6) — so the engine takes the shape as a parameter rather than baking
/// one in.
///
/// **A surface's shape constant lives here and is derived from the same slot count
/// its address derivation uses** — see [`RecordShape::DM_KEY_RECORD`]. That is
/// deliberate: `o_cnt` is part of the address, so a shape hand-typed at a call
/// site that disagreed with the deriving module would open a *different,
/// perfectly valid record* — no error anywhere, and two participants who simply
/// never see each other's writes. A shared constant makes that disagreement a
/// compile error instead of a convention stated in prose (ISC-C100). The doorbell
/// and channel-page shapes get theirs when their transport lands; adding them
/// before there is anything to open would be an unused constant, not a check.
///
/// **The value cap is not a constant.** Veilid enforces
/// `min(MAX_SUBKEY_SIZE, MAX_RECORD_DATA_SIZE / o_cnt)` per subkey
/// (`veilid-core-0.5.7 src/storage_manager/schema.rs:61-63`), so slot count trades
/// directly against slot capacity: `dflt(32)` gets the full 32 KiB, `dflt(64)`
/// only 16 KiB, `dflt(256)` just 4 KiB. Deriving the write guard from the shape —
/// rather than comparing against a flat 32768 — is what stops a 16385-byte value
/// passing the local check and then being rejected by the network as "value too
/// big" (`docs/design/direct-messaging.md` § Schema sizing, consequence 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordShape {
    o_cnt: u16,
}

impl RecordShape {
    /// The shape every pre-DM rendezvous record uses: `dflt(64)`, 16 KiB/subkey.
    pub const RENDEZVOUS: Self = Self::new(SUBKEY_COUNT);

    /// Direct messaging's key record: `dflt(1)`.
    pub const DM_KEY_RECORD: Self = Self::new(daemonseed_core::dm::keyrec::KEY_RECORD_SLOTS);

    /// A DFLT shape with `o_cnt` subkeys. **Panics** outside Veilid's accepted
    /// `1..=MAX_SUBKEY_COUNT` range.
    ///
    /// Panicking is deliberate, and the alternative is worse. `o_cnt` is part of
    /// the record address, so silently clamping an out-of-range value would not
    /// produce an error — it would produce a *different, perfectly valid record*,
    /// and two participants who disagreed on `o_cnt` would simply never find each
    /// other's writes. A silent wrong-address is far harder to diagnose than a
    /// loud failure at the mistake site. Every caller passes a compile-time
    /// constant, so in practice this is a **compile-time** error: a `const fn`
    /// panic in a `const` context (as in [`RecordShape::RENDEZVOUS`]) fails the
    /// build rather than the run.
    pub const fn new(o_cnt: u16) -> Self {
        assert!(
            o_cnt >= 1 && o_cnt <= MAX_SUBKEY_COUNT,
            "o_cnt must be in 1..=1024 — it is part of the record address, so a \
             clamped value would silently name a different record"
        );
        Self { o_cnt }
    }

    /// The subkey count — the schema's `o_cnt`, and the sweep's upper bound.
    pub const fn o_cnt(self) -> u16 {
        self.o_cnt
    }

    /// The per-subkey value cap Veilid will actually enforce for this shape:
    /// `min(MAX_SUBKEY_SIZE, MAX_RECORD_DATA_SIZE / o_cnt)`.
    pub const fn max_value_len(self) -> usize {
        let by_record = MAX_RECORD_DATA_SIZE / (self.o_cnt as usize);
        if by_record < MAX_SUBKEY_SIZE {
            by_record
        } else {
            MAX_SUBKEY_SIZE
        }
    }
}

/// A rendezvous record's full identity: its deterministic [`RecordKey`] together
/// with the [`RecordShape`] that key was derived under.
///
/// The two travel together because they are **one fact**. `o_cnt` feeds
/// `get_dht_record_key`, so a key and a shape that disagree name *different
/// records*; and the shape also fixes the per-subkey write cap. Returning them
/// bound means a caller derives the shape once, at open time, and every later
/// write or sweep reads it back off the handle instead of re-supplying it by
/// hand — removing the failure mode where a copy-pasted shape constant at a write
/// site silently targets a different record than the one that was opened. That
/// mistake is exactly the class ISC-C100 exists to close, and it would otherwise
/// have reappeared at the derive/use boundary the moment direct messaging put
/// four shapes in play at once instead of one.
#[derive(Debug, Clone)]
pub struct RendezvousHandle {
    key: RecordKey,
    shape: RecordShape,
}

impl RendezvousHandle {
    /// Bind a record key to the shape it was derived under.
    pub fn new(key: RecordKey, shape: RecordShape) -> Self {
        Self { key, shape }
    }

    /// The deterministic record key.
    pub fn key(&self) -> &RecordKey {
        &self.key
    }

    /// The shape this key was derived under — the sweep bound and the write cap.
    pub fn shape(&self) -> RecordShape {
        self.shape
    }

    /// Consume the handle for an API that takes an owned [`RecordKey`].
    pub fn into_key(self) -> RecordKey {
        self.key
    }
}

/// The cache/lock identity of a record: its owner seed **and** its shape's
/// `o_cnt`.
///
/// Both dimensions are load-bearing. Before shapes were parameterized, every
/// rendezvous record shared one schema, so `owner_seed` alone was a record's full
/// identity and the caches keyed on it (ISA Decisions 2026-07-07, #128 D-0a).
/// That premise no longer holds: `o_cnt` is part of the derived address, so the
/// same seed under two shapes is two different records. Keying the open-cache on
/// the seed alone would let a lookup under one shape return a [`RecordKey`]
/// derived for another — a wrong-record write that no compiler or test would
/// catch. The pairing is not reachable today (every DM surface derives its owner
/// seed under a distinct HKDF domain), which is precisely why it is worth closing
/// now, while it is still theoretical.
/// The seed half is a **digest of** the owner seed, never the seed itself (#244).
/// Every record that existed when these caches were written had a world-derivable
/// owner seed, so holding one cost nothing. A DM channel page is the first
/// exception: its seed derives from the conversation secret `AR`, and under Veilid
/// a derivable owner seed **is** write access to the conversation. Copying that
/// into a process-lifetime, `Debug`-printable map key is exactly what
/// `redacted_secret_newtype::as_bytes` forbids, and it would undo the
/// zeroize-on-drop hygiene `DmPageOwnerSeed` carries. Hashing costs one SHA-384
/// per open — nothing against a DHT round trip — and removes the class outright
/// rather than threading a zeroizing type through every caller of the engine.
pub type CachedRecordId = (PublicKey, u16);

/// The cache/lock id for a record owned by `owner`, at `shape`.
///
/// Keyed on the owner's PUBLIC key, not the seed it was derived from. The public
/// key identifies the record at least as precisely — it is what
/// [`rendezvous_key`] derives the DHT address from, so two seeds sharing a public
/// key would be one record anyway — and it is public by nature, being the
/// record's identity on the network. It is also already a one-way function of the
/// seed, so no hashing step is needed and there is no fallible crypto call on the
/// open path.
pub fn cached_record_id(owner: &KeyPair, shape: RecordShape) -> CachedRecordId {
    (owner.key().clone(), shape.o_cnt())
}

/// Distinct member regions; a member maps to one by hashing its node pubkey.
/// Collision (two members → same region) degrades to slot-sharing, not a crash;
/// a roster (Phase 4) removes the blind hash. Sized for small circles.
pub const MEMBER_REGIONS: u32 = 32;

/// Append-ring depth per member — the bounded recent backlog surfaced on login.
/// "A couple of recent messages", deliberately not durable scrollback.
pub const RING_DEPTH: u32 = 2;

/// The DFLT schema for a given record [`RecordShape`].
fn schema(shape: RecordShape) -> Result<DHTSchema> {
    DHTSchema::dflt(shape.o_cnt()).map_err(|e| VeilidNetError::Routing(e.to_string()))
}

/// Compute a rendezvous record's deterministic record key from its owner
/// keypair and [`RecordShape`]. Local crypto only — no network round-trip.
///
/// The shape is part of the address: two records with the same owner but
/// different `o_cnt` are *different records*, so every participant must derive
/// with the same shape.
pub async fn rendezvous_key(
    api: &VeilidAPI,
    owner: &KeyPair,
    shape: RecordShape,
) -> Result<RendezvousHandle> {
    let key = api
        .get_dht_record_key(schema(shape)?, owner.key(), None)
        .await
        .map_err(|e| VeilidNetError::Routing(e.to_string()))?;
    Ok(RendezvousHandle::new(key, shape))
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
    shape: RecordShape,
) -> Result<RendezvousHandle> {
    let handle = rendezvous_key(api, owner, shape).await?;
    let key = handle.key().clone();
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
            return Ok(handle);
        }
        Err(e) => crate::vtrace!("open_or_create: open#1 failed ({e}); creating record"),
    }
    // Not present — create the network record. Ignore the result: on success
    // the handle carries create's random encryption key; on a lost create race
    // a peer already created it. Either way the reopen below (with our
    // no-encryption-key record key) resets the handle to verbatim storage.
    match rc
        .create_dht_record(CRYPTO_KIND_VLD0, schema(shape)?, Some(owner.clone()))
        .await
    {
        Ok(_) => crate::vtrace!("open_or_create: create ok"),
        Err(e) => crate::vtrace!("open_or_create: create failed ({e}) (lost race? reopen anyway)"),
    }
    let r = {
        let _ungated = gate.acquire_ungated().await;
        rc.open_dht_record(key.clone(), Some(owner.clone())).await
    }
    .map(|_| handle)
    .map_err(|e| VeilidNetError::Routing(e.to_string()));
    crate::vtrace!(
        "open_or_create: reopen {}",
        if r.is_ok() { "ok -> Ok" } else { "ERR" }
    );
    r
}

/// A session cache of rendezvous records already opened, keyed by
/// [`CachedRecordId`] → the post-reopen [`RendezvousHandle`]. [`open_or_create`]
/// pays a fresh open (~6–10 s live-measured) on every publish/subscribe; once a
/// handle is cached, callers reuse the open record and skip the round-trip. The
/// cached handle is the reopen result, so it carries the verbatim-storage
/// (no-encryption) handle semantics — never a raw `create` handle with a random
/// encryption key.
///
/// The id is `(owner_seed, o_cnt)`, not the seed alone — see [`CachedRecordId`]
/// for why the shape is part of a record's identity.
pub type OpenCache = Mutex<HashMap<CachedRecordId, RendezvousHandle>>;

/// Return the cached open handle for `id`, else run `open` once, cache its
/// result, and return it. Generic over both the id and the value so the caching
/// logic is unit-testable without veilid types. `open` is a lazy future built by
/// the caller: on a cache hit it is dropped un-awaited (an `async fn` future runs
/// no body until polled), so a hit costs nothing beyond the map lookup.
///
/// The record is opened once per session and never closed, so the cached handle
/// stays valid — there is deliberately no error-path invalidation. A `set`/`get`
/// failure is a transient network condition the caller surfaces (and may retry),
/// not a dead local handle; dropping the entry would only force a redundant
/// re-open, and on the shared lobby record (every share advert + the lobby
/// subscription derive the SAME `owner_seed`) it would evict an entry other
/// callers are actively using. See ISA Decisions (2026-07-06, #128 D-0a).
pub async fn open_cached<I: Eq + std::hash::Hash + Clone, K: Clone>(
    cache: &Mutex<HashMap<I, K>>,
    id: &I,
    open: impl std::future::Future<Output = Result<K>>,
) -> Result<K> {
    // Poison-recovery idiom (WB-5.1 / I5″.8, mirroring `ring_seq`): the guarded state
    // is a plain id→handle cache whose per-entry invariants survive an unwind, so a
    // panic elsewhere while holding this brief map guard must NOT poison-cascade and
    // wedge every subsequent record open (#168 failure class). Recover the inner map.
    if let Some(k) = cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(id)
        .cloned()
    {
        return Ok(k);
    }
    let k = open.await?;
    cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id.clone(), k.clone());
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
///
/// **Deliberately keyed on the seed's digest alone, unlike [`OpenCache`].** Where
/// the open cache MUST distinguish shapes (returning a key derived for the wrong
/// `o_cnt` would write to the wrong record), this lock only decides what
/// serializes against what. Two differently-shaped records sharing an owner seed
/// would share one lock — over-serializing, never under-serializing — so the
/// seed-only key is the conservative choice and keeps the CRSH-ISC-3/18 lock-span
/// invariants exactly as they were verified. It holds the owner's PUBLIC key
/// rather than the seed, for the reason [`CachedRecordId`] gives (#244): a lock
/// identity needs to tell records apart, not to carry write capability.
pub type RecordLocks = Mutex<HashMap<PublicKey, Arc<tokio::sync::Mutex<()>>>>;

/// The serialization lock for the record owned by `owner`, creating it on first use. The returned
/// `Arc` is `.lock().await`-ed by the caller; the brief `std::sync::Mutex` guard on
/// the map itself is never held across an await.
pub fn record_lock(locks: &RecordLocks, owner: &KeyPair) -> Arc<tokio::sync::Mutex<()>> {
    // Poison-recovery idiom (WB-5.1 / I5″.8, mirroring `ring_seq`): the guarded state
    // is a map of per-record lock handles whose invariants survive an unwind; a
    // poisoned-mutex cascade wedging every subsequent record open is the #168 failure
    // class with a different door, so recover the inner map rather than propagate.
    locks
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(owner.key().clone())
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
    handle: &RendezvousHandle,
    owner: &KeyPair,
    base: u32,
    seq: u32,
    sealed: Vec<u8>,
) -> Result<()> {
    publish_at_subkey(rc, handle, owner, base + (seq % RING_DEPTH), sealed).await
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

/// The schema-derived write guard, split out from [`publish_at_subkey`] so the
/// rule itself is unit-testable — the network call past it needs a live
/// `RoutingContext`, but the guard does not. Same seam as [`sweep_gated`] /
/// [`repair_gated`]: the decision is a pure function, the I/O is not.
///
/// Rejects `sealed_len` above `shape`'s [`RecordShape::max_value_len`], the same
/// bound Veilid enforces at `storage_manager/schema.rs:61-63` — so a value the
/// network would refuse with "value too big" fails locally first, naming the true
/// cap and the shape (ISC-C100).
fn check_write_cap(sealed_len: usize, shape: RecordShape) -> Result<()> {
    let cap = shape.max_value_len();
    if sealed_len > cap {
        return Err(VeilidNetError::Send(format!(
            "sealed {sealed_len} bytes exceeds the {cap}-byte subkey cap of dflt({}) (re-chunk)",
            shape.o_cnt()
        )));
    }
    Ok(())
}

/// Write `sealed` to a SPECIFIC subkey (owner-signed), last-writer-wins — the
/// current-state counterpart to [`publish`]'s append-ring write. The caller picks the
/// slot from a stable identity via [`current_state_subkey`], so re-publishing the same
/// item overwrites in place instead of orphaning a stale copy.
///
/// The write guard is **schema-derived**: the cap comes from the handle's shape's
/// [`RecordShape::max_value_len`], the same `min(MAX_SUBKEY_SIZE,
/// MAX_RECORD_DATA_SIZE / o_cnt)` Veilid itself enforces
/// (`veilid-core-0.5.7 src/storage_manager/schema.rs:61-63`) — never a flat
/// constant. A flat 32768 guard over-permits every shape denser than `dflt(32)`:
/// on the production `dflt(64)` records the true cap is 16384, so a 16385-byte
/// value passed the old local check and was then rejected by the network with
/// "value too big" (`docs/design/direct-messaging.md` § Schema sizing).
pub async fn publish_at_subkey(
    rc: &RoutingContext,
    handle: &RendezvousHandle,
    owner: &KeyPair,
    subkey: u32,
    sealed: Vec<u8>,
) -> Result<()> {
    check_write_cap(sealed.len(), handle.shape())?;
    rc.set_dht_value(
        handle.key().clone(),
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
/// `.ok().flatten()` swallowed); `found` counts populated slots handed to `on_slot`.
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
/// Bounded by the handle's shape (`o_cnt`); runs as a background task. Produces a [`SweepOutcome`],
/// traces its counts, and surfaces it per-record to the caller as a
/// [`VeilidNetEvent::SweepHealth`] so each frontend net actor can drive a session-health
/// tracker (CRSH-ISC-1; `docs/design/consumer-route-self-heal.md` §RS-1.1). Emitting the
/// health event changes no network behaviour and no on-slot `Inbound` emission.
pub async fn sweep(
    gate: Arc<DhtGate>,
    rc: RoutingContext,
    handle: RendezvousHandle,
    ev_tx: mpsc::UnboundedSender<VeilidNetEvent>,
) {
    let key = handle.key().clone();
    let outcome = sweep_collect(&gate, &rc, handle, &ev_tx).await;
    // Surface the per-record outcome to the frontend net actor's session-health tracker
    // (CRSH-ISC-1). A closed receiver (actor shut down) is non-fatal — the sweep is a
    // fire-and-forget background task and its `Inbound` sends tolerate the same drop.
    let _ = ev_tx.send(VeilidNetEvent::SweepHealth { key, outcome });
}

/// The full `0..o_cnt` sweep body (the bound comes from the handle's shape), emitting an [`VeilidNetEvent::Inbound`] per
/// populated slot and **returning** the [`SweepOutcome`] to the caller — WITHOUT emitting
/// [`VeilidNetEvent::SweepHealth`]. [`sweep`] is this plus the SweepHealth emission (the
/// steady/backlog path that drives the detection tracker). The repair arm ([`repair_gated`])
/// uses this directly: it awaits the re-sweep under the record lock and resets the tracker
/// itself at dispatch, so a duplicate SweepHealth from the repair's own sweep would only
/// muddy the K-consecutive stream. Each GET rides a per-GET read permit (WB-5.1 / I5″.2).
pub async fn sweep_collect(
    gate: &Arc<DhtGate>,
    rc: &RoutingContext,
    handle: RendezvousHandle,
    ev_tx: &mpsc::UnboundedSender<VeilidNetEvent>,
) -> SweepOutcome {
    let key = handle.key().clone();
    let outcome = sweep_gated(
        gate,
        handle.shape().o_cnt(),
        // The backlog ignores its slot: a rendezvous message lands wherever the
        // ring put it, so the position carries no meaning to the receiver.
        |_subkey, bytes| ev_tx.send(VeilidNetEvent::Inbound { bytes }).is_ok(),
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
    outcome
}

/// The testable per-GET sweep core (WB-5.1 / I5″.2). For each subkey it acquires ONE
/// read permit from `gate`, runs `get` (one DHT GET), releases the permit, then hands
/// any populated slot's SUBKEY INDEX and bytes to `on_slot`. The permit is held across the GET only —
/// never across the whole sweep and never across `on_slot` (the emit is not a DHT op)
/// — so `gate`'s read pool bounds instantaneous read concurrency regardless of live
/// sweep count. `on_slot` returns `false` to stop early (the receiver dropped).
///
/// **The subkey index is passed because a record's slot can be load-bearing.** For a
/// rendezvous backlog it is not — a slot is just where a message happened to land, and
/// that caller ignores it. For a DM channel page it is the message's sequence number
/// (`dm::paging::position_of`), and the frame's own declared `seq` must be checked
/// against it or the write-once mapping between the two is asserted by the writer and
/// verified by nobody. The index is the sweep loop's own variable, so handing it over
/// costs nothing; the alternative was every caller trusting the payload about where it
/// was found.
/// Generic over `get` so the per-GET permit discipline is unit-testable without veilid
/// types (WB-ISC-21/22).
///
/// `get` returns `Result<Option<Vec<u8>>, ()>`: `Err(())` is a failed GET, `Ok(None)`
/// an empty slot, `Ok(Some(bytes))` a populated one — the three cases the old
/// `Option`-only surface conflated (CRSH-ISC-1). A per-subkey GET error increments
/// `failed` and the sweep continues (a GET error is per-record health signal, not a
/// reason to abort the sweep); the receiver-dropped early return still applies only via
/// `on_slot` returning `false`. Returns a [`SweepOutcome`] with `attempted`/`failed`/
/// `found` counts.
pub async fn sweep_gated<Fut>(
    gate: &Arc<DhtGate>,
    subkey_count: u16,
    mut on_slot: impl FnMut(u32, Vec<u8>) -> bool,
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
                if !on_slot(subkey, bytes) {
                    return outcome; // receiver dropped — stop sweeping
                }
            }
            Ok(None) => {}
            Err(()) => outcome.failed += 1, // failed GET: per-record health signal, keep sweeping
        }
    }
    outcome
}

/// Whether the repair arm closes the record before re-opening it (§RS-1.2 / §RS-1.3
/// open question, **repro-gated**). `close_dht_record` cancels the desired watch
/// (`close_record.rs:117-119`), so a close-first yields a guaranteed-fresh session +
/// re-watch — the closest analog to the consumer *restart* that empirically heals the
/// felt-tested dead session; open-in-place (veilid updates an already-open record in
/// place, `open_record.rs:155-170`) is cheaper but may not clear a death that lives in
/// the opened-record session. Defaulted **`true`** (mirror the restart that is known to
/// work) pending the two-client reproduction (§RS-1.3); caraka flips it against the
/// repro. Either path satisfies CRSH-ISC-3's lock span — the close (when enabled) runs
/// inside the same `record_lock`-held span as the re-open/re-watch/re-sweep.
pub const REPAIR_CLOSE_FIRST: bool = true;

/// The testable **session re-establishment core** (§RS-1.2, CRSH-ISC-3/17/18) — the
/// heart of step 3b's repair arm. It runs, **all while holding `record_lock`**:
///
///   1. invalidate the [`open_cached`] entry for `owner_seed` (drop the dead handle);
///   2. optionally `close` the old record first (when `close_first` — [`REPAIR_CLOSE_FIRST`]);
///   3. `open` a fresh record session and re-cache its key;
///   4. `watch` the fresh session;
///   5. `sweep` it fully (`0..o_cnt`, the bound coming from the record's own shape) to
///      drain the backlog the dead session missed.
///
/// **Lock span (CRSH-ISC-3/18).** The `record_lock` guard is held across the *entire*
/// sequence, so a concurrent same-record write (a lobby chat publish, a share advert)
/// serializes behind it and, on acquiring the lock, reads the freshly re-cached key —
/// never a torn-down handle, never the invalidated empty cache.
///
/// **Permit discipline (CRSH-ISC-17).** `open`/`watch` acquire the §RS-2 un-gated-op
/// limiter; the `sweep`'s GETs acquire per-GET read permits. They are never nested:
/// open/watch complete (limiter dropped) before the sweep begins, so no task holds a
/// read permit while acquiring the limiter or vice versa. This is enforced by the phase
/// ordering here, not by inspection — the closures own their own permit acquisition and
/// this core simply sequences the phases.
///
/// Generic over the veilid ops (`close`/`open`/`watch`/`sweep` are caller-supplied
/// futures) so the ordering + lock span are unit-testable with an instrumented gate/lock
/// stand-in and no live veilid attach — exactly as [`sweep_gated`] makes the per-GET
/// permit discipline testable. Returns the re-sweep's [`SweepOutcome`].
#[allow(clippy::too_many_arguments)]
pub async fn repair_gated<I, K, CloseFut, OpenFut, WatchFut, SweepFut>(
    record_lock: &Arc<tokio::sync::Mutex<()>>,
    cache: &Mutex<HashMap<I, K>>,
    id: &I,
    close_first: bool,
    close: impl FnOnce(K) -> CloseFut,
    open: impl FnOnce() -> OpenFut,
    watch: impl FnOnce(K) -> WatchFut,
    sweep: impl FnOnce(K) -> SweepFut,
) -> Result<SweepOutcome>
where
    I: Eq + std::hash::Hash + Clone,
    K: Clone,
    CloseFut: std::future::Future<Output = ()>,
    OpenFut: std::future::Future<Output = Result<K>>,
    WatchFut: std::future::Future<Output = Result<()>>,
    SweepFut: std::future::Future<Output = SweepOutcome>,
{
    // Hold the record's serialization lock across the WHOLE re-establishment — this is
    // what makes deliberate eviction safe where ad-hoc eviction was not (CRSH-ISC-3/18).
    let _guard = record_lock.lock().await;

    // 1. Invalidate the open-cache entry. Keep the old key for a close-first. The brief
    //    map guard is never held across an await (poison-recovered, mirroring open_cached).
    let old_key = cache.lock().unwrap_or_else(|e| e.into_inner()).remove(id);

    // 2. Optionally close the old session first (cancels the desired watch → clean
    //    re-watch). Best-effort: `close`'s own body swallows a close error (releasing a
    //    session veilid already GC'd is a benign race, Evidence 3 sibling).
    if close_first {
        if let Some(k) = old_key {
            close(k).await;
        }
    }

    // 3. Re-open a fresh session (the `open` closure acquires the un-gated limiter) and
    //    re-cache its key so a subsequent same-record publish/subscribe reuses it.
    let key = open().await?;
    cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id.clone(), key.clone());

    // 4. Re-watch the fresh session (the `watch` closure acquires the un-gated limiter).
    watch(key.clone()).await?;

    // 5. Full re-sweep (per-GET read permits inside `sweep`) to drain the missed backlog.
    Ok(sweep(key).await)
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

    /// The per-subkey cap is `min(MAX_SUBKEY_SIZE, MAX_RECORD_DATA_SIZE / o_cnt)`
    /// (`veilid-core-0.5.7 src/storage_manager/schema.rs:61-63`). Pinned against the
    /// sizing table in `docs/design/direct-messaging.md` § Schema sizing, because
    /// every DM record's payload budget is derived from it.
    #[test]
    fn record_shape_value_cap_matches_the_veilid_formula() {
        let cases = [
            (1u16, 32768usize),
            (16, 32768),
            (32, 32768),
            (64, 16384),
            (128, 8192),
            (256, 4096),
            (512, 2048),
            (1024, 1024),
        ];
        for (o_cnt, expected) in cases {
            let shape = RecordShape::new(o_cnt);
            assert_eq!(shape.o_cnt(), o_cnt);
            assert_eq!(
                shape.max_value_len(),
                expected,
                "dflt({o_cnt}) per-subkey cap"
            );
        }
    }

    /// The `min()` crossover sits at `o_cnt = 32` (`1MiB/32 == 32768`, both terms
    /// tie). Every power-of-two case above divides 1 MiB exactly, so none of them
    /// can tell "the clamp switches at 32" from "somewhere near 32", and none
    /// exercises integer truncation at all. These three do both.
    #[test]
    fn record_shape_cap_crossover_and_truncation() {
        // Below/at the tie: the flat ceiling still wins.
        assert_eq!(RecordShape::new(31).max_value_len(), 32768); // 1MiB/31 = 33825 → clamped
        assert_eq!(RecordShape::new(32).max_value_len(), 32768); // exact tie
                                                                 // Past the tie: the per-record term wins, and it truncates.
        assert_eq!(RecordShape::new(33).max_value_len(), 1_048_576 / 33); // 31774, not round
        assert_eq!(RecordShape::new(100).max_value_len(), 1_048_576 / 100); // 10485, truncated
        assert!(
            RecordShape::new(33).max_value_len() < RecordShape::new(32).max_value_len(),
            "the cap must strictly fall once o_cnt passes the crossover"
        );
    }

    /// Of the three mirrored veilid constants, `MAX_SUBKEY_COUNT` is the only one
    /// veilid-core exports publicly — so it is the only one a test can pin against
    /// the real thing rather than against a source citation. Catches drift on a
    /// veilid-core version bump.
    #[test]
    fn max_subkey_count_matches_veilid_dht_schema() {
        assert_eq!(
            usize::from(MAX_SUBKEY_COUNT),
            veilid_core::DHTSchema::MAX_SUBKEY_COUNT
        );
    }

    /// ISC-C100's actual claim is about the *guard*, not the arithmetic: a value
    /// the network would reject as "value too big" must be rejected locally first.
    /// Pinned at the exact boundary for the production shape — 16384 accepted,
    /// 16385 rejected — which is the byte that slipped through the old flat-32768
    /// guard and bounced off the network.
    #[test]
    fn write_guard_rejects_exactly_one_byte_over_the_shape_cap() {
        let shape = RecordShape::RENDEZVOUS; // dflt(64) → 16384
        assert!(check_write_cap(0, shape).is_ok(), "empty value accepted");
        assert!(
            check_write_cap(16384, shape).is_ok(),
            "at-cap value accepted"
        );
        assert!(
            check_write_cap(16385, shape).is_err(),
            "cap+1 must be rejected locally, not by the network"
        );
        // The byte range the old flat guard wrongly admitted on dflt(64).
        for len in [16385usize, 20000, 32768] {
            assert!(
                check_write_cap(len, shape).is_err(),
                "{len} bytes passed the old flat 32768 guard and must now fail"
            );
        }
    }

    /// The same guard must ADMIT on a shape whose true cap is the full 32 KiB —
    /// otherwise the fix would have replaced an over-permit with an under-permit
    /// and broken the DM doorbell before it was written.
    #[test]
    fn write_guard_admits_up_to_the_full_cap_on_a_sparse_shape() {
        let doorbell = RecordShape::new(32); // dflt(32) → 32768
        assert!(check_write_cap(32768, doorbell).is_ok());
        assert!(check_write_cap(32769, doorbell).is_err());
        // ~23 KiB is the design's token-bearing first-contact entry.
        assert!(check_write_cap(23 * 1024, doorbell).is_ok());
    }

    /// The guard's error names the true cap and the shape, so a failure is
    /// diagnosable without re-deriving the formula by hand.
    #[test]
    fn write_guard_error_names_the_cap_and_the_shape() {
        let err =
            check_write_cap(16385, RecordShape::RENDEZVOUS).expect_err("over-cap write must error");
        let msg = err.to_string();
        assert!(msg.contains("16384"), "error names the true cap: {msg}");
        assert!(msg.contains("dflt(64)"), "error names the shape: {msg}");
    }

    /// The production rendezvous shape is `dflt(64)`, whose true cap is 16384 — HALF
    /// the flat `APP_MESSAGE_CAP` (32768) the guard used to compare against. That gap
    /// is the latent defect this shape closes: a 16385-byte value passed the old local
    /// check and was then rejected by the network as "value too big".
    #[test]
    fn rendezvous_shape_cap_is_half_the_old_flat_guard() {
        assert_eq!(RecordShape::RENDEZVOUS.o_cnt(), SUBKEY_COUNT);
        assert_eq!(RecordShape::RENDEZVOUS.max_value_len(), 16384);
        assert!(
            RecordShape::RENDEZVOUS.max_value_len() < MAX_SUBKEY_SIZE,
            "a flat MAX_SUBKEY_SIZE guard over-permits dflt(64) by 2x"
        );
    }

    /// The in-range boundaries `DHTSchema::dflt` accepts.
    #[test]
    fn record_shape_accepts_the_veilid_range_boundaries() {
        assert_eq!(RecordShape::new(1).o_cnt(), 1);
        assert_eq!(RecordShape::new(MAX_SUBKEY_COUNT).o_cnt(), MAX_SUBKEY_COUNT);
    }

    /// `o_cnt` is part of the record ADDRESS, so an out-of-range value must fail
    /// loudly rather than clamp. A clamp would not error — it would silently
    /// derive a different, perfectly valid record, and two participants who
    /// disagreed would simply never see each other's writes.
    #[test]
    #[should_panic(expected = "o_cnt must be in 1..=1024")]
    fn record_shape_rejects_zero_rather_than_clamping() {
        let _ = RecordShape::new(0);
    }

    #[test]
    #[should_panic(expected = "o_cnt must be in 1..=1024")]
    fn record_shape_rejects_above_max_rather_than_clamping() {
        let _ = RecordShape::new(MAX_SUBKEY_COUNT + 1);
    }

    /// A handle carries the shape its key was derived under, so a write or sweep
    /// reads the shape back off the handle instead of re-supplying it — the
    /// derive/use mismatch the type exists to prevent.
    #[test]
    fn cached_record_id_separates_the_same_owner_under_different_shapes() {
        let owner = crate::identity::rendezvous_owner_keypair(&[7u8; 32]).unwrap();
        let as_rendezvous = cached_record_id(&owner, RecordShape::RENDEZVOUS);
        let as_doorbell = cached_record_id(&owner, RecordShape::new(32));
        assert_ne!(
            as_rendezvous, as_doorbell,
            "one owner under two shapes is two records — the cache must not conflate them"
        );
        assert_eq!(
            as_rendezvous,
            cached_record_id(&owner, RecordShape::new(64))
        );
    }

    /// The cache and lock identities must not carry the owner SEED (#244).
    ///
    /// Every record that existed when these caches were written had a
    /// world-derivable seed, so holding one cost nothing. A DM channel page is the
    /// first whose seed is the conversation secret, and under Veilid a derivable
    /// owner seed IS write access — so a process-lifetime map holding one would
    /// hand out the conversation. Keyed on the owner's public key instead, which
    /// identifies the record just as precisely and is public by construction.
    #[test]
    fn cache_and_lock_identities_never_carry_the_owner_seed() {
        let seed = [0xABu8; 32];
        let owner = crate::identity::rendezvous_owner_keypair(&seed).unwrap();

        let id = cached_record_id(&owner, RecordShape::RENDEZVOUS);
        let id_bytes: Vec<u8> = id.0.value().as_ref().to_vec();
        assert_ne!(
            id_bytes.as_slice(),
            &seed[..],
            "the id must not BE the seed"
        );
        assert!(
            !id_bytes.windows(seed.len()).any(|w| w == seed),
            "the seed must not appear anywhere in the cache identity"
        );

        // And the lock map keys on the same public value.
        let locks = RecordLocks::default();
        let a = record_lock(&locks, &owner);
        let b = record_lock(&locks, &owner);
        assert!(
            Arc::ptr_eq(&a, &b),
            "the same owner must resolve to the same lock"
        );
        let other = crate::identity::rendezvous_owner_keypair(&[0xCDu8; 32]).unwrap();
        assert!(
            !Arc::ptr_eq(&a, &record_lock(&locks, &other)),
            "distinct owners must not share a lock"
        );
    }

    /// The three shapes the frozen DM design names (`docs/design/direct-messaging.md`
    /// DRAFT v6) must each hold their specified payload: the key record ≈ 6.2 KiB, the
    /// self-contained first-contact entry ≈ 18 KiB (≈ 23 KiB with an invite token), and
    /// a paged channel message ≈ 6–8 KiB. The R7 BLOCKER was exactly this arithmetic
    /// going unchecked, so it is pinned here rather than left to review.
    #[test]
    fn dm_record_shapes_hold_their_designed_payloads() {
        assert_eq!(RecordShape::new(1).max_value_len(), 32768, "key record");
        assert!(RecordShape::new(1).max_value_len() >= 6 * 1024 + 512);

        let doorbell = RecordShape::new(32);
        assert_eq!(doorbell.max_value_len(), 32768, "doorbell dflt(32)");
        assert!(
            doorbell.max_value_len() > 23 * 1024,
            "a token-bearing first-contact entry must fit with padding headroom"
        );

        let page = RecordShape::new(16);
        assert_eq!(page.max_value_len(), 32768, "channel page dflt(16)");
        assert!(page.max_value_len() >= 8 * 1024);

        // The rejected sizing: dflt(256) was the pre-R7 doorbell and cannot hold the
        // ~18 KiB self-contained entry — the BLOCKER that moved it to dflt(32).
        assert!(
            RecordShape::new(256).max_value_len() < 18 * 1024,
            "dflt(256) cannot hold the self-contained first-contact entry (R7 BLOCKER)"
        );
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
    fn record_lock_is_per_owner_same_shares_distinct_separate() {
        // Same owner → the SAME lock (same-record ops serialize); distinct owners
        // → distinct locks (different records run concurrently).
        let locks: RecordLocks = Mutex::new(HashMap::new());
        let one = crate::identity::rendezvous_owner_keypair(&[1u8; 32]).unwrap();
        let two = crate::identity::rendezvous_owner_keypair(&[2u8; 32]).unwrap();
        let a = record_lock(&locks, &one);
        let a2 = record_lock(&locks, &one);
        let b = record_lock(&locks, &two);
        assert!(Arc::ptr_eq(&a, &a2), "same owner reuses one lock");
        assert!(!Arc::ptr_eq(&a, &b), "distinct owners get distinct locks");
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
        let owner = crate::identity::rendezvous_owner_keypair(&[9u8; 32]).unwrap();
        let mut handles = Vec::new();
        for i in 0..8u32 {
            let locks = locks.clone();
            let log = log.clone();
            let owner = owner.clone();
            handles.push(tokio::spawn(async move {
                let lock = record_lock(&locks, &owner);
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
            |_subkey, _bytes| true,
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
                    |_subkey, _bytes| true,
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
            |_subkey, _bytes| true,
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

    /// The index handed to the callback is the slot the bytes were READ from, not a
    /// count of emissions — the distinction only shows up when some slots are empty
    /// or failed, which is the ordinary case for a sparsely-filled record.
    ///
    /// A DM channel page derives a message's sequence number from this index, so an
    /// off-by-anything here files every message at the wrong position, and the frame
    /// layer's seq-vs-slot check would reject honest traffic.
    #[tokio::test]
    async fn sweep_hands_the_callback_the_slot_the_bytes_came_from() {
        let gate = DhtGate::with_pools(2, 1, 2, 4);
        let mut seen: Vec<(u32, u8)> = Vec::new();
        // Only 2, 5 and 6 are populated; 0,3 fail and 1,4,7 are empty, so an
        // emission counter would report 0,1,2 where the slots are 2,5,6.
        let outcome = sweep_gated(
            &gate,
            8,
            |subkey, bytes| {
                seen.push((subkey, bytes[0]));
                true
            },
            |subkey| async move {
                match subkey {
                    0 | 3 => Err(()),
                    2 | 5 | 6 => Ok(Some(vec![subkey as u8 * 10])),
                    _ => Ok(None),
                }
            },
        )
        .await;
        assert_eq!(outcome.found, 3);
        assert_eq!(
            seen,
            vec![(2, 20), (5, 50), (6, 60)],
            "each callback must receive its own slot index alongside that slot's bytes"
        );
    }

    // ── CRSH-ISC-3 (+ CRSH-ISC-17): repair op ordering, lock span, permit discipline ──
    /// The instrumented-gate oracle for the re-establishment core. It asserts, without a
    /// live veilid attach:
    /// - **op ordering** — invalidate (implicit) → close → open → watch → the 0..N re-sweep
    ///   GETs, in exactly that sequence;
    /// - **lock span (CRSH-ISC-3)** — a competitor contending on the SAME `record_lock`
    ///   acquires it only AFTER the entire repair sequence (its trace entry lands last),
    ///   and then observes the FRESHLY re-cached key (the sibling of CRSH-ISC-18);
    /// - **permit discipline (CRSH-ISC-17)** — open/watch hold the un-gated limiter with NO
    ///   read permit held; each re-sweep GET holds a per-GET read permit with the limiter
    ///   NOT held. The two permit classes are never nested, by phase ordering.
    #[tokio::test]
    async fn crsh_isc_3_repair_ordered_trace_lock_span_and_permit_discipline() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        const SEED: [u8; 32] = [7u8; 32];
        const MARGIN: usize = crate::dht_gate::DHT_GATE_MARGIN;

        let gate = DhtGate::new(); // real pools (read 9, un-gated limiter = margin 2)
        let full_read = gate.available_read();
        let record_lock: Arc<tokio::sync::Mutex<()>> = Arc::new(tokio::sync::Mutex::new(()));
        let cache: Arc<Mutex<HashMap<[u8; 32], u32>>> = Arc::new(Mutex::new(HashMap::new()));
        cache.lock().unwrap().insert(SEED, 111); // the dead handle in-cache
        let trace: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
        let notify = Arc::new(tokio::sync::Notify::new());
        let competitor_key = Arc::new(AtomicUsize::new(0));

        // A competitor on the SAME record lock: signalled once repair is inside its
        // critical section, it must block until repair releases and then read the fresh key.
        let competitor = {
            let (lock, trace, notify, cache, ck) = (
                record_lock.clone(),
                trace.clone(),
                notify.clone(),
                cache.clone(),
                competitor_key.clone(),
            );
            tokio::spawn(async move {
                notify.notified().await; // repair holds the lock
                let _g = lock.lock().await; // serializes strictly behind repair
                trace.lock().unwrap().push("competitor");
                ck.store(
                    *cache.lock().unwrap().get(&SEED).unwrap() as usize,
                    Ordering::SeqCst,
                );
            })
        };

        let gets = Arc::new(AtomicUsize::new(0));
        let outcome = repair_gated(
            &record_lock,
            &cache,
            &SEED,
            true, // close_first (REPAIR_CLOSE_FIRST default)
            // close: tears down the OLD dead handle; no read permit held.
            |old| {
                let (trace, gate) = (trace.clone(), gate.clone());
                async move {
                    assert_eq!(old, 111, "close targets the OLD dead handle");
                    assert_eq!(
                        gate.available_read(),
                        full_read,
                        "no read permit held at close"
                    );
                    trace.lock().unwrap().push("close");
                }
            },
            // open: acquires the un-gated limiter; CRSH-ISC-17 — no read permit held.
            || {
                let (trace, gate, notify) = (trace.clone(), gate.clone(), notify.clone());
                async move {
                    let _ungated = gate.acquire_ungated().await;
                    assert_eq!(
                        gate.available_read(),
                        full_read,
                        "CRSH-ISC-17: no read permit held while holding the limiter (open)"
                    );
                    trace.lock().unwrap().push("open");
                    notify.notify_one(); // repair is now inside its critical section
                    Ok(999u32) // the fresh handle
                }
            },
            // watch: acquires the limiter on the FRESH handle; again no read permit held.
            |k| {
                let (trace, gate) = (trace.clone(), gate.clone());
                async move {
                    assert_eq!(k, 999, "watch targets the FRESH handle");
                    let _ungated = gate.acquire_ungated().await;
                    assert_eq!(
                        gate.available_read(),
                        full_read,
                        "CRSH-ISC-17: no read permit held while holding the limiter (watch)"
                    );
                    trace.lock().unwrap().push("watch");
                    Ok(())
                }
            },
            // sweep: per-GET read permits on the FRESH handle; CRSH-ISC-17 — limiter free.
            |k| {
                let (trace, gate, gets) = (trace.clone(), gate.clone(), gets.clone());
                async move {
                    assert_eq!(k, 999, "the re-sweep runs on the FRESH handle");
                    let get_gate = gate.clone(); // moved into the per-GET closure
                    sweep_gated(
                        &gate,
                        4,
                        |_subkey, _b| true,
                        move |_subkey| {
                            let (trace, gate, gets) =
                                (trace.clone(), get_gate.clone(), gets.clone());
                            async move {
                                assert!(
                                    gate.available_read() < full_read,
                                    "a per-GET read permit IS held during the GET"
                                );
                                assert_eq!(
                                gate.available_ungated(),
                                MARGIN,
                                "CRSH-ISC-17: the un-gated limiter is NOT held during a read GET"
                            );
                                gets.fetch_add(1, Ordering::SeqCst);
                                trace.lock().unwrap().push("get");
                                Ok(Some(vec![1u8]))
                            }
                        },
                    )
                    .await
                }
            },
        )
        .await
        .expect("repair completes");

        competitor.await.unwrap();
        assert_eq!(outcome.found, 4);
        assert_eq!(gets.load(Ordering::SeqCst), 4);
        // The fresh key is re-cached; the old dead handle is gone.
        assert_eq!(*cache.lock().unwrap().get(&SEED).unwrap(), 999);
        // Ordered op trace, then the competitor last (never interleaved in the lock span).
        let t = trace.lock().unwrap().clone();
        assert_eq!(
            t,
            vec![
                "close",
                "open",
                "watch",
                "get",
                "get",
                "get",
                "get",
                "competitor"
            ],
            "repair op trace + lock-span: {t:?}"
        );
        // The competitor observed the FRESH re-cached key, not the dead one (CRSH-ISC-18 sibling).
        assert_eq!(competitor_key.load(Ordering::SeqCst), 999);
    }

    // ── CRSH-ISC-18: a same-record chat write serializes behind repair, fresh session ──
    /// Paused-time interleave of a chat write with a same-record repair. The chat write
    /// takes the SAME `record_lock` the production sink takes and resolves the record via
    /// [`open_cached`] — exactly the sink's path. It must (a) block until repair releases
    /// the lock (never target the torn-down handle), and (b) dispatch against the FRESH
    /// re-cached session (999), reusing repair's insert rather than re-opening its own or
    /// reading the dead 111.
    #[tokio::test(start_paused = true)]
    async fn crsh_isc_18_chat_write_serializes_behind_repair_and_targets_fresh_session() {
        use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
        use std::time::Duration;
        const SEED: [u8; 32] = [3u8; 32];

        let record_lock: Arc<tokio::sync::Mutex<()>> = Arc::new(tokio::sync::Mutex::new(()));
        let cache: Arc<Mutex<HashMap<[u8; 32], u32>>> = Arc::new(Mutex::new(HashMap::new()));
        cache.lock().unwrap().insert(SEED, 111); // the dead handle in-cache
        let order: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
        let notify = Arc::new(tokio::sync::Notify::new());
        let chat_key = Arc::new(AtomicU32::new(0));
        let chat_opened_its_own = Arc::new(AtomicBool::new(false));

        let chat = {
            let (lock, cache, order, notify, ck, own) = (
                record_lock.clone(),
                cache.clone(),
                order.clone(),
                notify.clone(),
                chat_key.clone(),
                chat_opened_its_own.clone(),
            );
            tokio::spawn(async move {
                notify.notified().await; // repair is mid-repair, holding the lock
                let _g = lock.lock().await; // the sink's record_lock — serializes behind repair
                let own2 = own.clone();
                let k = open_cached(&cache, &SEED, async move {
                    // Runs ONLY on a cache miss — a torn-down/invalidated handle. A hit
                    // (repair re-cached the fresh key) drops this future un-awaited.
                    own2.store(true, Ordering::SeqCst);
                    Ok(777u32)
                })
                .await
                .unwrap();
                ck.store(k, Ordering::SeqCst);
                order.lock().unwrap().push("chat-write");
            })
        };

        let outcome = repair_gated(
            &record_lock,
            &cache,
            &SEED,
            true,
            |_old| async {}, // close
            {
                let (order, notify) = (order.clone(), notify.clone());
                move || async move {
                    notify.notify_one(); // let the chat write begin contending on the lock
                    tokio::time::sleep(Duration::from_secs(3)).await; // a slow re-open
                    order.lock().unwrap().push("repair-open");
                    Ok(999u32)
                }
            },
            |_k| async { Ok(()) }, // watch
            {
                let order = order.clone();
                move |_k| async move {
                    order.lock().unwrap().push("repair-sweep");
                    SweepOutcome {
                        attempted: 1,
                        failed: 0,
                        found: 1,
                    }
                }
            },
        )
        .await
        .unwrap();

        chat.await.unwrap();
        assert_eq!(outcome.found, 1);
        // Repair fully completed BEFORE the chat write ran — no interleave in the lock span.
        assert_eq!(
            *order.lock().unwrap(),
            vec!["repair-open", "repair-sweep", "chat-write"]
        );
        // The chat write dispatched against the FRESH re-cached session (999), never the
        // dead 111, and reused repair's handle (did not re-open its own).
        assert_eq!(chat_key.load(Ordering::SeqCst), 999);
        assert!(
            !chat_opened_its_own.load(Ordering::SeqCst),
            "the chat write reused repair's fresh session, not a torn-down/re-opened one"
        );
    }
}
