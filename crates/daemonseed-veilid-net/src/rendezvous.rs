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

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex};

use futures_util::stream::StreamExt;
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

    /// Direct messaging's channel page: `dflt(16)`, one subkey per message slot.
    ///
    /// Derived from [`PAGE_SLOTS`](daemonseed_core::dm::paging::PAGE_SLOTS) rather
    /// than a literal, because that constant is simultaneously the slot arithmetic
    /// (`seq % PAGE_SLOTS`) and part of the record address. A `16` typed here that
    /// later disagreed with the arithmetic would address a record the other party
    /// never sweeps, with no error on any surface — the exact ISC-C100 failure the
    /// paging module's own doc comment warns writers about.
    pub const DM_PAGE: Self = Self::new(daemonseed_core::dm::paging::PAGE_SLOTS);

    /// Direct messaging's doorbell: `dflt(32)`, one subkey per knock slot.
    ///
    /// Derived from [`DOORBELL_SLOTS`](daemonseed_core::dm::doorbell::DOORBELL_SLOTS)
    /// for the reason [`Self::DM_PAGE`] gives — `o_cnt` is part of the address and
    /// simultaneously the modulus of `doorbell::slot_for` — plus a second the page
    /// does not have. 32 is what makes this shape's [`RecordShape::max_value_len`]
    /// exactly `daemonseed_core::dm::firstcontact::MAX_ENTRY_LEN`: the doorbell's
    /// slot count was *chosen* by that cap, not the other way round (the top
    /// padding bucket must fit one subkey), so a literal typed here that drifted
    /// from the constant would either address a record no sender writes to or
    /// silently shrink the cap below the size a padded entry needs.
    pub const DM_DOORBELL: Self = Self::new(daemonseed_core::dm::doorbell::DOORBELL_SLOTS);

    /// Direct messaging's acknowledgement record: `dflt(1)`, one current-state
    /// slot per direction.
    ///
    /// Derived from
    /// [`ACK_RECORD_SLOTS`](daemonseed_core::dm::ack_record::ACK_RECORD_SLOTS) for
    /// the reason [`Self::DM_PAGE`] gives — `o_cnt` is part of the address, so a
    /// `1` typed here that later disagreed with the deriving module would address
    /// a record the peer never reads, with no error on any surface (ISC-C100).
    ///
    /// It shares [`Self::DM_KEY_RECORD`]'s shape and is deliberately a separate
    /// constant: the two are the same `o_cnt` today by coincidence of both holding
    /// a single value, and folding them into one name would tie two unrelated
    /// records' addresses together, so changing either would silently move the
    /// other.
    pub const DM_ACK: Self = Self::new(daemonseed_core::dm::ack_record::ACK_RECORD_SLOTS);

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

/// The cache/lock identity of a record: its owner's **public key** and its shape's
/// `o_cnt`.
///
/// Both dimensions are load-bearing. Before shapes were parameterized, every
/// rendezvous record shared one schema, so the owner alone was a record's full
/// identity and the caches keyed on it (ISA Decisions 2026-07-07, #128 D-0a).
/// That premise no longer holds: `o_cnt` is part of the derived address, so the
/// same owner under two shapes is two different records. Keying the open-cache on
/// the owner alone would let a lookup under one shape return a [`RecordKey`]
/// derived for another — a wrong-record write that no compiler or test would
/// catch. The pairing is not reachable today (every DM surface derives its owner
/// seed under a distinct HKDF domain), which is precisely why it is worth closing
/// now, while it is still theoretical.
///
/// The owner half is the **public** key, never the seed it was derived from (#244).
/// Every record that existed when these caches were written had a world-derivable
/// owner seed, so holding one cost nothing. A DM channel page is the first
/// exception: its seed derives from the conversation secret `AR`, and under Veilid
/// a derivable owner seed **is** write access to the conversation. Copying that
/// into a process-lifetime, `Debug`-printable map key is exactly what
/// `redacted_secret_newtype::as_bytes` forbids, and it would undo the
/// zeroize-on-drop hygiene `DmPageOwnerSeed` carries. The public key removes the
/// class outright rather than threading a zeroizing type through every caller of
/// the engine — and it is what a reader of a record it cannot write has anyway, so
/// one record is one entry however the party opening it holds the owner.
pub type CachedRecordId = (PublicKey, u16);

/// The cache/lock id for the record owned by `owner`, at `shape`.
///
/// The public key identifies the record at least as precisely as its seed would —
/// it is what [`rendezvous_key`] derives the DHT address from, so two seeds sharing
/// a public key would be one record anyway — and it is public by nature, being the
/// record's identity on the network. It is also already a one-way function of the
/// seed, so no hashing step is needed and there is no fallible crypto call on the
/// open path.
pub fn cached_record_id(owner: &PublicKey, shape: RecordShape) -> CachedRecordId {
    (owner.clone(), shape.o_cnt())
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
    rendezvous_key_for(api, owner.key(), shape).await
}

/// Compute a rendezvous record's deterministic record key from the owner's raw
/// 32-byte **public** key — [`rendezvous_key`]'s reader-side twin, which needs no
/// owner secret. Local crypto only, as [`rendezvous_key`] is.
///
/// The addressing consumes the owner's public half alone, so a caller with only a
/// record to *read* needs no keypair; [`rendezvous_key`] serves the callers that
/// already hold one. The project announce/MOTD record is the case
/// that matters: its owner secret is maintainer-held, so a client deriving it holds
/// a write credential it must never have. Circles and public rooms are deliberately
/// not this — every member there holds the owner secret because every member writes
/// — and must keep using [`rendezvous_key`].
///
/// Both derivations run [`rendezvous_key_for`] over the same `PublicKey`, so they
/// cannot drift to different addresses; `identity::owner_public_key` is pinned equal
/// to `KeyPair::key()` by a unit test, which is what closes the gap this body cannot
/// reach on its own.
pub async fn rendezvous_key_from_owner_public(
    api: &VeilidAPI,
    owner_public: &[u8; 32],
    shape: RecordShape,
) -> Result<RendezvousHandle> {
    rendezvous_key_for(api, crate::identity::owner_public_key(owner_public), shape).await
}

/// The single derivation body behind [`rendezvous_key`] and
/// [`rendezvous_key_from_owner_public`].
///
/// `get_dht_record_key` consumes the owner's public half and nothing else, so the
/// two entry points differ only in how they reach that `PublicKey`. Deriving here
/// once rather than in each is what makes "the keypair path and the pubkey-only
/// path name the same record" a structural fact instead of a claim about two
/// bodies staying in step.
async fn rendezvous_key_for(
    api: &VeilidAPI,
    owner_key: PublicKey,
    shape: RecordShape,
) -> Result<RendezvousHandle> {
    let key = api
        .get_dht_record_key(schema(shape)?, owner_key, None)
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
    // Only a genuine absence justifies creating. Every other error — `Timeout`,
    // `TryAgain`, `NoConnection` — is a transport fault on a record that may well
    // already exist, and creating on one manufactures a network record nobody asked
    // for (#253). The reopen below runs either way: `create` is the harmful step,
    // while the reopen is the recovery that makes a transient open failure
    // survivable, and every caller of this function depends on that tolerance.
    let absent = match open1 {
        Ok(_) => {
            crate::vtrace!("open_or_create: open#1 ok (record already on net) -> Ok");
            return Ok(handle);
        }
        Err(veilid_core::VeilidAPIError::KeyNotFound { .. }) => {
            crate::vtrace!("open_or_create: open#1 KeyNotFound (absent); creating record");
            true
        }
        Err(e) => {
            crate::vtrace!(
                "open_or_create: open#1 failed ({e}) — not an absence, NOT creating; reopening"
            );
            false
        }
    };
    // Create the network record. Ignore the result: on success the handle carries
    // create's random encryption key; on a lost create race a peer already created
    // it. Either way the reopen below (with our no-encryption-key record key)
    // resets the handle to verbatim storage.
    if absent {
        match rc
            .create_dht_record(CRYPTO_KIND_VLD0, schema(shape)?, Some(owner.clone()))
            .await
        {
            Ok(_) => crate::vtrace!("open_or_create: create ok"),
            Err(e) => {
                crate::vtrace!("open_or_create: create failed ({e}) (lost race? reopen anyway)")
            }
        }
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

/// Open a record that must already exist, reporting absence as `Ok(None)` rather
/// than creating it (#253).
///
/// [`open_or_create`] is right for a record this side legitimately brings into
/// being — a rendezvous, a key record, a page we are about to write. It is wrong
/// for a **read**. The DM paging design has the probe frontier deliberately running
/// ahead of what exists, so sweeping through `open_or_create` *materializes* every
/// page probed past the end of the conversation: one create plus two un-gated opens
/// (~6–10 s each) spent to manufacture an empty record on the network, and — worse
/// — "no such page" and "empty page" collapse into the same `Ok`, because the only
/// way to reach the empty case is to have just created the record.
///
/// **`Ok(None)` is an answer, not a failure.** An unwritten page is the ordinary
/// state of the frontier, exactly as an empty sweep is, and is deliberately
/// distinct from `Err`, a transport failure.
///
/// **The absence test is `KeyNotFound` alone, and `Ok(None)` means "this node did not
/// find it just now" — NOT "it does not exist".** The distinction is load-bearing for
/// any consumer and is deliberately spelled out here rather than left to be inferred.
///
/// `RoutingContext::open_dht_record` documents `KeyNotFound` as *"the record does not
/// exist on the network"*, and measured against a live node a never-created key did
/// return it twice (~10.0 s each) with an existing record opening cleanly as the
/// control. But the raise site is weaker than that wording: `open_record.rs` performs
/// a network inspect of subkey 0 and raises `KeyNotFound` whenever the result carries
/// **no descriptor** — a test its own comment calls "a bit of a hack" — and the
/// underlying fanout reports `Incomplete` (its default), `Timeout` and `Exhausted` as
/// ordinary non-error outcomes. So a record that exists but that this node reached
/// nobody for can plausibly surface as `KeyNotFound` too. That path is **untested**;
/// what is established is the genuinely-absent case, not the unfetchable one.
///
/// **The obligation this puts on the collector (#236, unwritten):** an `Ok(None)` must
/// not be treated as authoritative absence. It is safe as a reason to read no slots
/// and to leave the page alone; it is NOT evidence the correspondent has written
/// nothing, and it must not clear a health or repair latch on its own. The sweep
/// reports it as `attempted: 0`, which is distinguishable from both a populated page
/// and a present-but-empty one precisely so that decision stays with the collector.
pub async fn open_only(
    gate: &Arc<DhtGate>,
    api: &VeilidAPI,
    rc: &RoutingContext,
    owner: &KeyPair,
    shape: RecordShape,
) -> Result<Option<RendezvousHandle>> {
    let handle = rendezvous_key(api, owner, shape).await?;
    let key = handle.key().clone();
    crate::vtrace!("open_only: rendezvous key={key:?}; trying open (no create)");
    // §RS-2 margin limiter, for the reason `open_or_create` gives: the raw open is an
    // un-gated DHT op and holds an un-gated-op permit across the call, acquired at
    // raw-call granularity. This function issues no gated GET, so the single-permit
    // rule (CRSH-ISC-17) is respected.
    let opened = {
        let _ungated = gate.acquire_ungated().await;
        rc.open_dht_record(key, Some(owner.clone())).await
    };
    match opened {
        Ok(_) => {
            crate::vtrace!("open_only: open ok -> Some");
            Ok(Some(handle))
        }
        Err(veilid_core::VeilidAPIError::KeyNotFound { .. }) => {
            crate::vtrace!("open_only: KeyNotFound -> None (absent, not created)");
            Ok(None)
        }
        Err(e) => {
            crate::vtrace!("open_only: open failed ({e}) -> Err");
            Err(VeilidNetError::Routing(e.to_string()))
        }
    }
}

/// Open a record that must already exist, addressing it by the owner's raw 32-byte
/// **public** key and opening it with **no writer** — [`open_only`]'s reader-side
/// twin. Absence is `Ok(None)`; it never creates.
///
/// Everything [`open_only`] documents about `Ok(None)` applies here unchanged: the
/// absence test is `KeyNotFound` alone, `Ok(None)` means "this node did not find it
/// just now" and NOT "it does not exist", and a collector must not treat it as
/// authoritative absence or let it clear a health or repair latch.
///
/// **What differs is the writer, and it is the point.** [`open_only`] passes
/// `Some(owner)`, which requires the caller to hold the owner secret and leaves
/// veilid retaining a clone of it in `OpenedRecord.writer` for as long as the
/// record stays open (see `identity::vld0_keypair`'s residual note). A reader of a
/// record it will never write needs neither. Passing `None` opens read-only, so no
/// secret is derived, carried, or retained — the project announce/MOTD record being
/// the case that motivates it, since its owner secret is maintainer-held and a
/// client has no business reconstructing it merely to read the MOTD.
///
/// **The writerless handle is not itself a write barrier**, and nothing should be
/// built on the assumption that it is. `set_dht_value` resolves the writer as the
/// call's explicit `SetDHTValueOptions::writer` **or** the handle's, in that order
/// (`veilid-core-0.5.7 src/storage_manager/set_value.rs:82-85`), so a caller holding
/// the owner keypair writes this record through a handle opened here exactly as it
/// would through one opened with a writer. What opening read-only buys is the secret
/// it never derives, carries or retains — not a refusal it enforces.
///
/// The boundary that does hold is about what a caller can obtain rather than what a
/// handle permits: writing needs the owner keypair, and the derivation from seed to
/// public key runs one way, so a caller holding only the owner's public key has no
/// route to one. A caller that needs to write wants [`open_only`] or
/// [`open_or_create`] and the owner keypair that goes with them.
pub async fn open_read_only(
    gate: &Arc<DhtGate>,
    api: &VeilidAPI,
    rc: &RoutingContext,
    owner_public: &[u8; 32],
    shape: RecordShape,
) -> Result<Option<RendezvousHandle>> {
    let handle = rendezvous_key_from_owner_public(api, owner_public, shape).await?;
    let key = handle.key().clone();
    crate::vtrace!("open_read_only: rendezvous key={key:?}; trying open (no writer, no create)");
    // §RS-2 margin limiter, for the reason `open_or_create` gives: the raw open is an
    // un-gated DHT op and holds an un-gated-op permit across the call, acquired at
    // raw-call granularity. This function issues no gated GET, so the single-permit
    // rule (CRSH-ISC-17) is respected.
    let opened = {
        let _ungated = gate.acquire_ungated().await;
        rc.open_dht_record(key, None).await
    };
    match opened {
        Ok(_) => {
            crate::vtrace!("open_read_only: open ok -> Some");
            Ok(Some(handle))
        }
        Err(veilid_core::VeilidAPIError::KeyNotFound { .. }) => {
            crate::vtrace!("open_read_only: KeyNotFound -> None (absent, not created)");
            Ok(None)
        }
        Err(e) => {
            crate::vtrace!("open_read_only: open failed ({e}) -> Err");
            Err(VeilidNetError::Routing(e.to_string()))
        }
    }
}

/// A session cache of rendezvous records already opened, keyed by
/// [`CachedRecordId`] → the post-reopen [`RendezvousHandle`]. [`open_or_create`]
/// pays a fresh open (~6–10 s live-measured) on every publish/subscribe; once a
/// handle is cached, callers reuse the open record and skip the round-trip. The
/// cached handle is the reopen result, so it carries the verbatim-storage
/// (no-encryption) handle semantics — never a raw `create` handle with a random
/// encryption key.
///
/// The id is `(owner public key, o_cnt)`, not the owner alone — see
/// [`CachedRecordId`] for why the shape is part of a record's identity.
pub type OpenCache = Mutex<HashMap<CachedRecordId, RendezvousHandle>>;

/// Return the cached open handle for `id`, else run `open` once, cache its
/// result, and return it. Generic over both the id and the value so the caching
/// logic is unit-testable without veilid types. `open` is a lazy future built by
/// the caller: on a cache hit it is dropped un-awaited (an `async fn` future runs
/// no body until polled), so a hit costs nothing beyond the map lookup.
///
/// **This function never evicts, and that is a decision rather than an omission.**
/// A `set`/`get` failure is a transient network condition the caller surfaces (and
/// may retry), not a dead local handle; dropping the entry on error would only force
/// a redundant re-open, and on the shared lobby record (every share advert + the
/// lobby subscription derive the SAME `owner_seed`) it would evict an entry other
/// callers are actively using. See ISA Decisions (2026-07-06, #128 D-0a).
///
/// So a cached handle is held for the session and stays valid. The one family that
/// cannot live on those terms is the DM channel page, whose count grows with message
/// volume rather than with peers; it is bounded from OUTSIDE this function by
/// [`open_page_bounded`], which evicts and closes only the ids the page opener
/// recorded and leaves every other entry here on exactly these terms.
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

/// [`open_cached`] for an open that may legitimately find nothing, i.e. one built on
/// [`open_only`].
///
/// **An absence is never cached, and that is the whole reason this exists.** A hit
/// is served and a successful open is memoized exactly as [`open_cached`] does, but
/// `Ok(None)` returns without touching the map. Caching it would turn "this page is
/// not written *yet*" into "this page does not exist" for the remainder of the
/// session: the correspondent writes the page, every later sweep still answers from
/// the cached absence, and that half of the conversation goes silently dead with no
/// error on any surface — the same shape of un-noticeable failure that the direction
/// typing in `DmPageAddress` exists to prevent. A record that is absent now can be
/// created by the other party at any moment, so absence is a fact about an instant
/// and not about the record.
///
/// The cost of not caching is one open per probe of a still-unwritten page, which is
/// what the probe frontier is already paying and is bounded by the frontier's own
/// advance rule.
pub async fn open_cached_optional<I: Eq + std::hash::Hash + Clone, K: Clone>(
    cache: &Mutex<HashMap<I, K>>,
    id: &I,
    open: impl std::future::Future<Output = Result<Option<K>>>,
) -> Result<Option<K>> {
    // Same poison-recovery idiom as `open_cached`, for the same reason.
    if let Some(k) = cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(id)
        .cloned()
    {
        return Ok(Some(k));
    }
    let Some(k) = open.await? else {
        return Ok(None);
    };
    cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id.clone(), k.clone());
    Ok(Some(k))
}

/// How many DM channel-page records one session keeps open at once — the capacity
/// [`open_page_bounded`] enforces on the page path (#252).
///
/// Every other record family this engine serves has cardinality bounded by peers —
/// one rendezvous record per circle, one key record and one doorbell per
/// correspondent — so "open once, never close" is a constant per peer. Channel pages
/// are the exception: a new page owner seed appears every `PAGE_SLOTS` messages, per
/// direction, per conversation, plus every page a sweep probes ahead of the
/// frontier. Left unbounded that is a monotonic count of open DHT records for the
/// life of the process, and the DHT-side cost is the point — the local map entry is
/// the cheap half.
///
/// **The number does not carry the safety property.** No capacity could: a bound
/// chosen against a concurrency ceiling is a probability, not an invariant, because
/// what would have to be bounded is not simultaneous DHT operations but distinct
/// page opens completing while some holder is parked between permits. Not closing a
/// record someone is using is instead guaranteed by the [`PageLease`] refcount, and
/// this constant only decides how much *idle* cache is kept.
///
/// So it is sized for hit rate: 64 covers roughly twenty conversations' live
/// send/receive/probe pages, so the steady state of ordinary use is still
/// open-once, and it is deliberately kept above [`DHT_BUDGET`](crate::dht_gate::DHT_BUDGET)
/// — a capacity at or below the number of operations that can be in flight would
/// spend the cache thrashing pages that are all still busy, evicting nothing (every
/// candidate leased) while paying the scan on every open. That relation is asserted
/// below rather than left in prose.
pub const DM_PAGE_CACHE_CAPACITY: usize = 64;

// The capacity/throughput relation the doc above states, made unbreakable: raising
// the in-flight budget past the cache capacity would leave every eviction candidate
// leased, and would otherwise compile and pass the whole suite.
const _: () = assert!(
    DM_PAGE_CACHE_CAPACITY > crate::dht_gate::DHT_BUDGET,
    "the page cache must hold more pages than can be in flight at once, or it \
     thrashes: every open evicts a page a still-running operation re-opens moments \
     later. This pins a HIT-RATE floor and nothing else. It is not the safety \
     property (the lease is) and not a liveness one (a fully-leased ring evicts \
     nothing and is fine). In particular it does NOT bound the live-lease count — a \
     lease is held across permit waits, so a holder can be parked with zero permits"
);

/// Recency + live-borrow bookkeeping over **one record family's** entries in an
/// [`OpenCache`], oldest at the front.
///
/// Two facts are tracked per id and they answer different questions. `order` is the
/// LRU membership: which ids this family has opened, most-recently-used last, and
/// therefore which ids are eligible to be evicted at all. `live` is a borrow count:
/// how many callers currently hold a handle for that id, which decides whether an
/// eligible id may be closed *now*.
///
/// **The fields are private and this module exposes no way to write them except
/// through [`open_page_bounded`].** That is the structural half of the safety
/// property: a caller cannot record an id of some other family into the ring, so it
/// cannot widen the set of records this bound is allowed to close. The set is not
/// merely "what a reviewer saw a call site do" — it is unreachable from outside.
pub struct BoundedRing<I> {
    order: VecDeque<I>,
    live: HashMap<I, usize>,
}

impl<I: Eq + std::hash::Hash + Clone> BoundedRing<I> {
    pub fn new() -> Self {
        Self {
            order: VecDeque::new(),
            live: HashMap::new(),
        }
    }

    /// Take a borrow on `id`. Held until the matching [`PageLease`] drops.
    fn borrow_id(&mut self, id: &I) {
        *self.live.entry(id.clone()).or_insert(0) += 1;
    }

    /// Release one borrow, dropping the entry entirely at zero so `live` holds only
    /// ids that actually have a holder.
    fn release_id(&mut self, id: &I) {
        if let Some(n) = self.live.get_mut(id) {
            *n -= 1;
            if *n == 0 {
                self.live.remove(id);
            }
        }
    }

    /// Mark `id` most-recently-used, moving it to the back rather than duplicating
    /// it — the same id is opened repeatedly, which is the ordinary case for a page
    /// being written slot by slot.
    fn record(&mut self, id: &I) {
        if let Some(pos) = self.order.iter().position(|held| held == id) {
            self.order.remove(pos);
        }
        self.order.push_back(id.clone());
    }

    /// The id to close, if the ring is over `capacity`: the oldest one **nobody is
    /// holding**. A leased id is skipped rather than closed, which is what keeps an
    /// in-flight sweep's remaining GETs from failing into `outcome.failed` — the
    /// signal a collector is told to read as record ill-health.
    ///
    /// Skipping means the cache can sit above `capacity` by the number of live
    /// borrows. That excess is bounded by the count of page operations in flight, and
    /// since publishes and sweeps are `tokio::spawn`ed per command with no hard cap,
    /// that is a SOFT bound rather than an invariant. Nor does it drain merely because
    /// leases release: a stream of NEW page ids holds the length at its high-water
    /// mark indefinitely, each open recording one id and evicting one. It falls back
    /// to `capacity` on re-opens of ids already in the ring — the common case for a
    /// conversation writing one page slot by slot. Sitting above the bound is the
    /// price of never closing a record in use, which would be a silent,
    /// traffic-dependent fault.
    fn evictable(&mut self, capacity: usize) -> Option<I> {
        if self.order.len() <= capacity {
            return None;
        }
        let pos = self
            .order
            .iter()
            .position(|id| !self.live.contains_key(id))?;
        self.order.remove(pos)
    }

    /// Drop `id` from the ring if it is present and **nobody is holding it**,
    /// answering whether it was.
    ///
    /// The counterpart to [`Self::evictable`] for a close the caller asked for by
    /// name rather than one the capacity forced. It applies the identical live-borrow
    /// rule — a leased id is refused, never closed — so an explicit close cannot
    /// reach a record an in-flight operation is reading, which is the one thing the
    /// bound is not allowed to do.
    ///
    /// `false` for an id nobody opened, which is the ordinary answer for a page whose
    /// every open was of the *other* direction's record, and for one the capacity
    /// already evicted.
    fn take_unleased(&mut self, id: &I) -> bool {
        if self.live.contains_key(id) {
            return false;
        }
        match self.order.iter().position(|held| held == id) {
            Some(pos) => {
                self.order.remove(pos);
                true
            }
            None => false,
        }
    }

    /// How many ids the ring holds. Test-only: production reads the ring exclusively
    /// through [`open_page_bounded`], and a size accessor is exactly the sort of
    /// handle that lets a caller start making its own eviction decisions.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.order.len()
    }
}

impl<I: Eq + std::hash::Hash + Clone> Default for BoundedRing<I> {
    fn default() -> Self {
        Self::new()
    }
}

/// A live borrow on one cached page record. **Hold it for exactly as long as the
/// handle is used** — dropping it says the caller is done and the record may be
/// closed.
///
/// This is the whole of the safety argument, and it is needed because neither lock
/// in this crate covers the window. `sweep_dm_page` drops the record lock before its
/// GETs on purpose, so between two subkey reads a sweeper holds a live handle and
/// zero permits; `publish_dm_page` holds the record lock for *its own* owner key,
/// which is no exclusion against an eviction triggered by a different page. A
/// refcount is what those two have in common: it does not care which lock, which
/// permit, or which task the holder is parked in.
pub struct PageLease<'r, I: Eq + std::hash::Hash + Clone> {
    ring: &'r Mutex<BoundedRing<I>>,
    id: I,
}

impl<I: Eq + std::hash::Hash + Clone> Drop for PageLease<'_, I> {
    fn drop(&mut self) {
        // Poison-recovered, mirroring `open_cached`: a panicked holder elsewhere must
        // not wedge every later page open, and a lease that failed to release would
        // pin its record open for the session — the leak this bound exists to fix.
        self.ring
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .release_id(&self.id);
    }
}

/// LRU recency over the **DM-page subset** of an [`OpenCache`].
pub type DmPageRecency = Mutex<BoundedRing<CachedRecordId>>;

/// Open one page record through `cache`, bounded: take a borrow on `id`, memoize the
/// open exactly as [`open_cached_optional`] does, then — if the ring is over
/// `capacity` — drop the oldest unleased page from the cache and `close` its record.
/// Returns the handle together with the [`PageLease`] the caller must hold while
/// using it.
///
/// **[`open_cached`] is deliberately untouched, and its no-eviction property is a
/// decision rather than an oversight** (ISA Decisions 2026-07-06, #128 D-0a): its
/// entries include the shared lobby record, which every share advert and the lobby
/// subscription derive the SAME `owner_seed` for, so an entry evicted by one caller
/// is an entry taken from under several others.
///
/// What makes bounding safe here is that **eviction candidates come from the ring,
/// never from the cache.** An id that never reaches a ring cannot be chosen, so a
/// family whose cardinality is already bounded keeps exactly today's behaviour by
/// not being opened through this function — no reasoning about which map keys are
/// shared is required, and [`BoundedRing`]'s private fields mean no caller can add
/// one.
///
/// **Ordering is load-bearing twice over.** The borrow is taken *before* the cache
/// is consulted, so a concurrent eviction sees the id as live and skips it rather
/// than closing a record this call is about to return. And the eviction's cache
/// removal happens inside the same ring-lock section that chose the candidate, so
/// the two are one atomic decision: a concurrent opener either takes its borrow
/// first (and the candidate is skipped) or finds the entry already gone (and opens
/// afresh). Neither can be handed a handle that is about to be closed.
///
/// An absent page — the probe frontier's ordinary state — is never recorded in the
/// ring, for the reason [`open_cached_optional`] does not cache it: nothing was
/// opened, so there is nothing to bound, and ringing it would let probes ahead of
/// the frontier evict live pages.
///
/// **The close runs under the EVICTED record's own serialization lock, which
/// `lock_for` supplies.** Removing the entry and closing the record cannot be one
/// critical section — the close is an await and the ring guard is a `std::sync`
/// one — so between them there is a window in which the id is absent from the cache
/// and its record is still open. A concurrent opener of that same id would miss the
/// cache, open a FRESH session, and have it killed by a close that was issued for
/// the session before it. The lease cannot cover this: the victim is by definition
/// unleased. What does cover it is that every production page open already holds the
/// record's lock across the open (`publish_dm_page`, `sweep_dm_page`, and the publish
/// pre-warm all take it before calling the opener), so taking that same lock around
/// the close makes open-this-record and close-this-record mutually exclusive. It is
/// also the crate's existing answer to this question — [`repair_gated`] holds the
/// record lock across its whole tear-down-and-reopen for the identical reason.
///
/// **No lock cycle, and the lease is what rules one out.** A caller can hold its own
/// record's lock while this function takes the victim's, so hold-and-wait exists;
/// a cycle would additionally need some task waiting on the FIRST caller's record
/// while holding the victim's. That task could only be another evictor, and it cannot
/// select the first caller's record because the first caller holds a lease on it. The
/// victim is likewise never the id being opened — that one was just recorded and is
/// leased — so this never waits on a lock it already holds.
///
/// `close` is the caller's, so the veilid `close_dht_record` stays out of this
/// module and the ordering, the removal and the close are all unit-testable with
/// stand-ins. Closing is the entire point: dropping the map entry alone would leave
/// the record open on the network, which is the cardinality the bound reclaims.
/// The lock to hold across an eviction's close: the victim's own, **unless the
/// victim is the id being opened**, in which case there is no lock to take.
///
/// That degenerate case is unreachable today and this is not a fallback for it — it
/// is a refusal to hang. The caller already holds a lock into
/// [`open_page_bounded`], so locking the id it is opening would self-deadlock: a
/// permanent, silent stall with no error on any surface. The property that rules it
/// out is real but structural — the lease is taken before anything else and
/// [`BoundedRing::evictable`] skips every leased id — and a structural property is
/// exactly the kind that a later reordering breaks without anyone noticing. A
/// `debug_assert` would not have caught it either: this workspace's release profile
/// sets `overflow-checks` and NOT `debug-assertions`, so an assert-only invariant
/// does not exist in the profile that ships. Skipping costs one comparison on every
/// real eviction and converts the worst available failure shape — a release hang —
/// into a close that runs unlocked in a situation that cannot arise.
fn victim_lock<I: Eq>(
    evicted_id: I,
    opening: &I,
    lock_for: impl FnOnce(I) -> Arc<tokio::sync::Mutex<()>>,
) -> Option<Arc<tokio::sync::Mutex<()>>> {
    if &evicted_id == opening {
        return None;
    }
    Some(lock_for(evicted_id))
}

#[allow(clippy::too_many_arguments)]
pub async fn open_page_bounded<'r, I, K, CloseFut>(
    cache: &Mutex<HashMap<I, K>>,
    ring: &'r Mutex<BoundedRing<I>>,
    id: &I,
    capacity: usize,
    open: impl std::future::Future<Output = Result<Option<K>>>,
    lock_for: impl FnOnce(I) -> Arc<tokio::sync::Mutex<()>>,
    close: impl FnOnce(K) -> CloseFut,
) -> Result<Option<(K, PageLease<'r, I>)>>
where
    I: Eq + std::hash::Hash + Clone,
    K: Clone,
    CloseFut: std::future::Future<Output = ()>,
{
    // A capacity of zero would make the id this call is opening its own eviction
    // candidate the moment its lease drops, so the floor is one entry.
    let capacity = capacity.max(1);
    // The borrow comes first — see the ordering paragraph above. The lease releases
    // it on drop, including on the `?` below.
    ring.lock().unwrap_or_else(|e| e.into_inner()).borrow_id(id);
    let lease = PageLease {
        ring,
        id: id.clone(),
    };
    let Some(handle) = open_cached_optional(cache, id, open).await? else {
        return Ok(None);
    };
    // Choosing the victim and removing it from the cache are ONE critical section:
    // split, a concurrent opener could be served the entry between the two. The
    // cache lock nests inside the ring lock here and nowhere takes them the other
    // way round, so the order is total. No await is held across either guard.
    let stale = {
        let mut ring = ring.lock().unwrap_or_else(|e| e.into_inner());
        ring.record(id);
        ring.evictable(capacity).and_then(|evicted| {
            cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&evicted)
                .map(|handle| (evicted, handle))
        })
    };
    if let Some((evicted_id, evicted)) = stale {
        // Exclude a concurrent open of the record being closed. Held across the close
        // and released immediately after; the opener that was waiting then misses the
        // cache and opens a genuinely fresh session.
        let closing = victim_lock(evicted_id, id, lock_for);
        let _closing_guard = match &closing {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };
        close(evicted).await;
    }
    Ok(Some((handle, lease)))
}

/// Close one page record **by name**, because its holder says it is finished with
/// it — the driver-signalled counterpart to [`open_page_bounded`]'s
/// capacity-forced eviction. Answers whether a record was actually closed.
///
/// The capacity bound reclaims records because too many are open; this reclaims one
/// because nothing will ask for it again. They are the same act on the same two
/// structures and differ only in what chose the victim, so this reuses every rule
/// the eviction path established rather than restating any of them:
///
/// - **A leased id is refused, never closed.** [`BoundedRing::take_unleased`]
///   applies the identical live-borrow test [`BoundedRing::evictable`] does, so a
///   caller cannot close a record a sweep or a publish is parked inside — the
///   failure that turns an in-flight sweep's remaining GETs into `outcome.failed`.
/// - **Choosing and removing are one critical section**, ring lock outside cache
///   lock, matching the order [`open_page_bounded`] takes and never the reverse.
/// - **The close runs under the record's own serialization lock**, so it cannot kill
///   a session a concurrent opener has just established for the same id.
///
/// **A refusal is silent and the record simply stays open.** The caller has already
/// decided it is done with the page, so there is nothing to retry against: what a
/// refusal means is that some operation is still using the record, and the capacity
/// bound remains the backstop that will reclaim it later. Answering rather than
/// erroring is what lets a caller count reclaimed records without treating "busy"
/// as a fault.
pub async fn close_page_now<I, K, CloseFut>(
    cache: &Mutex<HashMap<I, K>>,
    ring: &Mutex<BoundedRing<I>>,
    id: &I,
    lock_for: impl FnOnce(I) -> Arc<tokio::sync::Mutex<()>>,
    close: impl FnOnce(K) -> CloseFut,
) -> bool
where
    I: Eq + std::hash::Hash + Clone,
    CloseFut: std::future::Future<Output = ()>,
{
    let taken = {
        let mut ring = ring.lock().unwrap_or_else(|e| e.into_inner());
        if !ring.take_unleased(id) {
            return false;
        }
        cache.lock().unwrap_or_else(|e| e.into_inner()).remove(id)
    };
    // Dropped from the ring but absent from the cache: the id was recorded by an
    // open whose entry something else has since removed. Nothing to close, and the
    // ring is now consistent with the cache, which is the state this wanted.
    let Some(handle) = taken else {
        return false;
    };
    let closing = lock_for(id.clone());
    let _closing_guard = closing.lock().await;
    close(handle).await;
    true
}

/// Per-rendezvous-record serialization lock: one async mutex per record, keyed by
/// the owner's public key. Two operations on the SAME record must not run concurrently —
/// spawned append-ring [`publish`]es (the off-loop publish path) would otherwise
/// race into the shared `base + (seq % RING_DEPTH)` slot, and an older write landing
/// after a newer one silently DROPS the newer message (not merely reorders it — the
/// receiver's `sent_unix_ms` sort cannot recover a value that was never stored); and
/// two cold-cache callers would both run [`open_or_create`] on the same record.
/// Holding this lock across the open+write of one record serializes both, while
/// DISTINCT records take DISTINCT locks and stay fully concurrent — so a slow write
/// to one record never blocks another's traffic or the actor command loop. See ISA
/// Decisions (2026-07-07, #128 review).
///
/// **Deliberately keyed on the owner alone, unlike [`OpenCache`].** Where the open
/// cache MUST distinguish shapes (returning a key derived for the wrong `o_cnt`
/// would write to the wrong record), this lock only decides what serializes against
/// what. Two differently-shaped records sharing an owner would share one lock —
/// over-serializing, never under-serializing — so the owner-only key is the
/// conservative choice and keeps the CRSH-ISC-3/18 lock-span invariants exactly as
/// they were verified. It holds the owner's PUBLIC key rather than the seed, for the
/// reason [`CachedRecordId`] gives (#244): a lock identity needs to tell records
/// apart, not to carry write capability.
pub type RecordLocks = Mutex<HashMap<PublicKey, Arc<tokio::sync::Mutex<()>>>>;

/// The serialization lock for the record owned by `owner`, creating it on first use. The returned
/// `Arc` is `.lock().await`-ed by the caller; the brief `std::sync::Mutex` guard on
/// the map itself is never held across an await.
pub fn record_lock(locks: &RecordLocks, owner: &PublicKey) -> Arc<tokio::sync::Mutex<()>> {
    // Poison-recovery idiom (WB-5.1 / I5″.8, mirroring `ring_seq`): the guarded state
    // is a map of per-record lock handles whose invariants survive an unwind; a
    // poisoned-mutex cascade wedging every subsequent record open is the #168 failure
    // class with a different door, so recover the inner map rather than propagate.
    locks
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(owner.clone())
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

/// Reject a subkey outside the record's schema, naming the slot and the bound.
///
/// Veilid rejects an out-of-range subkey itself, so this changes a *loud* failure
/// into a loud failure — but it moves it from after `open_or_create` (a record
/// created or opened on the network before anything is validated) to before, and
/// from a generic "failed schema validation" to an error that names the offending
/// slot and the shape it escaped. Every pre-DM caller derives its slot from a hash
/// reduced mod the shape and cannot trip this; the DM page is the first to take a
/// slot from arithmetic a caller supplies, which is what makes the check worth its
/// line count.
fn check_subkey_range(subkey: u32, shape: RecordShape) -> Result<()> {
    let o_cnt = u32::from(shape.o_cnt());
    if subkey >= o_cnt {
        return Err(VeilidNetError::Send(format!(
            "subkey {subkey} is outside dflt({o_cnt}) — valid slots are 0..{o_cnt}"
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
    check_subkey_range(subkey, handle.shape())?;
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

/// How long one subkey GET inside a sweep may run before it is abandoned (#397).
///
/// The bound sits above the slowest routine DHT operation the design record prices:
/// `open_or_create` at 6–10s (`docs/design/direct-messaging.md`; the route's hop count is
/// `NetConfig::hop_count`, D5). A single GET is a fraction of that —
/// `docs/design/consumer-route-self-heal.md` §RS-1.2 budgets a whole repair, the open plus
/// the re-watch plus 64 GETs, at 30–60s. 15s therefore never cuts off a read that is
/// merely slow, while a read that is not coming back does not hold the sweep open. With
/// [`SWEEP_READ_FANOUT`], a sweep of an `o_cnt`-subkey record none of whose reads answer
/// spends at most `o_cnt.div_ceil(SWEEP_READ_FANOUT) × 15s` on those reads — 240s at the
/// 64-subkey rendezvous shape, 120s and 60s at the 32- and 16-subkey direct-message
/// shapes. Time queued for a read permit is on top of that, and is bounded by whatever
/// else is drawing on the pool rather than by this constant.
///
/// The bound also caps how long a sweep's GET occupies the read-pool permit it holds for
/// that GET's duration. That is a ceiling on the occupancy and not on the wait for it:
/// `acquire_read` is awaited outside the bound, so a sweep can still queue indefinitely
/// for a permit. One read-lane site outside a sweep is also governed by it: the two
/// direct-message fetch reads bound their GET by this constant through
/// `actor::gated_bounded_get`, under the same occupancy-not-wait split. Any other
/// read-lane site draws the same pool without being governed by this constant.
///
/// A GET cut off here counts in both `SweepOutcome::failed` and
/// `SweepOutcome::timed_out` — see [`SweepOutcome`].
pub const SWEEP_GET_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// How many of a sweep's subkey GETs may be in flight at once (#397).
///
/// Four at a time costs a 64-subkey record 16 round trips' worth of latency rather than
/// one per slot, so a record's later slots are not held behind its earlier ones. The
/// *set* of reads does not depend on it — every slot is read exactly once, whatever it
/// holds, which is what keeps the sweep's traffic shape independent of the record's
/// contents (WB-0).
///
/// Sized to stay well inside the read partition it draws from: the shared
/// [`DhtGate`]'s read pool is 9 permits (WB-5.1 §I5″.1, `chat 2 · floor 1 · write 2 ·
/// read 9`), and each in-flight GET holds one for its duration. Read occupancy is
/// bounded by that pool rather than by this number, so concurrent sweeps of several
/// records stay within the partition however wide the fan-out is; the fan-out only
/// decides how quickly one sweep can consume its share.
pub const SWEEP_READ_FANOUT: usize = 4;

/// Per-sweep GET accounting. `attempted` counts every subkey GET whose result the sweep
/// read — every GET it issues, except on `sweep_gated`'s early stop, where the reads
/// still in flight are dropped rather than awaited for a count nobody will use; `failed`
/// counts GETs that did not deliver an answer — an error from the GET itself, or a read
/// abandoned at the per-GET bound `SWEEP_GET_TIMEOUT` — as distinct from an empty slot;
/// `timed_out` is the subset of
/// `failed` that was abandoned at the bound rather than reported as an error; `found`
/// counts populated slots handed to `on_slot`.
/// Surfacing `failed` separately from empty/`found` is the enabling signal for
/// consumer-side session-health tracking (CRSH-ISC-1): an erroring record session
/// produces `failed > 0` sweeps instead of silent zero-yield ones. A wedged session is
/// the same signal reached a different way, which is why an abandoned read counts in
/// `failed` too and `timed_out` only splits out *why* — a consumer reading `failed`
/// keeps the meaning it was written against.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepOutcome {
    pub attempted: u32,
    pub failed: u32,
    pub timed_out: u32,
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
///
/// Traces on both edges — the record, its slot count, the fan-out and the per-GET bound
/// before the first GET, and the counts on completion — so a sweep that is in flight is
/// distinguishable in a log from one that was never spawned.
pub async fn sweep_collect(
    gate: &Arc<DhtGate>,
    rc: &RoutingContext,
    handle: RendezvousHandle,
    ev_tx: &mpsc::UnboundedSender<VeilidNetEvent>,
) -> SweepOutcome {
    let key = handle.key().clone();
    let slots = handle.shape().o_cnt();
    // Traced BEFORE the first GET, so a sweep in flight is distinguishable in a log from
    // one that was never spawned. A sweep is bounded but not instant — its reads alone
    // can take `slots.div_ceil(SWEEP_READ_FANOUT) × SWEEP_GET_TIMEOUT` — so a record
    // whose reads all go unanswered prints nothing between these two lines. Naming the
    // fan-out and the bound here is what makes that gap readable as a duration rather
    // than as an absence.
    crate::vtrace!(
        "sweep: starting on key={key:?}, {slots} slot(s), {SWEEP_READ_FANOUT} at a time, each bounded at {}s",
        SWEEP_GET_TIMEOUT.as_secs()
    );
    let outcome = sweep_gated(
        gate,
        slots,
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
        "sweep: done, {} attempted, {} found and emitted, {} failed ({} of them timed out)",
        outcome.attempted,
        outcome.found,
        outcome.failed,
        outcome.timed_out
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
/// `on_slot` returning `false`. Returns a [`SweepOutcome`] with
/// `attempted`/`failed`/`timed_out`/`found` counts.
///
/// **Every GET is bounded by [`SWEEP_GET_TIMEOUT`] and up to [`SWEEP_READ_FANOUT`] of
/// them are in flight at once** (#397). Neither changes *which* subkeys are read: the
/// sweep still reads `0..subkey_count` exactly once each, in index order, whatever the
/// record holds. That slot-blindness is a privacy property (WB-0: a read pattern that
/// varies with content is a content oracle to the storage host), so the bound and the
/// fan-out are applied uniformly to every slot, including empty ones.
///
/// The GETs are driven by `buffered`, which preserves index order in the results, so
/// `on_slot` is still called in ascending subkey order and from this one task — no
/// spawn, so `get`'s futures need be neither `Send` nor `'static`. A permit is acquired
/// inside each GET's own future and released when that GET ends, so per-GET granularity
/// is unchanged and read occupancy stays bounded by `gate`'s read partition however
/// wide the fan-out is (WB-5.1 §I5″.1: the partition is the cap, by construction).
///
/// On the early stop the whole stream is dropped, which cancels the reads still in
/// flight and drops the permits they hold with them. That release is what keeps the
/// early stop from costing the read pool anything: without it, a sweep that stopped on
/// slot 2 of 64 would strand up to `SWEEP_READ_FANOUT − 1` permits for the process's
/// lifetime, and the pool would narrow by that much on every stopped sweep.
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
    let get = &get;
    let mut reads = futures_util::stream::iter(0..u32::from(subkey_count))
        .map(|subkey| async move {
            // The read permit is scoped to THIS GET: acquired inside the GET's own
            // future and dropped when that future ends (RAII — releases even on unwind,
            // #168, and on the early return below, which drops the whole stream).
            let _read_permit = gate.acquire_read().await;
            (
                subkey,
                tokio::time::timeout(SWEEP_GET_TIMEOUT, get(subkey)).await,
            )
        })
        .buffered(SWEEP_READ_FANOUT);

    let mut outcome = SweepOutcome::default();
    while let Some((subkey, got)) = reads.next().await {
        outcome.attempted += 1;
        match got {
            Ok(Ok(Some(bytes))) => {
                outcome.found += 1;
                if !on_slot(subkey, bytes) {
                    return outcome; // receiver dropped — stop sweeping
                }
            }
            Ok(Ok(None)) => {}
            Ok(Err(())) => outcome.failed += 1, // failed GET: per-record health signal, keep sweeping
            Err(_elapsed) => {
                // A GET that did not answer within the bound. Counted in `failed` as
                // well, because every consumer of `failed` asks the same question a
                // timeout also answers — did this record serve its reads? — and a
                // record whose GETs hang is exactly the ill health the repair arm is
                // watching for (`daemonseed_core::session_health`).
                outcome.failed += 1;
                outcome.timed_out += 1;
                crate::vtrace!(
                    "sweep: GET on subkey {subkey} exceeded {}s, abandoned",
                    SWEEP_GET_TIMEOUT.as_secs()
                );
            }
        }
    }
    outcome
}

/// Whether the repair arm closes the record before re-opening it (§RS-1.2 / §RS-1.3
/// open question, **repro-gated**). `close_dht_record` cancels the desired watch
/// (`close_record.rs:117-119`), so a close-first yields a guaranteed-fresh session +
/// re-watch — the closest analog to the consumer *restart* that empirically heals the
/// manually tested dead session; open-in-place (veilid updates an already-open record in
/// place, `open_record.rs:155-170`) is cheaper but may not clear a death that lives in
/// the opened-record session. Defaulted **`true`** (mirror the restart that is known to
/// work) pending the two-client reproduction (§RS-1.3). TODO: re-evaluate this
/// default once that reproduction exists — open-in-place may suffice. Either
/// path satisfies CRSH-ISC-3's lock span — the close (when enabled) runs
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

    /// [`counting_open`] for the optional path: counts every actual open and answers
    /// `ret`, where `None` stands for the record being absent from the network.
    async fn counting_open_optional(opens: &AtomicU32, ret: Option<u32>) -> Result<Option<u32>> {
        opens.fetch_add(1, Ordering::SeqCst);
        Ok(ret)
    }

    #[tokio::test]
    async fn an_absent_record_is_never_cached_so_a_later_write_becomes_visible() {
        // The #253 invariant, and the one whose failure is silent: `open_cached`
        // memoizes what it opens, so an optional open that cached its `None` would
        // answer "absent" for the rest of the session — the correspondent writes the
        // page, every later sweep still sees nothing, and that half of the
        // conversation dies with no error on any surface.
        let cache: Mutex<HashMap<[u8; 32], u32>> = Mutex::new(HashMap::new());
        let opens = AtomicU32::new(0);
        let seed = [9u8; 32];

        // Three probes of a page nobody has written yet.
        for _ in 0..3 {
            assert_eq!(
                open_cached_optional(&cache, &seed, counting_open_optional(&opens, None))
                    .await
                    .unwrap(),
                None,
                "an unwritten page reports absent"
            );
        }
        assert_eq!(
            opens.load(Ordering::SeqCst),
            3,
            "each probe of an absent record must re-open: caching the absence is the bug"
        );
        assert!(
            cache.lock().unwrap().is_empty(),
            "an absence must leave no entry behind"
        );

        // The correspondent writes the page; the very next probe must see it.
        assert_eq!(
            open_cached_optional(&cache, &seed, counting_open_optional(&opens, Some(77)))
                .await
                .unwrap(),
            Some(77),
            "a page written after an absent probe must become visible"
        );
        assert_eq!(opens.load(Ordering::SeqCst), 4);

        // And from there it memoizes exactly as `open_cached` does: this call would
        // answer 999 if it ran, so returning 77 proves the future was dropped
        // un-awaited on the hit.
        assert_eq!(
            open_cached_optional(&cache, &seed, counting_open_optional(&opens, Some(999)))
                .await
                .unwrap(),
            Some(77),
            "a present record is cached on the same terms as open_cached"
        );
        assert_eq!(opens.load(Ordering::SeqCst), 4, "the hit must not re-open");
    }

    #[tokio::test]
    async fn an_optional_open_that_errors_caches_nothing() {
        // A transport failure is not an absence and not a handle. `open_only` maps
        // only `KeyNotFound` to `None` and propagates everything else, so the cache
        // must come out of an error exactly as it went in — otherwise a single
        // timeout would poison the entry.
        let cache: Mutex<HashMap<[u8; 32], u32>> = Mutex::new(HashMap::new());
        let seed = [3u8; 32];
        let failing = async { Err(VeilidNetError::Routing("transport".to_string())) };
        assert!(open_cached_optional(&cache, &seed, failing).await.is_err());
        assert!(
            cache.lock().unwrap().is_empty(),
            "an error must leave no entry behind"
        );
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
        let as_rendezvous = cached_record_id(&owner.key(), RecordShape::RENDEZVOUS);
        let as_doorbell = cached_record_id(&owner.key(), RecordShape::new(32));
        assert_ne!(
            as_rendezvous, as_doorbell,
            "one owner under two shapes is two records — the cache must not conflate them"
        );
        assert_eq!(
            as_rendezvous,
            cached_record_id(&owner.key(), RecordShape::new(64))
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

        let id = cached_record_id(&owner.key(), RecordShape::RENDEZVOUS);
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
        let a = record_lock(&locks, &owner.key());
        let b = record_lock(&locks, &owner.key());
        assert!(
            Arc::ptr_eq(&a, &b),
            "the same owner must resolve to the same lock"
        );
        let other = crate::identity::rendezvous_owner_keypair(&[0xCDu8; 32]).unwrap();
        assert!(
            !Arc::ptr_eq(&a, &record_lock(&locks, &other.key())),
            "distinct owners must not share a lock"
        );
    }

    /// **A reader and a writer of ONE record share ONE cache entry and ONE lock.**
    ///
    /// The identity a caller supplies now comes from
    /// [`crate::identity::RendezvousOwner::resolve`], whose two arms hold the record
    /// differently — a keypair, or the public key alone. If they produced different
    /// ids, the same record would occupy two cache entries and two locks, and the
    /// serialization the lock exists to give would not apply between them. The
    /// mirror control is the second half: a DIFFERENT record must still be a
    /// different id, or the equality above would pass on a constant.
    #[test]
    fn a_reader_and_a_writer_of_one_record_share_one_identity() {
        use crate::identity::{OwnerPublic, OwnerSeed, RendezvousOwner};

        let seed = OwnerSeed::new([0x3Cu8; 32]);
        let writer = RendezvousOwner::Held(seed.clone()).resolve().unwrap();
        let reader = RendezvousOwner::PublicOnly(OwnerPublic::of_seed(&seed))
            .resolve()
            .unwrap();

        assert_eq!(
            cached_record_id(&writer.public_key(), RecordShape::RENDEZVOUS),
            cached_record_id(&reader.public_key(), RecordShape::RENDEZVOUS),
        );
        let locks = RecordLocks::default();
        assert!(Arc::ptr_eq(
            &record_lock(&locks, &writer.public_key()),
            &record_lock(&locks, &reader.public_key()),
        ));

        let elsewhere = RendezvousOwner::held([0x3Du8; 32]).resolve().unwrap();
        assert_ne!(
            cached_record_id(&writer.public_key(), RecordShape::RENDEZVOUS),
            cached_record_id(&elsewhere.public_key(), RecordShape::RENDEZVOUS),
        );
        assert!(!Arc::ptr_eq(
            &record_lock(&locks, &writer.public_key()),
            &record_lock(&locks, &elsewhere.public_key()),
        ));
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
    /// One page open through the real bounded path, with stand-ins for the two
    /// veilid pieces: the open (a counter) and the close (a recorder). Handles are
    /// `id * 100`, so a closed handle names the page it belonged to.
    ///
    /// The close recorder asserts, from INSIDE the closure, that the cache entry is
    /// already gone. That ordering is a race fix — a concurrent opener must miss
    /// rather than be handed a handle about to be closed — and swapping the two
    /// statements is otherwise invisible to a test that only looks at the end state.
    async fn open_page<'r>(
        cache: &Mutex<HashMap<u32, u32>>,
        ring: &'r Mutex<BoundedRing<u32>>,
        locks: &TestRecordLocks,
        id: u32,
        capacity: usize,
        opens: &AtomicU32,
        closed: &Mutex<Vec<u32>>,
    ) -> Option<(u32, PageLease<'r, u32>)> {
        let got = open_page_bounded(
            cache,
            ring,
            &id,
            capacity,
            counting_open_optional(opens, Some(id * 100)),
            |evicted: u32| test_lock(locks, evicted),
            |evicted: u32| async move {
                assert!(
                    !cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .values()
                        .any(|h| *h == evicted),
                    "the cache entry is dropped BEFORE the close, so a concurrent \
                     opener misses instead of being handed a dying handle"
                );
                closed
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(evicted);
            },
        )
        .await
        .unwrap();
        // Unconditional, unlike an `.inspect` on the evicted id: this must hold on
        // every open, not only on the ones that happened to evict something.
        if let Some((handle, _)) = &got {
            assert_eq!(*handle, id * 100, "the opener returns its own page");
        }
        got
    }

    /// [`open_page`] for a caller that is done the moment it returns — the shape of
    /// the publish path's pre-warm, and of every test line that only wants the side
    /// effect. Dropping the lease here is the point, not an oversight.
    async fn open_page_and_release(
        cache: &Mutex<HashMap<u32, u32>>,
        ring: &Mutex<BoundedRing<u32>>,
        locks: &TestRecordLocks,
        id: u32,
        capacity: usize,
        opens: &AtomicU32,
        closed: &Mutex<Vec<u32>>,
    ) {
        drop(open_page(cache, ring, locks, id, capacity, opens, closed).await);
    }

    /// The four stand-ins one bounded-cache test drives: the open cache, the page
    /// ring, a count of real opens, and the log of handles actually closed.
    type PageFixture = (
        Mutex<HashMap<u32, u32>>,
        Mutex<BoundedRing<u32>>,
        AtomicU32,
        Mutex<Vec<u32>>,
        TestRecordLocks,
    );

    /// Stand-in for [`RecordLocks`], keyed on the test's `u32` id rather than an
    /// owner public key. Same shape and same discipline: one async mutex per record,
    /// created on first use.
    type TestRecordLocks = Mutex<HashMap<u32, Arc<tokio::sync::Mutex<()>>>>;

    fn test_lock(locks: &TestRecordLocks, id: u32) -> Arc<tokio::sync::Mutex<()>> {
        locks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(id)
            .or_default()
            .clone()
    }

    /// A fresh fixture for one bounded-cache test.
    fn page_fixture() -> PageFixture {
        (
            Mutex::new(HashMap::new()),
            Mutex::new(BoundedRing::new()),
            AtomicU32::new(0),
            Mutex::new(Vec::new()),
            Mutex::new(HashMap::new()),
        )
    }

    #[tokio::test]
    async fn a_page_open_past_the_bound_closes_the_least_recently_used_page() {
        // The #252 mechanism: pages accumulate until the bound, and the (bound+1)th
        // open closes exactly one — the oldest — and drops it from the cache.
        let (cache, ring, opens, closed, locks) = page_fixture();
        const CAP: usize = 3;

        for id in 1..=CAP as u32 {
            open_page_and_release(&cache, &ring, &locks, id, CAP, &opens, &closed).await;
        }
        assert!(
            closed.lock().unwrap().is_empty(),
            "nothing is closed while the ring is under the bound"
        );

        open_page_and_release(&cache, &ring, &locks, 4, CAP, &opens, &closed).await;
        assert_eq!(
            *closed.lock().unwrap(),
            vec![100],
            "the fourth open CLOSES the first page's record — dropping the map entry \
             alone would leave it open on the network, which is the cardinality #252 \
             is about"
        );
        assert_eq!(
            cache.lock().unwrap().len(),
            CAP,
            "the cache holds at the bound rather than growing with message count"
        );
        assert!(!cache.lock().unwrap().contains_key(&1));
        assert_eq!(ring.lock().unwrap().len(), CAP);

        // The evicted page is genuinely gone, not merely unreachable: re-opening it
        // is a fresh open, not a hit serving the handle that was just closed.
        let before = opens.load(Ordering::SeqCst);
        open_page_and_release(&cache, &ring, &locks, 1, CAP, &opens, &closed).await;
        assert_eq!(
            opens.load(Ordering::SeqCst),
            before + 1,
            "a re-open of an evicted page opens; a hit here would serve a closed record"
        );
    }

    /// Close one page by name through the real path, with the same stand-ins
    /// [`open_page`] uses.
    async fn close_page(
        cache: &Mutex<HashMap<u32, u32>>,
        ring: &Mutex<BoundedRing<u32>>,
        locks: &TestRecordLocks,
        id: u32,
        closed: &Mutex<Vec<u32>>,
    ) -> bool {
        close_page_now(
            cache,
            ring,
            &id,
            |closing: u32| test_lock(locks, closing),
            |handle: u32| async move {
                closed
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(handle);
            },
        )
        .await
    }

    /// A page closed by name is released; one somebody is holding is refused.
    ///
    /// The driver-signalled half of #252. A close asked for by name reaches a page
    /// the capacity bound would not have chosen — it is neither the oldest nor over
    /// any bound — so the only thing standing between it and a record in use is the
    /// live-borrow test, which is why that is the half pinned here.
    ///
    /// Three claims, and the first two are controls for the third: an unleased page
    /// closes and leaves the cache, a leased one is refused and does NOT, and the
    /// refused page closes once its lease drops. Without the last, "refused" is
    /// indistinguishable from a close path that never works.
    #[tokio::test]
    async fn a_page_closed_by_name_is_released_unless_somebody_holds_it() {
        let (cache, ring, opens, closed, locks) = page_fixture();
        const CAP: usize = 8;

        open_page_and_release(&cache, &ring, &locks, 1, CAP, &opens, &closed).await;
        let held = open_page(&cache, &ring, &locks, 2, CAP, &opens, &closed)
            .await
            .expect("page two opens");
        assert_eq!(
            cache.lock().unwrap().len(),
            2,
            "both pages must be open, or neither close below means anything"
        );

        assert!(
            close_page(&cache, &ring, &locks, 1, &closed).await,
            "an unleased page must be released when its holder asks"
        );
        assert_eq!(
            *closed.lock().unwrap(),
            vec![100],
            "the record must be CLOSED, not merely dropped from the cache — the map \
             entry is the cheap half"
        );
        assert!(!cache.lock().unwrap().contains_key(&1));
        assert_eq!(ring.lock().unwrap().len(), 1, "the ring drops it too");

        assert!(
            !close_page(&cache, &ring, &locks, 2, &closed).await,
            "a page somebody is holding must be refused: closing a record mid-sweep \
             turns its remaining reads into failures"
        );
        assert!(
            cache.lock().unwrap().contains_key(&2),
            "a refused close must leave the entry exactly where it was"
        );
        assert_eq!(
            *closed.lock().unwrap(),
            vec![100],
            "a refused close must not have closed anything"
        );

        // The lease drops, so the same ask now succeeds — which is what makes the
        // refusal a deferral rather than a page that can never be reclaimed.
        drop(held);
        assert!(
            close_page(&cache, &ring, &locks, 2, &closed).await,
            "a page whose holder is done must be releasable"
        );
        assert_eq!(*closed.lock().unwrap(), vec![100, 200]);

        // A page nobody opened answers false and closes nothing, which is what a
        // caller counting reclaimed records has to be able to tell apart.
        assert!(
            !close_page(&cache, &ring, &locks, 7, &closed).await,
            "a page nobody opened releases no record"
        );
        assert_eq!(*closed.lock().unwrap(), vec![100, 200]);

        // **The unknown-id arm, asserted on the ring directly.** Through
        // `close_page_now` it is masked: an id the ring does not hold is also an id
        // the cache does not hold, so inverting this answer still returns false at
        // the cache miss one line later, and the assertion above passes either way.
        // The ring is what has to be right — a `true` here would drop nothing and
        // report that it had.
        assert!(
            !ring.lock().unwrap().take_unleased(&9),
            "an id the ring never held is not something to take"
        );
    }

    #[tokio::test]
    async fn eviction_follows_use_order_not_insertion_order() {
        // The ordering is what makes the bound cheap on a live conversation: the page
        // being written is re-opened on every publish, so it sits at the back of the
        // ring and the page that leaves is one nothing has referenced in a while.
        let (cache, ring, opens, closed, locks) = page_fixture();
        const CAP: usize = 3;

        for id in 1..=3 {
            open_page_and_release(&cache, &ring, &locks, id, CAP, &opens, &closed).await;
        }
        // Re-use page 1 — a cache hit, which still re-records it as most-recent.
        open_page_and_release(&cache, &ring, &locks, 1, CAP, &opens, &closed).await;
        assert_eq!(
            opens.load(Ordering::SeqCst),
            3,
            "the re-use was a cache hit"
        );
        assert!(
            closed.lock().unwrap().is_empty(),
            "a hit at the bound evicts nothing: the id was already in the ring"
        );
        // And again, consecutively — the ordinary case for a page written slot by
        // slot. A ring that appended instead of moving would now hold 1 three times,
        // be over the bound, and start closing live pages.
        open_page_and_release(&cache, &ring, &locks, 1, CAP, &opens, &closed).await;
        assert!(closed.lock().unwrap().is_empty());
        assert_eq!(ring.lock().unwrap().len(), 3, "no duplicate ring entries");

        open_page_and_release(&cache, &ring, &locks, 4, CAP, &opens, &closed).await;
        assert_eq!(
            *closed.lock().unwrap(),
            vec![200],
            "page 2 is now the least recently used — page 1 was refreshed by its re-use"
        );
        assert!(
            cache.lock().unwrap().contains_key(&1),
            "the re-used page survives, which insertion order would not have given"
        );
    }

    #[tokio::test]
    async fn a_leased_page_is_skipped_rather_than_closed_and_returns_when_released() {
        // The safety property #252's first cut got wrong. A sweeper drops the record
        // lock before its GETs and holds no permit between two of them, so no lock and
        // no permit ceiling covers the window in which it is holding a live handle.
        // The lease does: an id someone is holding is skipped as an eviction
        // candidate, however far down the ring it has fallen.
        let (cache, ring, opens, closed, locks) = page_fixture();
        const CAP: usize = 2;

        // Page 1 is the oldest AND held — the shape of a long sweep.
        let held = open_page(&cache, &ring, &locks, 1, CAP, &opens, &closed).await;
        open_page_and_release(&cache, &ring, &locks, 2, CAP, &opens, &closed).await;
        open_page_and_release(&cache, &ring, &locks, 3, CAP, &opens, &closed).await;

        assert_eq!(
            *closed.lock().unwrap(),
            vec![200],
            "the oldest UNLEASED page is closed; the leased one is passed over"
        );
        assert!(
            cache.lock().unwrap().contains_key(&1),
            "closing a leased record would fail the holder's remaining GETs into \
             `outcome.failed`, which a collector reads as record ill-health"
        );
        assert_eq!(
            cache.lock().unwrap().len(),
            CAP,
            "skipping it costs nothing here — an unleased candidate existed further \
             along the ring and was closed instead"
        );

        // When EVERY ring entry is leased there is no candidate at all, so the cache
        // sits above capacity rather than closing a record in use.
        let five = open_page(&cache, &ring, &locks, 5, CAP, &opens, &closed).await;
        let six = open_page(&cache, &ring, &locks, 6, CAP, &opens, &closed).await;
        assert_eq!(
            *closed.lock().unwrap(),
            vec![200, 300],
            "page 5's open closed the unleased page 3; page 6's found nothing to close"
        );
        assert_eq!(
            cache.lock().unwrap().len(),
            3,
            "1, 5 and 6 are all held, so the cache exceeds the bound by the live \
             borrows — an excess bounded by concurrency, where closing a live record \
             would be a silent traffic-dependent fault"
        );

        // Releasing makes them ordinary candidates again. The excess drains at one
        // page per subsequent open — eviction closes at most one record per call, so
        // this is a decay back to the bound rather than a burst of closes.
        drop((held, five, six));
        open_page_and_release(&cache, &ring, &locks, 4, CAP, &opens, &closed).await;
        assert_eq!(
            *closed.lock().unwrap(),
            vec![200, 300, 100],
            "once released, the page that was skipped is the next one closed"
        );
        assert_eq!(cache.lock().unwrap().len(), CAP + 1, "one closed per open");
        open_page_and_release(&cache, &ring, &locks, 5, CAP, &opens, &closed).await;
        assert_eq!(*closed.lock().unwrap(), vec![200, 300, 100, 600]);
        assert_eq!(
            cache.lock().unwrap().len(),
            CAP,
            "drained back to the bound"
        );
    }

    #[test]
    fn a_victim_that_is_the_id_being_opened_takes_no_lock_at_all() {
        // Driven directly rather than trusted to be unreachable. The caller already
        // holds a lock into `open_page_bounded`, so taking the opened id's lock would
        // self-deadlock — a permanent release hang with no signal anywhere, and the
        // profile that ships compiles `debug_assert` out. The guard must SKIP.
        let locks: TestRecordLocks = Mutex::new(HashMap::new());

        // The degenerate case, driven with the id's lock already held: a `None` is the
        // whole point, because there is no lock here that could ever be awaited.
        let held = test_lock(&locks, 7);
        let _guard = held.try_lock().expect("uncontended in this test");
        assert!(
            victim_lock(7u32, &7u32, |id| test_lock(&locks, id)).is_none(),
            "closing the id being opened must take NO lock — the caller holds it"
        );

        // The ordinary case still locks, and locks the VICTIM: a guard that skipped
        // everything would satisfy the assertion above and reopen the close race.
        let chosen = victim_lock(8u32, &7u32, |id| test_lock(&locks, id))
            .expect("a victim that is not the opened id is locked");
        assert!(
            Arc::ptr_eq(&chosen, &test_lock(&locks, 8)),
            "and it is the evicted record's lock, not the opened one's"
        );
        assert!(
            !Arc::ptr_eq(&chosen, &test_lock(&locks, 7)),
            "the opened id's lock is never what an eviction waits on"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_eviction_closes_under_the_evicted_records_own_lock() {
        // The residual race the lease cannot cover, because the victim is by
        // definition UNLEASED. Removal and close cannot be one critical section — the
        // close is an await, the ring guard is not — so between them the id is absent
        // from the cache while its record is still open. A concurrent open of that id
        // would miss, establish a FRESH session, and have this close kill it; the
        // symptom is the one the lease exists to prevent, failed GETs read as record
        // ill-health. Every production page open holds the record's lock across the
        // open, so the close takes that same lock.
        //
        // Driven, not argued: hold the victim's lock and the eviction must not
        // proceed. Virtual time (`start_paused`) makes the timeout fire the moment
        // nothing else can run, so this is deterministic rather than timing-based.
        let (cache, ring, opens, closed, locks) = page_fixture();
        const CAP: usize = 1;

        open_page_and_release(&cache, &ring, &locks, 1, CAP, &opens, &closed).await;
        assert!(cache.lock().unwrap().contains_key(&1));

        // Stand in for a concurrent opener of page 1, which takes page 1's record lock
        // across its own open exactly as `publish_dm_page` and `sweep_dm_page` do.
        let held = test_lock(&locks, 1);
        let opener_guard = held.lock().await;

        let blocked = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            open_page_and_release(&cache, &ring, &locks, 2, CAP, &opens, &closed),
        )
        .await;
        assert!(
            blocked.is_err(),
            "the eviction of page 1 must WAIT for page 1's record lock — without that \
             wait it closes a record another task is in the middle of re-opening"
        );
        assert!(
            closed.lock().unwrap().is_empty(),
            "and nothing was closed while the lock was held"
        );
        drop(opener_guard);

        // Positive control on a fresh fixture: the identical call with the lock free
        // completes and closes, so the assertion above is about the lock and not about
        // the eviction being unreachable.
        let (cache, ring, opens, closed, locks) = page_fixture();
        open_page_and_release(&cache, &ring, &locks, 1, CAP, &opens, &closed).await;
        open_page_and_release(&cache, &ring, &locks, 2, CAP, &opens, &closed).await;
        assert_eq!(*closed.lock().unwrap(), vec![100]);
        assert!(!cache.lock().unwrap().contains_key(&1));
    }

    #[tokio::test]
    async fn an_absent_page_is_neither_cached_nor_ringed() {
        // The probe frontier runs ahead of what exists, so most probes find nothing.
        // A miss opened no record, so there is nothing to bound — and ringing it would
        // let probes ahead of the frontier close pages a conversation is still using.
        let (cache, ring, opens, closed, locks) = page_fixture();
        const CAP: usize = 2;

        for id in 1..=CAP as u32 {
            open_page_and_release(&cache, &ring, &locks, id, CAP, &opens, &closed).await;
        }
        let absent = open_page_bounded(
            &cache,
            &ring,
            &99,
            CAP,
            counting_open_optional(&opens, None),
            |_evicted: u32| test_lock(&locks, 0),
            |_evicted: u32| async { unreachable!("an absent page evicts nothing") },
        )
        .await
        .unwrap();

        assert!(absent.is_none());
        assert!(closed.lock().unwrap().is_empty());
        assert_eq!(
            ring.lock().unwrap().len(),
            CAP,
            "the probe is not in the ring"
        );
        assert!(!cache.lock().unwrap().contains_key(&99));
    }

    #[tokio::test]
    async fn a_capacity_below_one_still_keeps_the_page_it_just_opened() {
        // A literal zero would make the page this call opened its own eviction
        // candidate the moment its lease dropped — the caller would be handed a
        // handle to a record already closed.
        let (cache, ring, opens, closed, locks) = page_fixture();
        open_page_and_release(&cache, &ring, &locks, 1, 0, &opens, &closed).await;
        assert!(closed.lock().unwrap().is_empty());
        assert_eq!(cache.lock().unwrap().get(&1), Some(&100));

        // And at the floor it behaves as a capacity of one: the next page closes it.
        open_page_and_release(&cache, &ring, &locks, 2, 0, &opens, &closed).await;
        assert_eq!(*closed.lock().unwrap(), vec![100]);
        assert_eq!(cache.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn an_entry_never_opened_as_a_page_is_never_evicted_or_closed() {
        // The property the whole shape rests on, and why #128 D-0a survives intact.
        // The shared lobby record lives in this same cache — every share advert and
        // the lobby subscription derive the SAME owner seed — so closing it would take
        // it from callers actively using it. It never enters a ring, and eviction
        // candidates come from the ring, so it cannot be chosen. `BoundedRing`'s
        // fields are private, so no caller can put it there either.
        let (cache, ring, opens, closed, locks) = page_fixture();
        const CAP: usize = 2;
        const SHARED: u32 = 999;

        // Cached the way every non-page caller caches: `open_cached` alone.
        open_cached(&cache, &SHARED, counting_open(&opens, 42))
            .await
            .unwrap();

        for id in 1..=20 {
            open_page_and_release(&cache, &ring, &locks, id, CAP, &opens, &closed).await;
        }

        assert_eq!(
            closed.lock().unwrap().len(),
            18,
            "every page past the bound was closed"
        );
        assert!(
            !closed.lock().unwrap().contains(&42),
            "and the shared record was NEVER closed"
        );
        assert_eq!(
            cache.lock().unwrap().get(&SHARED),
            Some(&42),
            "the shared entry keeps the open-once behaviour exactly (#128 D-0a)"
        );
        assert_eq!(
            cache.lock().unwrap().len(),
            CAP + 1,
            "bounded pages plus the untouched shared entry"
        );
    }

    #[test]
    fn record_lock_is_per_owner_same_shares_distinct_separate() {
        // Same owner → the SAME lock (same-record ops serialize); distinct owners
        // → distinct locks (different records run concurrently).
        let locks: RecordLocks = Mutex::new(HashMap::new());
        let one = crate::identity::rendezvous_owner_keypair(&[1u8; 32]).unwrap();
        let two = crate::identity::rendezvous_owner_keypair(&[2u8; 32]).unwrap();
        let a = record_lock(&locks, &one.key());
        let a2 = record_lock(&locks, &one.key());
        let b = record_lock(&locks, &two.key());
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
                let lock = record_lock(&locks, &owner.key());
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
    ///
    /// The sweep must have MORE slots than [`SWEEP_READ_FANOUT`] for this to prove
    /// anything: the sweep queues one permit request per in-flight GET, so a sweep no
    /// longer than the fan-out has every one of its requests queued ahead of the
    /// competitor's, and the competitor would come last however briefly each permit is
    /// held. The slot count is derived from the fan-out so that widening the fan-out
    /// keeps the probe honest instead of quietly disarming it.
    #[tokio::test]
    async fn wb_isc_21_read_permit_is_per_get_not_per_sweep() {
        let slots = u16::try_from(SWEEP_READ_FANOUT + 4).expect("a small slot count");
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

        // Sweep: each GET records 's' while holding the read permit, then yields so the
        // FIFO-queued competitor can take the permit once it is released.
        let outcome = sweep_gated(
            &gate,
            slots,
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
        assert_eq!(outcome.found, u32::from(slots), "every slot populated");

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

    // ── #397: one unanswered slot must not hold the sweep open for ever ───────
    /// A GET that never answers is abandoned at [`SWEEP_GET_TIMEOUT`], so the sweep
    /// finishes and every other slot is still delivered. The counts say exactly what
    /// happened: `attempted` covers all eight slots, `timed_out` names the one that was
    /// abandoned, and `failed` counts it too, so the session-health rule written against
    /// `failed` reads a wedged record as ill exactly as it reads an erroring one.
    ///
    /// Runs on tokio's paused clock: the elapsed figure asserted is virtual time
    /// advanced by the sweep's own timer, so the asserted figure is exact and does not
    /// depend on wall-clock time. The outer
    /// timeout is what turns a sweep that never returns into a failed assertion instead
    /// of a test that hangs.
    #[tokio::test(start_paused = true)]
    async fn sweep_abandons_a_get_that_never_answers() {
        const WEDGED_SLOT: u32 = 3;
        let gate = DhtGate::with_pools(2, 1, 2, 9);
        let started = tokio::time::Instant::now();
        let outcome = tokio::time::timeout(
            SWEEP_GET_TIMEOUT + std::time::Duration::from_secs(30),
            sweep_gated(
                &gate,
                8,
                |_subkey, _bytes| true,
                |subkey| async move {
                    if subkey == WEDGED_SLOT {
                        std::future::pending::<()>().await; // never answers
                    }
                    Ok(Some(vec![1u8]))
                },
            ),
        )
        .await
        .expect("the sweep finished — an unanswered GET is abandoned, not awaited for ever");
        let elapsed = started.elapsed();

        assert_eq!(outcome.attempted, 8, "every slot is still attempted");
        assert_eq!(outcome.found, 7, "the seven answering slots are delivered");
        assert_eq!(
            outcome.timed_out, 1,
            "exactly the unanswered slot timed out"
        );
        assert_eq!(
            outcome.failed, 1,
            "an abandoned read counts as a failed read for record health"
        );
        assert!(
            elapsed >= SWEEP_GET_TIMEOUT,
            "the unanswered slot was given its full bound before being abandoned: {elapsed:?}"
        );
        assert!(
            elapsed < SWEEP_GET_TIMEOUT + std::time::Duration::from_secs(1),
            "the sweep ended at the bound, not later: {elapsed:?}"
        );
    }

    // ── #397: a sweep's reads run several at a time ───────────────────────────
    /// Both populated slots of a 64-subkey record reach the caller inside ONE sweep,
    /// and the sweep costs `ceil(64 / SWEEP_READ_FANOUT)` read latencies rather than 64.
    ///
    /// The record's shape is the real one: two slots hold payloads and the other 62 are
    /// empty. Every slot costs the same fixed second to read whatever it holds, so the
    /// elapsed figure measures round trips and nothing else — and the sweep still reads
    /// all 64, which is what keeps its traffic shape independent of the contents.
    #[tokio::test(start_paused = true)]
    async fn sweep_reads_fan_out_and_delivers_every_populated_slot() {
        const SLOTS: u16 = 64;
        const POPULATED: [u32; 2] = [21, 31];
        const READ_LATENCY: std::time::Duration = std::time::Duration::from_secs(1);
        let gate = DhtGate::with_pools(2, 1, 2, 9);
        let mut delivered: Vec<(u32, Vec<u8>)> = Vec::new();

        let started = tokio::time::Instant::now();
        let outcome = sweep_gated(
            &gate,
            SLOTS,
            |subkey, bytes| {
                delivered.push((subkey, bytes));
                true
            },
            |subkey| async move {
                tokio::time::sleep(READ_LATENCY).await;
                if POPULATED.contains(&subkey) {
                    Ok(Some(vec![
                        u8::try_from(subkey).expect("slot index fits a byte")
                    ]))
                } else {
                    Ok(None)
                }
            },
        )
        .await;
        let elapsed = started.elapsed();

        assert_eq!(
            delivered,
            vec![(21, vec![21u8]), (31, vec![31u8])],
            "both populated slots delivered, in slot order, within one sweep"
        );
        assert_eq!(outcome.attempted, u32::from(SLOTS), "all 64 slots are read");
        assert_eq!(
            outcome.found, 2,
            "exactly the two populated slots are found"
        );
        assert_eq!(outcome.failed, 0, "no read errored");
        assert_eq!(outcome.timed_out, 0, "no read hit the bound");

        // 16 = 64 slots read four at a time. Written as a literal rather than derived
        // from `SWEEP_READ_FANOUT`, so that changing the fan-out fails this assertion
        // instead of quietly moving the bound it is measured against. Equality, not a
        // ceiling: a ceiling is satisfied by any narrower sweep too, so it would pass on
        // a fan-out of 5 or 8 as readily as on 4 and pin nothing but the direction.
        const EXPECTED_ROUNDS: u32 = 16;
        assert_eq!(
            elapsed,
            READ_LATENCY * EXPECTED_ROUNDS,
            "the sweep cost {EXPECTED_ROUNDS} read latencies, one per fan-out round"
        );
    }

    // ── #397: stopping early must cost the read pool nothing ──────────────────
    /// A sweep stopped by `on_slot` stops issuing reads, and every permit its in-flight
    /// reads held is back in the pool by the time it returns.
    ///
    /// Both halves matter only because reads run several at a time: some are always in
    /// flight when the stop lands, and they are cancelled by dropping the stream rather
    /// than awaited. The permit count is the half that would fail silently — a sweep that
    /// stranded permits would still return the right counts, and the read pool would
    /// simply narrow by a few permits per stopped sweep until reads stopped being served
    /// at all.
    #[tokio::test(start_paused = true)]
    async fn a_stopped_sweep_issues_no_more_reads_and_strands_no_permit() {
        const SLOTS: u16 = 64;
        const LAST_WANTED: u32 = 2;
        const READ_POOL: usize = 9;
        const READ_LATENCY: std::time::Duration = std::time::Duration::from_secs(1);
        let gate = DhtGate::with_pools(2, 1, 2, READ_POOL);
        let issued = Arc::new(AtomicUsize::new(0));
        let mut delivered: Vec<u32> = Vec::new();

        let outcome = sweep_gated(
            &gate,
            SLOTS,
            |subkey, _bytes| {
                delivered.push(subkey);
                subkey < LAST_WANTED
            },
            |_subkey| {
                let issued = issued.clone();
                async move {
                    issued.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(READ_LATENCY).await;
                    Ok(Some(vec![1u8]))
                }
            },
        )
        .await;

        assert_eq!(
            delivered,
            vec![0, 1, 2],
            "delivery stops at the slot whose callback answered false"
        );
        assert_eq!(
            outcome.attempted, 3,
            "only the reads the sweep took a result from are counted"
        );

        let issued = issued.load(Ordering::SeqCst);
        assert!(
            issued < usize::from(SLOTS),
            "the stop ends the sweep — it did not read all {SLOTS} slots ({issued} issued)"
        );
        assert!(
            issued <= outcome.attempted as usize + SWEEP_READ_FANOUT,
            "reads run ahead of the stop by at most one buffer's worth ({issued} issued)"
        );
        assert_eq!(
            gate.available_read(),
            READ_POOL,
            "the cancelled reads gave their permits back"
        );
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
                        timed_out: 0,
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
