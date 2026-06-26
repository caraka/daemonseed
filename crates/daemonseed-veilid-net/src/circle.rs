//! Phase 2 — circle group messaging over a shared-owner DFLT DHT record.
//!
//! Design (`docs/design/veilid-migration.md`): a circle's owner keypair is
//! derived deterministically from the shared circle entropy (a sibling of the
//! content `cot_key`), so every member computes the SAME DFLT record key — the
//! relay-free rendezvous address (the DHT analog of the relay-era
//! `SHA-384(cot_key ‖ server_id)`). Every member holds the owner secret, so all
//! write owner-signed subkeys with no pre-known member list (which is what an
//! `SMPL` baked-in member set could not give for open membership). Each member
//! writes a small append-ring within its own region (region = hash of its node
//! pubkey), so a connecting member finds a bounded backlog of recent messages
//! with no relay and no roster. Content stays sealed under the circle key — this
//! layer moves opaque bytes only.

use tokio::sync::mpsc;
use veilid_core::{
    DHTSchema, KeyPair, RecordKey, RoutingContext, SetDHTValueOptions, VeilidAPI, CRYPTO_KIND_VLD0,
};

use crate::actor::APP_MESSAGE_CAP;
use crate::error::{Result, VeilidNetError};
use crate::event::VeilidNetEvent;

/// Total subkeys in a circle's DFLT record. Fixed — it is part of the
/// deterministic record key, so every member MUST agree. Kept small so a
/// connecting member can sweep the whole record for backlog cheaply.
/// `= MEMBER_REGIONS * RING_DEPTH`.
pub const SUBKEY_COUNT: u16 = 64;

/// Distinct member regions; a member maps to one by hashing its node pubkey.
/// Collision (two members → same region) degrades to slot-sharing, not a crash;
/// a roster (Phase 4) removes the blind hash. Sized for small circles.
pub const MEMBER_REGIONS: u32 = 32;

/// Append-ring depth per member — the bounded recent backlog surfaced on login.
/// "A couple of recent messages", deliberately not durable scrollback.
pub const RING_DEPTH: u32 = 2;

/// The fixed DFLT schema shared by every circle record.
fn schema() -> Result<DHTSchema> {
    DHTSchema::dflt(SUBKEY_COUNT).map_err(|e| VeilidNetError::Routing(e.to_string()))
}

/// Compute a circle's deterministic rendezvous record key from its owner
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
    if rc
        .open_dht_record(key.clone(), Some(owner.clone()))
        .await
        .is_ok()
    {
        return Ok(key);
    }
    // Not present — create the network record. Ignore the result: on success
    // the handle carries create's random encryption key; on a lost create race
    // a peer already created it. Either way the reopen below (with our
    // no-encryption-key record key) resets the handle to verbatim storage.
    let _ = rc
        .create_dht_record(CRYPTO_KIND_VLD0, schema()?, Some(owner.clone()))
        .await;
    rc.open_dht_record(key.clone(), Some(owner.clone()))
        .await
        .map(|_| key)
        .map_err(|e| VeilidNetError::Routing(e.to_string()))
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
    if sealed.len() > APP_MESSAGE_CAP {
        return Err(VeilidNetError::Send(format!(
            "sealed {} bytes exceeds the {APP_MESSAGE_CAP}-byte subkey cap (re-chunk)",
            sealed.len()
        )));
    }
    let subkey = base + (seq % RING_DEPTH);
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
    for subkey in 0..u32::from(SUBKEY_COUNT) {
        if let Ok(Some(v)) = rc.get_dht_value(key.clone(), subkey, true).await {
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
}
