//! D3 — turn the daemonseed-derived [`VeilidNodeSeed`] into a VLD0 node keypair
//! and the routing-table identity groups that pin it.
//!
//! VLD0 is Ed25519, so the seed IS the secret and the public is its verifying
//! key — byte-identical to veilid-core's own `vld0_generate_keypair`, minus the
//! RNG (proven in veilid-ds-spike `phase0-d3`).

use std::str::FromStr;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use daemonseed_core::identity::keys::VeilidNodeSeed;
use ed25519_dalek::SigningKey;
use veilid_core::{KeyPair, PublicKeyGroup, SecretKeyGroup};

use crate::error::{Result, VeilidNetError};

/// Build a VLD0 keypair from any 32-byte Ed25519 seed — the node identity (D3)
/// or a rendezvous-owner seed (a circle's, a public room's). VLD0 is Ed25519,
/// so the seed IS the secret and the public is its verifying key.
///
/// **Residual, for callers holding a genuinely secret seed (a DM page's, #244).**
/// The returned `KeyPair` *contains* the seed — it is the VLD0 secret — held in
/// veilid's `BareSecretKey`, a plain `Bytes` with no zeroize-on-drop. Three more
/// unwiped copies exist for the length of this call: the `format!` below
/// materialises the secret as a base64 `String`, `sk.to_bytes()` materialises it as
/// a bare `[u8; 32]` temporary to feed that encode, and `SigningKey` itself holds
/// it (that one IS wiped — dalek zeroizes on drop, which is why the `zeroize`
/// feature is declared explicitly in `Cargo.toml` rather than inherited from
/// defaults). All are unavoidable while veilid's own key types are the signing
/// interface.
///
/// **Per-operation derivation does NOT bound the secret's lifetime, and it is
/// important not to believe that it does.** Handing the keypair to
/// `open_dht_record` / `create_dht_record` — which every record path does, since
/// without a writer every `set_value` fails — makes veilid retain a clone in
/// `OpenedRecord.writer` (`veilid-core-0.5.7`, `storage_manager/record_store/
/// opened_record.rs`), a struct that derives `Debug` over that secret and lives as
/// long as the record stays open. daemonseed opens records once per session and
/// never closes them (see `rendezvous::open_cached`), so for a DM page that copy is
/// effectively process-lifetime and is NOT under a caller's control. The only lever
/// on it is closing the record / evicting the open cache, which is #252's subject —
/// so #252 is a key-hygiene fix as much as a resource one.
///
/// What a caller CAN control is everything on this side of that boundary: derive
/// per operation, never cache a keypair yourself, and never key a long-lived map on
/// a seed. Use [`rendezvous_owner_public_bytes`] when only a record *identity* is
/// wanted, which needs no secret at all.
fn vld0_keypair(seed: &[u8; 32]) -> Result<KeyPair> {
    let sk = SigningKey::from_bytes(seed);
    let pk = sk.verifying_key();
    let s = format!(
        "VLD0:{}:{}",
        URL_SAFE_NO_PAD.encode(pk.to_bytes()),
        URL_SAFE_NO_PAD.encode(sk.to_bytes())
    );
    KeyPair::from_str(&s).map_err(|e| VeilidNetError::Identity(e.to_string()))
}

/// Build the VLD0 node keypair from a daemonseed Veilid node seed (D3).
pub fn node_keypair(seed: &VeilidNodeSeed) -> Result<KeyPair> {
    vld0_keypair(seed.as_bytes())
}

/// Build the VLD0 **rendezvous-owner** keypair from a deterministic owner seed
/// (a circle's, Phase 2; a public room's, Phase 3/4). Every participant derives
/// the same keypair, so all compute the same DHT record key and can write
/// owner-signed subkeys.
pub fn rendezvous_owner_keypair(owner_seed: &[u8; 32]) -> Result<KeyPair> {
    vld0_keypair(owner_seed)
}

/// A rendezvous-owner keypair's 32-byte Ed25519 **public** key, as raw bytes.
///
/// The same value [`rendezvous_owner_keypair`] puts in `KeyPair::key()`, reached
/// without the string round-trip and without the fallible parse: VLD0 is Ed25519,
/// so the public key is exactly 32 bytes for every possible seed, which is what
/// lets this be total where `rendezvous_owner_keypair` is not. Pinned equal to the
/// keypair's own public key by
/// `owner_public_bytes_is_the_keypairs_own_public_key` below, so the two cannot
/// drift.
///
/// Exists so a record can be *identified* without the secret being carried: the
/// DHT address derives from this key, so it separates records at least as
/// precisely as the seed does, and it is public by construction (#244).
///
/// **Residual:** `SigningKey::from_bytes` copies the seed into a `SigningKey`,
/// which is `ZeroizeOnDrop` — the copy is wiped when this function returns. No
/// copy of the seed outlives the call.
pub fn rendezvous_owner_public_bytes(owner_seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(owner_seed)
        .verifying_key()
        .to_bytes()
}

/// This node's 32-byte Ed25519 public key — a pure function of the node seed,
/// used to spread members across the circle record's subkey regions.
pub fn node_public_bytes(seed: &VeilidNodeSeed) -> [u8; 32] {
    SigningKey::from_bytes(seed.as_bytes())
        .verifying_key()
        .to_bytes()
}

/// Build the `(public_keys, secret_keys)` groups to pin this identity in the
/// veilid `routing_table` config (empty groups = "generate fresh").
pub fn identity_groups(seed: &VeilidNodeSeed) -> Result<(PublicKeyGroup, SecretKeyGroup)> {
    let kp = node_keypair(seed)?;
    let mut pks = PublicKeyGroup::new();
    pks.add(kp.key());
    let mut sks = SecretKeyGroup::new();
    sks.add(kp.secret());
    Ok((pks, sks))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The two ways to reach a rendezvous owner's public key agree.**
    ///
    /// [`rendezvous_owner_public_bytes`] exists as a second, total path to a value
    /// [`rendezvous_owner_keypair`] also computes, and callers rely on them naming
    /// the SAME record: the write funnel keys a page's FIFO/coalescing scope on the
    /// bytes, while the open cache and record locks key on the `KeyPair`'s own
    /// `PublicKey` (#244). If these drifted, one page would be two records to the
    /// engine — two lock identities, two cache entries, and a coalescing scope that
    /// no longer matches the thing being written, none of it visible on any surface.
    #[test]
    fn owner_public_bytes_is_the_keypairs_own_public_key() {
        // Byte-distinct seeds: a run of equal bytes would pass under a derivation
        // that mis-sliced its input.
        for tag in [0u8, 1, 0x5c, 0xff] {
            let mut seed = [0u8; 32];
            for (i, b) in seed.iter_mut().enumerate() {
                *b = tag ^ (i as u8).wrapping_mul(31).wrapping_add(7);
            }
            let kp = rendezvous_owner_keypair(&seed).expect("derive the owner keypair");
            assert_eq!(
                rendezvous_owner_public_bytes(&seed).as_slice(),
                kp.key().value().as_ref(),
                "the raw-bytes path and the KeyPair path must name one public key"
            );
        }
    }

    /// **The public key is not the seed.** Load-bearing rather than obvious: the
    /// funnel's record id is `[u8; 32]` and so is the seed, so a regression that
    /// put the secret back where the identity belongs would still type-check
    /// everywhere (#244).
    #[test]
    fn owner_public_bytes_is_not_the_seed() {
        let seed = [0x9du8; 32];
        assert_ne!(
            rendezvous_owner_public_bytes(&seed),
            seed,
            "the record identity must not BE the owner seed"
        );
    }

    /// A VLD0 public key is exactly 32 bytes, which is what lets it stand in for a
    /// `schedule::RecordId` without a fallible length check on the write path.
    #[test]
    fn a_vld0_public_key_is_thirty_two_bytes() {
        let kp = rendezvous_owner_keypair(&[0x11u8; 32]).expect("derive the owner keypair");
        assert_eq!(kp.key().value().len(), 32);
    }
}
