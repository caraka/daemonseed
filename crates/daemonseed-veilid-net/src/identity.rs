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

/// Build the VLD0 node keypair from a daemonseed Veilid node seed (D3).
pub fn node_keypair(seed: &VeilidNodeSeed) -> Result<KeyPair> {
    let sk = SigningKey::from_bytes(seed.as_bytes());
    let pk = sk.verifying_key();
    let s = format!(
        "VLD0:{}:{}",
        URL_SAFE_NO_PAD.encode(pk.to_bytes()),
        URL_SAFE_NO_PAD.encode(sk.to_bytes())
    );
    KeyPair::from_str(&s).map_err(|e| VeilidNetError::Identity(e.to_string()))
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
