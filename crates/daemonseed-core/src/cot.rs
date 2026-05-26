//! Circle-of-trust rendezvous addressing (M8 — ISC-8 / ISC-S4 / F23).
//!
//! A circle's members exchange traffic through a *rendezvous address* on each
//! relay they share. The circle key itself ([`crate::circle::key::CotKey`])
//! never leaves a member's machine; what reaches the relay is the address
//!
//! ```text
//!   asset_address = SHA-384(cot_key || server_id)
//! ```
//!
//! - **Only a member can compute it.** Deriving the address needs `cot_key`,
//!   the circle secret, so a non-member cannot guess which address a circle
//!   uses. The relay sees an opaque 48-byte rendezvous point and a refcount —
//!   never the circle, its membership, or any notion of "joining" (ISC-A-S2).
//! - **`server_id` namespaces the address per relay.** The same circle on two
//!   relays presents two unlinkable addresses, so an observer correlating
//!   across relays learns nothing (cross-server unlinkability). This does NOT
//!   tie the circle to a relay: `cot_key` is server-independent, and a member
//!   derives a fresh address for whichever relay it connects to. Multi-relay
//!   reach via client multi-homing is post-MVP additive.
//!
//! SHA-384 (truncated SHA-512) is not length-extendable, and the address is a
//! public *identifier* rather than a MAC, so a plain hash of the concatenation
//! suffices. `cot_key` is fixed at [`COT_KEY_LEN`] bytes, so `cot_key ||
//! server_id` parses unambiguously regardless of `server_id` length. The
//! `server_id` operand must be the *same* stable byte representation on the
//! deriving member and the relay (the relay's canonical wire server-id); the
//! choice of representation is pinned at the wire layer, not here.

use oxicrypt_module::Error as OxicryptError;
use oxicrypt_sha::sha384;
use zeroize::Zeroize;

use crate::circle::key::{COT_KEY_LEN, CotKey};

/// Length of a circle-of-trust rendezvous address, in bytes (SHA-384).
pub const ASSET_ADDR_LEN: usize = 48;

/// A `SHA-384(cot_key || server_id)` circle-of-trust rendezvous address
/// (ISC-8 / ISC-S4).
///
/// This is the opaque 48-byte point a relay routes a circle's traffic through.
/// It is derived from the circle secret, never asserted by the relay; two
/// members who agree on the same circle phrase and connect to the same relay
/// derive the byte-identical address and meet there.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AssetAddr([u8; ASSET_ADDR_LEN]);

impl AssetAddr {
    /// The raw 48-byte address.
    pub fn as_bytes(&self) -> &[u8; ASSET_ADDR_LEN] {
        &self.0
    }

    /// Reconstruct an address from raw bytes — e.g. a subscribe request naming
    /// the rendezvous point it wants to join. The bytes are an opaque name; no
    /// validation is possible (only a member could check, and the relay is not
    /// one).
    pub fn from_bytes(bytes: [u8; ASSET_ADDR_LEN]) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Display for AssetAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl core::fmt::Debug for AssetAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("AssetAddr")
            .field(&hex::encode(self.0))
            .finish()
    }
}

/// Derive a circle's rendezvous address on a given relay: `SHA-384(cot_key ||
/// server_id)` (ISC-8). The transient `cot_key || server_id` buffer is zeroed
/// the moment the digest is taken — it carries the circle secret.
///
/// Returns the underlying oxicrypt error only if SHA-384's power-up self-test
/// has not yet passed (first hash in a fresh process).
pub fn asset_address(cot_key: &CotKey, server_id: &[u8]) -> Result<AssetAddr, OxicryptError> {
    let mut input = Vec::with_capacity(COT_KEY_LEN + server_id.len());
    input.extend_from_slice(cot_key.as_bytes());
    input.extend_from_slice(server_id);
    let digest = sha384(&input);
    input.zeroize();
    let digest = digest?;

    let mut out = [0u8; ASSET_ADDR_LEN];
    out.copy_from_slice(&digest[..ASSET_ADDR_LEN]);
    Ok(AssetAddr(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circle::key::{EXAMPLE_ENTROPY, derive_cot_key};
    use crate::crypto::suite::CNSA_2_0;

    const RELAY_A: &[u8] = b"relay-alpha#001122334455";
    const RELAY_B: &[u8] = b"relay-bravo#66778899aabb";

    fn example_key() -> CotKey {
        let _ = oxicrypt_module::initialize();
        derive_cot_key(EXAMPLE_ENTROPY, &CNSA_2_0).unwrap()
    }

    /// ISC-8 — the address is deterministic: same circle key + same relay yield
    /// the byte-identical address, so two members meet at the same point.
    #[test]
    fn asset_address_is_deterministic() {
        let a = asset_address(&example_key(), RELAY_A).unwrap();
        let b = asset_address(&example_key(), RELAY_A).unwrap();
        assert_eq!(a, b);
        assert_eq!(ASSET_ADDR_LEN, 48);
    }

    /// Cross-server unlinkability — the same circle on two relays presents two
    /// distinct addresses (server_id namespacing).
    #[test]
    fn asset_address_namespaced_per_relay() {
        let on_a = asset_address(&example_key(), RELAY_A).unwrap();
        let on_b = asset_address(&example_key(), RELAY_B).unwrap();
        assert_ne!(on_a, on_b);
    }

    /// The address is keyed by the circle secret — different circles (different
    /// phrases) on the same relay get different addresses.
    #[test]
    fn asset_address_keyed_by_circle() {
        let _ = oxicrypt_module::initialize();
        let circle_one = derive_cot_key("phrase alpha here", &CNSA_2_0).unwrap();
        let circle_two = derive_cot_key("phrase bravo here", &CNSA_2_0).unwrap();
        let addr_one = asset_address(&circle_one, RELAY_A).unwrap();
        let addr_two = asset_address(&circle_two, RELAY_A).unwrap();
        assert_ne!(addr_one, addr_two);
    }

    /// A round-trip address survives `as_bytes` → `from_bytes` (the form a
    /// subscribe request names a rendezvous by).
    #[test]
    fn asset_address_bytes_roundtrip() {
        let addr = asset_address(&example_key(), RELAY_A).unwrap();
        assert_eq!(AssetAddr::from_bytes(*addr.as_bytes()), addr);
    }
}
