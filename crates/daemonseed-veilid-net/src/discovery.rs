//! Slice 2b — the signed route-advert wrapper for public-share discovery (D-3.5).
//!
//! Discovery publishes a `ShareAnnouncement` (sealed + self-signed in
//! `daemonseed-core`) onto the world-readable lobby rendezvous record. That tells
//! a fetcher a share EXISTS and WHO announced it, but not WHERE to fetch it: the
//! sharer's content is served over a Veilid private route whose opaque blob must
//! travel with the announcement. The lobby record is world-WRITABLE (open
//! rendezvous), so a man-in-the-middle could pair a victim's announcement with a
//! ROGUE route blob and silently redirect the fetch — unless the route blob is
//! cryptographically bound to the announcer.
//!
//! This module is that binding, and it lives entirely in the transport layer:
//! the core `ShareAnnouncement` / its proto / its `provenance_input` are
//! UNTOUCHED. Route delivery is transport routing, kept decoupled so a future
//! Veilid change never reaches the content/relay layers. A discovery item becomes
//! a [`DiscoveryEnvelope`] `{ sealed_announcement, route_blob, route_sig }` where
//! `route_sig` is the announcer's ML-DSA-87 signature over a domain-separated
//! input binding `share_id ‖ route_blob` ([`route_provenance_input`]).
//!
//! ## Anti-swap
//! The announcement is the root of trust: `open_announcement` (core) yields a
//! provenance-verified `(sender_pubkey, share_id)`. A fetcher then checks
//! [`verify_route_advert`] — `route_sig` over `(share_id, route_blob)` against
//! that pubkey. A MITM cannot re-pair the announcement with a rogue blob without
//! the announcer's ML-DSA secret, and cannot lift the announcement onto another
//! share (the signed `share_id` binds the two). A wrong route only ever yields a
//! dead fetch (fail closed) — content is SHA-384-verified regardless (ISC-S28).
//!
//! ## Least-authority signing capability
//! veilid-net never holds the announcer's long-term identity key. The sharer's
//! app passes an [`RouteAdvertSigner`] — a capability that signs ONLY a route
//! advert for a given `(share_id, route_blob)` — so even this network-facing
//! crate cannot coerce an arbitrary-message signature out of the identity key,
//! and the key never enters this crate's reachable set. The signed bytes are
//! defined once, here ([`route_provenance_input`]); the implementor only applies
//! the key, so sign and verify can never drift.

use daemonseed_core::identity::keys::verify_signature;

use crate::error::{Result, VeilidNetError};

/// Domain-separation prefix for the route-advert signature, distinct from every
/// other input the announcer's ML-DSA-87 key signs (share announcements,
/// heartbeats, room messages) so a route-advert signature can never be replayed
/// as any of them, nor any of them as it.
pub const ROUTE_ADVERT_DOMAIN: &[u8] = b"daemonseed/veilid/share-route/v1";

/// Build the domain-separated bytes a route advert is signed over: the domain
/// tag, then length-prefixed `share_id` and `route_blob`. Length-prefixing makes
/// the concatenation unambiguous (no `share_id`/`route_blob` boundary confusion).
/// This is the SINGLE definition of the signed bytes — both [`RouteAdvertSigner`]
/// implementors and [`verify_route_advert`] go through it.
pub fn route_provenance_input(share_id: &str, route_blob: &[u8]) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(ROUTE_ADVERT_DOMAIN.len() + 16 + share_id.len() + route_blob.len());
    buf.extend_from_slice(ROUTE_ADVERT_DOMAIN);
    buf.extend_from_slice(&(share_id.len() as u64).to_be_bytes());
    buf.extend_from_slice(share_id.as_bytes());
    buf.extend_from_slice(&(route_blob.len() as u64).to_be_bytes());
    buf.extend_from_slice(route_blob);
    buf
}

/// A capability that signs a share's route advert with the sharer's long-term
/// ML-DSA-87 identity key. The implementor (the app, which owns the identity)
/// MUST sign exactly [`route_provenance_input`]`(share_id, route_blob)`.
///
/// Passed as `Arc<dyn RouteAdvertSigner>` so veilid-net can INVOKE signing
/// locally (e.g. to refresh an advert on `RouteChanged`) but never holds or reads
/// key material — the identity secret stays out of this network-facing crate's
/// reachable set, and the capability is scoped to route adverts alone (it is not
/// a general signing oracle).
pub trait RouteAdvertSigner: Send + Sync {
    /// Sign this node's route advert for `share_id` reachable at `route_blob`.
    fn sign_route_advert(&self, share_id: &str, route_blob: &[u8]) -> Result<Vec<u8>>;
}

/// Verify a route advert against the announcer's ML-DSA-87 public key (the one
/// `open_announcement` already provenance-verified). Returns `false` — fail
/// closed — on a wrong-length key/signature, a tampered or rogue `route_blob`, a
/// `share_id` mismatch, or a forged signature; the caller cannot tell which
/// (uniform close-shape, mirroring core `verify_signature`).
pub fn verify_route_advert(
    announcer_pubkey: &[u8],
    share_id: &str,
    route_blob: &[u8],
    route_sig: &[u8],
) -> bool {
    fn fixed<const N: usize>(s: &[u8]) -> Option<&[u8; N]> {
        s.try_into().ok()
    }
    let (Some(pk), Some(sig)) = (fixed(announcer_pubkey), fixed(route_sig)) else {
        return false;
    };
    let input = route_provenance_input(share_id, route_blob);
    verify_signature(pk, &input, sig).is_ok()
}

/// A public-share discovery item as it rides the lobby rendezvous record: the
/// sealed + self-signed core announcement, the sharer's opaque Veilid
/// private-route blob, and the announcer's signature binding them
/// ([`route_provenance_input`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryEnvelope {
    /// The sealed `wire::ShareAnnouncement` bytes (opened under the room key in core).
    pub sealed_announcement: Vec<u8>,
    /// The sharer's Veilid private-route blob (anti-dox: hides the sharer's node/IP).
    pub route_blob: Vec<u8>,
    /// ML-DSA-87 signature over `route_provenance_input(share_id, route_blob)`.
    pub route_sig: Vec<u8>,
}

impl DiscoveryEnvelope {
    /// Serialize as `[len(ann)][ann][len(blob)][blob][len(sig)][sig]`, each length
    /// a `u32` big-endian. Published as the opaque `sealed` payload of a rendezvous
    /// write — the rendezvous engine never inspects it.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            12 + self.sealed_announcement.len() + self.route_blob.len() + self.route_sig.len(),
        );
        for field in [&self.sealed_announcement, &self.route_blob, &self.route_sig] {
            buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
            buf.extend_from_slice(field);
        }
        buf
    }

    /// Parse an inbound discovery item. Fails closed on any malformed input
    /// (truncation, a length running past the buffer, or trailing bytes) — a
    /// hostile or foreign blob on the world-writable lobby record yields an error,
    /// never a partial parse.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut rest = bytes;
        let sealed_announcement = take_field(&mut rest)?;
        let route_blob = take_field(&mut rest)?;
        let route_sig = take_field(&mut rest)?;
        if !rest.is_empty() {
            return Err(malformed());
        }
        Ok(Self {
            sealed_announcement,
            route_blob,
            route_sig,
        })
    }
}

fn malformed() -> VeilidNetError {
    VeilidNetError::Routing("malformed discovery envelope".to_owned())
}

/// Pull one `[u32 len][bytes]` field, advancing `rest`. Fails closed on a short
/// header or a length that runs past the remaining buffer.
fn take_field(rest: &mut &[u8]) -> Result<Vec<u8>> {
    let (len_bytes, after_len) = rest.split_at_checked(4).ok_or_else(malformed)?;
    let len = u32::from_be_bytes(len_bytes.try_into().map_err(|_| malformed())?) as usize;
    let (field, after_field) = after_len.split_at_checked(len).ok_or_else(malformed)?;
    *rest = after_field;
    Ok(field.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemonseed_core::identity::keys::SignKeypair;

    /// A test [`RouteAdvertSigner`] wrapping a real ML-DSA-87 keypair — it signs
    /// exactly `route_provenance_input`, the same definition `verify_route_advert`
    /// checks, so the two can never drift.
    struct TestSigner(SignKeypair);
    impl RouteAdvertSigner for TestSigner {
        fn sign_route_advert(&self, share_id: &str, route_blob: &[u8]) -> Result<Vec<u8>> {
            self.0
                .sign(&route_provenance_input(share_id, route_blob))
                .map(|s| s.to_vec())
                .map_err(|e| VeilidNetError::Send(e.to_string()))
        }
    }

    fn signer(seed: u8) -> TestSigner {
        let _ = oxicrypt_module::initialize();
        TestSigner(SignKeypair::from_ml_dsa_seed(&[seed; 32]).unwrap())
    }

    #[test]
    fn envelope_round_trips_and_rejects_malformed() {
        let env = DiscoveryEnvelope {
            sealed_announcement: vec![1, 2, 3, 4],
            route_blob: vec![9; 200],
            route_sig: vec![7; 50],
        };
        let bytes = env.encode();
        assert_eq!(DiscoveryEnvelope::decode(&bytes).unwrap(), env);

        // Trailing byte → malformed (no partial parse on the world-writable record).
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(DiscoveryEnvelope::decode(&trailing).is_err());

        // Truncation anywhere → malformed.
        assert!(DiscoveryEnvelope::decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(DiscoveryEnvelope::decode(&[]).is_err());
        assert!(DiscoveryEnvelope::decode(b"\x00\x00\x00\x05ab").is_err());
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let s = signer(1);
        let share_id = "0123456789abcdef0123456789abcdef";
        let blob = vec![0xAB; 256];
        let sig = s.sign_route_advert(share_id, &blob).unwrap();
        assert!(verify_route_advert(s.0.public_key(), share_id, &blob, &sig));
    }

    #[test]
    fn anti_swap_a_rogue_route_blob_is_rejected() {
        let s = signer(2);
        let share_id = "0123456789abcdef0123456789abcdef";
        let honest = vec![0x11; 256];
        let sig = s.sign_route_advert(share_id, &honest).unwrap();
        // A MITM keeps the announcement + signature but swaps the route blob.
        let rogue = vec![0x22; 256];
        assert!(!verify_route_advert(
            s.0.public_key(),
            share_id,
            &rogue,
            &sig
        ));
    }

    #[test]
    fn a_different_announcer_key_is_rejected() {
        let a = signer(3);
        let b = signer(4);
        let share_id = "0123456789abcdef0123456789abcdef";
        let blob = vec![0x33; 256];
        let sig = a.sign_route_advert(share_id, &blob).unwrap();
        // Verifying A's advert against B's pubkey must fail.
        assert!(!verify_route_advert(
            b.0.public_key(),
            share_id,
            &blob,
            &sig
        ));
    }

    #[test]
    fn a_different_share_id_is_rejected() {
        let s = signer(5);
        let blob = vec![0x44; 256];
        let sig = s
            .sign_route_advert("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &blob)
            .unwrap();
        // The signed share_id binds the advert to ONE share — reusing the route on
        // another share fails (no cross-share route reuse).
        assert!(!verify_route_advert(
            s.0.public_key(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            &blob,
            &sig
        ));
    }

    #[test]
    fn wrong_length_key_or_signature_fails_closed() {
        let s = signer(6);
        let share_id = "0123456789abcdef0123456789abcdef";
        let blob = vec![0x55; 256];
        let sig = s.sign_route_advert(share_id, &blob).unwrap();
        // A short/garbage pubkey or signature must return false, never panic.
        assert!(!verify_route_advert(b"too-short", share_id, &blob, &sig));
        assert!(!verify_route_advert(
            s.0.public_key(),
            share_id,
            &blob,
            b"short-sig"
        ));
        assert!(!verify_route_advert(&[], share_id, &blob, &[]));
    }
}
