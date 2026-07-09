//! Circle chat-message sealing (ISC-10..14 / ISC-C15 / ISC-C17 / ISC-C57 /
//! ISC-A-S2).
//!
//! A circle is a public room with a secret key: a circle chat message is a
//! signed [`wire::RoomMessage`] sealed under the circle's `cot_key`, sharing the
//! ONE seal/open path in [`crate::room_message`] with public rooms. This module
//! is the thin circle-side wrapper — it supplies the circle's key, its DISTINCT
//! AEAD AAD + provenance domain ([`MESSAGE_AAD`] / [`CIRCLE_PROVENANCE_DOMAIN`],
//! both `daemonseed/circle/message/v2`), and the circle `room_id`
//! ([`crate::circle::key::circle_room_id`]).
//!
//! ```text
//!   RoomMessage  ──sign(sender)──▶  signature
//!                ──prost──────────▶  plaintext
//!                ──AES-256-GCM(cot_key)──▶  sealed = nonce ‖ ct ‖ tag
//! ```
//!
//! - **Keyed by the circle secret.** The AEAD key *is* the 32-byte `cot_key`
//!   ([`CircleKey`]). Only a circle member can seal or open; the relay/DHT and
//!   any non-member see indistinguishable ciphertext (ISC-A-S2).
//! - **Signed for provenance (ISC-C57).** Every message carries an ML-DSA-87
//!   signature by the poster's OWN identity, so authorship is verifiable and a
//!   circle-key holder can no longer post attributable to no one or spoofing
//!   another member's handle — the pre-merge gap this convergence closes. The
//!   authoritative handle derives from `SHA-384(sender_pubkey)[:12]` (ISC-C4);
//!   `sender_handle` is decorative.
//! - **v2 domain separation.** The AAD + provenance domain are bumped to
//!   `.../v2` for the signed shape, so a pre-merge unsigned `v1` circle message
//!   can never be opened by — nor substituted into — the signed path (it fails
//!   AEAD authentication on the AAD mismatch). No migration: ephemeral relay/DHT
//!   content, any unsigned backlog simply drops.
//! - **Verifier recomputes the room_id** from its own `cot_key`; the carried
//!   `room_id` is never trusted for the signature check ([`crate::room_message`]).

use daemonseed_proto::v1 as wire;

use crate::circle::key::{CircleKey, circle_room_id};
use crate::identity::keys::SignKeypair;
use crate::room_message::{open_signed_room_message, seal_signed_room_message};

pub use crate::room_message::RoomMessageError as MessageError;

/// AES-GCM nonce length in bytes (96-bit, the GCM-canonical size). The generic
/// envelope constant shared by every sealed `CotFrame` payload kind.
pub const NONCE_LEN: usize = 12;

/// AES-GCM authentication-tag length in bytes (128-bit).
pub const TAG_LEN: usize = 16;

/// Domain-separation tag bound as AEAD additional-authenticated-data for the
/// signed circle-message seal. `.../v2` marks the signed shape (the pre-merge
/// unsigned `.../v1` seal can never open under this), and it is DISTINCT from
/// [`crate::public_room::ROOM_MESSAGE_AAD`] so a circle-sealed message can never
/// be opened/confused as a public-room one even under a coincidentally-equal key.
pub const MESSAGE_AAD: &[u8] = b"daemonseed/circle/message/v2";

/// Domain-separation prefix for the circle provenance signature's signed input
/// (ISC-C57). DISTINCT from [`crate::public_room::ROOM_PROVENANCE_DOMAIN`], so a
/// circle signature can never be replayed as a public-room signature — the
/// load-bearing detail that makes one shared seal/open helper safe.
pub const CIRCLE_PROVENANCE_DOMAIN: &[u8] = b"daemonseed/circle/message/v2";

/// Seal a signed circle chat message under `cot_key` into an opaque
/// `nonce ‖ ciphertext ‖ tag` envelope for a `CotFrame.payload`.
///
/// `sender` is the poster's OWN identity keypair — the ML-DSA-87 signature
/// establishes authorship. The bound `room_id` is [`circle_room_id`] of the key.
pub fn seal_message(
    cot_key: &CircleKey,
    sender: &SignKeypair,
    sender_handle: &str,
    body: &str,
    sent_unix_ms: i64,
) -> Result<Vec<u8>, MessageError> {
    let room_id = circle_room_id(cot_key);
    seal_signed_room_message(
        cot_key,
        MESSAGE_AAD,
        CIRCLE_PROVENANCE_DOMAIN,
        sender,
        &room_id,
        sender_handle,
        body,
        sent_unix_ms,
    )
}

/// Open + VERIFY a sealed circle message produced by [`seal_message`] back into
/// a verified [`wire::RoomMessage`]. Fails closed: a wrong key or tamper surfaces
/// as [`MessageError::Authentication`]; an absent/bad signature or a message
/// signed for a different circle surfaces as [`MessageError::Provenance`]. The
/// expected `room_id` is recomputed from `cot_key`, never trusted from the wire.
pub fn open_message(cot_key: &CircleKey, sealed: &[u8]) -> Result<wire::RoomMessage, MessageError> {
    let room_id = circle_room_id(cot_key);
    open_signed_room_message(
        cot_key,
        MESSAGE_AAD,
        CIRCLE_PROVENANCE_DOMAIN,
        sealed,
        &room_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circle::key::{EXAMPLE_ENTROPY, derive_cot_key};
    use crate::crypto::suite::CNSA_2_0;

    fn key(phrase: &str) -> CircleKey {
        let _ = oxicrypt_module::initialize();
        derive_cot_key(phrase, &CNSA_2_0).unwrap()
    }

    fn sender(seed: u8) -> SignKeypair {
        let _ = oxicrypt_module::initialize();
        SignKeypair::from_ml_dsa_seed(&[seed; 32]).unwrap()
    }

    /// A signed message sealed and opened under the same circle key round-trips
    /// and verifies (ISC-10): two members sharing a phrase exchange authenticated
    /// chat.
    #[test]
    fn seal_open_round_trip_verifies() {
        let k = key(EXAMPLE_ENTROPY);
        let s = sender(1);
        let sealed = seal_message(
            &k,
            &s,
            "river-otter#aabbccddeeff",
            "hello circle",
            1_700_000_000_000,
        )
        .unwrap();
        let opened = open_message(&k, &sealed).unwrap();
        assert_eq!(opened.body, "hello circle");
        assert_eq!(opened.sender_pubkey, s.public_key().to_vec());
        assert_eq!(opened.sender_handle, "river-otter#aabbccddeeff");
    }

    /// Each seal draws a fresh nonce, so sealing the same message twice yields
    /// distinct ciphertext — no deterministic-encryption leak — and both open.
    #[test]
    fn nonce_is_per_message_random() {
        let k = key(EXAMPLE_ENTROPY);
        let s = sender(2);
        let one = seal_message(&k, &s, "a#000000000000", "same body", 1).unwrap();
        let two = seal_message(&k, &s, "a#000000000000", "same body", 1).unwrap();
        assert_ne!(one, two, "fresh nonce per seal");
        assert_eq!(
            open_message(&k, &one).unwrap().body,
            open_message(&k, &two).unwrap().body
        );
    }

    /// A non-member (different phrase → different key) cannot open the envelope:
    /// it fails closed with `Authentication` (ISC-A-S2 — the relay, holding only
    /// ciphertext, is in exactly this position).
    #[test]
    fn wrong_key_fails_authentication() {
        let member = key(EXAMPLE_ENTROPY);
        let outsider = key("a completely different circle phrase");
        let s = sender(3);
        let sealed = seal_message(&member, &s, "a#000000000000", "secret", 1).unwrap();
        match open_message(&outsider, &sealed) {
            Err(MessageError::Authentication) => {}
            other => panic!("expected Authentication, got {other:?}"),
        }
    }

    /// A single flipped ciphertext bit fails authentication (GCM integrity).
    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let k = key(EXAMPLE_ENTROPY);
        let s = sender(4);
        let mut sealed = seal_message(&k, &s, "a#000000000000", "intact", 1).unwrap();
        let last = sealed.len() - TAG_LEN - 1;
        sealed[last] ^= 0x01;
        match open_message(&k, &sealed) {
            Err(MessageError::Authentication) => {}
            other => panic!("expected Authentication, got {other:?}"),
        }
    }

    /// A buffer too short to hold `nonce ‖ tag` is rejected as truncated, not
    /// passed to the AEAD.
    #[test]
    fn truncated_envelope_rejected() {
        let k = key(EXAMPLE_ENTROPY);
        let short = vec![0u8; NONCE_LEN + TAG_LEN - 1];
        match open_message(&k, &short) {
            Err(MessageError::Truncated) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }
}
