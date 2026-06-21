//! Circle chat-message sealing (ISC-10..14 / ISC-C15 / ISC-C17 / ISC-A-S2).
//!
//! A circle chat message travels inside a `CotFrame.payload` on the live relay.
//! The relay is a structurally-blind forwarder: it routes by the opaque
//! rendezvous address and never sees plaintext (ISC-A-S2). This module is that
//! blindness made real — the boundary where a plaintext
//! [`wire::CircleMessage`] becomes opaque bytes and back:
//!
//! ```text
//!   CircleMessage  ──prost──▶  plaintext  ──AES-256-GCM(cot_key)──▶  sealed
//!   sealed         = nonce(12) ‖ ciphertext ‖ tag(16)
//! ```
//!
//! - **Keyed by the circle secret.** The AEAD key *is* the 32-byte `cot_key`
//!   ([`CircleKey`], derived from the shared phrase). Only a circle member can
//!   seal or open a message; the relay and any non-member see indistinguishable
//!   ciphertext. AES-256-GCM matches the CNSA-2.0 AEAD and the 32-byte key.
//! - **Per-message random nonce.** A fresh 96-bit nonce per [`seal_message`]
//!   call, prepended to the output. AES-GCM with random nonces is safe well
//!   past any realistic per-circle message volume.
//! - **Domain-separated AAD.** [`MESSAGE_AAD`] is bound as additional
//!   authenticated data so a `cot_key`-sealed chat message can never be
//!   confused with, or substituted from, another use of the same key.
//! - **Authenticated, fail-closed.** A wrong key, a truncated buffer, a flipped
//!   bit, or a swapped nonce all surface as [`MessageError::Authentication`]
//!   with no detail about which check failed.
//!
//! The `sender_handle` inside the message is *self-asserted* (a member can
//! claim any handle): circle membership is the trust boundary, not per-message
//! authorship. Recipients use that handle CLIENT-SIDE only — for @mention
//! highlighting (ISC-C17) and mute suppression (ISC-C15) — neither of which the
//! relay can observe (ISC-A-C3 / ISC-A-C4).

use daemonseed_proto::v1 as wire;
use oxicrypt_aes::{Aes256Key, ModeError, gcm_decrypt, gcm_encrypt};
use oxicrypt_module::Error as OxicryptError;
use prost::Message;
use zeroize::Zeroize;

use crate::circle::key::CircleKey;

/// AES-GCM nonce length in bytes (96-bit, the GCM-canonical size).
pub const NONCE_LEN: usize = 12;

/// AES-GCM authentication-tag length in bytes (128-bit).
pub const TAG_LEN: usize = 16;

/// Domain-separation tag bound as AEAD additional-authenticated-data, so a
/// `cot_key`-sealed chat message cannot be confused with another use of the
/// same key. Versioned so a future payload type can take a distinct tag.
pub const MESSAGE_AAD: &[u8] = b"daemonseed/circle/message/v1";

/// Failure modes for [`seal_message`] / [`open_message`].
#[derive(Debug)]
pub enum MessageError {
    /// The AES-256 key schedule failed to initialise (crypto module not yet
    /// powered up). Unreachable once any prior crypto op has run in-process.
    KeyInit(OxicryptError),
    /// The OS entropy source failed while drawing a nonce.
    EntropySource(getrandom::Error),
    /// A non-`TagMismatch` AEAD mode error (e.g. an internal length invariant).
    Aead(ModeError),
    /// Authentication failed: wrong `cot_key`, tampered ciphertext, swapped
    /// nonce, or wrong AAD. Deliberately carries no sub-cause.
    Authentication,
    /// The sealed buffer is shorter than `nonce ‖ tag` — not a valid envelope.
    Truncated,
    /// The decrypted bytes did not decode as a [`wire::CircleMessage`].
    Decode(prost::DecodeError),
}

impl core::fmt::Display for MessageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::KeyInit(e) => write!(f, "circle-message AES key init failed: {e}"),
            Self::EntropySource(e) => write!(f, "circle-message nonce entropy failed: {e}"),
            Self::Aead(e) => write!(f, "circle-message AEAD error: {e:?}"),
            Self::Authentication => write!(f, "circle-message authentication failed"),
            Self::Truncated => write!(f, "circle-message envelope is truncated"),
            Self::Decode(e) => write!(f, "circle-message decode failed: {e}"),
        }
    }
}

impl core::error::Error for MessageError {}

/// Seal a plaintext [`wire::CircleMessage`] under `cot_key` into an opaque
/// `nonce ‖ ciphertext ‖ tag` envelope suitable for a `CotFrame.payload`.
///
/// The prost-encoded plaintext is zeroed the moment GCM has consumed it.
pub fn seal_message(
    cot_key: &CircleKey,
    message: &wire::CircleMessage,
) -> Result<Vec<u8>, MessageError> {
    let aes = Aes256Key::new(cot_key.as_bytes()).map_err(MessageError::KeyInit)?;

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(MessageError::EntropySource)?;

    let mut plaintext = message.encode_to_vec();

    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = [0u8; TAG_LEN];
    let result = gcm_encrypt(
        &aes,
        &nonce,
        MESSAGE_AAD,
        &plaintext,
        &mut ciphertext,
        &mut tag,
    );
    plaintext.zeroize();
    result.map_err(MessageError::Aead)?;

    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len() + TAG_LEN);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    sealed.extend_from_slice(&tag);
    Ok(sealed)
}

/// Open a sealed envelope produced by [`seal_message`] back into a
/// [`wire::CircleMessage`]. Fails closed: a wrong key or any tamper surfaces as
/// [`MessageError::Authentication`].
///
/// The recovered plaintext bytes are zeroed before returning the decoded
/// message (the decoded `String` fields are the rendered surface; the raw
/// buffer is secret-adjacent).
pub fn open_message(
    cot_key: &CircleKey,
    sealed: &[u8],
) -> Result<wire::CircleMessage, MessageError> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(MessageError::Truncated);
    }
    let nonce: &[u8; NONCE_LEN] = sealed[..NONCE_LEN].try_into().expect("checked length");
    let after_nonce = &sealed[NONCE_LEN..];
    let ciphertext_len = after_nonce.len() - TAG_LEN;
    let ciphertext = &after_nonce[..ciphertext_len];
    let tag: &[u8; TAG_LEN] = after_nonce[ciphertext_len..]
        .try_into()
        .expect("checked length");

    let aes = Aes256Key::new(cot_key.as_bytes()).map_err(MessageError::KeyInit)?;

    let mut plaintext = vec![0u8; ciphertext_len];
    gcm_decrypt(&aes, nonce, MESSAGE_AAD, ciphertext, tag, &mut plaintext).map_err(
        |e| match e {
            ModeError::TagMismatch => MessageError::Authentication,
            other => MessageError::Aead(other),
        },
    )?;

    let decoded = wire::CircleMessage::decode(plaintext.as_slice());
    plaintext.zeroize();
    decoded.map_err(MessageError::Decode)
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

    fn msg(handle: &str, body: &str) -> wire::CircleMessage {
        wire::CircleMessage {
            sender_handle: handle.to_owned(),
            body: body.to_owned(),
            sent_unix_ms: 1_700_000_000_000,
        }
    }

    /// A message sealed and opened under the same circle key round-trips
    /// byte-for-byte (ISC-10): two members sharing a phrase exchange chat.
    #[test]
    fn seal_open_round_trip() {
        let k = key(EXAMPLE_ENTROPY);
        let original = msg("river-otter#aabbccddeeff", "hello circle");
        let sealed = seal_message(&k, &original).unwrap();
        let opened = open_message(&k, &sealed).unwrap();
        assert_eq!(opened, original);
    }

    /// The envelope shape is `nonce ‖ ciphertext ‖ tag` — the ciphertext length
    /// equals the prost plaintext length (GCM is a stream cipher core).
    #[test]
    fn envelope_layout_is_nonce_ciphertext_tag() {
        let k = key(EXAMPLE_ENTROPY);
        let m = msg("a#000000000000", "x");
        let plaintext_len = m.encode_to_vec().len();
        let sealed = seal_message(&k, &m).unwrap();
        assert_eq!(sealed.len(), NONCE_LEN + plaintext_len + TAG_LEN);
    }

    /// Each seal draws a fresh nonce, so sealing the same message twice yields
    /// distinct ciphertext — no deterministic-encryption leak.
    #[test]
    fn nonce_is_per_message_random() {
        let k = key(EXAMPLE_ENTROPY);
        let m = msg("a#000000000000", "same body");
        let one = seal_message(&k, &m).unwrap();
        let two = seal_message(&k, &m).unwrap();
        assert_ne!(one, two, "fresh nonce per seal");
        // But both open to the same plaintext.
        assert_eq!(
            open_message(&k, &one).unwrap(),
            open_message(&k, &two).unwrap()
        );
    }

    /// A non-member (different phrase → different key) cannot open the
    /// envelope: it fails closed with `Authentication` (ISC-A-S2 — the relay,
    /// holding only ciphertext, is in exactly this position).
    #[test]
    fn wrong_key_fails_authentication() {
        let member = key(EXAMPLE_ENTROPY);
        let outsider = key("a completely different circle phrase");
        let sealed = seal_message(&member, &msg("a#000000000000", "secret")).unwrap();
        match open_message(&outsider, &sealed) {
            Err(MessageError::Authentication) => {}
            other => panic!("expected Authentication, got {other:?}"),
        }
    }

    /// A single flipped ciphertext bit fails authentication (GCM integrity).
    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let k = key(EXAMPLE_ENTROPY);
        let mut sealed = seal_message(&k, &msg("a#000000000000", "intact")).unwrap();
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
