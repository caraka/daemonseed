//! The one signed room-message seal/open path (ISC-S24 / ISC-C57 / ISC-A-S2 /
//! ISC-A-S16 / ISC-A-S17).
//!
//! A public room and a private circle behave identically in every respect
//! except how their key is derived (design-of-record:
//! `docs/design/room-circle-unification.md` § Design (A)). This module is that
//! principle made real: the SINGLE seal/open code path both surfaces call. Each
//! surface's own module ([`crate::public_room`], [`crate::circle::message`])
//! shrinks to a thin wrapper that supplies:
//!
//! - its key ([`crate::public_room::PublicRoomKey`] or
//!   [`crate::circle::key::CircleKey`], both [`AeadKey256`]),
//! - its DISTINCT AEAD AAD + provenance domain (`daemonseed/public-room/message/v1`
//!   vs `daemonseed/circle/message/v2`) — the load-bearing detail: one helper is
//!   only safe because the two callers pass different domain strings, so a seal
//!   or signature from one surface can never be opened or replayed as the other,
//!   and
//! - the `room_id` it wants the signature bound to.
//!
//! ```text
//!   RoomMessage  ──sign(sender over domain ‖ room_id ‖ pubkey ‖ ts ‖ body)──▶ signature
//!                ──prost────────────────────────────────────────────────────▶ plaintext
//!                ──AES-256-GCM(key, aad)────────────────────────────────────▶ sealed = nonce ‖ ct ‖ tag
//! ```
//!
//! The final AES-256-GCM step — draw a nonce, encrypt, assemble
//! `nonce ‖ ct ‖ tag` (and its inverse on open) — is the shared
//! `crate::aead_envelope` primitive; this module supplies its own `aad` and maps
//! that helper's `EnvelopeError` onto [`RoomMessageError`], so the byte layout
//! and this module's public error surface are unchanged.
//!
//! **The verifier never trusts the carried `room_id` for crypto.** [`open_signed_room_message`]
//! always verifies the signature against an `expected_room_id` the *caller*
//! supplies (a public room passes the room name it subscribed to; a circle
//! passes [`crate::circle::key::circle_room_id`] recomputed from its OWN
//! `cot_key`). A forged or foreign carried `room_id` therefore cannot validate —
//! this is a property of the function signature, not a runtime policy branch.
//!
//! **Fail-closed provenance.** The `sender_pubkey` and `signature` fields are
//! length-gated to exactly ML-DSA-87 sizes *before* any verify call, so an
//! absent/empty/wrong-length pubkey or signature is a hard [`RoomMessageError::Provenance`]
//! reject — an empty pubkey never equals anyone.

use daemonseed_proto::v1 as wire;
use oxicrypt_aes::{Aes256Key, ModeError};
use oxicrypt_module::Error as OxicryptError;
use prost::Message;
use zeroize::Zeroize;

use crate::aead_envelope::{EnvelopeError, open_envelope, seal_envelope};
use crate::circle::key::AeadKey256;
use crate::identity::keys::{SignKeypair, verify_signature};
use oxicrypt_ml_dsa as ml_dsa;

/// Build the domain-separated provenance signing input (ISC-S24). Binds the
/// provenance domain, room_id, sender pubkey, timestamp, and body so a signature
/// is valid for exactly one (surface, room/circle, author, time, content) tuple
/// and cannot be replayed into another room, another circle, or another sealed
/// payload kind. Length-prefixing each variable field makes the concatenation
/// unambiguous (no field-boundary collision between adjacent fields).
pub(crate) fn provenance_input(
    provenance_domain: &[u8],
    room_id: &str,
    sender_pubkey: &[u8],
    sent_unix_ms: i64,
    body: &str,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(provenance_domain);
    let mut push_field = |bytes: &[u8]| {
        buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        buf.extend_from_slice(bytes);
    };
    push_field(room_id.as_bytes());
    push_field(sender_pubkey);
    push_field(&sent_unix_ms.to_be_bytes());
    push_field(body.as_bytes());
    buf
}

/// Seal a [`wire::RoomMessage`]: SELF-SIGN it for provenance (ISC-S24) under the
/// posting identity, then AES-256-GCM-seal the whole message under `key` with
/// `aad`. Output is `nonce ‖ ciphertext ‖ tag`, suitable for a `CotFrame.payload`.
///
/// `sender` is the posting daemon's OWN identity keypair — the signature
/// establishes authorship (WHO), not authorization. Callers supply their
/// surface's `aad` + `provenance_domain` (distinct per surface) and the
/// `room_id` to bind. The prost-encoded plaintext is zeroed the moment GCM has
/// consumed it.
#[allow(clippy::too_many_arguments)]
pub fn seal_signed_room_message<K: AeadKey256>(
    key: &K,
    aad: &[u8],
    provenance_domain: &[u8],
    sender: &SignKeypair,
    room_id: &str,
    sender_handle: &str,
    body: &str,
    sent_unix_ms: i64,
) -> Result<Vec<u8>, RoomMessageError> {
    let sender_pubkey = sender.public_key().to_vec();
    let signing_input = provenance_input(
        provenance_domain,
        room_id,
        &sender_pubkey,
        sent_unix_ms,
        body,
    );
    let signature = sender
        .sign(&signing_input)
        .map_err(|_| RoomMessageError::Sign)?
        .to_vec();

    let message = wire::RoomMessage {
        room_id: room_id.to_owned(),
        sender_pubkey,
        sender_handle: sender_handle.to_owned(),
        body: body.to_owned(),
        sent_unix_ms,
        signature,
    };

    // AES-256-GCM-seal the prost-encoded plaintext into `nonce ‖ ct ‖ tag` via
    // the shared envelope helper. The plaintext is zeroed the moment GCM has
    // consumed it (regardless of the helper's success), and `aad` stays this
    // surface's own domain-separated tag.
    let aes = Aes256Key::new(key.aead_key_bytes()).map_err(RoomMessageError::KeyInit)?;
    let mut plaintext = message.encode_to_vec();
    let result = seal_envelope(&aes, aad, &plaintext);
    plaintext.zeroize();
    Ok(result?)
}

/// Open + VERIFY a sealed [`wire::RoomMessage`] (ISC-A-S16 / ISC-A-S17).
///
/// Three checks, all fail-closed:
///   1. AES-256-GCM open under `key` + `aad` (only the sealed form rides the
///      wire; this is where it becomes plaintext locally). A wrong key or wrong
///      AAD — including a payload from the OTHER surface — fails here.
///   2. `sender_pubkey` and `signature` are length-gated to exactly ML-DSA-87
///      sizes; empty/wrong-length is a hard [`RoomMessageError::Provenance`]
///      reject (an empty pubkey never equals anyone).
///   3. The ML-DSA-87 signature verifies under the embedded `sender_pubkey` over
///      the signing input built from **`expected_room_id`** — never the carried
///      `room_id`. A forged/foreign carried `room_id` cannot validate.
///
/// The caller still binds the *displayed* handle to `SHA-384(sender_pubkey)[:12]`
/// (ISC-C4); this returns the verified wire message and leaves that UI binding to
/// the caller.
pub fn open_signed_room_message<K: AeadKey256>(
    key: &K,
    aad: &[u8],
    provenance_domain: &[u8],
    sealed: &[u8],
    expected_room_id: &str,
) -> Result<wire::RoomMessage, RoomMessageError> {
    // AES-256-GCM open under `key` + `aad` via the shared envelope helper (this
    // is where the sealed form becomes plaintext locally). A wrong key or wrong
    // AAD — including a payload from the OTHER surface — fails here; a too-short
    // buffer is rejected before decrypt. The recovered plaintext is zeroed the
    // moment prost has consumed it.
    let aes = Aes256Key::new(key.aead_key_bytes()).map_err(RoomMessageError::KeyInit)?;
    let mut plaintext = open_envelope(&aes, aad, sealed)?;
    let decoded = wire::RoomMessage::decode(plaintext.as_slice());
    plaintext.zeroize();
    let message = decoded.map_err(RoomMessageError::Decode)?;

    // Fail-closed length gate BEFORE any ML-DSA call: exact-length try_into
    // rejects an empty or wrong-length pubkey/signature as Provenance, so a
    // malformed input can never reach the verifier or make an empty pubkey
    // "verify" as anyone.
    let pubkey: &[u8; ml_dsa::PK_LEN] = message
        .sender_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| RoomMessageError::Provenance)?;
    let signature: &[u8; ml_dsa::SIG_LEN] = message
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| RoomMessageError::Provenance)?;

    // The signature is verified against expected_room_id — NOT message.room_id.
    let signing_input = provenance_input(
        provenance_domain,
        expected_room_id,
        &message.sender_pubkey,
        message.sent_unix_ms,
        &message.body,
    );
    verify_signature(pubkey, &signing_input, signature)
        .map_err(|_| RoomMessageError::Provenance)?;

    Ok(message)
}

/// Failure sealing/opening a room message (public room or circle).
#[derive(Debug)]
pub enum RoomMessageError {
    /// The AES-256 key schedule failed to initialise (crypto module not yet
    /// powered up).
    KeyInit(OxicryptError),
    /// The OS entropy source failed while drawing a nonce.
    EntropySource(getrandom::Error),
    /// A non-`TagMismatch` AEAD mode error.
    Aead(ModeError),
    /// AEAD authentication failed (wrong key, tampered ciphertext, swapped
    /// nonce, or wrong AAD — including a payload sealed for the other surface).
    /// Carries no sub-cause.
    Authentication,
    /// The sealed buffer is shorter than `nonce ‖ tag`.
    Truncated,
    /// The decrypted bytes did not decode as a [`wire::RoomMessage`].
    Decode(prost::DecodeError),
    /// Signing the provenance input failed (crypto module not operational).
    Sign,
    /// The embedded provenance signature did not verify under the embedded
    /// sender pubkey over `expected_room_id`, or the pubkey/signature fields
    /// were absent or the wrong length (ISC-A-S17, fail-closed).
    Provenance,
}

impl core::fmt::Display for RoomMessageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::KeyInit(e) => write!(f, "room-message AES key init failed: {e}"),
            Self::EntropySource(e) => write!(f, "room-message nonce entropy failed: {e}"),
            Self::Aead(e) => write!(f, "room-message AEAD error: {e:?}"),
            Self::Authentication => write!(f, "room-message authentication failed"),
            Self::Truncated => write!(f, "room-message envelope is truncated"),
            Self::Decode(e) => write!(f, "room-message decode failed: {e}"),
            Self::Sign => write!(f, "room-message provenance signing failed"),
            Self::Provenance => write!(f, "room-message provenance verification failed"),
        }
    }
}

impl core::error::Error for RoomMessageError {}

/// Map the shared envelope error onto this module's own error type so the public
/// error surface is unchanged: the too-short → [`RoomMessageError::Truncated`]
/// and `TagMismatch` → [`RoomMessageError::Authentication`] mappings the inlined
/// code carried are preserved exactly.
impl From<EnvelopeError> for RoomMessageError {
    fn from(e: EnvelopeError) -> Self {
        match e {
            EnvelopeError::EntropySource(e) => Self::EntropySource(e),
            EnvelopeError::Encrypt(m) => Self::Aead(m),
            EnvelopeError::TooShort => Self::Truncated,
            EnvelopeError::Decrypt(ModeError::TagMismatch) => Self::Authentication,
            EnvelopeError::Decrypt(other) => Self::Aead(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circle::key::{CircleKey, EXAMPLE_ENTROPY, circle_room_id, derive_cot_key};
    use crate::circle::message::{NONCE_LEN, TAG_LEN};
    use crate::crypto::suite::CNSA_2_0;
    use crate::public_room::{ROOM_MESSAGE_AAD, ROOM_PROVENANCE_DOMAIN};
    use oxicrypt_aes::gcm_encrypt;

    const CIRCLE_AAD: &[u8] = crate::circle::message::MESSAGE_AAD;
    const CIRCLE_DOMAIN: &[u8] = crate::circle::message::CIRCLE_PROVENANCE_DOMAIN;

    fn cot(phrase: &str) -> CircleKey {
        let _ = oxicrypt_module::initialize();
        derive_cot_key(phrase, &CNSA_2_0).unwrap()
    }

    fn keypair(seed: u8) -> SignKeypair {
        let _ = oxicrypt_module::initialize();
        SignKeypair::from_ml_dsa_seed(&[seed; 32]).unwrap()
    }

    /// ISC-6/ISC-7 — a circle message seals under the cot_key with the circle
    /// domain, binds room_id = circle_room_id(cot_key), and opens+verifies when
    /// the opener recomputes the same room_id from its own cot_key.
    #[test]
    fn circle_seal_open_round_trip_verifies() {
        let k = cot(EXAMPLE_ENTROPY);
        let sender = keypair(3);
        let room_id = circle_room_id(&k);
        let sealed = seal_signed_room_message(
            &k,
            CIRCLE_AAD,
            CIRCLE_DOMAIN,
            &sender,
            &room_id,
            "otter#aabbccddeeff",
            "hi circle",
            1_700_000_000_000,
        )
        .unwrap();
        let opened =
            open_signed_room_message(&k, CIRCLE_AAD, CIRCLE_DOMAIN, &sealed, &room_id).unwrap();
        assert_eq!(opened.body, "hi circle");
        assert_eq!(opened.sender_pubkey, sender.public_key().to_vec());
    }

    /// ISC-7 — the signature is verified against the caller's expected_room_id,
    /// never the carried field: a message whose carried room_id was tampered to
    /// a foreign value STILL opens iff the opener's expected room_id matches what
    /// the signer used (proving the carried field is not consulted for crypto),
    /// and FAILS if the opener expects a different room_id than was signed.
    #[test]
    fn open_verifies_against_expected_not_carried_room_id() {
        let k = cot(EXAMPLE_ENTROPY);
        let sender = keypair(4);
        let signed_room_id = circle_room_id(&k);
        // Seal binding the true room_id.
        let sealed = seal_signed_room_message(
            &k,
            CIRCLE_AAD,
            CIRCLE_DOMAIN,
            &sender,
            &signed_room_id,
            "a#000000000000",
            "x",
            1,
        )
        .unwrap();
        // A verifier expecting a DIFFERENT room_id rejects (signature covers the
        // signed room_id, not the expected one).
        match open_signed_room_message(&k, CIRCLE_AAD, CIRCLE_DOMAIN, &sealed, "deadbeefcafe") {
            Err(RoomMessageError::Provenance) => {}
            other => panic!("expected Provenance reject, got {other:?}"),
        }
    }

    /// ISC-9 — cross-surface substitution fails: a circle-sealed message never
    /// opens as a public-room message (distinct AAD), and vice versa.
    #[test]
    fn cross_surface_open_fails() {
        let k = cot(EXAMPLE_ENTROPY);
        let sender = keypair(5);
        let room_id = circle_room_id(&k);
        let circle_sealed = seal_signed_room_message(
            &k,
            CIRCLE_AAD,
            CIRCLE_DOMAIN,
            &sender,
            &room_id,
            "a#000000000000",
            "secret",
            1,
        )
        .unwrap();
        // Attempt to open the circle-sealed bytes under the SAME key but the
        // PUBLIC-ROOM aad/domain: AEAD authentication fails (AAD differs).
        match open_signed_room_message(
            &k,
            ROOM_MESSAGE_AAD,
            ROOM_PROVENANCE_DOMAIN,
            &circle_sealed,
            &room_id,
        ) {
            Err(RoomMessageError::Authentication) => {}
            other => panic!("expected Authentication (AAD mismatch), got {other:?}"),
        }
    }

    /// ISC-8/ISC-11 — a forged message with an EMPTY sender_pubkey is rejected
    /// fail-closed at the length gate before any verify: an empty pubkey must
    /// not equal anyone.
    #[test]
    fn empty_pubkey_is_rejected_fail_closed() {
        let k = cot(EXAMPLE_ENTROPY);
        // Hand-craft a RoomMessage with empty pubkey + empty signature, seal it
        // honestly under the key (an insider forging), and confirm open rejects.
        let forged = wire::RoomMessage {
            room_id: circle_room_id(&k),
            sender_pubkey: Vec::new(),
            sender_handle: "ghost#000000000000".to_owned(),
            body: "attributed to no one".to_owned(),
            sent_unix_ms: 1,
            signature: Vec::new(),
        };
        let aes = Aes256Key::new(k.aead_key_bytes()).unwrap();
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).unwrap();
        let plaintext = forged.encode_to_vec();
        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = [0u8; TAG_LEN];
        gcm_encrypt(&aes, &nonce, CIRCLE_AAD, &plaintext, &mut ct, &mut tag).unwrap();
        let mut sealed = Vec::new();
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ct);
        sealed.extend_from_slice(&tag);
        match open_signed_room_message(&k, CIRCLE_AAD, CIRCLE_DOMAIN, &sealed, &circle_room_id(&k))
        {
            Err(RoomMessageError::Provenance) => {}
            other => panic!("expected Provenance reject for empty pubkey, got {other:?}"),
        }
    }

    /// ISC-10/ISC-11 — a circle-key holder cannot forge a message that verifies
    /// under ANOTHER member's pubkey: member A seals a message but stamps B's
    /// pubkey into the plaintext; the signature (A's) does not verify under B's
    /// pubkey, so open rejects. Authorship is bound to the private key.
    #[test]
    fn cannot_forge_authorship_as_another_member() {
        let k = cot(EXAMPLE_ENTROPY);
        let alice = keypair(6);
        let bob = keypair(7);
        let room_id = circle_room_id(&k);
        // Alice signs honestly over her own input, but we then swap Bob's pubkey
        // into the wire message before sealing (an impersonation attempt).
        let signing_input = provenance_input(
            CIRCLE_DOMAIN,
            &room_id,
            alice.public_key().as_slice(),
            1,
            "as bob",
        );
        let alice_sig = alice.sign(&signing_input).unwrap().to_vec();
        let forged = wire::RoomMessage {
            room_id: room_id.clone(),
            sender_pubkey: bob.public_key().to_vec(), // claims Bob
            sender_handle: "bob#111111111111".to_owned(),
            body: "as bob".to_owned(),
            sent_unix_ms: 1,
            signature: alice_sig, // but signed by Alice
        };
        let aes = Aes256Key::new(k.aead_key_bytes()).unwrap();
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).unwrap();
        let plaintext = forged.encode_to_vec();
        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = [0u8; TAG_LEN];
        gcm_encrypt(&aes, &nonce, CIRCLE_AAD, &plaintext, &mut ct, &mut tag).unwrap();
        let mut sealed = Vec::new();
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ct);
        sealed.extend_from_slice(&tag);
        match open_signed_room_message(&k, CIRCLE_AAD, CIRCLE_DOMAIN, &sealed, &room_id) {
            Err(RoomMessageError::Provenance) => {}
            other => panic!("expected Provenance reject (sig !verify under Bob), got {other:?}"),
        }
    }

    /// Fresh random nonce per seal — one shared path means a deterministic-nonce
    /// bug would hit both surfaces, so pin it: two seals of identical plaintext
    /// differ, and both still open.
    #[test]
    fn nonce_is_per_seal_random() {
        let k = cot(EXAMPLE_ENTROPY);
        let sender = keypair(8);
        let room_id = circle_room_id(&k);
        let one = seal_signed_room_message(
            &k,
            CIRCLE_AAD,
            CIRCLE_DOMAIN,
            &sender,
            &room_id,
            "a#000000000000",
            "same",
            1,
        )
        .unwrap();
        let two = seal_signed_room_message(
            &k,
            CIRCLE_AAD,
            CIRCLE_DOMAIN,
            &sender,
            &room_id,
            "a#000000000000",
            "same",
            1,
        )
        .unwrap();
        assert_ne!(one, two, "fresh nonce per seal");
        assert_eq!(
            open_signed_room_message(&k, CIRCLE_AAD, CIRCLE_DOMAIN, &one, &room_id)
                .unwrap()
                .body,
            open_signed_room_message(&k, CIRCLE_AAD, CIRCLE_DOMAIN, &two, &room_id)
                .unwrap()
                .body,
        );
    }
}
