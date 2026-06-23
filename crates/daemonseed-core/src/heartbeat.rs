//! Member-plane connected-presence heartbeat sealing (presence superstructure;
//! design-of-record: `docs/design/presence-superstructure.md`).
//!
//! A [`wire::MemberHeartbeat`] is the member-plane presence beacon: every
//! connected member periodically posts a sealed, self-signed heartbeat into each
//! room/circle it is subscribed to, as a `CotFrame.payload` at that room's
//! rendezvous address, so members can see *who* is online while the relay stays
//! blind. It is the member-plane counterpart to the relay-plane
//! subscription-refcount presence (ISC-S20): the relay knows an address has live
//! subscribers but never their identities; this beacon carries the member's
//! presence INSIDE the seal, where only room members can read it.
//!
//! ```text
//!   MemberHeartbeat ──sign(member)────▶  signature
//!                   ──prost────────────▶  plaintext
//!                   ──AES-256-GCM(key)─▶  sealed = nonce(12) ‖ ct ‖ tag(16)
//! ```
//!
//! This module is the presence-tier analogue of [`crate::share_announce`] and
//! reuses its exact envelope shape, with the same two tier choices:
//!
//! - **Which key seals it.** A *public* heartbeat seals under the public room key
//!   ([`crate::public_room::derive_room_key`]); a *circle* heartbeat seals under
//!   the circle `cot_key` ([`crate::circle::key`]). The two are **distinct
//!   types** ([`PublicRoomKey`] vs [`CircleKey`]) so a seal cannot take the wrong
//!   tier's key — the key-class guard.
//! - **Provenance is always self-signed (ISC-C57).** Every heartbeat carries an
//!   ML-DSA-87 signature by the member's own identity over a domain-separated
//!   input binding room, member pubkey, and timestamp. [`open_heartbeat`]
//!   verifies it and returns the message only on success — a bad signature is
//!   dropped.
//!
//! A distinct AAD ([`HEARTBEAT_AAD`]) and provenance domain
//! ([`HEARTBEAT_PROVENANCE_DOMAIN`]) keep a heartbeat from ever being confused
//! with — or substituted from — a chat message, a public-room message, a share
//! announcement, or a roll-call, even under a coincidentally-equal key. The
//! sealed envelope is wire-shape-identical to those frames, so the heartbeat adds
//! no new distinguishable flow (ISC-A-S2 traffic-shape).
//!
//! The heartbeat carries ONLY the beacon's own presence assertion (its handle,
//! pubkey, and timestamp) — never a roster or a peer list (ISC-A-C38). The
//! receiver-side liveness view that ages members out is [`crate::presence`].

use daemonseed_proto::v1 as wire;
use oxicrypt_aes::{Aes256Key, ModeError, gcm_decrypt, gcm_encrypt};
use oxicrypt_module::Error as OxicryptError;
use prost::Message;
use zeroize::Zeroize;

use crate::circle::key::{AeadKey256, COT_KEY_LEN, CircleKey};
use crate::circle::message::{NONCE_LEN, TAG_LEN};
use crate::identity::keys::{SignKeypair, verify_signature};
use crate::public_room::PublicRoomKey;
use oxicrypt_ml_dsa as ml_dsa;

/// Domain-separation tag bound as AEAD additional-authenticated-data for the
/// heartbeat seal, distinct from every other sealed-frame AAD
/// ([`crate::circle::message::MESSAGE_AAD`], [`crate::public_room::ROOM_MESSAGE_AAD`],
/// [`crate::share_announce::SHARE_ANNOUNCE_AAD`],
/// [`crate::share_rollcall::SHARE_ROLLCALL_AAD`]) so a heartbeat can never be
/// opened/confused as any of them under an equal key.
pub const HEARTBEAT_AAD: &[u8] = b"daemonseed/presence/heartbeat/v1";

/// Domain-separation prefix for the heartbeat's provenance signature, bound first
/// so a heartbeat signature can never be replayed as any other ML-DSA-87
/// signature daemonseed produces.
pub const HEARTBEAT_PROVENANCE_DOMAIN: &[u8] = b"daemonseed/presence/heartbeat/v1";

/// The plaintext fields of a heartbeat the caller supplies; the member pubkey and
/// the signature are filled in by [`seal_public_heartbeat`] /
/// [`seal_circle_heartbeat`]. Borrowed so sealing never forces a clone.
pub struct HeartbeatFields<'a> {
    /// The room/circle the heartbeat belongs to (e.g. `"lobby"` for public).
    pub room: &'a str,
    /// The member's self-asserted display handle (`name#12hex`). Advisory.
    pub sender_handle: &'a str,
    /// Member wall-clock at beacon time, unix milliseconds (advisory ordering +
    /// liveness aging).
    pub sent_unix_ms: i64,
}

/// Build the domain-separated provenance signing input. Binds room, member
/// pubkey, and timestamp so a signature is valid for exactly one (room, member,
/// time) tuple and cannot be replayed into another room. Length-prefixing each
/// field makes the concatenation unambiguous.
fn provenance_input(room: &str, sender_pubkey: &[u8], sent_unix_ms: i64) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(HEARTBEAT_PROVENANCE_DOMAIN);
    let mut push_field = |bytes: &[u8]| {
        buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        buf.extend_from_slice(bytes);
    };
    push_field(room.as_bytes());
    push_field(sender_pubkey);
    push_field(&sent_unix_ms.to_be_bytes());
    buf
}

/// Seal a heartbeat for a PUBLIC room: SELF-SIGN it for provenance (ISC-C57),
/// then AES-256-GCM-seal the whole [`wire::MemberHeartbeat`] under the public
/// room key. The output is `nonce ‖ ciphertext ‖ tag` for a `CotFrame.payload`.
/// Taking a [`PublicRoomKey`] (never a [`CircleKey`]) is the key-class guard.
/// `member` is the posting daemon's OWN identity keypair.
pub fn seal_public_heartbeat(
    key: &PublicRoomKey,
    member: &SignKeypair,
    fields: &HeartbeatFields<'_>,
) -> Result<Vec<u8>, HeartbeatError> {
    seal_heartbeat_with(key.as_bytes(), member, fields)
}

/// Seal a heartbeat for a CIRCLE — as [`seal_public_heartbeat`] but under the
/// circle `cot_key`. Taking a [`CircleKey`] (never a [`PublicRoomKey`]) is the
/// key-class guard in the other direction.
pub fn seal_circle_heartbeat(
    key: &CircleKey,
    member: &SignKeypair,
    fields: &HeartbeatFields<'_>,
) -> Result<Vec<u8>, HeartbeatError> {
    seal_heartbeat_with(key.as_bytes(), member, fields)
}

/// Shared seal body, keyed by the raw 32-byte AEAD key the tier-split entry
/// points pass. Private, so the only public seal paths are the typed ones above.
fn seal_heartbeat_with(
    key_bytes: &[u8; COT_KEY_LEN],
    member: &SignKeypair,
    fields: &HeartbeatFields<'_>,
) -> Result<Vec<u8>, HeartbeatError> {
    let sender_pubkey = member.public_key().to_vec();
    let signing_input = provenance_input(fields.room, &sender_pubkey, fields.sent_unix_ms);
    let signature = member
        .sign(&signing_input)
        .map_err(|_| HeartbeatError::Sign)?
        .to_vec();

    let message = wire::MemberHeartbeat {
        room: fields.room.to_owned(),
        sender_pubkey,
        sender_handle: fields.sender_handle.to_owned(),
        sent_unix_ms: fields.sent_unix_ms,
        signature,
    };

    let aes = Aes256Key::new(key_bytes).map_err(HeartbeatError::KeyInit)?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(HeartbeatError::EntropySource)?;

    let mut plaintext = message.encode_to_vec();
    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = [0u8; TAG_LEN];
    let result = gcm_encrypt(
        &aes,
        &nonce,
        HEARTBEAT_AAD,
        &plaintext,
        &mut ciphertext,
        &mut tag,
    );
    plaintext.zeroize();
    result.map_err(HeartbeatError::Aead)?;

    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len() + TAG_LEN);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    sealed.extend_from_slice(&tag);
    Ok(sealed)
}

/// Open + VERIFY a sealed heartbeat (the presence-tier analogue of
/// [`crate::share_announce::open_announcement`]).
///
/// Two checks, both fail-closed:
///   1. AES-256-GCM open under `key` (only the sealed form ever rides the wire).
///   2. The embedded ML-DSA-87 provenance signature verifies under the embedded
///      `sender_pubkey` (ISC-C57). A bad signature is rejected — the heartbeat is
///      never surfaced unverified.
///
/// On success the recipient still must bind the *displayed* handle to
/// `SHA-384(sender_pubkey)[:12]` (ISC-C4 / ISC-C57); this function returns the
/// verified wire message and leaves that binding to the caller.
pub fn open_heartbeat<K: AeadKey256>(
    key: &K,
    sealed: &[u8],
) -> Result<wire::MemberHeartbeat, HeartbeatError> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(HeartbeatError::Truncated);
    }
    let nonce: &[u8; NONCE_LEN] = sealed[..NONCE_LEN].try_into().expect("checked length");
    let after_nonce = &sealed[NONCE_LEN..];
    let ciphertext_len = after_nonce.len() - TAG_LEN;
    let ciphertext = &after_nonce[..ciphertext_len];
    let tag: &[u8; TAG_LEN] = after_nonce[ciphertext_len..]
        .try_into()
        .expect("checked length");

    let aes = Aes256Key::new(key.aead_key_bytes()).map_err(HeartbeatError::KeyInit)?;
    let mut plaintext = vec![0u8; ciphertext_len];
    gcm_decrypt(&aes, nonce, HEARTBEAT_AAD, ciphertext, tag, &mut plaintext).map_err(
        |e| match e {
            ModeError::TagMismatch => HeartbeatError::Authentication,
            other => HeartbeatError::Aead(other),
        },
    )?;

    let decoded = wire::MemberHeartbeat::decode(plaintext.as_slice());
    plaintext.zeroize();
    let message = decoded.map_err(HeartbeatError::Decode)?;

    // Verify the self-signed provenance before returning (ISC-C57).
    let pubkey: &[u8; ml_dsa::PK_LEN] = message
        .sender_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| HeartbeatError::Provenance)?;
    let signature: &[u8; ml_dsa::SIG_LEN] = message
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| HeartbeatError::Provenance)?;
    let signing_input =
        provenance_input(&message.room, &message.sender_pubkey, message.sent_unix_ms);
    verify_signature(pubkey, &signing_input, signature).map_err(|_| HeartbeatError::Provenance)?;

    Ok(message)
}

/// Failure sealing/opening a heartbeat.
#[derive(Debug)]
pub enum HeartbeatError {
    /// The AES-256 key schedule failed to initialise.
    KeyInit(OxicryptError),
    /// The OS entropy source failed while drawing a nonce.
    EntropySource(getrandom::Error),
    /// A non-`TagMismatch` AEAD mode error.
    Aead(ModeError),
    /// AEAD authentication failed (wrong key, tampered ciphertext, swapped nonce,
    /// or wrong AAD). Carries no sub-cause.
    Authentication,
    /// The sealed buffer is shorter than `nonce ‖ tag`.
    Truncated,
    /// The decrypted bytes did not decode as a [`wire::MemberHeartbeat`].
    Decode(prost::DecodeError),
    /// Signing the provenance input failed (crypto module not operational).
    Sign,
    /// The embedded provenance signature did not verify under the embedded sender
    /// pubkey, or those fields were the wrong length.
    Provenance,
}

impl core::fmt::Display for HeartbeatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::KeyInit(e) => write!(f, "heartbeat AES key init failed: {e}"),
            Self::EntropySource(e) => write!(f, "heartbeat nonce entropy failed: {e}"),
            Self::Aead(e) => write!(f, "heartbeat AEAD error: {e:?}"),
            Self::Authentication => write!(f, "heartbeat authentication failed"),
            Self::Truncated => write!(f, "heartbeat envelope is truncated"),
            Self::Decode(e) => write!(f, "heartbeat decode failed: {e}"),
            Self::Sign => write!(f, "heartbeat provenance signing failed"),
            Self::Provenance => write!(f, "heartbeat provenance verification failed"),
        }
    }
}

impl core::error::Error for HeartbeatError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circle::key::{EXAMPLE_ENTROPY, derive_cot_key};
    use crate::crypto::suite::CNSA_2_0;
    use crate::identity::keys::SignKeypair;
    use crate::public_room::{DEFAULT_ROOM, derive_room_key};

    fn member(seed: u8) -> SignKeypair {
        let _ = oxicrypt_module::initialize();
        SignKeypair::from_ml_dsa_seed(&[seed; 32]).unwrap()
    }

    fn fields<'a>(handle: &'a str) -> HeartbeatFields<'a> {
        HeartbeatFields {
            room: DEFAULT_ROOM,
            sender_handle: handle,
            sent_unix_ms: 1_700_000_000_000,
        }
    }

    fn room_key(room: &str) -> PublicRoomKey {
        let _ = oxicrypt_module::initialize();
        derive_room_key(room, &CNSA_2_0).unwrap()
    }

    /// Round-trip under the PUBLIC room key: seal, open, and the embedded
    /// provenance verifies.
    #[test]
    fn seal_open_round_trip_public_verifies_provenance() {
        let key = room_key(DEFAULT_ROOM);
        let me = member(7);
        let sealed = seal_public_heartbeat(&key, &me, &fields("river-otter#aabbccddeeff")).unwrap();
        let opened = open_heartbeat(&key, &sealed).unwrap();
        assert_eq!(opened.room, DEFAULT_ROOM);
        assert_eq!(opened.sender_handle, "river-otter#aabbccddeeff");
        assert_eq!(opened.sender_pubkey, me.public_key().to_vec());
        assert_eq!(opened.sent_unix_ms, 1_700_000_000_000);
    }

    /// The same seal/open works under a CIRCLE key — the module is tier-agnostic;
    /// only the key (and thus who can open) differs.
    #[test]
    fn seal_open_round_trip_under_circle_key() {
        let _ = oxicrypt_module::initialize();
        let key = derive_cot_key(EXAMPLE_ENTROPY, &CNSA_2_0).unwrap();
        let me = member(8);
        let sealed = seal_circle_heartbeat(&key, &me, &fields("a#000000000000")).unwrap();
        let opened = open_heartbeat(&key, &sealed).unwrap();
        assert_eq!(opened.sender_handle, "a#000000000000");
    }

    /// The self-asserted handle is NEVER present in the sealed bytes (it rode the
    /// wire as ciphertext, even under a public, server-derivable key).
    #[test]
    fn handle_never_wire_cleartext() {
        let key = room_key(DEFAULT_ROOM);
        let me = member(10);
        let secret_handle = "uniquely-identifiable-handle-12345#abcdefabcdef";
        let sealed = seal_public_heartbeat(&key, &me, &fields(secret_handle)).unwrap();
        assert!(
            !sealed
                .windows(secret_handle.len())
                .any(|w| w == secret_handle.as_bytes()),
            "the handle must not appear in the sealed wire bytes"
        );
    }

    /// A forged signature (signed for a different room, shipped claiming another)
    /// fails provenance: presence cannot be spoofed into a room the member never
    /// beaconed into.
    #[test]
    fn tampered_room_rejected() {
        let key = room_key(DEFAULT_ROOM);
        let me = member(11);
        // Sign for room "other", then ship a message claiming DEFAULT_ROOM.
        let signing_input = provenance_input("other", me.public_key().as_ref(), 1);
        let signature = me.sign(&signing_input).unwrap().to_vec();
        let forged = wire::MemberHeartbeat {
            room: DEFAULT_ROOM.to_owned(), // signature does not cover this room
            sender_pubkey: me.public_key().to_vec(),
            sender_handle: "a#000000000000".to_owned(),
            sent_unix_ms: 1,
            signature,
        };
        let aes = Aes256Key::new(key.as_bytes()).unwrap();
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).unwrap();
        let plaintext = forged.encode_to_vec();
        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = [0u8; TAG_LEN];
        gcm_encrypt(&aes, &nonce, HEARTBEAT_AAD, &plaintext, &mut ct, &mut tag).unwrap();
        let mut sealed = Vec::new();
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ct);
        sealed.extend_from_slice(&tag);

        match open_heartbeat(&key, &sealed) {
            Err(HeartbeatError::Provenance) => {}
            other => panic!("expected Provenance rejection, got {other:?}"),
        }
    }

    /// A wrong key (different room) fails AEAD authentication — the position a
    /// non-member / the relay (holding only ciphertext) is in.
    #[test]
    fn wrong_key_fails_authentication() {
        let lobby = room_key("lobby");
        let other = room_key("other-room");
        let me = member(12);
        let sealed = seal_public_heartbeat(&lobby, &me, &fields("a#000000000000")).unwrap();
        match open_heartbeat(&other, &sealed) {
            Err(HeartbeatError::Authentication) => {}
            other => panic!("expected Authentication, got {other:?}"),
        }
    }

    /// A single flipped ciphertext bit fails authentication (GCM integrity).
    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let key = room_key(DEFAULT_ROOM);
        let me = member(13);
        let mut sealed = seal_public_heartbeat(&key, &me, &fields("a#000000000000")).unwrap();
        let last = sealed.len() - TAG_LEN - 1;
        sealed[last] ^= 0x01;
        match open_heartbeat(&key, &sealed) {
            Err(HeartbeatError::Authentication) => {}
            other => panic!("expected Authentication, got {other:?}"),
        }
    }

    /// A buffer too short to hold `nonce ‖ tag` is rejected as truncated.
    #[test]
    fn truncated_envelope_rejected() {
        let key = room_key(DEFAULT_ROOM);
        let short = vec![0u8; NONCE_LEN + TAG_LEN - 1];
        match open_heartbeat(&key, &short) {
            Err(HeartbeatError::Truncated) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    /// A heartbeat sealed under a circle key never opens under a public room key
    /// for the same logical name — the AAD + key-class separation holds at the
    /// open boundary (the seal-side guard is enforced at compile time by the
    /// distinct `seal_public_*` / `seal_circle_*` entry points).
    #[test]
    fn circle_sealed_does_not_open_as_public() {
        let _ = oxicrypt_module::initialize();
        let circle = derive_cot_key(EXAMPLE_ENTROPY, &CNSA_2_0).unwrap();
        let public = room_key(DEFAULT_ROOM);
        let me = member(14);
        let sealed = seal_circle_heartbeat(&circle, &me, &fields("a#000000000000")).unwrap();
        match open_heartbeat(&public, &sealed) {
            Err(HeartbeatError::Authentication) => {}
            other => panic!("expected Authentication, got {other:?}"),
        }
    }
}
