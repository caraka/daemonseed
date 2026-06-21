//! Share-announcement sealing (unified share model — relay-blind in-band
//! discovery; design-of-record: `docs/design/unified-share-model.md`).
//!
//! A [`wire::ShareAnnouncement`] is the in-band replacement for the
//! relay-hosted share registry: instead of a relay `ListPublicShares` call, a
//! sharer posts a sealed, self-signed announcement into a room/circle as a
//! `CotFrame.payload` at that room's rendezvous address, and discovery becomes
//! "listen to the stream" — exactly as chat already works. The relay therefore
//! holds no share directory (ISC-A-S2) and is a pure blind forwarder for shares
//! as it already is for chat.
//!
//! ```text
//!   ShareAnnouncement ──sign(announcer)──▶  signature
//!                     ──prost────────────▶  plaintext
//!                     ──AES-256-GCM(key)─▶  sealed = nonce(12) ‖ ct ‖ tag(16)
//! ```
//!
//! This module is the share-tier analogue of [`crate::public_room`] and reuses
//! its exact envelope shape, with two tier choices left to the caller:
//!
//! - **Which key seals it.** A *public* announcement seals under the public room
//!   key ([`crate::public_room::derive_room_key`]) — server-readable by design,
//!   the deliberately-public tier. A *circle* announcement seals under the
//!   circle `cot_key` ([`crate::circle::key`]) — members only. The two are
//!   **distinct types** ([`crate::public_room::PublicRoomKey`] vs
//!   [`crate::circle::key::CircleKey`]) so a seal cannot take the wrong tier's
//!   key — the key-class guard; only the derivation (and who can open) differs.
//! - **Provenance is always self-signed (ISC-C57).** Every announcement carries
//!   an ML-DSA-87 signature by the announcer's own identity over a
//!   domain-separated input binding room, announcer pubkey, share id, name,
//!   rating, the withdraw flag, and the timestamp. The signature proves WHO
//!   announced, not that they were authorized to. [`open_announcement`] verifies
//!   it and returns the message only on success — a bad signature is dropped
//!   (the share-tier analogue of ISC-A-S17).
//!
//! A distinct AAD ([`SHARE_ANNOUNCE_AAD`]) and a distinct provenance domain
//! ([`SHARE_ANNOUNCE_PROVENANCE_DOMAIN`]) keep an announcement from ever being
//! confused with — or substituted from — a chat message
//! ([`crate::circle::message`]) or a public-room message
//! ([`crate::public_room`]) even under a coincidentally-equal key.
//!
//! The announcement is **relay-agnostic**: it carries the opaque `share_id`
//! (ISC-S21), never a `server_id`. A fetcher derives the rendezvous address it
//! subscribes to from `share_id` plus the relay it is connected to
//! ([`crate::cot::public_share_asset_address`]), so the same announcement is
//! portable across relays — the basis for a future cross-relay sharing path.

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
/// share-announcement seal, distinct from [`crate::circle::message::MESSAGE_AAD`]
/// and [`crate::public_room::ROOM_MESSAGE_AAD`] so an announcement can never be
/// opened/confused as a chat or public-room message under an equal key.
pub const SHARE_ANNOUNCE_AAD: &[u8] = b"daemonseed/share/announce/v1";

/// Domain-separation prefix for the announcement's provenance signature, bound
/// first so a share-announcement signature can never be replayed as any other
/// ML-DSA-87 signature daemonseed produces.
pub const SHARE_ANNOUNCE_PROVENANCE_DOMAIN: &[u8] = b"daemonseed/share/announce/v1";

/// Mint an opaque, unpredictable `share_id`: 128 bits from the OS CSPRNG,
/// lowercase-hex encoded (32 chars), so ids are not order-derived and the
/// published-share space is not enumerable (ISC-S21 / ISC-A-S15). The publisher
/// mints it client-side and the announcement hands it out in-band. An OS-entropy
/// failure is unrecoverable (the same posture as every key/nonce draw in the
/// process), so this panics rather than degrade to a predictable id.
pub fn mint_share_id() -> String {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("OS CSPRNG entropy for share_id");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// The plaintext fields of an announcement the caller supplies; the announcer
/// pubkey and the signature are filled in by [`seal_public_announcement`] /
/// [`seal_circle_announcement`]. Borrowed so sealing never forces a clone.
pub struct AnnouncementFields<'a> {
    /// The room/circle the announcement belongs to (e.g. `"lobby"` for public).
    pub room: &'a str,
    /// The announcer's self-asserted display handle (`name#12hex`). Advisory.
    pub sender_handle: &'a str,
    /// The share's opaque id (ISC-S21) — the fetcher derives the rendezvous
    /// address from it.
    pub share_id: &'a str,
    /// Display name of the shared folder.
    pub name: &'a str,
    /// Sharer-assigned rating label (advisory, never relay-enforced).
    pub rating: &'a str,
    /// `true` = withdraw (unpublish); `false` = announce/refresh.
    pub withdraw: bool,
    /// Announcer wall-clock at announce time, unix milliseconds (advisory
    /// ordering + liveness aging).
    pub sent_unix_ms: i64,
}

/// Build the domain-separated provenance signing input. Binds every
/// semantically-meaningful field — including the withdraw flag and the share id
/// — so a signature is valid for exactly one (room, announcer, share, name,
/// rating, withdraw, time) tuple and cannot be replayed into another room or
/// flipped from announce to withdraw. Length-prefixing each field makes the
/// concatenation unambiguous.
fn provenance_input(
    room: &str,
    sender_pubkey: &[u8],
    share_id: &str,
    name: &str,
    rating: &str,
    withdraw: bool,
    sent_unix_ms: i64,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(SHARE_ANNOUNCE_PROVENANCE_DOMAIN);
    let mut push_field = |bytes: &[u8]| {
        buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        buf.extend_from_slice(bytes);
    };
    push_field(room.as_bytes());
    push_field(sender_pubkey);
    push_field(share_id.as_bytes());
    push_field(name.as_bytes());
    push_field(rating.as_bytes());
    push_field(&[withdraw as u8]);
    push_field(&sent_unix_ms.to_be_bytes());
    buf
}

/// Seal a share announcement for a PUBLIC room: SELF-SIGN it for provenance
/// (ISC-C57), then AES-256-GCM-seal the whole [`wire::ShareAnnouncement`] under
/// the public room key. The output is `nonce ‖ ciphertext ‖ tag` for a
/// `CotFrame.payload`. Taking a [`PublicRoomKey`] (never a [`CircleKey`]) is the
/// key-class guard: a circle announcement can never be sealed under a public key
/// by mistake — it is a compile error. `announcer` is the posting daemon's OWN
/// identity keypair; any daemon may announce, and the signature establishes
/// authorship, not authorization.
pub fn seal_public_announcement(
    key: &PublicRoomKey,
    announcer: &SignKeypair,
    fields: &AnnouncementFields<'_>,
) -> Result<Vec<u8>, ShareAnnounceError> {
    seal_announcement_with(key.as_bytes(), announcer, fields)
}

/// Seal a share announcement for a CIRCLE — as [`seal_public_announcement`] but
/// under the circle `cot_key`. Taking a [`CircleKey`] (never a [`PublicRoomKey`])
/// is the key-class guard in the other direction.
pub fn seal_circle_announcement(
    key: &CircleKey,
    announcer: &SignKeypair,
    fields: &AnnouncementFields<'_>,
) -> Result<Vec<u8>, ShareAnnounceError> {
    seal_announcement_with(key.as_bytes(), announcer, fields)
}

/// Shared seal body, keyed by the raw 32-byte AEAD key the tier-split entry
/// points pass. Private, so the only public seal paths are the typed ones above.
fn seal_announcement_with(
    key_bytes: &[u8; COT_KEY_LEN],
    announcer: &SignKeypair,
    fields: &AnnouncementFields<'_>,
) -> Result<Vec<u8>, ShareAnnounceError> {
    let sender_pubkey = announcer.public_key().to_vec();
    let signing_input = provenance_input(
        fields.room,
        &sender_pubkey,
        fields.share_id,
        fields.name,
        fields.rating,
        fields.withdraw,
        fields.sent_unix_ms,
    );
    let signature = announcer
        .sign(&signing_input)
        .map_err(|_| ShareAnnounceError::Sign)?
        .to_vec();

    let message = wire::ShareAnnouncement {
        room: fields.room.to_owned(),
        sender_pubkey,
        sender_handle: fields.sender_handle.to_owned(),
        share_id: fields.share_id.to_owned(),
        name: fields.name.to_owned(),
        rating: fields.rating.to_owned(),
        withdraw: fields.withdraw,
        sent_unix_ms: fields.sent_unix_ms,
        signature,
    };

    let aes = Aes256Key::new(key_bytes).map_err(ShareAnnounceError::KeyInit)?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(ShareAnnounceError::EntropySource)?;

    let mut plaintext = message.encode_to_vec();
    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = [0u8; TAG_LEN];
    let result = gcm_encrypt(
        &aes,
        &nonce,
        SHARE_ANNOUNCE_AAD,
        &plaintext,
        &mut ciphertext,
        &mut tag,
    );
    plaintext.zeroize();
    result.map_err(ShareAnnounceError::Aead)?;

    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len() + TAG_LEN);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    sealed.extend_from_slice(&tag);
    Ok(sealed)
}

/// Open + VERIFY a sealed announcement (the share-tier analogue of
/// [`crate::public_room::open_room_message`]).
///
/// Two checks, both fail-closed:
///   1. AES-256-GCM open under `key` (only the sealed form ever rides the wire;
///      this is where it becomes plaintext locally).
///   2. The embedded ML-DSA-87 provenance signature verifies under the embedded
///      `sender_pubkey` (ISC-C57). A bad signature is rejected — the
///      announcement is never surfaced unverified.
///
/// On success the recipient still must bind the *displayed* handle to
/// `SHA-384(sender_pubkey)[:12]` (ISC-C4 / ISC-C57); this function returns the
/// verified wire message and leaves that UI-layer binding to the caller.
pub fn open_announcement<K: AeadKey256>(
    key: &K,
    sealed: &[u8],
) -> Result<wire::ShareAnnouncement, ShareAnnounceError> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(ShareAnnounceError::Truncated);
    }
    let nonce: &[u8; NONCE_LEN] = sealed[..NONCE_LEN].try_into().expect("checked length");
    let after_nonce = &sealed[NONCE_LEN..];
    let ciphertext_len = after_nonce.len() - TAG_LEN;
    let ciphertext = &after_nonce[..ciphertext_len];
    let tag: &[u8; TAG_LEN] = after_nonce[ciphertext_len..]
        .try_into()
        .expect("checked length");

    let aes = Aes256Key::new(key.aead_key_bytes()).map_err(ShareAnnounceError::KeyInit)?;
    let mut plaintext = vec![0u8; ciphertext_len];
    gcm_decrypt(
        &aes,
        nonce,
        SHARE_ANNOUNCE_AAD,
        ciphertext,
        tag,
        &mut plaintext,
    )
    .map_err(|e| match e {
        ModeError::TagMismatch => ShareAnnounceError::Authentication,
        other => ShareAnnounceError::Aead(other),
    })?;

    let decoded = wire::ShareAnnouncement::decode(plaintext.as_slice());
    plaintext.zeroize();
    let message = decoded.map_err(ShareAnnounceError::Decode)?;

    // Verify the self-signed provenance before returning (ISC-C57).
    let pubkey: &[u8; ml_dsa::PK_LEN] = message
        .sender_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| ShareAnnounceError::Provenance)?;
    let signature: &[u8; ml_dsa::SIG_LEN] = message
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| ShareAnnounceError::Provenance)?;
    let signing_input = provenance_input(
        &message.room,
        &message.sender_pubkey,
        &message.share_id,
        &message.name,
        &message.rating,
        message.withdraw,
        message.sent_unix_ms,
    );
    verify_signature(pubkey, &signing_input, signature)
        .map_err(|_| ShareAnnounceError::Provenance)?;

    Ok(message)
}

/// Failure sealing/opening a share announcement.
#[derive(Debug)]
pub enum ShareAnnounceError {
    /// The AES-256 key schedule failed to initialise.
    KeyInit(OxicryptError),
    /// The OS entropy source failed while drawing a nonce.
    EntropySource(getrandom::Error),
    /// A non-`TagMismatch` AEAD mode error.
    Aead(ModeError),
    /// AEAD authentication failed (wrong key, tampered ciphertext, swapped
    /// nonce, or wrong AAD). Carries no sub-cause.
    Authentication,
    /// The sealed buffer is shorter than `nonce ‖ tag`.
    Truncated,
    /// The decrypted bytes did not decode as a [`wire::ShareAnnouncement`].
    Decode(prost::DecodeError),
    /// Signing the provenance input failed (crypto module not operational).
    Sign,
    /// The embedded provenance signature did not verify under the embedded
    /// sender pubkey, or those fields were the wrong length.
    Provenance,
}

impl core::fmt::Display for ShareAnnounceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::KeyInit(e) => write!(f, "share-announce AES key init failed: {e}"),
            Self::EntropySource(e) => write!(f, "share-announce nonce entropy failed: {e}"),
            Self::Aead(e) => write!(f, "share-announce AEAD error: {e:?}"),
            Self::Authentication => write!(f, "share-announce authentication failed"),
            Self::Truncated => write!(f, "share-announce envelope is truncated"),
            Self::Decode(e) => write!(f, "share-announce decode failed: {e}"),
            Self::Sign => write!(f, "share-announce provenance signing failed"),
            Self::Provenance => write!(f, "share-announce provenance verification failed"),
        }
    }
}

impl core::error::Error for ShareAnnounceError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circle::key::{EXAMPLE_ENTROPY, derive_cot_key};
    use crate::crypto::suite::CNSA_2_0;
    use crate::identity::keys::SignKeypair;
    use crate::public_room::{DEFAULT_ROOM, derive_room_key};

    fn announcer(seed: u8) -> SignKeypair {
        let _ = oxicrypt_module::initialize();
        SignKeypair::from_ml_dsa_seed(&[seed; 32]).unwrap()
    }

    fn fields<'a>(share_id: &'a str, name: &'a str, withdraw: bool) -> AnnouncementFields<'a> {
        AnnouncementFields {
            room: DEFAULT_ROOM,
            sender_handle: "river-otter#aabbccddeeff",
            share_id,
            name,
            rating: "PG",
            withdraw,
            sent_unix_ms: 1_700_000_000_000,
        }
    }

    /// Derive a public room key, initializing the crypto module first so each
    /// test stands alone (no cross-test ordering dependency).
    fn room_key(room: &str) -> PublicRoomKey {
        let _ = oxicrypt_module::initialize();
        derive_room_key(room, &CNSA_2_0).unwrap()
    }

    /// A minted share_id is 32 lowercase-hex chars (128 bits) and two mints
    /// differ — opaque and not enumerable (ISC-S21 / ISC-A-S15).
    #[test]
    fn mint_share_id_is_32_lowercase_hex_and_unpredictable() {
        let a = mint_share_id();
        let b = mint_share_id();
        assert_eq!(a.len(), 32);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_ne!(a, b);
    }

    /// Round-trip under the PUBLIC room key: seal, open, and the embedded
    /// provenance verifies — the public tier (server-readable key).
    #[test]
    fn seal_open_round_trip_verifies_provenance() {
        let key = room_key(DEFAULT_ROOM);
        let me = announcer(7);
        let sealed =
            seal_public_announcement(&key, &me, &fields("deadbeef", "my docs", false)).unwrap();
        let opened = open_announcement(&key, &sealed).unwrap();
        assert_eq!(opened.share_id, "deadbeef");
        assert_eq!(opened.name, "my docs");
        assert!(!opened.withdraw);
        assert_eq!(opened.sender_pubkey, me.public_key().to_vec());
        assert_eq!(opened.room, DEFAULT_ROOM);
    }

    /// The same seal/open works under a CIRCLE key — the module is
    /// tier-agnostic; only the key (and thus who can open) differs.
    #[test]
    fn seal_open_round_trip_under_circle_key() {
        let _ = oxicrypt_module::initialize();
        let key = derive_cot_key(EXAMPLE_ENTROPY, &CNSA_2_0).unwrap();
        let me = announcer(8);
        let sealed =
            seal_circle_announcement(&key, &me, &fields("c0ffee", "circle share", false)).unwrap();
        let opened = open_announcement(&key, &sealed).unwrap();
        assert_eq!(opened.share_id, "c0ffee");
    }

    /// The withdraw flag round-trips and is bound into the provenance signature.
    #[test]
    fn withdraw_flag_round_trips() {
        let key = room_key(DEFAULT_ROOM);
        let me = announcer(9);
        let sealed =
            seal_public_announcement(&key, &me, &fields("abc123", "going away", true)).unwrap();
        let opened = open_announcement(&key, &sealed).unwrap();
        assert!(opened.withdraw, "withdraw flag survives the round trip");
    }

    /// The share metadata is NEVER present in the sealed bytes (it rode the wire
    /// as ciphertext, even under a public, server-derivable key).
    #[test]
    fn metadata_never_wire_cleartext() {
        let key = room_key(DEFAULT_ROOM);
        let me = announcer(10);
        let secret_name = "uniquely-identifiable-folder-name-12345";
        let sealed =
            seal_public_announcement(&key, &me, &fields("sid", secret_name, false)).unwrap();
        assert!(
            !sealed
                .windows(secret_name.len())
                .any(|w| w == secret_name.as_bytes()),
            "the share name must not appear in the sealed wire bytes"
        );
    }

    /// A flipped withdraw flag (re-sealed without re-signing) fails provenance:
    /// an attacker cannot forge a withdraw against another announcer's share.
    #[test]
    fn tampered_withdraw_rejected() {
        let key = room_key(DEFAULT_ROOM);
        let me = announcer(11);
        // Sign for withdraw=false, then ship a message claiming withdraw=true.
        let signing_input = provenance_input(
            DEFAULT_ROOM,
            me.public_key().as_ref(),
            "sid",
            "n",
            "PG",
            false,
            1,
        );
        let signature = me.sign(&signing_input).unwrap().to_vec();
        let forged = wire::ShareAnnouncement {
            room: DEFAULT_ROOM.to_owned(),
            sender_pubkey: me.public_key().to_vec(),
            sender_handle: "a#000000000000".to_owned(),
            share_id: "sid".to_owned(),
            name: "n".to_owned(),
            rating: "PG".to_owned(),
            withdraw: true, // signature does not cover this
            sent_unix_ms: 1,
            signature,
        };
        let aes = Aes256Key::new(key.as_bytes()).unwrap();
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).unwrap();
        let plaintext = forged.encode_to_vec();
        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = [0u8; TAG_LEN];
        gcm_encrypt(
            &aes,
            &nonce,
            SHARE_ANNOUNCE_AAD,
            &plaintext,
            &mut ct,
            &mut tag,
        )
        .unwrap();
        let mut sealed = Vec::new();
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ct);
        sealed.extend_from_slice(&tag);

        match open_announcement(&key, &sealed) {
            Err(ShareAnnounceError::Provenance) => {}
            other => panic!("expected Provenance rejection, got {other:?}"),
        }
    }

    /// A wrong key (different room) fails AEAD authentication — the position a
    /// non-member / the relay (holding only ciphertext) is in.
    #[test]
    fn wrong_key_fails_authentication() {
        let lobby = room_key("lobby");
        let other = room_key("other-room");
        let me = announcer(12);
        let sealed = seal_public_announcement(&lobby, &me, &fields("sid", "n", false)).unwrap();
        match open_announcement(&other, &sealed) {
            Err(ShareAnnounceError::Authentication) => {}
            other => panic!("expected Authentication, got {other:?}"),
        }
    }

    /// A single flipped ciphertext bit fails authentication (GCM integrity).
    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let key = room_key(DEFAULT_ROOM);
        let me = announcer(13);
        let mut sealed =
            seal_public_announcement(&key, &me, &fields("sid", "intact", false)).unwrap();
        let last = sealed.len() - TAG_LEN - 1;
        sealed[last] ^= 0x01;
        match open_announcement(&key, &sealed) {
            Err(ShareAnnounceError::Authentication) => {}
            other => panic!("expected Authentication, got {other:?}"),
        }
    }

    /// A buffer too short to hold `nonce ‖ tag` is rejected as truncated.
    #[test]
    fn truncated_envelope_rejected() {
        let key = room_key(DEFAULT_ROOM);
        let short = vec![0u8; NONCE_LEN + TAG_LEN - 1];
        match open_announcement(&key, &short) {
            Err(ShareAnnounceError::Truncated) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }
}
