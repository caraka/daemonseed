//! Interactive public rooms (ISC-S4 / ISC-S22..S26 / ISC-C56..C58 / ISC-A-S16..A-S19).
//!
//! A public room is the **public tier** of the public-vs-circle bifurcation
//! (ISC-S4), built over the exact same `CircleOfTrust.Subscribe` live relay and
//! `CotFrame` mechanism as a circle (M8 / ISC-S20). The only differences from a
//! circle are *who holds the key* and *how authorship is established*:
//!
//! - **A public room is a circle-of-trust the server is a member of (ISC-S22 /
//!   ISC-A-S2)** — its key is a global, server-readable key, so server
//!   compromise exposes public content, unlike a private circle where the server
//!   is not a member and never holds the key. The room key
//!   derives from *public* inputs — the crypto family token and the room name —
//!   under a fixed protocol salt ([`info::PUBLIC_ROOM_KEY_SALT`]). There is no
//!   secret IKM, so every client AND the relay derive the byte-identical key.
//!   The room is therefore *server-readable by construction*: content is
//!   AES-256-GCM-sealed (never wire-cleartext, ISC-A-S16) but under a key
//!   everyone holds. Contrast a circle, whose `cot_key` derives from a secret
//!   shared phrase the relay never sees ([`crate::circle::key`]) — that is the
//!   tier with an actual confidentiality guarantee. The room seal is **protocol
//!   uniformity + server-readability, NOT a confidentiality barrier**: the
//!   public tier carries no confidentiality guarantee by design (anyone who can
//!   reach the server derives the key). Transport security (TLS today,
//!   transport-agnostic) is a separate layer protecting all tiers equally.
//!
//! - **Self-signed for provenance (ISC-S24 / ISC-C57).** Any daemon may post to
//!   a public room — there is no whitelist gate (contrast operator
//!   announcements, ISC-S7/S8). Each message carries an ML-DSA-87 signature by
//!   the *posting daemon's own* identity over a domain-separated input binding
//!   the room, sender pubkey, timestamp, and body. The signature proves WHO
//!   posted, not that they were AUTHORIZED to. Recipients verify it client-side
//!   ([`open_room_message`] returns the verified message only) and bind the
//!   displayed handle to `SHA-384(sender_pubkey)[:12]` (ISC-C4) so a spoofed
//!   `sender_handle` cannot impersonate a real key.
//!
//! ```text
//!   PublicRoomMessage  ──sign(sender)──▶  signature
//!                      ──prost──────────▶  plaintext
//!                      ──AES-256-GCM(room_key)──▶  sealed = nonce ‖ ct ‖ tag
//! ```
//!
//! The seal layer reuses [`crate::circle::message`]'s envelope shape exactly,
//! with a distinct AAD ([`ROOM_MESSAGE_AAD`]) so a room-sealed message can never
//! be confused with a circle-sealed one even under a coincidentally-equal key.

use daemonseed_proto::v1 as wire;
use oxicrypt_aes::{Aes256Key, ModeError, gcm_decrypt, gcm_encrypt};
use oxicrypt_kdf::HkdfSha384;
use oxicrypt_module::Error as OxicryptError;
use oxicrypt_sha::sha384;
use prost::Message;
use zeroize::Zeroize;

use crate::circle::key::{AeadKey256, COT_KEY_LEN};
use crate::circle::message::{NONCE_LEN, TAG_LEN};
use crate::cot::{ASSET_ADDR_LEN, AssetAddr};
use crate::crypto::suite::Suite;
use crate::identity::keys::{SignKeypair, verify_signature};
use crate::kdf::info;
use oxicrypt_ml_dsa as ml_dsa;

/// The well-known default public room every daemon lands in by default
/// (ISC-S22 / ISC-C56). A public, fixed name — there is nothing secret about a
/// public room, and a shared default is what makes "everyone reads by default"
/// concrete without any prior coordination.
pub const DEFAULT_ROOM: &str = "lobby";

/// Domain-separation tag bound as AEAD additional-authenticated-data for the
/// public-room seal, distinct from [`crate::circle::message::MESSAGE_AAD`] so a
/// room-sealed message can never be opened/confused as a circle-sealed one.
pub const ROOM_MESSAGE_AAD: &[u8] = b"daemonseed/public-room/message/v1";

/// Domain-separation prefix for the provenance signature's signed input
/// (ISC-S24). Bound first so a public-room signature can never be replayed as
/// any other ML-DSA-87 signature daemonseed produces.
pub const ROOM_PROVENANCE_DOMAIN: &[u8] = b"daemonseed/public-room/message/v1";

/// A derived public-room key — the global, server-readable AEAD key for a public
/// room (ISC-S22). A **distinct type** from [`crate::circle::key::CircleKey`] so
/// the two can never be substituted at a seal site (the key-class guard): a
/// public payload can only be sealed with a `PublicRoomKey` and a circle payload
/// only with a `CircleKey` — the wrong one is a compile error. Both implement
/// [`AeadKey256`], so a tier-agnostic *open* path can still accept either (a
/// wrong key merely fails AEAD authentication, no confidentiality loss). Zeroes
/// on drop; `Debug` is redacted (ISC-A-C1).
#[derive(zeroize::ZeroizeOnDrop)]
pub struct PublicRoomKey(Box<[u8; COT_KEY_LEN]>);

impl PublicRoomKey {
    /// Borrow the raw key bytes for AEAD use. Callers must not copy these into a
    /// non-zeroizing buffer.
    pub fn as_bytes(&self) -> &[u8; COT_KEY_LEN] {
        &self.0
    }

    /// Wrap raw key bytes into a zeroizing `PublicRoomKey`. The caller zeroes its
    /// own copy of `bytes` after this call (the boxed copy here zeroes on drop).
    pub fn from_bytes(bytes: [u8; COT_KEY_LEN]) -> Self {
        PublicRoomKey(Box::new(bytes))
    }
}

impl core::fmt::Debug for PublicRoomKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PublicRoomKey(<redacted>)")
    }
}

impl AeadKey256 for PublicRoomKey {
    fn aead_key_bytes(&self) -> &[u8; COT_KEY_LEN] {
        self.as_bytes()
    }
}

/// Derive the **global shared** key for a public room (ISC-S22).
///
/// ```text
///   room_key = HKDF-SHA-384(
///       salt = PUBLIC_ROOM_KEY_SALT,
///       ikm  = family_token,                          // PUBLIC, not secret
///       info = "daemonseed/public-room/<family>/<room>")
/// ```
///
/// Every input is public, so this is reproducible by every client and by the
/// relay — the room is server-readable by design (ISC-A-S2 public tier). The
/// derivation is family-anchored exactly like a circle key, so within-family
/// suite ratchets leave the room key unchanged. Returns a [`PublicRoomKey`] purely to
/// reuse the existing AEAD plumbing — it is a *global* key, not a circle secret.
pub fn derive_room_key(room: &str, suite: &Suite) -> Result<PublicRoomKey, RoomKeyError> {
    // The IKM is the public family token — a public room has no secret IKM. The
    // per-room distinguisher rides entirely in the `info` string.
    let family = suite.family_token();
    let extract = HkdfSha384::extract(Some(info::PUBLIC_ROOM_KEY_SALT), family.as_bytes())
        .map_err(RoomKeyError::Hkdf)?;
    let info_str = info::public_room(family, room);

    let mut key = [0u8; COT_KEY_LEN];
    if let Err(e) = extract.expand(info_str.as_bytes(), &mut key) {
        key.zeroize();
        return Err(RoomKeyError::Hkdf(e));
    }
    let out = PublicRoomKey::from_bytes(key);
    key.zeroize();
    Ok(out)
}

/// Derive a public room's rendezvous address on a given relay (ISC-S23):
/// `SHA-384(room_key ‖ server_id)` — byte-identical in shape to a circle's
/// [`crate::cot::asset_address`], so a public room rides the SAME
/// `CircleOfTrust.Subscribe` relay surface with no relay change. Because the
/// room key is public, the relay can compute this address too — but it does not
/// need to: the relay routes blindly by the address its subscribers present
/// (the fan-out mechanism is identical to a circle, ISC-S20).
pub fn room_asset_address(
    room_key: &PublicRoomKey,
    server_id: &[u8],
) -> Result<AssetAddr, OxicryptError> {
    let mut input = Vec::with_capacity(COT_KEY_LEN + server_id.len());
    input.extend_from_slice(room_key.as_bytes());
    input.extend_from_slice(server_id);
    let digest = sha384(&input);
    input.zeroize();
    let digest = digest?;
    let mut out = [0u8; ASSET_ADDR_LEN];
    out.copy_from_slice(&digest[..ASSET_ADDR_LEN]);
    Ok(AssetAddr::from_bytes(out))
}

/// Build the domain-separated provenance signing input for a public-room
/// message (ISC-S24). Binds the room, sender pubkey, timestamp, and body so a
/// signature is valid for exactly one (room, author, time, content) tuple and
/// cannot be replayed into another room. Length-prefixing each variable field
/// makes the concatenation unambiguous.
fn provenance_input(room: &str, sender_pubkey: &[u8], sent_unix_ms: i64, body: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(ROOM_PROVENANCE_DOMAIN);
    let mut push_field = |bytes: &[u8]| {
        buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        buf.extend_from_slice(bytes);
    };
    push_field(room.as_bytes());
    push_field(sender_pubkey);
    push_field(&sent_unix_ms.to_be_bytes());
    push_field(body.as_bytes());
    buf
}

/// Seal a public-room message: SELF-SIGN it for provenance (ISC-S24), then
/// AES-256-GCM-seal the whole [`wire::PublicRoomMessage`] under the global room
/// key (ISC-S22). The output is `nonce ‖ ciphertext ‖ tag` suitable for a
/// `CotFrame.payload`. `sender` is the posting daemon's OWN identity keypair —
/// any daemon may post; the signature establishes authorship, not authorization.
pub fn seal_room_message(
    room_key: &PublicRoomKey,
    sender: &SignKeypair,
    room: &str,
    sender_handle: &str,
    body: &str,
    sent_unix_ms: i64,
) -> Result<Vec<u8>, RoomMessageError> {
    let sender_pubkey = sender.public_key().to_vec();
    let signing_input = provenance_input(room, &sender_pubkey, sent_unix_ms, body);
    let signature = sender
        .sign(&signing_input)
        .map_err(|_| RoomMessageError::Sign)?
        .to_vec();

    let message = wire::PublicRoomMessage {
        room: room.to_owned(),
        sender_pubkey,
        sender_handle: sender_handle.to_owned(),
        body: body.to_owned(),
        sent_unix_ms,
        signature,
    };

    let aes = Aes256Key::new(room_key.as_bytes()).map_err(RoomMessageError::KeyInit)?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(RoomMessageError::EntropySource)?;

    let mut plaintext = message.encode_to_vec();
    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = [0u8; TAG_LEN];
    let result = gcm_encrypt(
        &aes,
        &nonce,
        ROOM_MESSAGE_AAD,
        &plaintext,
        &mut ciphertext,
        &mut tag,
    );
    plaintext.zeroize();
    result.map_err(RoomMessageError::Aead)?;

    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len() + TAG_LEN);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    sealed.extend_from_slice(&tag);
    Ok(sealed)
}

/// Open + VERIFY a sealed public-room envelope (ISC-S22 / ISC-C57 / ISC-A-S17).
///
/// Two checks, both fail-closed:
///   1. AES-256-GCM open under the global room key (ISC-A-S16: only the sealed
///      form ever rides the wire; this is where it becomes plaintext locally).
///   2. The embedded ML-DSA-87 provenance signature verifies under the embedded
///      `sender_pubkey` (ISC-S24). A bad signature is rejected — the message is
///      never surfaced unverified (ISC-A-S17).
///
/// On success the recipient still must bind the *displayed* handle to
/// `SHA-384(sender_pubkey)[:12]` (ISC-C4 / ISC-C57); this function returns the
/// verified wire message and leaves that UI-layer binding to the caller.
pub fn open_room_message(
    room_key: &PublicRoomKey,
    sealed: &[u8],
) -> Result<wire::PublicRoomMessage, RoomMessageError> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(RoomMessageError::Truncated);
    }
    let nonce: &[u8; NONCE_LEN] = sealed[..NONCE_LEN].try_into().expect("checked length");
    let after_nonce = &sealed[NONCE_LEN..];
    let ciphertext_len = after_nonce.len() - TAG_LEN;
    let ciphertext = &after_nonce[..ciphertext_len];
    let tag: &[u8; TAG_LEN] = after_nonce[ciphertext_len..]
        .try_into()
        .expect("checked length");

    let aes = Aes256Key::new(room_key.as_bytes()).map_err(RoomMessageError::KeyInit)?;
    let mut plaintext = vec![0u8; ciphertext_len];
    gcm_decrypt(
        &aes,
        nonce,
        ROOM_MESSAGE_AAD,
        ciphertext,
        tag,
        &mut plaintext,
    )
    .map_err(|e| match e {
        ModeError::TagMismatch => RoomMessageError::Authentication,
        other => RoomMessageError::Aead(other),
    })?;

    let decoded = wire::PublicRoomMessage::decode(plaintext.as_slice());
    plaintext.zeroize();
    let message = decoded.map_err(RoomMessageError::Decode)?;

    // ISC-S24 / ISC-A-S17: verify the self-signed provenance before returning.
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
    let signing_input = provenance_input(
        &message.room,
        &message.sender_pubkey,
        message.sent_unix_ms,
        &message.body,
    );
    verify_signature(pubkey, &signing_input, signature)
        .map_err(|_| RoomMessageError::Provenance)?;

    Ok(message)
}

/// Failure deriving a public-room key.
#[derive(Debug)]
pub enum RoomKeyError {
    /// The HKDF extract/expand step failed.
    Hkdf(oxicrypt_kdf::KdfError),
}

impl core::fmt::Display for RoomKeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RoomKeyError::Hkdf(e) => write!(f, "public-room HKDF failed: {e:?}"),
        }
    }
}

impl core::error::Error for RoomKeyError {}

/// Failure sealing/opening a public-room message.
#[derive(Debug)]
pub enum RoomMessageError {
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
    /// The decrypted bytes did not decode as a [`wire::PublicRoomMessage`].
    Decode(prost::DecodeError),
    /// Signing the provenance input failed (crypto module not operational).
    Sign,
    /// The embedded provenance signature did not verify under the embedded
    /// sender pubkey, or those fields were the wrong length (ISC-A-S17).
    Provenance,
}

impl core::fmt::Display for RoomMessageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::KeyInit(e) => write!(f, "public-room AES key init failed: {e}"),
            Self::EntropySource(e) => write!(f, "public-room nonce entropy failed: {e}"),
            Self::Aead(e) => write!(f, "public-room AEAD error: {e:?}"),
            Self::Authentication => write!(f, "public-room authentication failed"),
            Self::Truncated => write!(f, "public-room envelope is truncated"),
            Self::Decode(e) => write!(f, "public-room decode failed: {e}"),
            Self::Sign => write!(f, "public-room provenance signing failed"),
            Self::Provenance => write!(f, "public-room provenance verification failed"),
        }
    }
}

impl core::error::Error for RoomMessageError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::CNSA_2_0;

    const SERVER_ID: &[u8] = b"relay-test#001122334455";

    fn keypair(seed: u8) -> SignKeypair {
        let _ = oxicrypt_module::initialize();
        SignKeypair::from_ml_dsa_seed(&[seed; 32]).unwrap()
    }

    /// ISC-S22 — the room key is deterministic from PUBLIC inputs: every client
    /// (and the relay) derives the byte-identical global key for the same room.
    #[test]
    fn room_key_is_deterministic_global() {
        let _ = oxicrypt_module::initialize();
        let a = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        let b = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    /// Distinct room names yield distinct keys (the name is the sole
    /// distinguisher).
    #[test]
    fn distinct_rooms_distinct_keys() {
        let _ = oxicrypt_module::initialize();
        let lobby = derive_room_key("lobby", &CNSA_2_0).unwrap();
        let news = derive_room_key("announcements", &CNSA_2_0).unwrap();
        assert_ne!(lobby.as_bytes(), news.as_bytes());
    }

    /// ISC-S22 / ISC-A-S2 — a public room key MUST NOT collide with a circle
    /// key, even for an identically-named input: the salts and info templates
    /// differ, so the two derivation domains are disjoint.
    #[test]
    fn room_key_does_not_collide_with_circle_key() {
        use crate::circle::key::derive_cot_key;
        let _ = oxicrypt_module::initialize();
        let room = derive_room_key("correct horse battery staple", &CNSA_2_0).unwrap();
        let circle = derive_cot_key("correct horse battery staple", &CNSA_2_0).unwrap();
        assert_ne!(
            room.as_bytes(),
            circle.as_bytes(),
            "public-room and circle derivation domains must be disjoint"
        );
    }

    /// ISC-S23 — the rendezvous address is deterministic and namespaced per
    /// relay (so the same room on two relays presents two addresses).
    #[test]
    fn room_address_deterministic_and_namespaced() {
        let _ = oxicrypt_module::initialize();
        let key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        let a = room_asset_address(&key, SERVER_ID).unwrap();
        let b = room_asset_address(&key, SERVER_ID).unwrap();
        assert_eq!(a, b);
        let other = room_asset_address(&key, b"relay-other#aabbccddeeff").unwrap();
        assert_ne!(a, other);
    }

    /// ISC-S22 / ISC-S24 round-trip: a posted message seals, the global key
    /// opens it, and the embedded provenance signature verifies.
    #[test]
    fn seal_open_round_trip_verifies_provenance() {
        let key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        let sender = keypair(7);
        let sealed = seal_room_message(
            &key,
            &sender,
            DEFAULT_ROOM,
            "river-otter#aabbccddeeff",
            "hello public room",
            1_700_000_000_000,
        )
        .unwrap();
        let opened = open_room_message(&key, &sealed).unwrap();
        assert_eq!(opened.body, "hello public room");
        assert_eq!(opened.sender_pubkey, sender.public_key().to_vec());
        assert_eq!(opened.room, DEFAULT_ROOM);
    }

    /// ISC-A-S16 — the body is NEVER present in the sealed bytes (it rode the
    /// wire as ciphertext, even though the relay holds the global key).
    #[test]
    fn body_never_wire_cleartext() {
        let key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        let sender = keypair(8);
        let body = "uniquely identifiable plaintext body 12345";
        let sealed =
            seal_room_message(&key, &sender, DEFAULT_ROOM, "a#000000000000", body, 1).unwrap();
        assert!(
            !sealed.windows(body.len()).any(|w| w == body.as_bytes()),
            "the plaintext body must not appear in the sealed wire bytes"
        );
    }

    /// ISC-A-S17 — a tampered body (re-sealed without re-signing) fails
    /// provenance verification: the message is never surfaced unverified.
    #[test]
    fn tampered_provenance_rejected() {
        let key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        let sender = keypair(9);
        // Forge a message: valid seal under the (public) global key, but the
        // signature covers a DIFFERENT body than the one we ship.
        let good_sig_input = provenance_input(
            DEFAULT_ROOM,
            sender.public_key().as_ref(),
            1,
            "the honest body",
        );
        let signature = sender.sign(&good_sig_input).unwrap().to_vec();
        let forged = wire::PublicRoomMessage {
            room: DEFAULT_ROOM.to_owned(),
            sender_pubkey: sender.public_key().to_vec(),
            sender_handle: "a#000000000000".to_owned(),
            body: "TAMPERED body".to_owned(), // signature does not cover this
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
            ROOM_MESSAGE_AAD,
            &plaintext,
            &mut ct,
            &mut tag,
        )
        .unwrap();
        let mut sealed = Vec::new();
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ct);
        sealed.extend_from_slice(&tag);

        match open_room_message(&key, &sealed) {
            Err(RoomMessageError::Provenance) => {}
            other => panic!("expected Provenance rejection, got {other:?}"),
        }
    }

    /// A wrong global key (different room) fails AEAD authentication — the same
    /// position a daemon NOT in the public-room key set would be in.
    #[test]
    fn wrong_room_key_fails_authentication() {
        let lobby = derive_room_key("lobby", &CNSA_2_0).unwrap();
        let other = derive_room_key("other-room", &CNSA_2_0).unwrap();
        let sender = keypair(10);
        let sealed = seal_room_message(&lobby, &sender, "lobby", "a#000000000000", "x", 1).unwrap();
        match open_room_message(&other, &sealed) {
            Err(RoomMessageError::Authentication) => {}
            other => panic!("expected Authentication, got {other:?}"),
        }
    }
}
