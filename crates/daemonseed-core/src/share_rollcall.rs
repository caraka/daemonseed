//! Share-roll-call sealing (unified share model — relay-blind late-join
//! discovery; design-of-record: `docs/design/unified-share-model.md`).
//!
//! A [`wire::ShareRollCall`] is the *request* half of in-band discovery; a
//! [`crate::share_announce::wire::ShareAnnouncement`] is the *response*. Because
//! the relay is a pure blind forwarder it cannot tell live sharers that a new
//! member subscribed, so fast late-join is pull-based: a joining or refreshing
//! client posts a sealed roll-call into the room, and every currently-connected
//! sharer answers by re-posting its announcement(s). One late-join hook —
//! startup discovery, the Refresh action, and the jittered reconcile timer all
//! post a roll-call — and it needs no new relay capability (it is just another
//! `CotFrame.payload` at the room's rendezvous address).
//!
//! ```text
//!   ShareRollCall ──sign(requester)──▶  signature
//!                 ──prost────────────▶  plaintext
//!                 ──AES-256-GCM(key)─▶  sealed = nonce(12) ‖ ct ‖ tag(16)
//! ```
//!
//! It is the **distinct sealed kind** the design chose over implicit-on-subscribe
//! (the relay emits no subscribe events, so the request must travel in-band as
//! its own message). It mirrors [`crate::share_announce`] exactly:
//!
//! - **Which key seals it.** A *public* roll-call seals under the public room key
//!   ([`crate::public_room::PublicRoomKey`]); a *circle* roll-call under the
//!   circle `cot_key` ([`crate::circle::key::CircleKey`]). The two are distinct
//!   types so a seal cannot take the wrong tier's key — the key-class guard.
//! - **Provenance is always self-signed (ISC-C57).** Every roll-call carries an
//!   ML-DSA-87 signature by the requester's own identity over a domain-separated
//!   input binding room, requester pubkey, and timestamp. A roll-call confers no
//!   authority — any member may ask — but the signature proves WHO asked, in
//!   keeping with the room's "every posted message is self-signed" property.
//!
//! The AES-256-GCM envelope (nonce ‖ ct ‖ tag) is the shared
//! `crate::aead_envelope` primitive; this module supplies its own
//! [`SHARE_ROLLCALL_AAD`] and maps that helper's `EnvelopeError` onto
//! [`ShareRollCallError`], so the wire bytes and this module's public error
//! surface are unchanged.
//!
//! A distinct AAD ([`SHARE_ROLLCALL_AAD`]) and a distinct provenance domain
//! ([`SHARE_ROLLCALL_PROVENANCE_DOMAIN`]) keep a roll-call from ever being
//! confused with — or substituted from — a chat message
//! ([`crate::circle::message`]), a public-room message ([`crate::public_room`]),
//! a share announcement ([`crate::share_announce`]), or a sealed content frame
//! ([`crate::share_seal`]) even under a coincidentally-equal key.

use daemonseed_proto::v1 as wire;
use oxicrypt_aes::{Aes256Key, ModeError};
use oxicrypt_module::Error as OxicryptError;
use prost::Message;
use zeroize::Zeroize;

use crate::aead_envelope::{EnvelopeError, open_envelope, seal_envelope};
use crate::circle::key::{AeadKey256, COT_KEY_LEN, CircleKey};
use crate::identity::keys::{SignKeypair, verify_signature};
use crate::public_room::PublicRoomKey;
use oxicrypt_ml_dsa as ml_dsa;

/// Domain-separation tag bound as AEAD additional-authenticated-data for the
/// share-roll-call seal, distinct from [`crate::circle::message::MESSAGE_AAD`],
/// [`crate::public_room::ROOM_MESSAGE_AAD`],
/// [`crate::share_announce::SHARE_ANNOUNCE_AAD`], and
/// [`crate::share_seal::SHARE_FRAME_AAD`] so a roll-call can never be
/// opened/confused as any of those under an equal key.
pub const SHARE_ROLLCALL_AAD: &[u8] = b"daemonseed/share/rollcall/v1";

/// Domain-separation prefix for the roll-call's provenance signature, bound
/// first so a roll-call signature can never be replayed as any other ML-DSA-87
/// signature daemonseed produces.
pub const SHARE_ROLLCALL_PROVENANCE_DOMAIN: &[u8] = b"daemonseed/share/rollcall/v1";

/// The plaintext fields of a roll-call the caller supplies; the requester pubkey
/// and the signature are filled in by [`seal_public_rollcall`] /
/// [`seal_circle_rollcall`]. Borrowed so sealing never forces a clone.
pub struct RollCallFields<'a> {
    /// The room/circle the roll-call probes (e.g. `"lobby"` for public).
    pub room: &'a str,
    /// The requester's self-asserted display handle (`name#12hex`). Advisory.
    pub requester_handle: &'a str,
    /// Requester wall-clock at request time, unix milliseconds (advisory only).
    pub sent_unix_ms: i64,
}

/// Build the domain-separated provenance signing input. Binds the room,
/// requester pubkey, and timestamp so a signature is valid for exactly one
/// (room, requester, time) tuple and cannot be replayed into another room.
/// Length-prefixing each field makes the concatenation unambiguous.
fn provenance_input(room: &str, requester_pubkey: &[u8], sent_unix_ms: i64) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(SHARE_ROLLCALL_PROVENANCE_DOMAIN);
    let mut push_field = |bytes: &[u8]| {
        buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        buf.extend_from_slice(bytes);
    };
    push_field(room.as_bytes());
    push_field(requester_pubkey);
    push_field(&sent_unix_ms.to_be_bytes());
    buf
}

/// Seal a roll-call for a PUBLIC room: SELF-SIGN it for provenance (ISC-C57),
/// then AES-256-GCM-seal the whole [`wire::ShareRollCall`] under the public room
/// key. The output is `nonce ‖ ciphertext ‖ tag` for a `CotFrame.payload`.
/// Taking a [`PublicRoomKey`] (never a [`CircleKey`]) is the key-class guard.
/// `requester` is the posting daemon's OWN identity keypair.
pub fn seal_public_rollcall(
    key: &PublicRoomKey,
    requester: &SignKeypair,
    fields: &RollCallFields<'_>,
) -> Result<Vec<u8>, ShareRollCallError> {
    seal_rollcall_with(key.as_bytes(), requester, fields)
}

/// Seal a roll-call for a CIRCLE — as [`seal_public_rollcall`] but under the
/// circle `cot_key`. Taking a [`CircleKey`] (never a [`PublicRoomKey`]) is the
/// key-class guard in the other direction.
pub fn seal_circle_rollcall(
    key: &CircleKey,
    requester: &SignKeypair,
    fields: &RollCallFields<'_>,
) -> Result<Vec<u8>, ShareRollCallError> {
    seal_rollcall_with(key.as_bytes(), requester, fields)
}

/// Shared seal body, keyed by the raw 32-byte AEAD key the tier-split entry
/// points pass. Private, so the only public seal paths are the typed ones above.
fn seal_rollcall_with(
    key_bytes: &[u8; COT_KEY_LEN],
    requester: &SignKeypair,
    fields: &RollCallFields<'_>,
) -> Result<Vec<u8>, ShareRollCallError> {
    let requester_pubkey = requester.public_key().to_vec();
    let signing_input = provenance_input(fields.room, &requester_pubkey, fields.sent_unix_ms);
    let signature = requester
        .sign(&signing_input)
        .map_err(|_| ShareRollCallError::Sign)?
        .to_vec();

    let message = wire::ShareRollCall {
        room: fields.room.to_owned(),
        requester_pubkey,
        requester_handle: fields.requester_handle.to_owned(),
        sent_unix_ms: fields.sent_unix_ms,
        signature,
    };

    // AES-256-GCM-seal the prost-encoded plaintext into `nonce ‖ ct ‖ tag` via
    // the shared envelope helper, binding this kind's own SHARE_ROLLCALL_AAD. The
    // plaintext is zeroed once GCM has consumed it.
    let aes = Aes256Key::new(key_bytes).map_err(ShareRollCallError::KeyInit)?;
    let mut plaintext = message.encode_to_vec();
    let result = seal_envelope(&aes, SHARE_ROLLCALL_AAD, &plaintext);
    plaintext.zeroize();
    Ok(result?)
}

/// Open + VERIFY a sealed roll-call (the request-side analogue of
/// [`crate::share_announce::open_announcement`]).
///
/// Two checks, both fail-closed:
///   1. AES-256-GCM open under `key` (only the sealed form ever rides the wire).
///   2. The embedded ML-DSA-87 provenance signature verifies under the embedded
///      `requester_pubkey` (ISC-C57). A bad signature is rejected — the roll-call
///      is never acted on unverified.
///
/// On success the recipient (a live sharer) re-announces its shares into the
/// same room; binding the *displayed* handle to `SHA-384(requester_pubkey)[:12]`
/// (ISC-C4 / ISC-C57) is left to the caller.
pub fn open_rollcall<K: AeadKey256>(
    key: &K,
    sealed: &[u8],
) -> Result<wire::ShareRollCall, ShareRollCallError> {
    // AES-256-GCM open via the shared envelope helper; a too-short buffer is
    // rejected before decrypt, and a wrong key or wrong AAD fails authentication.
    // The recovered plaintext is zeroed once prost has consumed it.
    let aes = Aes256Key::new(key.aead_key_bytes()).map_err(ShareRollCallError::KeyInit)?;
    let mut plaintext = open_envelope(&aes, SHARE_ROLLCALL_AAD, sealed)?;
    let decoded = wire::ShareRollCall::decode(plaintext.as_slice());
    plaintext.zeroize();
    let message = decoded.map_err(ShareRollCallError::Decode)?;

    // Verify the self-signed provenance before returning (ISC-C57).
    let pubkey: &[u8; ml_dsa::PK_LEN] = message
        .requester_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| ShareRollCallError::Provenance)?;
    let signature: &[u8; ml_dsa::SIG_LEN] = message
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| ShareRollCallError::Provenance)?;
    let signing_input = provenance_input(
        &message.room,
        &message.requester_pubkey,
        message.sent_unix_ms,
    );
    verify_signature(pubkey, &signing_input, signature)
        .map_err(|_| ShareRollCallError::Provenance)?;

    Ok(message)
}

/// Failure sealing/opening a share roll-call.
#[derive(Debug)]
pub enum ShareRollCallError {
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
    /// The decrypted bytes did not decode as a [`wire::ShareRollCall`].
    Decode(prost::DecodeError),
    /// Signing the provenance input failed (crypto module not operational).
    Sign,
    /// The embedded provenance signature did not verify under the embedded
    /// requester pubkey, or those fields were the wrong length.
    Provenance,
}

impl core::fmt::Display for ShareRollCallError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::KeyInit(e) => write!(f, "share-rollcall AES key init failed: {e}"),
            Self::EntropySource(e) => write!(f, "share-rollcall nonce entropy failed: {e}"),
            Self::Aead(e) => write!(f, "share-rollcall AEAD error: {e:?}"),
            Self::Authentication => write!(f, "share-rollcall authentication failed"),
            Self::Truncated => write!(f, "share-rollcall envelope is truncated"),
            Self::Decode(e) => write!(f, "share-rollcall decode failed: {e}"),
            Self::Sign => write!(f, "share-rollcall provenance signing failed"),
            Self::Provenance => write!(f, "share-rollcall provenance verification failed"),
        }
    }
}

impl core::error::Error for ShareRollCallError {}

/// Map the shared envelope error onto this module's own error type so the public
/// error surface is unchanged: too-short → [`ShareRollCallError::Truncated`] and
/// `TagMismatch` → [`ShareRollCallError::Authentication`] are preserved exactly.
impl From<EnvelopeError> for ShareRollCallError {
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
    use crate::circle::key::{EXAMPLE_ENTROPY, derive_cot_key};
    use crate::circle::message::{NONCE_LEN, TAG_LEN};
    use crate::crypto::suite::CNSA_2_0;
    use crate::identity::keys::SignKeypair;
    use crate::public_room::{DEFAULT_ROOM, derive_room_key};
    use crate::share_announce::{AnnouncementFields, open_announcement, seal_public_announcement};
    use oxicrypt_aes::gcm_encrypt;

    fn requester(seed: u8) -> SignKeypair {
        let _ = oxicrypt_module::initialize();
        SignKeypair::from_ml_dsa_seed(&[seed; 32]).unwrap()
    }

    fn fields(room: &str) -> RollCallFields<'_> {
        RollCallFields {
            room,
            requester_handle: "river-otter#aabbccddeeff",
            sent_unix_ms: 1_700_000_000_000,
        }
    }

    /// Derive a public room key, initializing the crypto module first so each
    /// test stands alone (no cross-test ordering dependency).
    fn room_key(room: &str) -> PublicRoomKey {
        let _ = oxicrypt_module::initialize();
        derive_room_key(room, &CNSA_2_0).unwrap()
    }

    /// Round-trip under the PUBLIC room key: seal, open, and the embedded
    /// provenance verifies.
    #[test]
    fn seal_open_round_trip_verifies_provenance() {
        let key = room_key(DEFAULT_ROOM);
        let me = requester(7);
        let sealed = seal_public_rollcall(&key, &me, &fields(DEFAULT_ROOM)).unwrap();
        let opened = open_rollcall(&key, &sealed).unwrap();
        assert_eq!(opened.room, DEFAULT_ROOM);
        assert_eq!(opened.requester_pubkey, me.public_key().to_vec());
        assert_eq!(opened.requester_handle, "river-otter#aabbccddeeff");
    }

    /// The same seal/open works under a CIRCLE key — the module is
    /// tier-agnostic; only the key (and thus who can open) differs.
    #[test]
    fn seal_open_round_trip_under_circle_key() {
        let _ = oxicrypt_module::initialize();
        let key = derive_cot_key(EXAMPLE_ENTROPY, &CNSA_2_0).unwrap();
        let me = requester(8);
        let sealed = seal_circle_rollcall(&key, &me, &fields("a circle")).unwrap();
        let opened = open_rollcall(&key, &sealed).unwrap();
        assert_eq!(opened.room, "a circle");
    }

    /// A re-sealed message with a flipped room (not re-signed) fails provenance:
    /// a roll-call signature cannot be replayed into a different room.
    #[test]
    fn tampered_room_rejected() {
        let key = room_key(DEFAULT_ROOM);
        let me = requester(9);
        // Sign for "lobby", then ship a message claiming a different room.
        let signing_input = provenance_input(DEFAULT_ROOM, me.public_key().as_ref(), 1);
        let signature = me.sign(&signing_input).unwrap().to_vec();
        let forged = wire::ShareRollCall {
            room: "another-room".to_owned(), // signature does not cover this
            requester_pubkey: me.public_key().to_vec(),
            requester_handle: "a#000000000000".to_owned(),
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
            SHARE_ROLLCALL_AAD,
            &plaintext,
            &mut ct,
            &mut tag,
        )
        .unwrap();
        let mut sealed = Vec::new();
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ct);
        sealed.extend_from_slice(&tag);

        match open_rollcall(&key, &sealed) {
            Err(ShareRollCallError::Provenance) => {}
            other => panic!("expected Provenance rejection, got {other:?}"),
        }
    }

    /// A wrong key (different room) fails AEAD authentication — the position a
    /// non-member / the relay (holding only ciphertext) is in.
    #[test]
    fn wrong_key_fails_authentication() {
        let lobby = room_key("lobby");
        let other = room_key("other-room");
        let me = requester(12);
        let sealed = seal_public_rollcall(&lobby, &me, &fields("lobby")).unwrap();
        match open_rollcall(&other, &sealed) {
            Err(ShareRollCallError::Authentication) => {}
            other => panic!("expected Authentication, got {other:?}"),
        }
    }

    /// A single flipped ciphertext bit fails authentication (GCM integrity).
    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let key = room_key(DEFAULT_ROOM);
        let me = requester(13);
        let mut sealed = seal_public_rollcall(&key, &me, &fields(DEFAULT_ROOM)).unwrap();
        let last = sealed.len() - TAG_LEN - 1;
        sealed[last] ^= 0x01;
        match open_rollcall(&key, &sealed) {
            Err(ShareRollCallError::Authentication) => {}
            other => panic!("expected Authentication, got {other:?}"),
        }
    }

    /// A buffer too short to hold `nonce ‖ tag` is rejected as truncated.
    #[test]
    fn truncated_envelope_rejected() {
        let key = room_key(DEFAULT_ROOM);
        let short = vec![0u8; NONCE_LEN + TAG_LEN - 1];
        match open_rollcall(&key, &short) {
            Err(ShareRollCallError::Truncated) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    /// Domain separation: a sealed roll-call cannot be opened as a share
    /// *announcement* (distinct AAD) even under the same key, and vice versa —
    /// the two payload kinds can never be confused or substituted.
    #[test]
    fn rollcall_and_announcement_are_not_substitutable() {
        let key = room_key(DEFAULT_ROOM);
        let me = requester(14);
        let rollcall = seal_public_rollcall(&key, &me, &fields(DEFAULT_ROOM)).unwrap();
        assert!(
            open_announcement(&key, &rollcall).is_err(),
            "a roll-call must not open as an announcement (AAD domain separation)"
        );

        let announcement = seal_public_announcement(
            &key,
            &me,
            &AnnouncementFields {
                room: DEFAULT_ROOM,
                sender_handle: "a#000000000000",
                share_id: "sid",
                root_commitment: &[0u8; 48],
                name: "n",
                rating: "PG",
                withdraw: false,
                sent_unix_ms: 1,
            },
        )
        .unwrap();
        assert!(
            open_rollcall(&key, &announcement).is_err(),
            "an announcement must not open as a roll-call (AAD domain separation)"
        );
    }
}
