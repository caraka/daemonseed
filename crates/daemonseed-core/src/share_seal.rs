//! Share-content sealing (unified share model — workstream A; design-of-record:
//! `docs/design/unified-share-model.md`).
//!
//! A [`ShareFrame`] (the manifest/chunk transfer codec, [`crate::share_envelope`])
//! is AES-256-GCM-sealed before it enters a `CotFrame.payload`, so share traffic
//! is **structurally indistinguishable** from chat traffic on the wire — closing
//! the one place the relay (or an observer) could tell a public-share frame from
//! a circle frame, since the alpha shipped public-share content in the clear.
//!
//! ```text
//!   ShareFrame ──encode──▶ plaintext ──AES-256-GCM(key)──▶ nonce(12) ‖ ct ‖ tag(16)
//! ```
//!
//! Two properties distinguish this from the chat/announcement seals:
//!
//! - **No provenance signature.** A content frame carries no ML-DSA signature:
//!   integrity is already inside the frame (each [`crate::share_envelope::ManifestEntry`]
//!   and [`ShareFrame::ChunkResponse`] is bound to a per-chunk SHA-384 the fetcher
//!   re-derives), and authorship is established once by the share *announcement*
//!   ([`crate::share_announce`]), not per frame. This seal is the confidentiality
//!   / indistinguishability layer only — the share-tier analogue of
//!   [`crate::circle::message`] (seal, no sign), not of [`crate::public_room`].
//! - **The key-class guard.** Sealing is tier-split: a public-share frame can
//!   only be sealed with a [`PublicRoomKey`] and a circle-share frame only with a
//!   [`CircleKey`] — the wrong tier's key is a compile error, so a circle share
//!   can never be silently sealed under the (public, anyone-derivable) room key.
//!   Opening is tier-agnostic ([`AeadKey256`]): a wrong key merely fails AEAD
//!   authentication, with no confidentiality loss.
//!
//! A distinct AAD ([`SHARE_FRAME_AAD`]) keeps a sealed content frame from ever
//! being opened as — or substituted from — a chat message, a public-room message,
//! or a share *announcement* under a coincidentally-equal key.

use oxicrypt_aes::{Aes256Key, ModeError, gcm_decrypt, gcm_encrypt};
use oxicrypt_module::Error as OxicryptError;
use zeroize::Zeroize;

use crate::circle::key::{AeadKey256, COT_KEY_LEN, CircleKey};
use crate::circle::message::{NONCE_LEN, TAG_LEN};
use crate::public_room::PublicRoomKey;
use crate::share_envelope::{self, ShareFrame};

/// Domain-separation tag bound as AEAD additional-authenticated-data for a sealed
/// share **content** frame, distinct from [`crate::circle::message::MESSAGE_AAD`],
/// [`crate::public_room::ROOM_MESSAGE_AAD`], and
/// [`crate::share_announce::SHARE_ANNOUNCE_AAD`] so a content frame can never be
/// opened/confused as any of those under an equal key.
pub const SHARE_FRAME_AAD: &[u8] = b"daemonseed/share/frame/v1";

/// Seal a share content frame for a PUBLIC share — AES-256-GCM under the public
/// room key. The output is `nonce ‖ ciphertext ‖ tag` for a `CotFrame.payload`.
/// Taking a [`PublicRoomKey`] (never a [`CircleKey`]) is the key-class guard.
pub fn seal_public_share_frame(
    key: &PublicRoomKey,
    frame: &ShareFrame,
) -> Result<Vec<u8>, ShareSealError> {
    seal_frame_with(key.as_bytes(), frame)
}

/// Seal a share content frame for a CIRCLE share — as
/// [`seal_public_share_frame`] but under the circle `cot_key`. Taking a
/// [`CircleKey`] (never a [`PublicRoomKey`]) is the key-class guard in the other
/// direction.
pub fn seal_circle_share_frame(
    key: &CircleKey,
    frame: &ShareFrame,
) -> Result<Vec<u8>, ShareSealError> {
    seal_frame_with(key.as_bytes(), frame)
}

/// Shared seal body, keyed by the raw 32-byte AEAD key the tier-split entry
/// points pass. Private, so the only public seal paths are the typed ones above.
fn seal_frame_with(
    key_bytes: &[u8; COT_KEY_LEN],
    frame: &ShareFrame,
) -> Result<Vec<u8>, ShareSealError> {
    let aes = Aes256Key::new(key_bytes).map_err(ShareSealError::KeyInit)?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(ShareSealError::EntropySource)?;

    let mut plaintext = frame.encode();
    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = [0u8; TAG_LEN];
    let result = gcm_encrypt(
        &aes,
        &nonce,
        SHARE_FRAME_AAD,
        &plaintext,
        &mut ciphertext,
        &mut tag,
    );
    plaintext.zeroize();
    result.map_err(ShareSealError::Aead)?;

    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len() + TAG_LEN);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    sealed.extend_from_slice(&tag);
    Ok(sealed)
}

/// Open a sealed share content frame back into a [`ShareFrame`]. Tier-agnostic
/// over [`AeadKey256`] — the caller opens with whichever tier key it holds; a
/// wrong key fails closed as [`ShareSealError::Authentication`] (no
/// confidentiality loss). A malformed inner frame fails as
/// [`ShareSealError::Decode`] — the same fail-closed posture
/// [`ShareFrame::decode`] already takes toward hostile relay noise.
pub fn open_share_frame<K: AeadKey256>(
    key: &K,
    sealed: &[u8],
) -> Result<ShareFrame, ShareSealError> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(ShareSealError::Truncated);
    }
    let nonce: &[u8; NONCE_LEN] = sealed[..NONCE_LEN].try_into().expect("checked length");
    let after_nonce = &sealed[NONCE_LEN..];
    let ciphertext_len = after_nonce.len() - TAG_LEN;
    let ciphertext = &after_nonce[..ciphertext_len];
    let tag: &[u8; TAG_LEN] = after_nonce[ciphertext_len..]
        .try_into()
        .expect("checked length");

    let aes = Aes256Key::new(key.aead_key_bytes()).map_err(ShareSealError::KeyInit)?;
    let mut plaintext = vec![0u8; ciphertext_len];
    gcm_decrypt(
        &aes,
        nonce,
        SHARE_FRAME_AAD,
        ciphertext,
        tag,
        &mut plaintext,
    )
    .map_err(|e| match e {
        ModeError::TagMismatch => ShareSealError::Authentication,
        other => ShareSealError::Aead(other),
    })?;

    let decoded = ShareFrame::decode(&plaintext);
    plaintext.zeroize();
    decoded.map_err(ShareSealError::Decode)
}

/// Failure sealing/opening a share content frame.
#[derive(Debug)]
pub enum ShareSealError {
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
    /// The decrypted bytes did not decode as a [`ShareFrame`].
    Decode(share_envelope::DecodeError),
}

impl core::fmt::Display for ShareSealError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::KeyInit(e) => write!(f, "share-frame AES key init failed: {e}"),
            Self::EntropySource(e) => write!(f, "share-frame nonce entropy failed: {e}"),
            Self::Aead(e) => write!(f, "share-frame AEAD error: {e:?}"),
            Self::Authentication => write!(f, "share-frame authentication failed"),
            Self::Truncated => write!(f, "share-frame envelope is truncated"),
            Self::Decode(e) => write!(f, "share-frame decode failed: {e}"),
        }
    }
}

impl core::error::Error for ShareSealError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circle::key::derive_cot_key;
    use crate::crypto::suite::CNSA_2_0;
    use crate::public_room::{DEFAULT_ROOM, derive_room_key};
    use crate::share_announce::{AnnouncementFields, open_announcement, seal_public_announcement};
    use crate::share_envelope::{ManifestEntry, ShareFrame};

    fn room_key() -> PublicRoomKey {
        let _ = oxicrypt_module::initialize();
        derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap()
    }

    fn circle_key() -> CircleKey {
        let _ = oxicrypt_module::initialize();
        derive_cot_key("a shared circle phrase for sealing", &CNSA_2_0).unwrap()
    }

    /// A manifest response naming one (empty) file — no chunk addresses needed,
    /// so the fixture stands alone without the CAS hasher.
    fn manifest_frame(rel_path: &str) -> ShareFrame {
        ShareFrame::ManifestResponse {
            entries: vec![ManifestEntry {
                rel_path: rel_path.to_owned(),
                size: 0,
                chunks: Vec::new(),
            }],
        }
    }

    /// Round-trip under the PUBLIC room key: a sealed content frame opens back to
    /// the identical frame.
    #[test]
    fn public_frame_round_trips() {
        let key = room_key();
        let frame = manifest_frame("docs/readme.txt");
        let sealed = seal_public_share_frame(&key, &frame).unwrap();
        assert_eq!(open_share_frame(&key, &sealed).unwrap(), frame);
    }

    /// Round-trip under a CIRCLE key — the seal is tier-agnostic in mechanism;
    /// only the key (and thus who can open) differs.
    #[test]
    fn circle_frame_round_trips() {
        let key = circle_key();
        let frame = ShareFrame::ManifestRequest;
        let sealed = seal_circle_share_frame(&key, &frame).unwrap();
        assert_eq!(open_share_frame(&key, &sealed).unwrap(), frame);
    }

    /// The frame contents are NEVER present in the sealed bytes (the whole point:
    /// a public share's content stops riding the wire in the clear).
    #[test]
    fn frame_never_wire_cleartext() {
        let key = room_key();
        let secret_path = "uniquely-identifiable-folder/secret-name-12345.txt";
        let sealed = seal_public_share_frame(&key, &manifest_frame(secret_path)).unwrap();
        assert!(
            !sealed
                .windows(secret_path.len())
                .any(|w| w == secret_path.as_bytes()),
            "the rel_path must not appear in the sealed wire bytes"
        );
    }

    /// A wrong key fails authentication — the position the relay (holding only
    /// ciphertext) or a non-member is in.
    #[test]
    fn wrong_key_fails_authentication() {
        let lobby = derive_room_key("lobby", &CNSA_2_0).unwrap();
        let other = derive_room_key("a-different-room", &CNSA_2_0).unwrap();
        let _ = oxicrypt_module::initialize();
        let sealed = seal_public_share_frame(&lobby, &manifest_frame("f.txt")).unwrap();
        match open_share_frame(&other, &sealed) {
            Err(ShareSealError::Authentication) => {}
            other => panic!("expected Authentication, got {other:?}"),
        }
    }

    /// A single flipped ciphertext bit fails authentication (GCM integrity).
    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let key = room_key();
        let mut sealed = seal_public_share_frame(&key, &manifest_frame("intact.txt")).unwrap();
        let last = sealed.len() - TAG_LEN - 1;
        sealed[last] ^= 0x01;
        match open_share_frame(&key, &sealed) {
            Err(ShareSealError::Authentication) => {}
            other => panic!("expected Authentication, got {other:?}"),
        }
    }

    /// A buffer too short to hold `nonce ‖ tag` is rejected as truncated.
    #[test]
    fn truncated_envelope_rejected() {
        let key = room_key();
        let short = vec![0u8; NONCE_LEN + TAG_LEN - 1];
        match open_share_frame(&key, &short) {
            Err(ShareSealError::Truncated) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    /// Domain separation: a sealed content frame cannot be opened as a share
    /// *announcement* (distinct AAD) even under the same key — it fails closed,
    /// so the two payload kinds can never be confused or substituted.
    #[test]
    fn content_frame_cannot_open_as_announcement() {
        let key = room_key();
        let sealed = seal_public_share_frame(&key, &manifest_frame("f.txt")).unwrap();
        assert!(
            open_announcement(&key, &sealed).is_err(),
            "a content frame must not open as an announcement (AAD domain separation)"
        );
    }

    /// And the converse: a sealed announcement cannot be opened as a content
    /// frame.
    #[test]
    fn announcement_cannot_open_as_content_frame() {
        let _ = oxicrypt_module::initialize();
        let key = room_key();
        let announcer = crate::identity::keys::SignKeypair::from_ml_dsa_seed(&[5u8; 32]).unwrap();
        let sealed = seal_public_announcement(
            &key,
            &announcer,
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
            open_share_frame(&key, &sealed).is_err(),
            "an announcement must not open as a content frame (AAD domain separation)"
        );
    }
}
