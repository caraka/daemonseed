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
use oxicrypt_kdf::HkdfSha384;
use oxicrypt_module::Error as OxicryptError;
use oxicrypt_sha::sha384;
use prost::Message;
use zeroize::Zeroize;

use crate::circle::key::{AeadKey256, COT_KEY_LEN, CircleKey};
use crate::circle::message::{NONCE_LEN, TAG_LEN};
use crate::identity::keys::{SignKeypair, verify_signature};
use crate::public_room::PublicRoomKey;
use oxicrypt_ml_dsa as ml_dsa;

/// Domain-separation tag bound as AEAD additional-authenticated-data for the
/// share-announcement seal, distinct from [`crate::circle::message::MESSAGE_AAD`],
/// [`crate::public_room::ROOM_MESSAGE_AAD`], AND from
/// [`SHARE_ANNOUNCE_PROVENANCE_DOMAIN`] (the #156 v2 split — the two were an
/// identical string under v1) so an announcement can never be opened/confused as
/// a chat or public-room message, nor its AEAD-AAD confused with its provenance
/// domain, under an equal key.
pub const SHARE_ANNOUNCE_AAD: &[u8] = b"daemonseed/share/announce/aad/v2";

/// Domain-separation prefix for the announcement's provenance signature, bound
/// first so a share-announcement signature can never be replayed as any other
/// ML-DSA-87 signature daemonseed produces. Distinct from [`SHARE_ANNOUNCE_AAD`]
/// (the #156 v2 split — they were the same string under v1).
pub const SHARE_ANNOUNCE_PROVENANCE_DOMAIN: &[u8] = b"daemonseed/share/announce/provenance/v2";

/// Mint an opaque, unpredictable `share_id`: 128 bits from the OS CSPRNG,
/// lowercase-hex encoded (32 chars). **Retired from every publish path at #156**
/// (a randomly-minted id is not receiver-verifiable — a v2 receiver rejects it, an
/// availability cliff): publishers MUST derive via [`derive_share_id_v2`]. Retained
/// only as a test helper (an opaque-but-arbitrary / deliberately-non-derivable id);
/// it appears at NO production publish site. An OS-entropy failure is unrecoverable,
/// so this panics rather than degrade to a predictable id.
pub fn mint_share_id() -> String {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("OS CSPRNG entropy for share_id");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Domain separation for [`derive_share_id`] — distinct from every other label
/// the identity key material feeds, so the derivation can't collide with another
/// protocol input.
const SHARE_ID_DERIVE_DOMAIN: &[u8] = b"daemonseed/share-id/v1";

// ── Receiver-verifiable v2 binding (#156; docs/design/share-id-binding.md) ────
//
// FROZEN constants — a second implementation MUST reproduce every value below
// byte-for-byte, or a republish re-mints the `share_id` (the #112/#118
// ghost-share bug). Do not change without a coordinated cutover.

/// Pinned, non-empty HKDF-Extract salt for the per-share hiding nonce (#156). No
/// implicit zero-salt: the salt is normative. FROZEN.
pub const SHARE_NONCE_SALT: &[u8] = b"daemonseed/share-root-nonce-salt/v2";

/// HKDF-Expand `info` domain-label for the per-share hiding nonce. FROZEN.
const SHARE_ROOT_NONCE_DOMAIN: &[u8] = b"daemonseed/share-root-nonce/v2";

/// Domain label for the SHA-384 `root_commitment`. FROZEN.
const SHARE_ROOT_COMMITMENT_DOMAIN: &[u8] = b"daemonseed/share-root-commitment/v2";

/// Domain label for the v2 `share_id` derivation. FROZEN.
const SHARE_ID_V2_DOMAIN: &[u8] = b"daemonseed/share-id/v2";

/// Byte length of the per-share hiding nonce. Normative / FROZEN.
pub const SHARE_ROOT_NONCE_LEN: usize = 32;

/// Byte length of the `root_commitment` carried on the wire (a SHA-384 digest).
/// Normative / FROZEN — ingest hard-rejects any other length.
pub const ROOT_COMMITMENT_LEN: usize = 48;

/// Length-prefix helper: append `len(bytes) as u64 BE ‖ bytes`, so every
/// variable-length input is unambiguously bounded (matches [`provenance_input`]'s
/// `push_field`). `lp(x)` in the design.
fn push_lp(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Derive the per-share hiding nonce (#156): `HKDF-SHA-384(salt =
/// [`SHARE_NONCE_SALT`], ikm = the identity's [`crate::identity::keys::ShareRootIkm`]
/// bytes, info = lp([`SHARE_ROOT_NONCE_DOMAIN`]) ‖ lp(root))` → exactly
/// [`SHARE_ROOT_NONCE_LEN`] bytes. Deterministic per `(identity, root)`, secret,
/// never persisted, never on the wire — re-derivable at every republish so the
/// `share_id` is stable. Panics only on an unrecoverable crypto-module failure.
pub fn derive_share_root_nonce(ikm: &[u8], root: &str) -> [u8; SHARE_ROOT_NONCE_LEN] {
    let hkdf = HkdfSha384::extract(Some(SHARE_NONCE_SALT), ikm)
        .expect("HKDF-Extract for share-root nonce");
    let mut info = Vec::new();
    push_lp(&mut info, SHARE_ROOT_NONCE_DOMAIN);
    push_lp(&mut info, root.as_bytes());
    let mut out = [0u8; SHARE_ROOT_NONCE_LEN];
    hkdf.expand(&info, &mut out)
        .expect("HKDF-Expand for share-root nonce");
    out
}

/// Derive the `root_commitment` (#156): `SHA-384(lp([`SHARE_ROOT_COMMITMENT_DOMAIN`])
/// ‖ lp(root) ‖ lp(nonce))` → [`ROOT_COMMITMENT_LEN`] bytes. An opaque per-share
/// witness that keeps `root` off the wire while making `share_id` receiver-
/// recomputable. Hiding, because `nonce` is secret-derived. Panics only on an
/// unrecoverable crypto-module failure.
pub fn derive_root_commitment(root: &str, nonce: &[u8]) -> [u8; ROOT_COMMITMENT_LEN] {
    let mut input = Vec::new();
    push_lp(&mut input, SHARE_ROOT_COMMITMENT_DOMAIN);
    push_lp(&mut input, root.as_bytes());
    push_lp(&mut input, nonce);
    sha384(&input).expect("crypto module for root_commitment derivation")
}

/// Derive the receiver-verifiable v2 `share_id` (#156): `SHA-384(lp(
/// [`SHARE_ID_V2_DOMAIN`]) ‖ lp(sender_pubkey) ‖ lp(root_commitment))[..16]`,
/// lowercase-hex (32 chars). The id bakes the publisher key in, so occupying a
/// *specific* victim id is a fixed-target truncated-SHA-384 second preimage (2^128,
/// no birthday shortcut). A receiver recomputes this from the announcement's own
/// `sender_pubkey` + `root_commitment` (no secret needed) and rejects any
/// mismatch. Panics only on an unrecoverable crypto-module failure.
pub fn derive_share_id_v2(sender_pubkey: &[u8], root_commitment: &[u8]) -> String {
    let mut input = Vec::new();
    push_lp(&mut input, SHARE_ID_V2_DOMAIN);
    push_lp(&mut input, sender_pubkey);
    push_lp(&mut input, root_commitment);
    let digest = sha384(&input).expect("crypto module for share_id v2 derivation");
    digest[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// The receiver-side v2 binding check (#156) — the single self-contained predicate
/// every ingest point gates on: the `root_commitment` MUST be exactly
/// [`ROOT_COMMITMENT_LEN`] bytes AND `share_id == derive_share_id_v2(sender_pubkey,
/// root_commitment)`. Needs ONLY wire fields (no IKM), so it runs identically at
/// the catalog fold, the route-import gate, and the circle path. There is NO
/// legacy / owner-binding fallback for an absent or malformed commitment — proto3
/// decodes an omitted `root_commitment` as empty bytes, and this rejects it
/// (design §2/§5 anti-requirement).
pub fn share_binding_is_valid(ann: &wire::ShareAnnouncement) -> bool {
    ann.root_commitment.len() == ROOT_COMMITMENT_LEN
        && ann.share_id == derive_share_id_v2(&ann.sender_pubkey, &ann.root_commitment)
}

/// Derive a DETERMINISTIC `share_id` for `root` under the publisher's stable
/// identity public key `sender_pubkey`. Unlike [`mint_share_id`], the same
/// (identity, root) always yields the same id, so a republish (e.g. on reconnect
/// under a fresh ephemeral node) re-asserts the SAME id and a fetcher folds it
/// onto its existing catalog entry instead of seeing a second, dead-route copy.
/// Output shape matches `mint_share_id`: SHA-384 over a domain-separated,
/// length-prefixed `(pubkey ‖ root)`, truncated to 128 bits, lowercase-hex
/// (32 chars). This adds no linkability — the announcement already carries
/// `sender_pubkey` as its provenance + verification anchor, so an observer can
/// already tie the publisher to the share (Demonsaw lineage: a derived, stable
/// share id). Panics only on an unrecoverable crypto-module failure, the same
/// posture as `mint_share_id`'s entropy draw.
/// **Superseded by [`derive_share_id_v2`] (#156).** No publish path calls this —
/// every publisher moved to the receiver-verifiable v2 derivation. Retained only
/// for its own unit tests; a v2 receiver rejects any id this produces. Do NOT wire
/// it into a publish path (that would re-open the #112/#118 re-mint / availability
/// cliff).
pub fn derive_share_id(sender_pubkey: &[u8], root: &str) -> String {
    let mut input =
        Vec::with_capacity(SHARE_ID_DERIVE_DOMAIN.len() + 16 + sender_pubkey.len() + root.len());
    input.extend_from_slice(SHARE_ID_DERIVE_DOMAIN);
    input.extend_from_slice(&(sender_pubkey.len() as u64).to_be_bytes());
    input.extend_from_slice(sender_pubkey);
    input.extend_from_slice(&(root.len() as u64).to_be_bytes());
    input.extend_from_slice(root.as_bytes());
    let digest = sha384(&input).expect("crypto module for share_id derivation");
    digest[..16].iter().map(|b| format!("{b:02x}")).collect()
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
    /// address from it. At #156 this MUST be
    /// [`derive_share_id_v2`]`(announcer_pubkey, root_commitment)`.
    pub share_id: &'a str,
    /// The receiver-verifiable root commitment (#156), exactly
    /// [`ROOT_COMMITMENT_LEN`] bytes ([`derive_root_commitment`]). Carried on the
    /// wire; the receiver recomputes `share_id` from `(announcer_pubkey, this)`.
    pub root_commitment: &'a [u8],
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
#[allow(clippy::too_many_arguments)]
fn provenance_input(
    room: &str,
    sender_pubkey: &[u8],
    share_id: &str,
    root_commitment: &[u8],
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
    // #156: bind the root_commitment into the signed transcript (defense-in-depth
    // — the id already commits to it transitively, but signing it directly means a
    // valid signature never covers a mismatched commitment even before the ingest
    // derive-check runs).
    push_field(root_commitment);
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
        fields.root_commitment,
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
        root_commitment: fields.root_commitment.to_vec(),
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
        &message.root_commitment,
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

    /// A fixed 48-byte commitment for round-trip tests that don't exercise the
    /// binding derivation (seal never validates the commitment; ingest does).
    const TEST_RC: &[u8] = &[7u8; ROOT_COMMITMENT_LEN];

    fn announcer(seed: u8) -> SignKeypair {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        SignKeypair::from_ml_dsa_seed(&[seed; 32]).unwrap()
    }

    fn fields<'a>(share_id: &'a str, name: &'a str, withdraw: bool) -> AnnouncementFields<'a> {
        AnnouncementFields {
            room: DEFAULT_ROOM,
            sender_handle: "river-otter#aabbccddeeff",
            share_id,
            root_commitment: TEST_RC,
            name,
            rating: "PG",
            withdraw,
            sent_unix_ms: 1_700_000_000_000,
        }
    }

    /// Derive a public room key, initializing the crypto module first so each
    /// test stands alone (no cross-test ordering dependency).
    fn room_key(room: &str) -> PublicRoomKey {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
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

    /// A derived share_id is the same shape as a minted one, deterministic for a
    /// given (identity, root), and varies with either input — so a republish
    /// re-asserts the SAME id (no duplicate) while distinct shares stay distinct.
    #[test]
    fn derive_share_id_is_deterministic_and_shaped() {
        let kp = announcer(7);
        let pk = kp.public_key();
        let a = derive_share_id(pk, "/srv/docs");
        assert_eq!(a.len(), 32);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        // Stable across calls (the property that kills the duplicate-share bug).
        assert_eq!(a, derive_share_id(pk, "/srv/docs"));
        // A different root → a different id.
        assert_ne!(a, derive_share_id(pk, "/srv/other"));
        // A different identity → a different id (no cross-publisher collision).
        assert_ne!(a, derive_share_id(announcer(8).public_key(), "/srv/docs"));
    }

    /// #156: the full v2 pipeline is self-consistent — a nonce derived from an
    /// IKM + root yields a commitment, the commitment + pubkey yield an id, and
    /// `share_binding_is_valid` accepts exactly that (announcer_pubkey, id, rc)
    /// triple. Deterministic across calls (the stable-republish property).
    #[test]
    fn v2_derivation_round_trips_and_binding_validates() {
        let kp = announcer(3);
        let pk = kp.public_key();
        let ikm = [42u8; 32];
        let root = "/srv/photos";
        let nonce = derive_share_root_nonce(&ikm, root);
        assert_eq!(nonce.len(), SHARE_ROOT_NONCE_LEN);
        // Deterministic: the whole chain re-derives identically (kills #112/#118).
        assert_eq!(nonce, derive_share_root_nonce(&ikm, root));
        let rc = derive_root_commitment(root, &nonce);
        assert_eq!(rc.len(), ROOT_COMMITMENT_LEN);
        let id = derive_share_id_v2(pk, &rc);
        assert_eq!(id.len(), 32);
        assert!(
            id.bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        let ann = wire::ShareAnnouncement {
            room: DEFAULT_ROOM.to_owned(),
            sender_pubkey: pk.to_vec(),
            sender_handle: String::new(),
            share_id: id.clone(),
            root_commitment: rc.to_vec(),
            name: "photos".to_owned(),
            rating: String::new(),
            withdraw: false,
            sent_unix_ms: 1,
            signature: Vec::new(),
        };
        assert!(
            share_binding_is_valid(&ann),
            "genuine derived triple validates"
        );
    }

    /// #156 (occupation resistance): an attacker pairing a victim's `share_id`
    /// with the attacker's OWN key fails the binding check — the id bakes the key
    /// in, so a different pubkey never recomputes to the same id.
    #[test]
    fn v2_binding_rejects_forged_pairing() {
        let victim = announcer(4);
        let attacker = announcer(5);
        let ikm = [1u8; 32];
        let root = "/victim/secret";
        let nonce = derive_share_root_nonce(&ikm, root);
        let rc = derive_root_commitment(root, &nonce);
        let victim_id = derive_share_id_v2(victim.public_key(), &rc);
        // Attacker scrapes victim_id + rc and announces under its own key.
        let forged = wire::ShareAnnouncement {
            room: DEFAULT_ROOM.to_owned(),
            sender_pubkey: attacker.public_key().to_vec(),
            sender_handle: String::new(),
            share_id: victim_id,
            root_commitment: rc.to_vec(),
            name: "evil".to_owned(),
            rating: String::new(),
            withdraw: false,
            sent_unix_ms: 1,
            signature: Vec::new(),
        };
        assert!(
            !share_binding_is_valid(&forged),
            "a victim id under the attacker's key must not validate"
        );
    }

    /// #156 (unconditional reject): an absent or non-48-byte `root_commitment`
    /// fails the binding check outright — no legacy / owner-binding fallback arm.
    #[test]
    fn v2_binding_rejects_absent_or_malformed_commitment() {
        let kp = announcer(6);
        let ikm = [9u8; 32];
        let root = "/some/path";
        let nonce = derive_share_root_nonce(&ikm, root);
        let rc = derive_root_commitment(root, &nonce);
        let id = derive_share_id_v2(kp.public_key(), &rc);
        let base = |root_commitment: Vec<u8>| wire::ShareAnnouncement {
            room: DEFAULT_ROOM.to_owned(),
            sender_pubkey: kp.public_key().to_vec(),
            sender_handle: String::new(),
            share_id: id.clone(),
            root_commitment,
            name: "n".to_owned(),
            rating: String::new(),
            withdraw: false,
            sent_unix_ms: 1,
            signature: Vec::new(),
        };
        // Empty (the proto3-default for an omitted field) is rejected.
        assert!(!share_binding_is_valid(&base(Vec::new())));
        // Wrong length is rejected even if it is a prefix of the real commitment.
        assert!(!share_binding_is_valid(&base(rc[..47].to_vec())));
        assert!(!share_binding_is_valid(&base(vec![
            0u8;
            ROOT_COMMITMENT_LEN + 1
        ])));
    }

    /// #156 (path-secrecy): the commitment for the SAME root differs across two
    /// identities' IKMs — the nonce is secret-derived, so a peer cannot confirm a
    /// guessed folder path by recomputing the commitment.
    #[test]
    fn v2_commitment_differs_across_identities_for_same_root() {
        let root = "/shared/name";
        let rc_a = derive_root_commitment(root, &derive_share_root_nonce(&[1u8; 32], root));
        let rc_b = derive_root_commitment(root, &derive_share_root_nonce(&[2u8; 32], root));
        assert_ne!(
            rc_a, rc_b,
            "distinct IKMs → distinct commitments for one root"
        );
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
        let _ = crate::kats::initialize_module_unsigned_test_binary();
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
            TEST_RC,
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
            root_commitment: TEST_RC.to_vec(),
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
