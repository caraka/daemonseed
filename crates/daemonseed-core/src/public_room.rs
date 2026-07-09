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
use oxicrypt_kdf::HkdfSha384;
use oxicrypt_module::Error as OxicryptError;
use oxicrypt_sha::sha384;
use zeroize::Zeroize;

use crate::circle::key::{AeadKey256, COT_KEY_LEN};
use crate::cot::{ASSET_ADDR_LEN, AssetAddr};
use crate::crypto::suite::Suite;
use crate::identity::keys::SignKeypair;
use crate::kdf::info;
use crate::room_message::{open_signed_room_message, seal_signed_room_message};

pub use crate::room_message::RoomMessageError;

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

/// Length of a public-room Veilid rendezvous-owner seed: a 32-byte Ed25519
/// (VLD0) secret seed.
pub const ROOM_VEILID_OWNER_SEED_LEN: usize = 32;

/// A public room's Veilid **rendezvous-owner** seed (Phase 3/4 transport) — the
/// deterministic DHT-address sibling of [`derive_room_key`], the public-room
/// analog of [`crate::circle::key::CircleVeilidOwnerSeed`]. Every input is
/// public, so every participant derives the byte-identical owner keypair and
/// thus the same lobby/public-room rendezvous record key, with no relay and no
/// key exchange (the DHT analog of [`room_asset_address`]). Zeroes on drop;
/// `Debug` is redacted (ISC-A-C1). Content NEVER derives from this — it binds
/// only the DHT record-owner / rendezvous address.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct RoomVeilidOwnerSeed(Box<[u8; ROOM_VEILID_OWNER_SEED_LEN]>);

impl RoomVeilidOwnerSeed {
    /// Borrow the raw seed bytes to build a VLD0 keypair. Callers must not copy
    /// these into a non-zeroizing buffer.
    pub fn as_bytes(&self) -> &[u8; ROOM_VEILID_OWNER_SEED_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for RoomVeilidOwnerSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RoomVeilidOwnerSeed(<redacted>)")
    }
}

/// Derive a public room's Veilid rendezvous-owner seed from its public inputs —
/// the deterministic transport-address sibling of [`derive_room_key`]. Re-extract
/// the same public-room PRK (the [`info::PUBLIC_ROOM_KEY_SALT`] extract of the
/// family token), then expand under the OWNER label, so neither the owner seed
/// nor the room key is a function of the other — exactly mirroring
/// [`crate::circle::key::derive_circle_veilid_owner_seed`]. Family-anchored (like
/// the room key) so a cross-family change moves the rendezvous and the room key
/// together. World-derivable: every participant computes the same owner, so the
/// lobby/public room is an open rendezvous by construction (ISC-S22).
/// Shared body for the three public-room Veilid rendezvous-owner seed derivations
/// (chat / presence / share) — collapses the triplicated extract/expand/zeroize
/// plumbing so a future hardening change to one cannot silently diverge the others
/// (#153 review). Re-extract the public-room PRK (the [`info::PUBLIC_ROOM_KEY_SALT`]
/// extract of the family token) and expand under the caller's distinct `info` label
/// into a fresh 32-byte VLD0 seed, zeroizing the stack buffer on every path. The
/// distinct newtypes (`Room*VeilidOwnerSeed`) are kept for key-class safety; only
/// this body is shared.
fn expand_room_owner_seed(
    suite: &Suite,
    info_str: &str,
) -> Result<Box<[u8; ROOM_VEILID_OWNER_SEED_LEN]>, RoomKeyError> {
    let family = suite.family_token();
    let extract = HkdfSha384::extract(Some(info::PUBLIC_ROOM_KEY_SALT), family.as_bytes())
        .map_err(RoomKeyError::Hkdf)?;
    let mut seed = [0u8; ROOM_VEILID_OWNER_SEED_LEN];
    if let Err(e) = extract.expand(info_str.as_bytes(), &mut seed) {
        seed.zeroize();
        return Err(RoomKeyError::Hkdf(e));
    }
    let boxed = Box::new(seed);
    seed.zeroize();
    Ok(boxed)
}

pub fn derive_room_veilid_owner_seed(
    room: &str,
    suite: &Suite,
) -> Result<RoomVeilidOwnerSeed, RoomKeyError> {
    let info_str = info::public_room_veilid_owner(suite.family_token(), room);
    Ok(RoomVeilidOwnerSeed(expand_room_owner_seed(
        suite, &info_str,
    )?))
}

/// A public room's **presence** Veilid rendezvous-owner seed (Phase 4) — a
/// second, distinct sibling of [`derive_room_key`], separate from the chat
/// rendezvous owner ([`RoomVeilidOwnerSeed`]). Presence beacons ride their OWN
/// world-derivable DHT record so a ~15 s heartbeat can never evict the room
/// chat's 2-slot append-ring (P1). Same shape/hygiene as its sibling: 32-byte
/// VLD0 seed, zeroes on drop, redacted `Debug`. Content NEVER derives from this.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct RoomPresenceVeilidOwnerSeed(Box<[u8; ROOM_VEILID_OWNER_SEED_LEN]>);

impl RoomPresenceVeilidOwnerSeed {
    /// Borrow the raw seed bytes to build a VLD0 keypair. Callers must not copy
    /// these into a non-zeroizing buffer.
    pub fn as_bytes(&self) -> &[u8; ROOM_VEILID_OWNER_SEED_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for RoomPresenceVeilidOwnerSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RoomPresenceVeilidOwnerSeed(<redacted>)")
    }
}

/// Derive a public room's **presence** Veilid rendezvous-owner seed from its
/// public inputs — a sibling of [`derive_room_key`] under a distinct
/// (`info::public_room_presence_veilid_owner`) label, so presence rides its own
/// DHT record, disjoint from both the room key and the chat rendezvous owner
/// ([`derive_room_veilid_owner_seed`]). World-derivable (public inputs), so every
/// participant computes the same presence rendezvous. Family-anchored like its
/// siblings; content never derives from this.
pub fn derive_room_presence_veilid_owner_seed(
    room: &str,
    suite: &Suite,
) -> Result<RoomPresenceVeilidOwnerSeed, RoomKeyError> {
    let info_str = info::public_room_presence_veilid_owner(suite.family_token(), room);
    Ok(RoomPresenceVeilidOwnerSeed(expand_room_owner_seed(
        suite, &info_str,
    )?))
}

/// A public room's **share-discovery** Veilid rendezvous-owner seed (#153) — a
/// third, distinct sibling of [`derive_room_key`], separate from BOTH the chat
/// rendezvous owner ([`RoomVeilidOwnerSeed`]) and the presence owner
/// ([`RoomPresenceVeilidOwnerSeed`]). Public-share announcements ride their OWN
/// world-derivable DHT record so a share advert (a current-state writer) can never
/// silently overwrite the room chat's append-ring, and vice versa — the collision
/// #153 documents. Same shape/hygiene as its siblings: 32-byte VLD0 seed, zeroes
/// on drop, redacted `Debug`. Content NEVER derives from this.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct RoomShareVeilidOwnerSeed(Box<[u8; ROOM_VEILID_OWNER_SEED_LEN]>);

impl RoomShareVeilidOwnerSeed {
    /// Borrow the raw seed bytes to build a VLD0 keypair. Callers must not copy
    /// these into a non-zeroizing buffer.
    pub fn as_bytes(&self) -> &[u8; ROOM_VEILID_OWNER_SEED_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for RoomShareVeilidOwnerSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RoomShareVeilidOwnerSeed(<redacted>)")
    }
}

/// Derive a public room's **share-discovery** Veilid rendezvous-owner seed from
/// its public inputs — a sibling of [`derive_room_key`] under a distinct
/// (`info::public_room_share_veilid_owner`) label, so share announcements ride
/// their own DHT record, disjoint from both the room key and the chat/presence
/// rendezvous owners. World-derivable (public inputs), so every participant
/// computes the same share rendezvous. Family-anchored like its siblings; content
/// never derives from this.
pub fn derive_room_share_veilid_owner_seed(
    room: &str,
    suite: &Suite,
) -> Result<RoomShareVeilidOwnerSeed, RoomKeyError> {
    let info_str = info::public_room_share_veilid_owner(suite.family_token(), room);
    Ok(RoomShareVeilidOwnerSeed(expand_room_owner_seed(
        suite, &info_str,
    )?))
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

/// Seal a public-room message via the unified signed room-message path
/// ([`crate::room_message::seal_signed_room_message`]): SELF-SIGN it for
/// provenance (ISC-S24) then AES-256-GCM-seal the whole [`wire::RoomMessage`]
/// under the global room key (ISC-S22). `sender` is the posting daemon's OWN
/// identity keypair — any daemon may post; the signature establishes authorship,
/// not authorization. The public-room `room_id` is the room name; the AAD +
/// provenance domain are the public-room-specific [`ROOM_MESSAGE_AAD`] /
/// [`ROOM_PROVENANCE_DOMAIN`], distinct from the circle surface's.
pub fn seal_room_message(
    room_key: &PublicRoomKey,
    sender: &SignKeypair,
    room: &str,
    sender_handle: &str,
    body: &str,
    sent_unix_ms: i64,
) -> Result<Vec<u8>, RoomMessageError> {
    seal_signed_room_message(
        room_key,
        ROOM_MESSAGE_AAD,
        ROOM_PROVENANCE_DOMAIN,
        sender,
        room,
        sender_handle,
        body,
        sent_unix_ms,
    )
}

/// Open + VERIFY a sealed public-room envelope via the unified path
/// ([`crate::room_message::open_signed_room_message`]) — AES-256-GCM open under
/// the global room key (ISC-A-S16) then ML-DSA-87 provenance verification
/// (ISC-S24 / ISC-A-S17), both fail-closed. The signature is verified against
/// the caller-supplied `room` (the room the client subscribed to), never the
/// carried `room_id`. On success the recipient still binds the *displayed*
/// handle to `SHA-384(sender_pubkey)[:12]` (ISC-C4 / ISC-C57).
pub fn open_room_message(
    room_key: &PublicRoomKey,
    room: &str,
    sealed: &[u8],
) -> Result<wire::RoomMessage, RoomMessageError> {
    open_signed_room_message(
        room_key,
        ROOM_MESSAGE_AAD,
        ROOM_PROVENANCE_DOMAIN,
        sealed,
        room,
    )
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
        let opened = open_room_message(&key, DEFAULT_ROOM, &sealed).unwrap();
        assert_eq!(opened.body, "hello public room");
        assert_eq!(opened.sender_pubkey, sender.public_key().to_vec());
        assert_eq!(opened.room_id, DEFAULT_ROOM);
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
        use crate::room_message::provenance_input;
        use oxicrypt_aes::{Aes256Key, gcm_encrypt};
        let key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        let sender = keypair(9);
        // Forge a message: valid seal under the (public) global key, but the
        // signature covers a DIFFERENT body than the one we ship.
        let good_sig_input = provenance_input(
            ROOM_PROVENANCE_DOMAIN,
            DEFAULT_ROOM,
            sender.public_key().as_ref(),
            1,
            "the honest body",
        );
        let signature = sender.sign(&good_sig_input).unwrap().to_vec();
        let forged = wire::RoomMessage {
            room_id: DEFAULT_ROOM.to_owned(),
            sender_pubkey: sender.public_key().to_vec(),
            sender_handle: "a#000000000000".to_owned(),
            body: "TAMPERED body".to_owned(), // signature does not cover this
            sent_unix_ms: 1,
            signature,
        };
        let aes = Aes256Key::new(key.as_bytes()).unwrap();
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).unwrap();
        let plaintext = prost::Message::encode_to_vec(&forged);
        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = [0u8; 16];
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

        match open_room_message(&key, DEFAULT_ROOM, &sealed) {
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
        match open_room_message(&other, "other-room", &sealed) {
            Err(RoomMessageError::Authentication) => {}
            other => panic!("expected Authentication, got {other:?}"),
        }
    }

    /// The room rendezvous-owner seed is deterministic from PUBLIC inputs: every
    /// participant derives the byte-identical owner (→ same lobby rendezvous).
    #[test]
    fn room_owner_seed_is_deterministic() {
        let _ = oxicrypt_module::initialize();
        let a = derive_room_veilid_owner_seed(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        let b = derive_room_veilid_owner_seed(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    /// Distinct room names yield distinct rendezvous owners (the name is the
    /// sole distinguisher, so two rooms never share a rendezvous).
    #[test]
    fn room_owner_seed_distinct_rooms() {
        let _ = oxicrypt_module::initialize();
        let lobby = derive_room_veilid_owner_seed("lobby", &CNSA_2_0).unwrap();
        let news = derive_room_veilid_owner_seed("announcements", &CNSA_2_0).unwrap();
        assert_ne!(lobby.as_bytes(), news.as_bytes());
    }

    /// ISC-A-S18 / ISC-A-S2 domain separation: the room rendezvous-owner seed is
    /// a sibling of the room key (distinct `info`), so it equals neither the room
    /// key bytes nor a like-named circle's rendezvous-owner seed (distinct salt +
    /// `info`). Transport material never collides with content material, and the
    /// public tier never bleeds into the circle tier.
    #[test]
    fn room_owner_seed_disjoint_from_room_key_and_circle_owner() {
        use crate::circle::key::derive_circle_veilid_owner_seed;
        let _ = oxicrypt_module::initialize();
        let owner = derive_room_veilid_owner_seed("lobby", &CNSA_2_0).unwrap();
        let room_key = derive_room_key("lobby", &CNSA_2_0).unwrap();
        assert_ne!(
            owner.as_bytes(),
            room_key.as_bytes(),
            "room rendezvous owner must not equal the room content key"
        );
        let circle_owner = derive_circle_veilid_owner_seed("lobby", &CNSA_2_0).unwrap();
        assert_ne!(
            owner.as_bytes(),
            circle_owner.as_bytes(),
            "public-room and circle rendezvous-owner domains must be disjoint"
        );
    }

    /// Phase 4 presence — the room presence rendezvous-owner seed is deterministic
    /// from PUBLIC inputs (every participant derives the same presence record) and
    /// per-room (two rooms never share a presence rendezvous).
    #[test]
    fn room_presence_owner_seed_is_deterministic_and_per_room() {
        let _ = oxicrypt_module::initialize();
        let a = derive_room_presence_veilid_owner_seed(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        let b = derive_room_presence_veilid_owner_seed(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        let news = derive_room_presence_veilid_owner_seed("announcements", &CNSA_2_0).unwrap();
        assert_ne!(a.as_bytes(), news.as_bytes());
    }

    /// P1 domain separation — the room presence rendezvous owner is a THIRD,
    /// distinct sibling: it equals neither the room key, nor the chat rendezvous
    /// owner, nor a like-named circle's presence owner. Presence beacons therefore
    /// ride their own record (never the chat append-ring), and the two tiers stay
    /// disjoint.
    #[test]
    fn room_presence_owner_disjoint_from_all_siblings() {
        use crate::circle::key::derive_circle_presence_veilid_owner_seed;
        let _ = oxicrypt_module::initialize();
        let presence = derive_room_presence_veilid_owner_seed("lobby", &CNSA_2_0).unwrap();
        let room_key = derive_room_key("lobby", &CNSA_2_0).unwrap();
        let chat_owner = derive_room_veilid_owner_seed("lobby", &CNSA_2_0).unwrap();
        assert_ne!(presence.as_bytes(), room_key.as_bytes());
        assert_ne!(
            presence.as_bytes(),
            chat_owner.as_bytes(),
            "presence must ride its own record, not the chat rendezvous"
        );
        let circle_presence = derive_circle_presence_veilid_owner_seed("lobby", &CNSA_2_0).unwrap();
        assert_ne!(
            presence.as_bytes(),
            circle_presence.as_bytes(),
            "public-room and circle presence-owner domains must be disjoint"
        );
    }

    /// #153 domain separation — the share-discovery rendezvous owner is a FOURTH,
    /// distinct sibling: it equals neither the room key, nor the chat rendezvous
    /// owner, nor the presence owner. Share announcements therefore ride their own
    /// DHT record and can never silently overwrite the chat append-ring (or be
    /// overwritten by it). Deterministic from public inputs and per-room.
    #[test]
    fn room_share_owner_seed_is_deterministic_and_disjoint_from_all_siblings() {
        let _ = oxicrypt_module::initialize();
        let a = derive_room_share_veilid_owner_seed("lobby", &CNSA_2_0).unwrap();
        let b = derive_room_share_veilid_owner_seed("lobby", &CNSA_2_0).unwrap();
        assert_eq!(
            a.as_bytes(),
            b.as_bytes(),
            "world-derivable + deterministic"
        );
        let other_room = derive_room_share_veilid_owner_seed("announcements", &CNSA_2_0).unwrap();
        assert_ne!(a.as_bytes(), other_room.as_bytes(), "per-room");

        let room_key = derive_room_key("lobby", &CNSA_2_0).unwrap();
        let chat_owner = derive_room_veilid_owner_seed("lobby", &CNSA_2_0).unwrap();
        let presence = derive_room_presence_veilid_owner_seed("lobby", &CNSA_2_0).unwrap();
        assert_ne!(a.as_bytes(), room_key.as_bytes());
        assert_ne!(
            a.as_bytes(),
            chat_owner.as_bytes(),
            "shares must ride their own record, not the chat rendezvous (#153)"
        );
        assert_ne!(a.as_bytes(), presence.as_bytes());
    }
}
