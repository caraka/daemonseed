//! Circle-of-trust key derivation (ISC-C8 / ISC-C9).
//!
//! A circle is born from shared entropy (a passphrase/sentence agreed among
//! members out-of-band). The entropy is the **sole** circle secret and the
//! **sole** distinguisher — there is no circle name, no per-circle salt, no
//! founder, and no signed metadata record (F16, resolved 2026-05-26). Two
//! circles differ iff their entropy differs; a collision requires
//! deliberately sharing the same phrase, which in the seed-key model *is*
//! being the same circle.
//!
//! ```text
//! entropy (raw text)
//!   → circle_canonicalize::canonicalize   (NFKC + whitespace, ISC-C9)
//!   → HkdfSha384::extract(salt = CIRCLE_KEY_SALT, ikm = canonical)   // PRK
//!   → expand(info = "daemonseed/circle/<family>")  → 32-byte cot_key
//! ```
//!
//! **Family-anchored, not suite-anchored.** The derivation is keyed on the
//! crypto *family* (KDF+hash, [`Suite::family_token`]), never the volatile
//! `suite_id`. Within-family server suite ratchets (which add/remove
//! asymmetric algos) leave `cot_key` unchanged, so every member connecting
//! under any same-family suite derives the byte-identical key. Only a
//! cross-family change re-derives — the circle-rekey/new-circle event of
//! ISC-A-C8.
//!
//! Strength gating (≥128-bit, ISC-C9) is the caller's responsibility via
//! [`crate::passphrase::strength`]; this function derives unconditionally.

use core::fmt::Write as _;

use oxicrypt_kdf::HkdfSha384;
use oxicrypt_sha::sha384;
use zeroize::Zeroize;

use crate::crypto::suite::Suite;
use crate::kdf::info;
use crate::passphrase::circle_canonicalize;

/// Length of a circle-of-trust key — 32 bytes for AES-256-GCM (ISC-C8).
pub const COT_KEY_LEN: usize = 32;

/// A public, illustrative circle entropy — the xkcd-936 passphrase.
///
/// **Not for real use.** It is published here as a *teaching example*, so the
/// `cot_key` it derives is public knowledge and any circle built from it is
/// public by construction. The client pre-fills it as the circle-creation
/// placeholder (M11 surface) so a user can watch entropy → key derive locally,
/// edit it, and see the key change — then clear it and type their own secret.
/// It is **never auto-joined to a relay**: nothing is private, and nothing
/// reaches the network, until the user supplies their own phrase. This is the
/// pedagogy of the seed-key model without the footgun of a live shared circle.
///
/// ```no_run
/// use daemonseed_core::circle::key::{derive_cot_key, EXAMPLE_ENTROPY};
/// use daemonseed_core::crypto::suite::CNSA_2_0;
/// // Every member who types this same phrase derives the identical key.
/// let key = derive_cot_key(EXAMPLE_ENTROPY, &CNSA_2_0).unwrap();
/// let _ = key;
/// ```
pub const EXAMPLE_ENTROPY: &str = "correct horse battery staple";

/// A derived circle-of-trust symmetric key. Zeroes on drop; `Debug` is
/// redacted so it never lands in a log surface (ISC-A-C1).
#[derive(zeroize::ZeroizeOnDrop)]
pub struct CircleKey(Box<[u8; COT_KEY_LEN]>);

impl CircleKey {
    /// Borrow the raw key bytes for AEAD use. Callers must not copy these
    /// into a non-zeroizing buffer.
    pub fn as_bytes(&self) -> &[u8; COT_KEY_LEN] {
        &self.0
    }

    /// Wrap raw key bytes into a zeroizing [`CircleKey`] (e.g. reconstructing a
    /// circle key from at-rest storage). The caller zeroes its own copy of
    /// `bytes` after this call (the boxed copy here zeroes on drop).
    pub fn from_bytes(bytes: [u8; COT_KEY_LEN]) -> Self {
        CircleKey(Box::new(bytes))
    }
}

impl core::fmt::Debug for CircleKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CircleKey(<redacted>)")
    }
}

/// A 32-byte AEAD key, abstracted so a *decrypt/open* path can accept either
/// tier's key — a [`CircleKey`] or a [`crate::public_room::PublicRoomKey`] —
/// without the two becoming substitutable at a *seal* site. Sealing is
/// type-split per tier (a circle payload can only be sealed with a `CircleKey`,
/// a public payload only with a `PublicRoomKey` — the wrong one is a compile
/// error, the key-class guard); opening is tier-agnostic because a wrong key
/// merely fails AEAD authentication with no confidentiality loss.
pub trait AeadKey256 {
    /// The raw 32-byte key for AEAD use. Callers must not copy it into a
    /// non-zeroizing buffer.
    fn aead_key_bytes(&self) -> &[u8; COT_KEY_LEN];
}

impl AeadKey256 for CircleKey {
    fn aead_key_bytes(&self) -> &[u8; COT_KEY_LEN] {
        self.as_bytes()
    }
}

/// Failure modes for [`derive_cot_key`].
#[derive(Debug)]
pub enum CircleKeyError {
    /// The HKDF extract/expand step failed (e.g. invalid output length).
    Hkdf(oxicrypt_kdf::KdfError),
}

impl core::fmt::Display for CircleKeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CircleKeyError::Hkdf(e) => write!(f, "circle-key HKDF failed: {e:?}"),
        }
    }
}

impl core::error::Error for CircleKeyError {}

/// Derive the circle-of-trust key from shared entropy under a crypto family
/// (ISC-C8). `entropy` is raw text; it is canonicalized (ISC-C9) internally
/// so every member who agrees on the same phrase — regardless of incidental
/// whitespace or Unicode form — derives the byte-identical key.
pub fn derive_cot_key(entropy: &str, suite: &Suite) -> Result<CircleKey, CircleKeyError> {
    // ISC-C9: canonicalize so members agreeing on the same phrase — modulo
    // incidental whitespace / Unicode form — derive the identical key. The
    // canonical form is secret-adjacent, so zero it the moment HKDF-Extract
    // has consumed it (mirrors the identity-derivation hygiene).
    let mut canonical = circle_canonicalize::canonicalize(entropy);
    let extract = HkdfSha384::extract(Some(info::CIRCLE_KEY_SALT), canonical.as_bytes());
    canonical.zeroize();
    let hkdf = extract.map_err(CircleKeyError::Hkdf)?;

    // ISC-C8: family-anchored info string. `family_token` swaps only on a
    // cross-family change, so within-family suite ratchets are transparent.
    let info_str = info::circle(suite.family_token());

    let mut key = [0u8; COT_KEY_LEN];
    if let Err(e) = hkdf.expand(info_str.as_bytes(), &mut key) {
        key.zeroize();
        return Err(CircleKeyError::Hkdf(e));
    }
    let boxed = Box::new(key);
    key.zeroize();
    Ok(CircleKey(boxed))
}

/// Length of a circle's Veilid rendezvous-owner seed — 32 bytes (a VLD0
/// Ed25519 seed).
pub const CIRCLE_VEILID_OWNER_SEED_LEN: usize = 32;

/// A circle's deterministic Veilid **rendezvous-owner** seed (Phase 2
/// transport): the 32-byte VLD0 (Ed25519) seed every member derives from the
/// shared circle entropy, so all members independently compute the SAME DHT
/// record key — the circle's relay-free rendezvous address (the DHT analog of
/// the relay-era `SHA-384(cot_key ‖ server_id)`). Zeroes on drop; `Debug` is
/// redacted (ISC-A-C1).
///
/// It is a **sibling** of [`derive_cot_key`]: both expand the same circle PRK
/// but under different `info` labels, so the rendezvous address is not a
/// function of the content key and vice versa. Every circle member can derive
/// it, and therefore every member can act as the DHT record owner — the trust
/// set is identical to the one that already holds `cot_key`, so this opens no
/// new boundary. The content key is unaffected: content NEVER derives from
/// transport material.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct CircleVeilidOwnerSeed(Box<[u8; CIRCLE_VEILID_OWNER_SEED_LEN]>);

impl CircleVeilidOwnerSeed {
    /// Borrow the raw seed bytes to build a VLD0 keypair. Callers must not copy
    /// these into a non-zeroizing buffer.
    pub fn as_bytes(&self) -> &[u8; CIRCLE_VEILID_OWNER_SEED_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for CircleVeilidOwnerSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CircleVeilidOwnerSeed(<redacted>)")
    }
}

/// Derive a circle's Veilid rendezvous-owner seed from shared entropy — the
/// deterministic transport-address sibling of [`derive_cot_key`]. `entropy` is
/// canonicalized identically (ISC-C9), so every member who agrees on the phrase
/// derives the byte-identical owner seed, and thus the same rendezvous record
/// key. Family-anchored (like the content key) so a cross-family rekey moves
/// the rendezvous and the content key together.
pub fn derive_circle_veilid_owner_seed(
    entropy: &str,
    suite: &Suite,
) -> Result<CircleVeilidOwnerSeed, CircleKeyError> {
    // Re-extract the same circle PRK (same salt + canonical entropy as
    // derive_cot_key), then expand under the OWNER label — a sibling expansion,
    // so neither the owner seed nor the content key is a function of the other.
    let mut canonical = circle_canonicalize::canonicalize(entropy);
    let extract = HkdfSha384::extract(Some(info::CIRCLE_KEY_SALT), canonical.as_bytes());
    canonical.zeroize();
    let hkdf = extract.map_err(CircleKeyError::Hkdf)?;

    let info_str = info::circle_veilid_owner(suite.family_token());

    let mut seed = [0u8; CIRCLE_VEILID_OWNER_SEED_LEN];
    if let Err(e) = hkdf.expand(info_str.as_bytes(), &mut seed) {
        seed.zeroize();
        return Err(CircleKeyError::Hkdf(e));
    }
    let boxed = Box::new(seed);
    seed.zeroize();
    Ok(CircleVeilidOwnerSeed(boxed))
}

/// Length of the hex fingerprint body (excluding the leading `#`). 12 hex chars
/// = 48 bits of the digest — enough for a human cross-check, short enough to
/// read aloud.
pub const CIRCLE_FINGERPRINT_HEX_LEN: usize = 12;

/// A short, **relay-independent** `#<hash-of-entropy>` fingerprint of a circle
/// (the ISC-C62 `#<hash-of-entropy>` floor form).
///
/// It is a pure function of the canonicalized entropy (ISC-C9), so two members
/// confirm "same circle" even across different relays — unlike the
/// rendezvous-derived adj-noun label ([`crate::handle::display_name`] keyed on
/// `SHA-384(cot_key ‖ server_id)`), which differs per relay by design
/// (cross-server unlinkability, ISC-C8).
///
/// **Hidden in the terminal client by design** (caraka, 2026-06-05): while TUI
/// space is limited the human-readable adj-noun label carries cross-daemon
/// verification, and this hash stays coded-but-unsurfaced. It is reserved for
/// the GUI era, where the user names the circle and this fingerprint backs
/// verification (the circle analogue of ISC-C4a's handle hash-prefix). The
/// canonical form is secret-adjacent, so it is zeroed the moment the digest is
/// taken (mirrors [`derive_cot_key`]). Returns a bare `"#"` only if the SHA
/// backend gate is uninitialized — a caller never relies on that path.
pub fn circle_fingerprint(entropy: &str) -> String {
    let mut canon = circle_canonicalize::canonicalize(entropy);
    let digest = sha384(canon.as_bytes());
    canon.zeroize();
    let Ok(digest) = digest else {
        return "#".to_owned();
    };
    let mut out = String::with_capacity(1 + CIRCLE_FINGERPRINT_HEX_LEN);
    out.push('#');
    for b in digest.iter().take(CIRCLE_FINGERPRINT_HEX_LEN / 2) {
        // Infallible write into a String; the result is intentionally ignored.
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::CNSA_2_0;

    /// ISC-C8 — derivation is deterministic: the same phrase yields the
    /// byte-identical key on every call (and so on every member's machine).
    #[test]
    fn derivation_is_deterministic() {
        let _ = oxicrypt_module::initialize();
        let a = derive_cot_key(EXAMPLE_ENTROPY, &CNSA_2_0).unwrap();
        let b = derive_cot_key(EXAMPLE_ENTROPY, &CNSA_2_0).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    /// ISC-C9 — entropy is canonicalized before derivation, so incidental
    /// whitespace / form differences between members collapse to the same key.
    #[test]
    fn canonicalizes_entropy_before_derivation() {
        let _ = oxicrypt_module::initialize();
        let plain = derive_cot_key(EXAMPLE_ENTROPY, &CNSA_2_0).unwrap();
        let messy = derive_cot_key("  correct   horse battery staple  ", &CNSA_2_0).unwrap();
        assert_eq!(plain.as_bytes(), messy.as_bytes());
    }

    /// ISC-C8 — distinct phrases yield distinct keys (the phrase is the sole
    /// distinguisher).
    #[test]
    fn distinct_entropy_yields_distinct_keys() {
        let _ = oxicrypt_module::initialize();
        let a = derive_cot_key("phrase alpha", &CNSA_2_0).unwrap();
        let b = derive_cot_key("phrase bravo", &CNSA_2_0).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    /// ISC-C62 — the `#<hash-of-entropy>` fingerprint is deterministic and shares
    /// the ISC-C9 canonicalization, so incidental whitespace differences between
    /// members collapse to the same fingerprint (the GUI-era verification check).
    #[test]
    fn fingerprint_is_deterministic_and_canonical() {
        let _ = oxicrypt_module::initialize();
        let a = circle_fingerprint(EXAMPLE_ENTROPY);
        let b = circle_fingerprint("  correct   horse battery staple  ");
        assert_eq!(a, b);
        assert!(a.starts_with('#'));
        assert_eq!(a.len(), 1 + CIRCLE_FINGERPRINT_HEX_LEN);
    }

    /// ISC-C62 — distinct entropy yields distinct fingerprints (the phrase is the
    /// sole distinguisher, ISC-C8).
    #[test]
    fn distinct_entropy_yields_distinct_fingerprints() {
        let _ = oxicrypt_module::initialize();
        assert_ne!(
            circle_fingerprint("phrase alpha"),
            circle_fingerprint("phrase bravo")
        );
    }

    /// The fingerprint is relay-independent — unlike the rendezvous-derived
    /// adj-noun label, it depends only on the entropy, so it never varies with
    /// `server_id`. (Same entropy in, same fingerprint out, no address input.)
    #[test]
    fn fingerprint_takes_only_entropy() {
        let _ = oxicrypt_module::initialize();
        // Two calls with the same phrase agree with no other input in play.
        assert_eq!(
            circle_fingerprint("a shared circle passphrase"),
            circle_fingerprint("a shared circle passphrase")
        );
    }

    /// `Debug` never leaks key bytes (ISC-A-C1 log-surface hygiene).
    #[test]
    fn debug_is_redacted() {
        let _ = oxicrypt_module::initialize();
        let k = derive_cot_key("some entropy phrase here", &CNSA_2_0).unwrap();
        assert_eq!(format!("{k:?}"), "CircleKey(<redacted>)");
    }

    /// Phase 2 — the rendezvous-owner seed is deterministic: every member who
    /// agrees on the phrase derives the byte-identical seed, hence the same DHT
    /// rendezvous address.
    #[test]
    fn veilid_owner_seed_is_deterministic() {
        let _ = oxicrypt_module::initialize();
        let a = derive_circle_veilid_owner_seed(EXAMPLE_ENTROPY, &CNSA_2_0).unwrap();
        let b = derive_circle_veilid_owner_seed(EXAMPLE_ENTROPY, &CNSA_2_0).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    /// Phase 2 — it shares the ISC-C9 canonicalization, so incidental
    /// whitespace / form differences between members collapse to the same seed.
    #[test]
    fn veilid_owner_seed_canonicalizes_entropy() {
        let _ = oxicrypt_module::initialize();
        let plain = derive_circle_veilid_owner_seed(EXAMPLE_ENTROPY, &CNSA_2_0).unwrap();
        let messy =
            derive_circle_veilid_owner_seed("  correct   horse battery staple  ", &CNSA_2_0)
                .unwrap();
        assert_eq!(plain.as_bytes(), messy.as_bytes());
    }

    /// Phase 2 — distinct phrases yield distinct rendezvous addresses (the
    /// phrase is the sole distinguisher, mirroring ISC-C8).
    #[test]
    fn veilid_owner_seed_diverges_by_entropy() {
        let _ = oxicrypt_module::initialize();
        let a = derive_circle_veilid_owner_seed("phrase alpha", &CNSA_2_0).unwrap();
        let b = derive_circle_veilid_owner_seed("phrase bravo", &CNSA_2_0).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    /// Transport/content separation — the rendezvous-owner seed is a sibling of
    /// the content key, not derived from it: for the same phrase the owner seed
    /// bytes differ from the `cot_key` bytes. The DHT address is not a function
    /// of the content key.
    #[test]
    fn veilid_owner_seed_differs_from_cot_key() {
        let _ = oxicrypt_module::initialize();
        let owner = derive_circle_veilid_owner_seed(EXAMPLE_ENTROPY, &CNSA_2_0).unwrap();
        let cot = derive_cot_key(EXAMPLE_ENTROPY, &CNSA_2_0).unwrap();
        assert_ne!(owner.as_bytes(), cot.as_bytes());
    }

    /// `Debug` never leaks the rendezvous-owner seed (ISC-A-C1).
    #[test]
    fn veilid_owner_seed_debug_is_redacted() {
        let _ = oxicrypt_module::initialize();
        let s = derive_circle_veilid_owner_seed("some entropy phrase here", &CNSA_2_0).unwrap();
        assert_eq!(format!("{s:?}"), "CircleVeilidOwnerSeed(<redacted>)");
    }
}
