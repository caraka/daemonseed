//! The one AES-256-GCM envelope seal/open primitive shared by every sealed
//! `CotFrame` payload kind.
//!
//! Every sealed frame daemonseed puts on the wire — a signed room/circle message
//! ([`crate::room_message`]), a presence heartbeat ([`crate::heartbeat`]), a
//! share roll-call ([`crate::share_rollcall`]) — carries the SAME envelope
//! invariant:
//!
//! ```text
//!   sealed = nonce(12) ‖ ciphertext ‖ tag(16)
//! ```
//!
//! [`seal_envelope`] draws a fresh 96-bit nonce, AES-256-GCM-encrypts the
//! plaintext under `key` binding `aad`, and assembles `nonce ‖ ct ‖ tag`.
//! [`open_envelope`] length-checks, splits those three regions, and decrypts.
//! Because this is the ONE place the byte layout lives, a fix (or a bug) can no
//! longer drift between the three call sites.
//!
//! **What lives here and what does not.** This primitive is *only* the AEAD
//! envelope — nonce, ciphertext, tag. Everything that makes a frame kind
//! distinct stays with its caller:
//!
//! - **The AAD is the caller's.** Each frame kind passes its OWN domain-separated
//!   `aad` ([`crate::public_room::ROOM_MESSAGE_AAD`],
//!   [`crate::circle::message::MESSAGE_AAD`], [`crate::heartbeat::HEARTBEAT_AAD`],
//!   [`crate::share_rollcall::SHARE_ROLLCALL_AAD`], …). This helper never unifies
//!   or substitutes an AAD — that separation is what keeps a heartbeat from ever
//!   opening as a room message under a coincidentally-equal key (ISC-A-S2).
//! - **Padding is the caller's.** The heartbeat pads its plaintext to a constant
//!   length ([`crate::heartbeat::HEARTBEAT_PADDED_PLAINTEXT_LEN`], WB-ISC-6)
//!   *before* calling [`seal_envelope`] and strips it *after* [`open_envelope`];
//!   this helper is length-preserving and knows nothing of framing.
//! - **The key is the caller's.** The caller builds the [`Aes256Key`] from its
//!   tier's key material (mapping any key-init failure to its own error type), so
//!   the tier-split key-class guard stays at the module boundary, not here.
//! - **Provenance signing / verification and prost decode are the caller's.**
//!
//! Each caller maps [`EnvelopeError`] onto its own existing error type via a
//! `From` impl, so this helper adds NO new variant to any module's public error
//! surface: the `TagMismatch` → `Authentication` and the too-short →
//! `Truncated` mappings are preserved exactly.

use oxicrypt_aes::{Aes256Key, ModeError, gcm_decrypt, gcm_encrypt};

use crate::circle::message::{NONCE_LEN, TAG_LEN};

/// Seal `plaintext` into a `nonce ‖ ciphertext ‖ tag` envelope: draw a fresh
/// 96-bit nonce, AES-256-GCM-encrypt under `key` binding `aad`, and assemble the
/// three regions with a single exact-capacity allocation.
///
/// The nonce is random per call, so the sealed bytes vary per call even for a
/// fixed key/aad/plaintext; for a FIXED nonce the assembled bytes are identical
/// to the historic inlined form. The caller owns `plaintext` and is responsible
/// for zeroizing it after this returns (the helper never copies it into a
/// retained buffer).
pub(crate) fn seal_envelope(
    key: &Aes256Key,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(EnvelopeError::EntropySource)?;

    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = [0u8; TAG_LEN];
    gcm_encrypt(key, &nonce, aad, plaintext, &mut ciphertext, &mut tag)
        .map_err(EnvelopeError::Encrypt)?;

    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len() + TAG_LEN);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    sealed.extend_from_slice(&tag);
    Ok(sealed)
}

/// Open a `nonce ‖ ciphertext ‖ tag` envelope produced by [`seal_envelope`]:
/// reject anything shorter than `nonce ‖ tag` ([`EnvelopeError::TooShort`]),
/// split the three regions, and AES-256-GCM-decrypt under `key` binding `aad`.
///
/// Returns the recovered plaintext, which the caller must zeroize after decoding
/// (this helper allocates it but does not zeroize on the returned/`Ok` path — it
/// hands ownership back). A wrong key or wrong `aad` fails as
/// [`EnvelopeError::Decrypt`] carrying [`ModeError::TagMismatch`].
pub(crate) fn open_envelope(
    key: &Aes256Key,
    aad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(EnvelopeError::TooShort);
    }
    let nonce: &[u8; NONCE_LEN] = sealed[..NONCE_LEN].try_into().expect("checked length");
    let after_nonce = &sealed[NONCE_LEN..];
    let ciphertext_len = after_nonce.len() - TAG_LEN;
    let ciphertext = &after_nonce[..ciphertext_len];
    let tag: &[u8; TAG_LEN] = after_nonce[ciphertext_len..]
        .try_into()
        .expect("checked length");

    let mut plaintext = vec![0u8; ciphertext_len];
    gcm_decrypt(key, nonce, aad, ciphertext, tag, &mut plaintext)
        .map_err(EnvelopeError::Decrypt)?;
    Ok(plaintext)
}

/// Failure sealing/opening the shared AEAD envelope. Each caller maps this onto
/// its own module error type via `From`, so it never widens a public error
/// surface. The variants mirror the shapes the three call sites already carried.
#[derive(Debug)]
pub(crate) enum EnvelopeError {
    /// The OS entropy source failed while drawing a nonce.
    EntropySource(getrandom::Error),
    /// AES-256-GCM encryption failed (a non-authentication mode error).
    Encrypt(ModeError),
    /// The sealed buffer is shorter than `nonce ‖ tag`.
    TooShort,
    /// AES-256-GCM decryption failed. [`ModeError::TagMismatch`] is the
    /// authentication failure (wrong key / tampered ciphertext / swapped nonce /
    /// wrong AAD); other variants are non-authentication mode errors.
    Decrypt(ModeError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Aes256Key {
        let _ = oxicrypt_module::initialize();
        Aes256Key::new(&[7u8; 32]).unwrap()
    }

    const AAD_A: &[u8] = b"daemonseed/test/aad/a";
    const AAD_B: &[u8] = b"daemonseed/test/aad/b";

    /// Round-trip: `open(seal(pt)) == pt` under matching key + aad.
    #[test]
    fn round_trip_recovers_plaintext() {
        let k = key();
        let pt = b"the quick brown fox".to_vec();
        let sealed = seal_envelope(&k, AAD_A, &pt).unwrap();
        let opened = open_envelope(&k, AAD_A, &sealed).unwrap();
        assert_eq!(opened, pt);
    }

    /// The assembled layout is exactly `nonce(12) ‖ ct(len) ‖ tag(16)`: splitting
    /// the sealed bytes at those offsets and decrypting the middle region under
    /// the extracted nonce+tag reproduces the plaintext. This pins the byte
    /// offsets the historic inlined code used.
    #[test]
    fn sealed_layout_is_nonce_ct_tag() {
        let k = key();
        let pt = b"layout check payload".to_vec();
        let sealed = seal_envelope(&k, AAD_A, &pt).unwrap();
        assert_eq!(sealed.len(), NONCE_LEN + pt.len() + TAG_LEN);
        let nonce: &[u8; NONCE_LEN] = sealed[..NONCE_LEN].try_into().unwrap();
        let ct = &sealed[NONCE_LEN..NONCE_LEN + pt.len()];
        let tag: &[u8; TAG_LEN] = sealed[NONCE_LEN + pt.len()..].try_into().unwrap();
        let mut recovered = vec![0u8; pt.len()];
        gcm_decrypt(&k, nonce, AAD_A, ct, tag, &mut recovered).unwrap();
        assert_eq!(recovered, pt);
    }

    /// A frame assembled the OLD way — a fixed nonce, manual `gcm_encrypt`, then
    /// `nonce ‖ ct ‖ tag` by hand — opens byte-for-byte under the new
    /// [`open_envelope`]. Proves format compatibility with the pre-refactor
    /// inlined code for a fixed nonce.
    #[test]
    fn historic_fixed_nonce_frame_opens() {
        let k = key();
        let pt = b"fixed nonce equivalence".to_vec();
        let nonce = [0x24u8; NONCE_LEN];
        let mut ct = vec![0u8; pt.len()];
        let mut tag = [0u8; TAG_LEN];
        gcm_encrypt(&k, &nonce, AAD_A, &pt, &mut ct, &mut tag).unwrap();
        let mut sealed = Vec::new();
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ct);
        sealed.extend_from_slice(&tag);
        let opened = open_envelope(&k, AAD_A, &sealed).unwrap();
        assert_eq!(opened, pt);
    }

    /// Wrong AAD fails as `Decrypt(TagMismatch)` — the mapping each caller turns
    /// into its own `Authentication` error. This is the cross-kind isolation
    /// guarantee (a payload sealed with one kind's AAD cannot open under another).
    #[test]
    fn wrong_aad_fails_tag_mismatch() {
        let k = key();
        let pt = b"aad separation".to_vec();
        let sealed = seal_envelope(&k, AAD_A, &pt).unwrap();
        match open_envelope(&k, AAD_B, &sealed) {
            Err(EnvelopeError::Decrypt(ModeError::TagMismatch)) => {}
            other => panic!("expected Decrypt(TagMismatch), got {other:?}"),
        }
    }

    /// A buffer shorter than `nonce ‖ tag` is rejected as `TooShort` (→ each
    /// caller's `Truncated`).
    #[test]
    fn too_short_is_rejected() {
        let k = key();
        let short = vec![0u8; NONCE_LEN + TAG_LEN - 1];
        match open_envelope(&k, AAD_A, &short) {
            Err(EnvelopeError::TooShort) => {}
            other => panic!("expected TooShort, got {other:?}"),
        }
    }

    /// A fresh random nonce per seal: two seals of identical plaintext differ,
    /// and both still open. A deterministic-nonce regression would hit all three
    /// callers at once, so it is pinned at the shared primitive.
    #[test]
    fn nonce_is_random_per_seal() {
        let k = key();
        let pt = b"same plaintext".to_vec();
        let one = seal_envelope(&k, AAD_A, &pt).unwrap();
        let two = seal_envelope(&k, AAD_A, &pt).unwrap();
        assert_ne!(one, two, "fresh nonce per seal");
        assert_eq!(open_envelope(&k, AAD_A, &one).unwrap(), pt);
        assert_eq!(open_envelope(&k, AAD_A, &two).unwrap(), pt);
    }
}
