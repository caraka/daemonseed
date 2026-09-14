//! Direct messaging — one-to-one conversation between two identities
//! (ISC-C38–C46 / ISC-A-C20–A-C25).
//!
//! Design of record: `docs/design/direct-messaging.md` (FROZEN, DRAFT v6). In one
//! sentence: **a DM is a circle with one other person, where their published
//! identity key replaces the shared phrase.** The sender encapsulates to the
//! recipient's published static ML-KEM-1024 key, seals under the encapsulated
//! secret, and publishes; the recipient decapsulates whenever they next come
//! online. No handshake round-trip, no session, no new transport.
//!
//! `docs/design/direct-messaging.md` is implemented by [`advert`], [`mod@drop`],
//! [`channel`], [`chain`], [`store`], [`delivery`] and [`flows`]. [`block_list`],
//! [`contact_cache`] and [`domain`] are counted outside the layer by
//! `cargo xtask dm-size`.

/// Append a `u64` big-endian length prefix and the bytes.
///
/// The repo's one preimage convention (`room_message::provenance_input`), and the
/// single definition of it for direct messaging. Signature preimages and HKDF
/// `info` strings are wire: two hand-rolled copies that drifted would surface only
/// as two clients unable to verify each other's signatures or find each other's
/// records, which is exactly the failure the frozen build notes record for the
/// direction labels.
pub(crate) fn push_lp(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Bytes of length prefix a padded plaintext carries, so the real length is
/// recoverable from a buffer padded out with zeros.
pub(crate) const LEN_PREFIX: usize = 4;

/// Recover the encoded body from a padded plaintext. `None` on a corrupt or
/// oversized length rather than slicing past the buffer.
pub(crate) fn unpad(padded: &[u8]) -> Option<&[u8]> {
    let prefix = padded.get(..LEN_PREFIX)?;
    let len = u32::from_le_bytes(prefix.try_into().expect("checked length")) as usize;
    let end = LEN_PREFIX.checked_add(len)?;
    padded.get(LEN_PREFIX..end)
}

pub mod advert;
pub mod block_list;
pub mod chain;
pub mod channel;
pub mod contact_cache;
pub mod delivery;
pub mod domain;
pub mod drop;
pub mod flows;
pub mod store;
