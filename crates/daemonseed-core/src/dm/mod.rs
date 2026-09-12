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
//! Four record kinds carry it, and the shape of each is part of its address:
//!
//! | Record | Schema | Role |
//! |---|---|---|
//! | key record ([`keyrec`]) | `dflt(1)` | the identity's published static KEM key — all of DM discovery |
//! | doorbell | `dflt(32)` | sender-blind first-contact entries, the only unauthenticated write surface |
//! | channel page | `dflt(16)` | the established conversation, owner-write-gated so no third party can forge or erase it |
//! | ack record ([`ack_record`]) | `dflt(1)` | one direction's settled state, sealed and owner-write-gated, rewritten in place |
//!
//! Only the doorbell is world-writable, and it carries no conversation content.
//!
//! Built in dependency order as GitHub issues #232–#236; modules land as their
//! slices do.

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

/// Pad an encoded body to the smallest bucket that holds it:
/// `len(4, LE) ‖ protobuf ‖ zero-pad`, matching [`crate::heartbeat`]'s scheme.
///
/// `None` means no bucket is large enough — the caller reports that with its own
/// error, since only the caller knows which record shape the ladder was sized
/// against. Shared by every DM frame kind so the two ladders cannot drift into
/// two incompatible paddings of the same shape.
pub(crate) fn pad_to_bucket(encoded: &[u8], buckets: &[usize]) -> Option<Vec<u8>> {
    let needed = LEN_PREFIX.checked_add(encoded.len())?;
    let bucket = buckets.iter().copied().find(|b| needed <= *b)?;
    let mut buf = vec![0u8; bucket];
    buf[..LEN_PREFIX].copy_from_slice(&(encoded.len() as u32).to_le_bytes());
    buf[LEN_PREFIX..needed].copy_from_slice(encoded);
    Some(buf)
}

/// Recover the encoded body from a padded plaintext. `None` on a corrupt or
/// oversized length rather than slicing past the buffer.
pub(crate) fn unpad(padded: &[u8]) -> Option<&[u8]> {
    let prefix = padded.get(..LEN_PREFIX)?;
    let len = u32::from_le_bytes(prefix.try_into().expect("checked length")) as usize;
    let end = LEN_PREFIX.checked_add(len)?;
    padded.get(LEN_PREFIX..end)
}

pub mod ack;
pub mod ack_budget;
pub mod ack_cadence;
pub mod ack_record;
pub mod admission;
pub mod advert;
pub mod block_list;
pub mod chain;
pub mod channel;
pub mod collect;
pub mod contact_cache;
pub mod domain;
pub mod doorbell;
pub mod drop;
pub mod firstcontact;
pub mod frame;
pub mod keyrec;
pub mod outbox;
pub mod paging;
pub mod persist;
pub mod pow;
pub mod provisional;
pub mod ratchet;
pub mod reest;
pub mod resume;
pub mod spent_store;
pub mod token;

/// A stand-in ephemeral decapsulation key for the resume-record fixtures.
///
/// A fixed pattern rather than a real ML-KEM keypair: every test that uses it
/// exercises the record's encoding and its guards, neither of which
/// decapsulates anything. The tests that do complete a handshake mint a real
/// keypair through [`reest::mint_ephemeral`].
///
/// One definition, read by `dm::resume`, `dm::reest` and `dm::persist`, so the
/// bytes a record is written with and the bytes it is asserted against cannot
/// drift apart.
#[cfg(test)]
pub(crate) fn eph_dk_fixture() -> ratchet::EphemeralDecapKey {
    ratchet::EphemeralDecapKey::new(Box::new([0x3du8; oxicrypt_ml_kem::DK_LEN]))
}
