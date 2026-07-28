//! The `daemonseed/dm/…` domain-label namespace.
//!
//! Every HKDF `info`, AEAD AAD, and signature domain used by direct messaging is
//! declared here so the whole namespace can be read — and prefix-checked — in one
//! place. The frozen design (`docs/design/direct-messaging.md` § Primitives &
//! identities) requires **one distinct label per purpose** with **no label a
//! prefix of another**: an owner-seed label is never a seal-key label is never a
//! signature domain. That property is what stops a value derived or signed for
//! one purpose from being replayed into another, and it is enforced by a test in
//! this module rather than left to review.
//!
//! Labels are byte-pinned. Changing one changes the wire, so each is FROZEN and
//! any edit is a deliberate, reviewed protocol change.
//!
//! **Convention note.** The pre-DM engine puts Veilid record-owner labels under
//! `daemonseed/veilid/…` (`kdf::info::circle_veilid_owner` and siblings). DM
//! deliberately keeps its owner labels under `daemonseed/dm/…` instead, because
//! the frozen design specifies the exact strings and groups the whole feature's
//! namespace together.
//!
//! **Scope of the guarantee, stated precisely.** The test below proves
//! prefix-freeness *within* the DM namespace, and that every DM label sits under
//! `daemonseed/dm/`. It does NOT — and cannot, without a workspace-wide label
//! registry that does not exist — prove prefix-freeness against labels in other
//! modules (`daemonseed/veilid/…`, `daemonseed/identity/…`, `daemonseed/circle/…`,
//! `daemonseed/share…`, `daemonseed/public-room/…`, `daemonseed/presence/…`). Those
//! were enumerated by hand on 2026-07-28 and none collides: every one diverges
//! from `daemonseed/dm/` at the segment immediately after the shared
//! `daemonseed/` prefix. That is verification by inspection, not an enforced
//! invariant — a cross-crate prefix-freeness test over every domain-label module
//! is the durable fix and is follow-up work.

/// HKDF-Extract salt for the KEY-RECORD derivation rooted in a published identity
/// key. Non-empty and normative — no implicit zero-salt. The doorbell derives from
/// the same kind of input under its own salt ([`DM_DOORBELL_SALT`]); the two must
/// not share one. FROZEN.
pub const DM_KEYREC_SALT: &[u8] = b"daemonseed/dm/keyrec/salt/v1";

/// HKDF-Expand `info` for the key record's Veilid owner seed, derived from the
/// identity's full ML-DSA-87 public key. World-derivable by design: anyone
/// holding the pubkey computes the address. FROZEN.
pub const DM_KEYREC_OWNER: &[u8] = b"daemonseed/dm/keyrec/owner/v1";

/// Signature domain for [`crate::dm::keyrec::DmKeyRecord`]'s inner ML-DSA-87
/// signature. FROZEN.
pub const DM_KEYREC_SIG: &[u8] = b"daemonseed/dm/keyrec/sig/v1";

/// HKDF-Extract salt for the doorbell's owner-seed derivation, which is rooted in
/// the RECIPIENT's published identity key. Distinct from [`DM_KEYREC_SALT`] so the
/// two derivations over that same public input cannot collide. FROZEN.
pub const DM_DOORBELL_SALT: &[u8] = b"daemonseed/dm/doorbell/salt/v1";

/// HKDF-Expand `info` for the doorbell's Veilid owner seed, derived from the
/// recipient's full ML-DSA-87 public key. World-derivable — and therefore
/// world-WRITABLE — by design: a stranger holding no shared secret must be able
/// to knock. That is what makes the doorbell the only unauthenticated write
/// surface in DM, and why it carries a sealed entry rather than trust. FROZEN.
pub const DM_DOORBELL_OWNER: &[u8] = b"daemonseed/dm/doorbell/addr/v4";

/// HKDF-Extract salt for the sender's doorbell SLOT derivation. Rooted in the
/// sender's secret slot IKM, not in any public key. FROZEN.
pub const DM_DOORBELL_SLOT_SALT: &[u8] = b"daemonseed/dm/doorbell/slot-salt/v1";

/// HKDF-Expand `info` for the sender's doorbell slot index. FROZEN.
pub const DM_DOORBELL_SLOT: &[u8] = b"daemonseed/dm/doorbell/slot/v5";

/// Every label in this namespace, for the prefix-freeness check.
#[cfg(test)]
const ALL: &[&[u8]] = &[
    DM_KEYREC_SALT,
    DM_KEYREC_OWNER,
    DM_KEYREC_SIG,
    DM_DOORBELL_SALT,
    DM_DOORBELL_OWNER,
    DM_DOORBELL_SLOT_SALT,
    DM_DOORBELL_SLOT,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-pinned: these strings are the wire. A change here is a protocol
    /// change, and this test is the tripwire that makes it deliberate.
    #[test]
    fn labels_are_byte_pinned() {
        assert_eq!(DM_KEYREC_SALT, b"daemonseed/dm/keyrec/salt/v1");
        assert_eq!(DM_KEYREC_OWNER, b"daemonseed/dm/keyrec/owner/v1");
        assert_eq!(DM_KEYREC_SIG, b"daemonseed/dm/keyrec/sig/v1");
        assert_eq!(DM_DOORBELL_SALT, b"daemonseed/dm/doorbell/salt/v1");
        assert_eq!(DM_DOORBELL_OWNER, b"daemonseed/dm/doorbell/addr/v4");
        assert_eq!(
            DM_DOORBELL_SLOT_SALT,
            b"daemonseed/dm/doorbell/slot-salt/v1"
        );
        assert_eq!(DM_DOORBELL_SLOT, b"daemonseed/dm/doorbell/slot/v5");
    }

    /// The frozen design's F11 requirement: no label may be a prefix of another.
    /// If one were, a derivation for the shorter purpose could be confused with a
    /// truncated derivation for the longer one.
    #[test]
    fn no_label_is_a_prefix_of_another() {
        for (i, a) in ALL.iter().enumerate() {
            for (j, b) in ALL.iter().enumerate() {
                if i == j {
                    continue;
                }
                assert!(
                    !b.starts_with(a),
                    "{} is a prefix of {}",
                    String::from_utf8_lossy(a),
                    String::from_utf8_lossy(b)
                );
            }
        }
    }

    /// Every DM label sits under the feature's own namespace, so it shares no
    /// prefix with any pre-DM label (`daemonseed/veilid/…`, `daemonseed/identity/…`,
    /// `daemonseed/circle/…`, `daemonseed/share*`, `daemonseed/public-room/…`).
    #[test]
    fn all_labels_are_namespaced_under_dm() {
        for label in ALL {
            assert!(
                label.starts_with(b"daemonseed/dm/"),
                "{} escapes the dm namespace",
                String::from_utf8_lossy(label)
            );
        }
    }

    #[test]
    fn labels_are_distinct() {
        let mut seen = std::collections::BTreeSet::new();
        for label in ALL {
            assert!(
                seen.insert(*label),
                "duplicate label {}",
                String::from_utf8_lossy(label)
            );
        }
    }
}
