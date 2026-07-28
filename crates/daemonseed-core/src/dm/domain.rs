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

/// HKDF-Extract salt for the first-contact seal key, rooted in the encapsulated
/// secret `ss0`. FROZEN.
pub const DM_FC_SALT: &[u8] = b"daemonseed/dm/fc/salt/v1";

/// HKDF-Expand `info` for the first-contact entry's AES-256-GCM seal key. FROZEN.
pub const DM_FC_SEAL: &[u8] = b"daemonseed/dm/fc/seal/v1";

/// AAD prefix for the first-contact seal. The recipient's key-record address and
/// the current first-contact epoch follow it, which is what makes an entry
/// un-openable at a different recipient or outside its epoch window. FROZEN.
pub const DM_FC_AAD: &[u8] = b"daemonseed/dm/fc/aad/v1";

/// Signature domain binding a per-contact pseudonym key to the long-term identity
/// that vouches for it, signed under the LONG-TERM key. FROZEN.
pub const DM_BIND_LT: &[u8] = b"daemonseed/dm/bind/lt/v1";

/// Signature domain for a DM frame's authorship signature, signed under the
/// PSEUDONYM key. The sole proof-of-possession path (the separate `bind_pop` was
/// folded into it), so it binds both public keys as well as the message. FROZEN.
pub const DM_MSG_SIG: &[u8] = b"daemonseed/dm/msg/sig/v6";

/// HKDF-Extract salt for the two roots derived from `ss0`. FROZEN.
pub const DM_ROOT_SALT: &[u8] = b"daemonseed/dm/root/salt/v1";

/// HKDF-Expand `info` for the address root `AR`, from which every ongoing-channel
/// address derives. Retained for the life of the conversation — addressing is
/// deliberately NOT forward-secret, while content is. FROZEN.
pub const DM_ADDR_ROOT: &[u8] = b"daemonseed/dm/addr/root/v3";

/// HKDF-Expand `info` for `chan_id`, the conversation identifier bound into every
/// signature and AAD. **Never serialized** — a receiver recomputes it from the
/// record it derived. Putting it on the wire would collapse the address scatter
/// it exists to protect. FROZEN.
pub const DM_CHAN_ID: &[u8] = b"daemonseed/dm/chanid/v2";

/// HKDF-Expand `info` for the ratchet root `RK0` — the third sibling of the same
/// extraction that yields [`DM_ADDR_ROOT`] and [`DM_CHAN_ID`]. Unlike those two,
/// this one is ratcheted forward and deleted, which is the whole of DM's forward
/// secrecy. FROZEN.
pub const DM_RATCHET_ROOT: &[u8] = b"daemonseed/dm/ratchet/root/v2";

/// HKDF-Expand `info` for a ratchet generation step. The extraction that precedes
/// it takes the PREVIOUS root as its salt and the freshly encapsulated secret as
/// its IKM, so a generation depends on both its ancestor and new entropy — the
/// standard double-ratchet root step, and what makes a compromise heal. FROZEN.
pub const DM_RATCHET_STEP: &[u8] = b"daemonseed/dm/ratchet/step/v2";

/// HKDF-Extract salt for deriving a direction's chain key from a ratchet root.
/// FROZEN.
pub const DM_CHAIN_SALT: &[u8] = b"daemonseed/dm/chain/salt/v1";

/// HKDF-Expand `info` for the initiator-to-recipient chain key. FROZEN.
pub const DM_CHAIN_A2B: &[u8] = b"daemonseed/dm/chain/a2b/v2";

/// HKDF-Expand `info` for the recipient-to-initiator chain key. Distinct from
/// [`DM_CHAIN_A2B`] so the two directions never share a message key — the defect
/// that made the single-chain draft reuse an AES-GCM nonce. FROZEN.
pub const DM_CHAIN_B2A: &[u8] = b"daemonseed/dm/chain/b2a/v2";

/// HKDF-Extract salt for one symmetric step along a chain. FROZEN.
pub const DM_CHAIN_STEP_SALT: &[u8] = b"daemonseed/dm/chain/step-salt/v1";

/// HKDF-Expand `info` for the message key at a chain position. FROZEN.
pub const DM_MK: &[u8] = b"daemonseed/dm/mk/v2";

/// HKDF-Expand `info` for the successor chain key. Sibling of [`DM_MK`] under one
/// extraction, so learning a message key never yields the chain it came from.
/// FROZEN.
pub const DM_CK: &[u8] = b"daemonseed/dm/ck/v2";

/// Every label in this namespace, for the prefix-freeness check.
#[cfg(test)]
const ALL: &[&[u8]] = &[
    DM_RATCHET_ROOT,
    DM_RATCHET_STEP,
    DM_CHAIN_SALT,
    DM_CHAIN_A2B,
    DM_CHAIN_B2A,
    DM_CHAIN_STEP_SALT,
    DM_MK,
    DM_CK,
    DM_FC_SALT,
    DM_FC_SEAL,
    DM_FC_AAD,
    DM_BIND_LT,
    DM_MSG_SIG,
    DM_ROOT_SALT,
    DM_ADDR_ROOT,
    DM_CHAN_ID,
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
        assert_eq!(DM_FC_SALT, b"daemonseed/dm/fc/salt/v1");
        assert_eq!(DM_FC_SEAL, b"daemonseed/dm/fc/seal/v1");
        assert_eq!(DM_FC_AAD, b"daemonseed/dm/fc/aad/v1");
        assert_eq!(DM_BIND_LT, b"daemonseed/dm/bind/lt/v1");
        assert_eq!(DM_MSG_SIG, b"daemonseed/dm/msg/sig/v6");
        assert_eq!(DM_ROOT_SALT, b"daemonseed/dm/root/salt/v1");
        assert_eq!(DM_ADDR_ROOT, b"daemonseed/dm/addr/root/v3");
        assert_eq!(DM_CHAN_ID, b"daemonseed/dm/chanid/v2");
        assert_eq!(DM_RATCHET_ROOT, b"daemonseed/dm/ratchet/root/v2");
        assert_eq!(DM_RATCHET_STEP, b"daemonseed/dm/ratchet/step/v2");
        assert_eq!(DM_CHAIN_SALT, b"daemonseed/dm/chain/salt/v1");
        assert_eq!(DM_CHAIN_A2B, b"daemonseed/dm/chain/a2b/v2");
        assert_eq!(DM_CHAIN_B2A, b"daemonseed/dm/chain/b2a/v2");
        assert_eq!(DM_CHAIN_STEP_SALT, b"daemonseed/dm/chain/step-salt/v1");
        assert_eq!(DM_MK, b"daemonseed/dm/mk/v2");
        assert_eq!(DM_CK, b"daemonseed/dm/ck/v2");
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

    /// `ALL` is hand-maintained, and the two checks above only ever see what is
    /// in it — so a label added without a registry line would be silently exempt
    /// from prefix-freeness forever, and no test would notice. This reads this
    /// module's own source and holds the registry to it in both directions:
    /// every declared label appears in `ALL`, and `ALL` contains nothing else.
    #[test]
    fn every_declared_label_is_registered_for_the_prefix_check() {
        let source = include_str!("domain.rs");
        let mut declared = Vec::new();

        for line in source.lines() {
            let Some(rest) = line.trim().strip_prefix("pub const DM_") else {
                continue;
            };
            let Some((_, literal)) = rest.split_once("= b\"") else {
                continue;
            };
            let value = literal
                .trim_end()
                .trim_end_matches(';')
                .trim_end_matches('"')
                .as_bytes()
                .to_vec();
            assert!(
                ALL.contains(&value.as_slice()),
                "{} is declared but missing from ALL, so nothing prefix-checks it",
                String::from_utf8_lossy(&value)
            );
            declared.push(value);
        }

        assert_eq!(
            declared.len(),
            ALL.len(),
            "ALL holds {} entries but {} labels are declared here",
            ALL.len(),
            declared.len()
        );
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
