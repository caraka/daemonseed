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

/// Declare every DM domain-separation label, and the registry over them, from one
/// place (#296).
///
/// **The registry is not checked against the declarations; it is BUILT from them.**
/// Before this, three tests read this module's own source as text and reconstructed
/// a fact the compiler already knew — so every guarantee was only as strong as that
/// parser, and a parse finding less than it should reported success. #283 was one
/// way it went wrong and there was no argument it was the last: an unusual
/// attribute, a doc comment containing the parsed token, a `cfg` block or a future
/// edition's formatting would each have reopened it, silently and in the same
/// direction.
///
/// A label therefore cannot exist without being in [`ALL`], because both come from
/// this one invocation, and the byte value cannot drift from the declaration for
/// the same reason. Formatting is irrelevant now, because nothing reads the source.
/// Prefix-freeness stays a real test — but it runs over an `ALL` that is complete by
/// construction rather than parsed and hoped complete.
macro_rules! dm_labels {
    ($( $(#[$meta:meta])* $name:ident = $value:literal; )+) => {
        $(
            $(#[$meta])*
            pub const $name: &[u8] = $value;
        )+

        /// Every label this module declares, in declaration order.
        ///
        /// Emitted by the same `dm_labels!` invocation as the declarations above, so
        /// it cannot omit one. Used by the prefix-freeness and namespacing checks.
        ///
        /// `#[cfg(test)]` as it was before #296: nothing in the shipped crate reads
        /// the registry, and emitting it unconditionally would be a `dead_code`
        /// warning the repo's `-D warnings` gate turns into a build failure.
        #[cfg(test)]
        const ALL: &[&[u8]] = &[$($name),+];
    };
}

dm_labels! {
    /// HKDF-Extract salt for the KEY-RECORD derivation rooted in a published identity
    /// key. Non-empty and normative — no implicit zero-salt. The doorbell derives from
    /// the same kind of input under its own salt ([`DM_DOORBELL_SALT`]); the two must
    /// not share one. FROZEN.
    DM_KEYREC_SALT = b"daemonseed/dm/keyrec/salt/v1";

    /// HKDF-Expand `info` for the key record's Veilid owner seed, derived from the
    /// identity's full ML-DSA-87 public key. World-derivable by design: anyone
    /// holding the pubkey computes the address. FROZEN.
    DM_KEYREC_OWNER = b"daemonseed/dm/keyrec/owner/v1";

    /// Signature domain for the [`crate::dm::keyrec`] record's inner ML-DSA-87
    /// signature. FROZEN.
    DM_KEYREC_SIG = b"daemonseed/dm/keyrec/sig/v1";

    /// HKDF-Extract salt for the doorbell's owner-seed derivation, which is rooted in
    /// the RECIPIENT's published identity key. Distinct from [`DM_KEYREC_SALT`] so the
    /// two derivations over that same public input cannot collide. FROZEN.
    DM_DOORBELL_SALT = b"daemonseed/dm/doorbell/salt/v1";

    /// HKDF-Expand `info` for the doorbell's Veilid owner seed, derived from the
    /// recipient's full ML-DSA-87 public key. World-derivable — and therefore
    /// world-WRITABLE — by design: a stranger holding no shared secret must be able
    /// to knock. That is what makes the doorbell the only unauthenticated write
    /// surface in DM, and why it carries a sealed entry rather than trust. FROZEN.
    DM_DOORBELL_OWNER = b"daemonseed/dm/doorbell/addr/v4";

    /// HKDF-Extract salt for the sender's doorbell SLOT derivation. Rooted in the
    /// sender's secret slot IKM, not in any public key. FROZEN.
    DM_DOORBELL_SLOT_SALT = b"daemonseed/dm/doorbell/slot-salt/v1";

    /// HKDF-Expand `info` for the sender's doorbell slot index. FROZEN.
    DM_DOORBELL_SLOT = b"daemonseed/dm/doorbell/slot/v5";

    /// HKDF-Extract salt for the first-contact seal key, rooted in the encapsulated
    /// secret `ss0`. FROZEN.
    DM_FC_SALT = b"daemonseed/dm/fc/salt/v1";

    /// HKDF-Expand `info` for the first-contact entry's AES-256-GCM seal key. FROZEN.
    DM_FC_SEAL = b"daemonseed/dm/fc/seal/v1";

    /// AAD prefix for the first-contact seal. The recipient's key-record address and
    /// the current first-contact epoch follow it, which is what makes an entry
    /// un-openable at a different recipient or outside its epoch window. FROZEN.
    DM_FC_AAD = b"daemonseed/dm/fc/aad/v1";

    /// Domain prefix for the first-contact proof-of-work preimage
    /// ([`crate::dm::pow::pow_input`]). The recipient's key-record address, the
    /// first-contact epoch, the entry hash and the nonce follow it, each
    /// length-prefixed.
    ///
    /// **The `/v1` is where the difficulty lives.** [`crate::dm::pow::FC_POW_BITS`]
    /// is a fixed protocol constant rather than an advertised or adaptive one, so
    /// there is nowhere on the wire that says what difficulty an entry was minted
    /// at — which means changing it is a change to what this label *means*, and the
    /// only way to make two clients disagree about that safely is to change the
    /// label with it. A `/v2` here is what a difficulty change costs. FROZEN.
    DM_FC_POW = b"daemonseed/dm/fc/pow/v1";

    /// Signature domain for a grantee-bound one-time invite token
    /// ([`crate::dm::token::TokenV1`]), signed under the ISSUER's long-term key.
    /// The grantee's long-term public key, the token nonce and the expiry follow
    /// it, each length-prefixed.
    ///
    /// **The grantee's key is inside the preimage and not inside the token.** The
    /// verifier takes it from `body.pk_lt` and rebuilds these bytes, so a token is
    /// only ever valid stapled to the identity it names — possession of the bytes
    /// proves nothing, and an intercepted token is inert. FROZEN.
    DM_TOKEN = b"daemonseed/dm/token/v1";

    /// HKDF-Extract salt for the provisional handshake record's at-rest seal key,
    /// rooted in the profile's at-rest key material — **never** in `ss0`, which is
    /// what the record holds. Pairs with [`DM_PROVISIONAL_SEAL`] exactly as
    /// [`DM_FC_SALT`] pairs with [`DM_FC_SEAL`]. FROZEN.
    DM_PROVISIONAL_SALT = b"daemonseed/dm/provisional/salt/v1";

    /// HKDF-Expand `info` for the provisional handshake record's AES-256-GCM seal
    /// key ([`crate::dm::provisional`]).
    ///
    /// **Its own label rather than the first-contact seal's.** That one is keyed on
    /// `ss0` and protects an entry on the wire; this one is keyed on local at-rest
    /// material and protects a record on the medium. Deriving both from one label
    /// would mean a first-contact entry and a provisional record could open as each
    /// other wherever the two key inputs ever coincided. FROZEN.
    DM_PROVISIONAL_SEAL = b"daemonseed/dm/provisional/seal/v1";

    /// AAD prefix for the provisional handshake record's at-rest seal. The
    /// correspondent's key-record address and the first-contact epoch follow it,
    /// length-prefixed — the same two fields [`DM_FC_AAD`] binds, for the same
    /// reason.
    ///
    /// **Per-record, where the key is only per-profile.** [`DM_PROVISIONAL_SEAL`]
    /// derives ONE key for a whole profile, so without a per-record binding every
    /// provisional record in a profile is an interchangeable ciphertext: copy one
    /// channel's record over another's and it opens cleanly, the version matches and
    /// the halves pair, so the channel silently resumes as the wrong correspondent.
    /// Binding what the caller *expects* the record to be is what makes that splice
    /// fail to authenticate. FROZEN.
    DM_PROVISIONAL_AAD = b"daemonseed/dm/provisional/aad/v1";

    /// HKDF-Extract salt for the provisional record's internal binding tag, rooted in
    /// `ss0`. Distinct from [`DM_PROVISIONAL_SALT`], which is rooted in the profile's
    /// at-rest material: the two extractions must not share a salt. FROZEN.
    DM_PROVISIONAL_BIND_SALT = b"daemonseed/dm/provisional/bind-salt/v1";

    /// HKDF-Expand `info` for the provisional record's binding tag. The opening
    /// ephemeral's public half follows it, length-prefixed.
    ///
    /// **The edge nothing else carried.** The AEAD authenticates the record's bytes
    /// and `EphemeralDecapKey::matches` binds the two ephemeral halves to each other,
    /// but nothing bound either of them to `ss0` — so a record splicing one channel's
    /// `ss0` onto another's ephemeral passed construction, the open and the ratchet
    /// handover, then failed every reply forever with `UnknownEphemeral`: the silent
    /// death #243 exists to abolish, reintroduced by the record meant to prevent it.
    /// FROZEN.
    DM_PROVISIONAL_BIND = b"daemonseed/dm/provisional/bind/v1";

    /// HKDF-Extract salt for the DM record store's at-rest seal key, rooted in the
    /// profile's at-rest key material — the same root [`DM_PROVISIONAL_SALT`] uses,
    /// under its own salt so the two extractions over that one input cannot collide.
    /// FROZEN.
    DM_STORE_SALT = b"daemonseed/dm/store/salt/v1";

    /// HKDF-Expand `info` for the DM record store's AES-256-GCM seal key
    /// ([`crate::storage::dm_store`]).
    ///
    /// **Its own label rather than [`DM_PROVISIONAL_SEAL`]'s.** That key protects one
    /// record kind's contents; this one protects every record's slot in the store,
    /// including a provisional record the other key already sealed. One label for
    /// both would mean a store blob and a provisional record could open as each other
    /// wherever the two key inputs coincided — which, both being derived from the
    /// same profile at-rest material, is always. FROZEN.
    DM_STORE_SEAL = b"daemonseed/dm/store/seal/v1";

    /// AAD prefix for a DM store record's at-rest seal. The correspondence label and
    /// the record-kind tag follow it, length-prefixed.
    ///
    /// **Per-slot, where the key is only per-profile.** [`DM_STORE_SEAL`] derives ONE
    /// key for a whole profile, so without this binding every file in the store is an
    /// interchangeable ciphertext: copy one correspondence's resume record over
    /// another's and it opens cleanly, or drop an outbox into a resume slot of the
    /// same size and it opens as state. Binding what the store *expects* the file to
    /// be is what makes both splices fail to authenticate. The same construction as
    /// [`DM_PROVISIONAL_AAD`], for the same reason. FROZEN.
    DM_STORE_AAD = b"daemonseed/dm/store/aad/v1";

    /// Signature domain binding a per-contact pseudonym key to the long-term identity
    /// that vouches for it, signed under the LONG-TERM key. FROZEN.
    DM_BIND_LT = b"daemonseed/dm/bind/lt/v1";

    /// Signature domain for a DM frame's authorship signature, signed under the
    /// PSEUDONYM key. The sole proof-of-possession path (the separate `bind_pop` was
    /// folded into it), so it binds both public keys as well as the message. FROZEN.
    DM_MSG_SIG = b"daemonseed/dm/msg/sig/v6";

    /// AAD prefix for an ongoing-channel frame's seal. Every clear field of the frame
    /// follows it, length-prefixed, so a header edited in flight fails the AEAD open
    /// rather than reaching the ratchet as an authenticated position. Distinct from
    /// [`DM_FC_AAD`] so a first-contact entry and a channel frame can never open as
    /// each other.
    ///
    /// **`/v4`, past the frozen text's three earlier spellings.** The design names
    /// this AAD three times and means something different each time: `/v1` binds
    /// `chan_id ‖ epoch`, `/v2` drops the epoch, `/v3` adds `dir`. What the build
    /// binds is broader than all of them — the whole clear header and both pieces of
    /// ephemeral material — so reusing any of those strings would let two
    /// implementations disagree about what a signature of that name covers, which is
    /// the exact failure the `msg/sig/v6` bump exists to prevent. FROZEN.
    DM_MSG_AAD = b"daemonseed/dm/msg/aad/v4";

    /// HKDF-Extract salt for the two roots derived from `ss0`. FROZEN.
    DM_ROOT_SALT = b"daemonseed/dm/root/salt/v1";

    /// HKDF-Expand `info` for the address root `AR`, from which every ongoing-channel
    /// address derives. Retained for the life of the conversation — addressing is
    /// deliberately NOT forward-secret, while content is. FROZEN.
    DM_ADDR_ROOT = b"daemonseed/dm/addr/root/v3";

    /// HKDF-Expand `info` for `chan_id`, the conversation identifier bound into every
    /// signature and AAD. **Never serialized** — a receiver recomputes it from the
    /// record it derived. Putting it on the wire would collapse the address scatter
    /// it exists to protect. FROZEN.
    DM_CHAN_ID = b"daemonseed/dm/chanid/v2";

    /// HKDF-Extract salt for a channel page's owner-seed derivation, rooted in the
    /// conversation's secret address root `AR`. FROZEN.
    DM_PAGE_SALT = b"daemonseed/dm/page/salt/v1";

    /// HKDF-Expand `info` prefix for a channel page's Veilid owner seed. The
    /// direction and page number follow it, length-prefixed. Unlike every other DM
    /// address this one is **not** world-derivable: it is rooted in a secret only the
    /// two parties hold, which is what makes the page owner-write-gated and therefore
    /// unforgeable and un-erasable by a third party. FROZEN.
    DM_PAGE_ADDR = b"daemonseed/dm/page/addr/v4";

    /// HKDF-Extract salt for a direction's delivery-acknowledgement seal key, rooted
    /// in the conversation's retained address root `AR`. Distinct from
    /// [`DM_PAGE_SALT`] so the two derivations over that same secret cannot collide.
    /// FROZEN.
    DM_ACK_SALT = b"daemonseed/dm/ack/salt/v1";

    /// HKDF-Expand `info` prefix for a direction's delivery-acknowledgement seal key.
    /// The direction follows it, length-prefixed.
    ///
    /// **Rooted in `AR`, not in the ratchet root**, which is what the `/v3` in the
    /// frozen name records: a ratchet-rooted ack key desyncs the moment the two
    /// parties sit at different generations (crypto F-3), and the acknowledgement
    /// would go dark exactly when a conversation is busiest. Per-direction for F-6.
    /// FROZEN.
    DM_ACK_SEAL = b"daemonseed/dm/ack/seal/v3";

    /// Signature domain for a delivery acknowledgement, signed under the PSEUDONYM
    /// key.
    ///
    /// **`/v3`, past the frozen text's `…/ack/sig/v2`.** That name was pinned in
    /// § DRAFT v2 for a preimage covering `chan_id ‖ high_water` alone — written while
    /// the gap bitmap was dropped. v6 restored the bitmap and made it decide
    /// confirmation, so a preimage of that shape leaves the deciding half unsigned.
    /// What this domain covers is `chan_id ‖ dir ‖ high_water ‖ the canonical run
    /// encoding`; reusing `/v2` for materially broader content would let two
    /// implementations disagree about what a signature of that name covers, which is
    /// the same failure the `msg/sig/v6` and `msg/aad/v4` bumps exist to prevent.
    /// FROZEN.
    DM_ACK_SIG = b"daemonseed/dm/ack/sig/v3";

    /// HKDF-Expand `info` for the ratchet root `RK0` — the third sibling of the same
    /// extraction that yields [`DM_ADDR_ROOT`] and [`DM_CHAN_ID`]. Unlike those two,
    /// this one is ratcheted forward and deleted, which is the whole of DM's forward
    /// secrecy. FROZEN.
    DM_RATCHET_ROOT = b"daemonseed/dm/ratchet/root/v2";

    /// HKDF-Expand `info` for a ratchet generation step. The extraction that precedes
    /// it takes the PREVIOUS root as its salt and the freshly encapsulated secret as
    /// its IKM, so a generation depends on both its ancestor and new entropy — the
    /// standard double-ratchet root step, and what makes a compromise heal. FROZEN.
    DM_RATCHET_STEP = b"daemonseed/dm/ratchet/step/v2";

    /// HKDF-Extract salt for deriving a direction's chain key from a ratchet root.
    /// FROZEN.
    DM_CHAIN_SALT = b"daemonseed/dm/chain/salt/v1";

    /// HKDF-Expand `info` for the initiator-to-recipient chain key. FROZEN.
    DM_CHAIN_A2B = b"daemonseed/dm/chain/a2b/v2";

    /// HKDF-Expand `info` for the recipient-to-initiator chain key. Distinct from
    /// [`DM_CHAIN_A2B`] so the two directions never share a message key — the defect
    /// that made the single-chain draft reuse an AES-GCM nonce. FROZEN.
    DM_CHAIN_B2A = b"daemonseed/dm/chain/b2a/v2";

    /// HKDF-Extract salt for one symmetric step along a chain. FROZEN.
    DM_CHAIN_STEP_SALT = b"daemonseed/dm/chain/step-salt/v1";

    /// HKDF-Expand `info` for the message key at a chain position. FROZEN.
    DM_MK = b"daemonseed/dm/mk/v2";

    /// HKDF-Expand `info` for the successor chain key. Sibling of [`DM_MK`] under one
    /// extraction, so learning a message key never yields the chain it came from.
    /// FROZEN.
    DM_CK = b"daemonseed/dm/ck/v2";
}

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
        assert_eq!(DM_FC_POW, b"daemonseed/dm/fc/pow/v1");
        assert_eq!(DM_TOKEN, b"daemonseed/dm/token/v1");
        assert_eq!(DM_PROVISIONAL_SALT, b"daemonseed/dm/provisional/salt/v1");
        assert_eq!(DM_PROVISIONAL_SEAL, b"daemonseed/dm/provisional/seal/v1");
        assert_eq!(DM_PROVISIONAL_AAD, b"daemonseed/dm/provisional/aad/v1");
        assert_eq!(
            DM_PROVISIONAL_BIND_SALT,
            b"daemonseed/dm/provisional/bind-salt/v1"
        );
        assert_eq!(DM_PROVISIONAL_BIND, b"daemonseed/dm/provisional/bind/v1");
        assert_eq!(DM_STORE_SALT, b"daemonseed/dm/store/salt/v1");
        assert_eq!(DM_STORE_SEAL, b"daemonseed/dm/store/seal/v1");
        assert_eq!(DM_STORE_AAD, b"daemonseed/dm/store/aad/v1");
        assert_eq!(DM_BIND_LT, b"daemonseed/dm/bind/lt/v1");
        assert_eq!(DM_MSG_SIG, b"daemonseed/dm/msg/sig/v6");
        assert_eq!(DM_MSG_AAD, b"daemonseed/dm/msg/aad/v4");
        assert_eq!(DM_ROOT_SALT, b"daemonseed/dm/root/salt/v1");
        assert_eq!(DM_ADDR_ROOT, b"daemonseed/dm/addr/root/v3");
        assert_eq!(DM_CHAN_ID, b"daemonseed/dm/chanid/v2");
        assert_eq!(DM_PAGE_SALT, b"daemonseed/dm/page/salt/v1");
        assert_eq!(DM_PAGE_ADDR, b"daemonseed/dm/page/addr/v4");
        assert_eq!(DM_ACK_SALT, b"daemonseed/dm/ack/salt/v1");
        assert_eq!(DM_ACK_SEAL, b"daemonseed/dm/ack/seal/v3");
        assert_eq!(DM_ACK_SIG, b"daemonseed/dm/ack/sig/v3");
        assert_eq!(DM_RATCHET_ROOT, b"daemonseed/dm/ratchet/root/v2");
        assert_eq!(DM_RATCHET_STEP, b"daemonseed/dm/ratchet/step/v2");
        assert_eq!(DM_CHAIN_SALT, b"daemonseed/dm/chain/salt/v1");
        assert_eq!(DM_CHAIN_A2B, b"daemonseed/dm/chain/a2b/v2");
        assert_eq!(DM_CHAIN_B2A, b"daemonseed/dm/chain/b2a/v2");
        assert_eq!(DM_CHAIN_STEP_SALT, b"daemonseed/dm/chain/step-salt/v1");
        assert_eq!(DM_MK, b"daemonseed/dm/mk/v2");
        assert_eq!(DM_CK, b"daemonseed/dm/ck/v2");
    }

    /// No label is a prefix of another.
    fn check_prefix_free(labels: &[&[u8]]) -> Result<(), String> {
        for (i, a) in labels.iter().enumerate() {
            for (j, b) in labels.iter().enumerate() {
                if i == j {
                    continue;
                }
                if b.starts_with(a) {
                    return Err(format!(
                        "{} is a prefix of {}",
                        String::from_utf8_lossy(a),
                        String::from_utf8_lossy(b)
                    ));
                }
            }
        }
        Ok(())
    }

    /// The frozen design's F11 requirement: no label may be a prefix of another.
    /// If one were, a derivation for the shorter purpose could be confused with a
    /// truncated derivation for the longer one.
    ///
    /// Runs over `ALL` alone since #296. It used to run twice — over `ALL` and over
    /// a set parsed out of this file — because `ALL` was hand-maintained and might
    /// not have been complete, which is the set #283 showed can silently shrink.
    /// `ALL` is now emitted by the same `dm_labels!` invocation that declares the
    /// labels, so the second pass had nothing left to disagree with and retired with
    /// the parser that fed it.
    #[test]
    fn no_label_is_a_prefix_of_another() {
        // `ALL` is emitted by the same `dm_labels!` invocation that declares the
        // labels, so it cannot omit one — which is what lets this run over `ALL`
        // alone. Before #296 it ran twice, once over `ALL` and once over a list
        // parsed out of this file, because `ALL` was hand-maintained and might not
        // have been complete. The second pass is gone with the parser that fed it.
        check_prefix_free(ALL).unwrap();
        assert!(
            !ALL.is_empty(),
            "the registry is empty, so this check proves nothing"
        );
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

    /// **Known-answer test over every label, written from the values as they stood
    /// BEFORE the `dm_labels!` migration (#296).**
    ///
    /// The macro removes the source-parsing class of bug, but a mechanical rewrite of
    /// 37 frozen cryptographic labels is exactly the operation that could corrupt one
    /// silently — and every other check in this module now derives from the same
    /// invocation, so none of them could notice. This list does not: it was captured
    /// from the pre-migration source by the parser being retired, and is the
    /// independent anchor the migration is verified against.
    ///
    /// It stays afterwards as the change-detector for a FROZEN label set. Editing a
    /// value here to make a test pass is the one thing this must never be used for —
    /// these strings are on the wire and in derivations shipped to peers.
    #[test]
    fn every_label_matches_its_pre_migration_value() {
        let pinned: [(&[u8], &[u8]); 39] = [
            (DM_ACK_SALT, b"daemonseed/dm/ack/salt/v1".as_slice()),
            (DM_ACK_SEAL, b"daemonseed/dm/ack/seal/v3".as_slice()),
            (DM_ACK_SIG, b"daemonseed/dm/ack/sig/v3".as_slice()),
            (DM_ADDR_ROOT, b"daemonseed/dm/addr/root/v3".as_slice()),
            (DM_BIND_LT, b"daemonseed/dm/bind/lt/v1".as_slice()),
            (DM_CHAIN_A2B, b"daemonseed/dm/chain/a2b/v2".as_slice()),
            (DM_CHAIN_B2A, b"daemonseed/dm/chain/b2a/v2".as_slice()),
            (DM_CHAIN_SALT, b"daemonseed/dm/chain/salt/v1".as_slice()),
            (
                DM_CHAIN_STEP_SALT,
                b"daemonseed/dm/chain/step-salt/v1".as_slice(),
            ),
            (DM_CHAN_ID, b"daemonseed/dm/chanid/v2".as_slice()),
            (DM_CK, b"daemonseed/dm/ck/v2".as_slice()),
            (
                DM_DOORBELL_OWNER,
                b"daemonseed/dm/doorbell/addr/v4".as_slice(),
            ),
            (
                DM_DOORBELL_SALT,
                b"daemonseed/dm/doorbell/salt/v1".as_slice(),
            ),
            (
                DM_DOORBELL_SLOT,
                b"daemonseed/dm/doorbell/slot/v5".as_slice(),
            ),
            (
                DM_DOORBELL_SLOT_SALT,
                b"daemonseed/dm/doorbell/slot-salt/v1".as_slice(),
            ),
            (DM_FC_AAD, b"daemonseed/dm/fc/aad/v1".as_slice()),
            (DM_FC_POW, b"daemonseed/dm/fc/pow/v1".as_slice()),
            (DM_FC_SALT, b"daemonseed/dm/fc/salt/v1".as_slice()),
            (DM_FC_SEAL, b"daemonseed/dm/fc/seal/v1".as_slice()),
            (DM_KEYREC_OWNER, b"daemonseed/dm/keyrec/owner/v1".as_slice()),
            (DM_KEYREC_SALT, b"daemonseed/dm/keyrec/salt/v1".as_slice()),
            (DM_KEYREC_SIG, b"daemonseed/dm/keyrec/sig/v1".as_slice()),
            (DM_MK, b"daemonseed/dm/mk/v2".as_slice()),
            (DM_MSG_AAD, b"daemonseed/dm/msg/aad/v4".as_slice()),
            (DM_MSG_SIG, b"daemonseed/dm/msg/sig/v6".as_slice()),
            (DM_PAGE_ADDR, b"daemonseed/dm/page/addr/v4".as_slice()),
            (DM_PAGE_SALT, b"daemonseed/dm/page/salt/v1".as_slice()),
            (
                DM_PROVISIONAL_AAD,
                b"daemonseed/dm/provisional/aad/v1".as_slice(),
            ),
            (
                DM_PROVISIONAL_BIND,
                b"daemonseed/dm/provisional/bind/v1".as_slice(),
            ),
            (
                DM_PROVISIONAL_BIND_SALT,
                b"daemonseed/dm/provisional/bind-salt/v1".as_slice(),
            ),
            (
                DM_PROVISIONAL_SALT,
                b"daemonseed/dm/provisional/salt/v1".as_slice(),
            ),
            (
                DM_PROVISIONAL_SEAL,
                b"daemonseed/dm/provisional/seal/v1".as_slice(),
            ),
            (DM_RATCHET_ROOT, b"daemonseed/dm/ratchet/root/v2".as_slice()),
            (DM_RATCHET_STEP, b"daemonseed/dm/ratchet/step/v2".as_slice()),
            (DM_ROOT_SALT, b"daemonseed/dm/root/salt/v1".as_slice()),
            (DM_STORE_AAD, b"daemonseed/dm/store/aad/v1".as_slice()),
            (DM_STORE_SALT, b"daemonseed/dm/store/salt/v1".as_slice()),
            (DM_STORE_SEAL, b"daemonseed/dm/store/seal/v1".as_slice()),
            (DM_TOKEN, b"daemonseed/dm/token/v1".as_slice()),
        ];
        assert_eq!(
            pinned.len(),
            ALL.len(),
            "the registry and this known-answer list disagree on how many labels exist"
        );
        for (actual, expected) in pinned {
            assert_eq!(
                actual,
                expected,
                "a frozen label changed value: {} != {}",
                String::from_utf8_lossy(actual),
                String::from_utf8_lossy(expected)
            );
        }
        // Loud-empty, preserved from #295 — but stated the way it is actually true
        // here. `pinned` is a fixed-size array, so `!is_empty()` is compile-time
        // true and reads as a control while being none: review caught that. What
        // can go wrong is a row DUPLICATED to make the count match while a real
        // label goes unpinned, so distinctness is the check that carries the load.
        let mut names: Vec<&[u8]> = pinned.iter().map(|(_, expected)| *expected).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(
            names.len(),
            before,
            "the known-answer list contains a duplicate, so it can match ALL's length \
             while leaving a label unpinned"
        );
    }

    /// Every declaration in `source` that bypassed `dm_labels!`.
    ///
    /// **Factored out so it can be driven over fixtures.** The first version of this
    /// check read `include_str!` inline, which meant nothing could prove it was able
    /// to fire — and that is exactly why its gaps went unnoticed: it was strictly
    /// weaker than the #295-hardened parser it replaced, missing a wrapped
    /// declaration, `&'static [u8]`, and `&[u8; N]` (which is the natural type of a
    /// byte literal, not an odd shape at all). A guard about formatting cannot be
    /// trusted on the strength of the formatting that happens to be in the file.
    ///
    /// **Continuation lines are joined before matching**, which is the specific
    /// hardening #295 added and the first version of this dropped. A `$` anywhere in
    /// the joined declaration excludes the macro's own template line, which is an
    /// expansion rule rather than a declaration.
    fn rogue_declarations(source: &str) -> Vec<String> {
        let mut joined = Vec::new();
        let mut acc = String::new();
        for line in source.lines() {
            let t = line.trim();
            if acc.is_empty() {
                if !(t.starts_with("pub const ") || t.starts_with("pub(crate) const ")) {
                    continue;
                }
                acc.push_str(t);
            } else {
                acc.push(' ');
                acc.push_str(t);
            }
            if acc.contains(';') {
                joined.push(std::mem::take(&mut acc));
            }
        }
        joined
            .into_iter()
            // A byte-slice or byte-array type, however it is spelled: `&[u8]`,
            // `&'static [u8]`, `&[u8; 24]`. Matching on `[u8` rather than an exact
            // rendering is what makes the lifetime and the array length irrelevant.
            .filter(|d| d.contains("[u8") && !d.contains('$'))
            .collect()
    }

    /// **No label may be declared outside `dm_labels!`.**
    ///
    /// #296's premise is that the macro makes an unregistered label
    /// "unrepresentable-otherwise" because the declaration and `ALL` come from one
    /// invocation. That is true of labels written *through* the macro and false of
    /// the module as a whole: nothing stops a future edit adding a plain
    /// `pub const DM_…` beside it, which compiles, is absent from `ALL`, and escapes
    /// prefix-freeness — the #283 class. **Verified by mutation, not assumed: a
    /// hand-written declaration outside the macro passed every other test here.**
    ///
    /// So one narrow check survives the three #296 retired. It is a different
    /// proposition from the parser it replaces: that one had to *extract* names and
    /// values, and a parse finding less than it should reported success. This asks a
    /// yes/no question whose expected answer is zero.
    ///
    /// **What it does not reach, stated rather than implied:** a label declared in
    /// another module, even one under the `daemonseed/dm/` prefix. Prefix-freeness
    /// is a property of the label set, and the label set is this module.
    #[test]
    fn no_label_is_declared_outside_the_macro() {
        let source = include_str!("domain.rs");
        assert!(
            source.contains("dm_labels! {"),
            "this module's source does not contain the macro invocation, so this \
             check is reading the wrong thing and proves nothing"
        );
        let rogue = rogue_declarations(source);
        assert!(
            rogue.is_empty(),
            "these labels are declared outside `dm_labels!`, so they are absent from \
             `ALL` and exempt from prefix-freeness: {rogue:?}"
        );
    }

    /// **Positive controls: every shape the guard must catch, proven to fail it.**
    ///
    /// Three of these escaped the first version of the guard and were found only by
    /// review — a wrapped declaration, a `&'static` lifetime, and a sized array. Each
    /// is pinned here so the guard cannot silently narrow again, which is what
    /// happened when #295's continuation-joining was dropped.
    #[test]
    fn the_guard_catches_every_rogue_shape() {
        let cases = [
            ("plain", "pub const DM_R: &[u8] = b\"daemonseed/dm/r/v1\";"),
            (
                "wrapped",
                "pub const DM_ROGUE_WITH_A_VERY_LONG_NAME:\n    &[u8] = b\"daemonseed/dm/r/v1\";",
            ),
            (
                "static lifetime",
                "pub const DM_R: &'static [u8] = b\"daemonseed/dm/r/v1\";",
            ),
            (
                "sized array",
                "pub const DM_R: &[u8; 18] = b\"daemonseed/dm/r/v1\";",
            ),
            (
                "pub(crate)",
                "pub(crate) const DM_R: &[u8] = b\"daemonseed/dm/r/v1\";",
            ),
        ];
        for (name, fixture) in cases {
            let found = rogue_declarations(fixture);
            assert_eq!(
                found.len(),
                1,
                "the guard missed a {name} declaration, which would ship absent from \
                 `ALL` and exempt from prefix-freeness"
            );
        }
    }

    /// The mirror control: the guard must not accuse the macro's own template, a doc
    /// comment, or an ordinary non-label constant.
    #[test]
    fn the_guard_does_not_accuse_what_it_should_not() {
        for benign in [
            "pub const $name: &[u8] = $value;",
            "/// pub const DM_R: &[u8] = b\"x\";",
            "pub const MAX_SKIP: usize = 64;",
            "    DM_R = b\"daemonseed/dm/r/v1\";",
        ] {
            assert!(
                rogue_declarations(benign).is_empty(),
                "the guard wrongly accused: {benign}"
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
