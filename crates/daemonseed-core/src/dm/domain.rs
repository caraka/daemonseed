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
    /// HKDF-Extract salt for the ADVERT's owner-seed derivation, rooted in the
    /// advertising identity's published ML-DSA-87 public key. Distinct from every
    /// other salt over that same public input, so two derivations from one key
    /// cannot collide onto one address. FROZEN.
    DM_ADVERT_SALT = b"daemonseed/dm/advert/salt/v1";

    /// HKDF-Expand `info` for the advert's Veilid owner seed, derived from the
    /// identity's full ML-DSA-87 public key. World-derivable by design: anyone
    /// holding the public key computes the address, which is what makes an
    /// identity's current ML-KEM-1024 public key findable. FROZEN.
    DM_ADVERT_OWNER = b"daemonseed/dm/advert/owner/v1";

    /// Signature domain for the [`crate::dm::advert`] record's inner ML-DSA-87
    /// signature. The identity public key, the serial, the validity start and the
    /// ML-KEM-1024 public key follow it, each length-prefixed. FROZEN.
    DM_ADVERT_SIG = b"daemonseed/dm/advert/sig/v1";

    /// HKDF-Extract salt for the DM record store's at-rest seal key, rooted in the
    /// profile's at-rest key material. That store holds fixed-size records, never a
    /// message archive. FROZEN.
    DM_STORE_SALT = b"daemonseed/dm/store/salt/v1";

    /// HKDF-Expand `info` for the DM record store's AES-256-GCM seal key
    /// ([`crate::storage::dm_store`]).
    ///
    /// FROZEN.
    DM_STORE_SEAL = b"daemonseed/dm/store/seal/v1";

    /// AAD prefix for a DM store record's at-rest seal. The correspondence label and
    /// the record-kind tag follow it, length-prefixed.
    ///
    /// **Per-slot, where the key is only per-profile.** [`DM_STORE_SEAL`] derives ONE
    /// key for a whole profile, so without this binding every file in the store is an
    /// interchangeable ciphertext: copy one correspondence's record over
    /// another's and it opens cleanly, or drop one kind into another kind's slot of
    /// the same size and it opens as that kind. Binding what the store *expects* the
    /// file to be is what makes both splices fail to authenticate. FROZEN.
    DM_STORE_AAD = b"daemonseed/dm/store/aad/v1";

    /// AAD prefix for a **profile-level** DM store record's at-rest seal — one that
    /// belongs to the profile itself rather than to any correspondence. Only the
    /// record-kind tag follows it, length-prefixed.
    ///
    /// **Its own label because there is no correspondence label to bind, and an
    /// absent field is not a separation.** [`DM_STORE_AAD`]'s two bound fields are
    /// the label and the kind; a profile record has no label, so reusing that prefix
    /// would leave the kind tag as the whole of the separation and make the
    /// construction's field count depend on which kind it is — a shape an
    /// implementation is free to guess wrong. Separating at the prefix keeps each
    /// construction's field list fixed, so a profile record and a correspondence
    /// record can never be parsed into one another. FROZEN.
    DM_STORE_PROFILE_AAD = b"daemonseed/dm/store/profile/aad/v1";

    /// HKDF-Extract salt for the DROP's owner-seed derivation, rooted in the
    /// RECIPIENT's published identity key. Distinct from every other salt over that
    /// same public input, so two derivations from one identity key cannot collide
    /// onto one address. FROZEN.
    DM_DROP_SALT = b"daemonseed/dm/drop/salt/v1";

    /// HKDF-Expand `info` for the drop's Veilid owner seed, derived from the
    /// recipient's full ML-DSA-87 public key. World-derivable — and therefore
    /// world-WRITABLE — by design: a stranger holding only the recipient's published
    /// identity must be able to reach it, which is what first contact is. FROZEN.
    DM_DROP_OWNER = b"daemonseed/dm/drop/owner/v1";

    /// HKDF-Extract salt for the hello seal key, rooted in `ss0` — the secret an
    /// encapsulation to the recipient's advert key yields. FROZEN.
    DM_DROP_HELLO_SALT = b"daemonseed/dm/drop/hello-salt/v1";

    /// HKDF-Expand `info` for `k_hello`, the key a hello's `lookup_key ‖ r` is
    /// sealed under. FROZEN.
    DM_DROP_HELLO = b"daemonseed/dm/drop/hello/v1";

    /// AEAD associated-data prefix for a hello. The ML-KEM ciphertext and the
    /// recipient's identity public key follow it, each length-prefixed, so a
    /// ciphertext cannot be lifted from one hello into another and a hello written
    /// at one identity's drop does not open at another's. FROZEN.
    DM_DROP_AAD = b"daemonseed/dm/drop/aad/v1";

    /// Proof-of-work domain for a hello's tag. The ML-KEM ciphertext, `r` and the
    /// recipient's identity public key follow it, each length-prefixed. FROZEN.
    DM_DROP_POW = b"daemonseed/dm/drop/pow/v1";

    /// Domain prefix for the digest that picks a hello's slot, with `r`
    /// length-prefixed after it. The slot is the digest's last byte, so this label
    /// is what stops it coinciding with a digest taken over the same `r` for another
    /// purpose. FROZEN.
    DM_DROP_SLOT = b"daemonseed/dm/drop/slot/v1";

    /// HKDF-Extract salt for a CHANNEL owner-seed derivation, rooted in the writer's
    /// identity SECRET. Not world-derivable, unlike the advert's and the drop's:
    /// only the writer, or another device holding the same recovery phrase, computes
    /// this address. FROZEN.
    DM_CHANNEL_SALT = b"daemonseed/dm/channel/salt/v1";

    /// HKDF-Expand `info` prefix for one direction's Veilid owner seed. The peer's
    /// identity public key and the conversation generation follow it, each
    /// length-prefixed, so the two directions of one conversation and two
    /// generations of one pair are four distinct records. FROZEN.
    DM_CHANNEL_OWNER = b"daemonseed/dm/channel/owner/v1";

    /// HKDF-Extract salt for the control subkey's seal key, rooted in the shared
    /// secret of the hello that named the channel. FROZEN.
    DM_CHANNEL_CONTROL_SALT = b"daemonseed/dm/channel/control-salt/v1";

    /// HKDF-Expand `info` for `k_control`, the key the control subkey — the channel
    /// opening and the writer's collection cursor — is sealed under. FROZEN.
    DM_CHANNEL_CONTROL = b"daemonseed/dm/channel/control/v1";

    /// AEAD associated-data prefix for the control subkey, with the subkey number
    /// length-prefixed after it. FROZEN.
    DM_CHANNEL_CONTROL_AAD = b"daemonseed/dm/channel/control-aad/v1";

    /// AEAD associated-data prefix for a channel message. The encoded message
    /// header follows it, so every clear field the header carries is bound to the
    /// body it heads and a rewritten field on a genuine slot fails to open. FROZEN.
    DM_CHANNEL_MSG_AAD = b"daemonseed/dm/channel/msg-aad/v1";

    /// Signature domain for a channel opening. The writer's identity public key, its
    /// first ratchet public key and the advert serial follow it, each
    /// length-prefixed; binding the serial is what makes a relayed hello land in a
    /// channel the reader refuses. FROZEN.
    DM_CHANNEL_OPENING_SIG = b"daemonseed/dm/channel/opening-sig/v1";

    /// HKDF-Extract salt for a conversation direction's seed root, rooted in the
    /// shared secret of the hello that named the channel. Distinct from
    /// [`DM_CHANNEL_CONTROL_SALT`], which extracts the control key from that same
    /// secret, so the two derivations over one input cannot collide. FROZEN.
    DM_CHANNEL_ROOT_SALT = b"daemonseed/dm/channel/root-salt/v1";

    /// HKDF-Expand `info` for a conversation direction's root
    /// ([`crate::dm::chain`]), both for the seed root and for every turn's
    /// successor.
    ///
    /// FROZEN.
    DM_CHANNEL_ROOT = b"daemonseed/dm/channel/root/v1";

    /// HKDF-Extract salt for a turn's chain key, rooted in that turn's root.
    /// FROZEN.
    DM_CHANNEL_CHAIN_SALT = b"daemonseed/dm/channel/chain-salt/v1";

    /// HKDF-Expand `info` for a turn's chain key.
    ///
    /// **One label for both directions.** The two directions share only the SEED root,
    /// derived from `ss0` and therefore one value on both sides, and diverge at
    /// each side's first own turn; from there each root is its own. A
    /// per-direction label would not separate the seed — both sides derive both
    /// halves of it — so what keeps the two directions off one chain is
    /// [`crate::dm::chain::Direction`] holding no chain until its first own turn.
    /// FROZEN.
    DM_CHANNEL_CHAIN = b"daemonseed/dm/channel/chain/v1";

    /// HKDF-Extract salt for one symmetric step along a turn's chain. FROZEN.
    DM_CHANNEL_STEP_SALT = b"daemonseed/dm/channel/step-salt/v1";

    /// HKDF-Expand `info` for the message key at a chain position. FROZEN.
    DM_CHANNEL_MK = b"daemonseed/dm/channel/mk/v1";

    /// HKDF-Expand `info` for the successor chain key. Sibling of
    /// [`DM_CHANNEL_MK`] under one extraction, so learning a message key never
    /// yields the chain it came from. FROZEN.
    DM_CHANNEL_CK = b"daemonseed/dm/channel/ck/v1";
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-pinned: these strings are the wire. A change here is a protocol
    /// change, and this test is the tripwire that makes it deliberate.
    #[test]
    fn labels_are_byte_pinned() {
        assert_eq!(DM_STORE_SALT, b"daemonseed/dm/store/salt/v1");
        assert_eq!(DM_STORE_SEAL, b"daemonseed/dm/store/seal/v1");
        assert_eq!(DM_STORE_AAD, b"daemonseed/dm/store/aad/v1");
        assert_eq!(DM_STORE_PROFILE_AAD, b"daemonseed/dm/store/profile/aad/v1");
        assert_eq!(DM_ADVERT_SALT, b"daemonseed/dm/advert/salt/v1");
        assert_eq!(DM_ADVERT_OWNER, b"daemonseed/dm/advert/owner/v1");
        assert_eq!(DM_ADVERT_SIG, b"daemonseed/dm/advert/sig/v1");
        assert_eq!(DM_DROP_SALT, b"daemonseed/dm/drop/salt/v1");
        assert_eq!(DM_DROP_OWNER, b"daemonseed/dm/drop/owner/v1");
        assert_eq!(DM_DROP_HELLO_SALT, b"daemonseed/dm/drop/hello-salt/v1");
        assert_eq!(DM_DROP_HELLO, b"daemonseed/dm/drop/hello/v1");
        assert_eq!(DM_DROP_AAD, b"daemonseed/dm/drop/aad/v1");
        assert_eq!(DM_DROP_POW, b"daemonseed/dm/drop/pow/v1");
        assert_eq!(DM_DROP_SLOT, b"daemonseed/dm/drop/slot/v1");
        assert_eq!(DM_CHANNEL_SALT, b"daemonseed/dm/channel/salt/v1");
        assert_eq!(DM_CHANNEL_OWNER, b"daemonseed/dm/channel/owner/v1");
        assert_eq!(
            DM_CHANNEL_CONTROL_SALT,
            b"daemonseed/dm/channel/control-salt/v1"
        );
        assert_eq!(DM_CHANNEL_CONTROL, b"daemonseed/dm/channel/control/v1");
        assert_eq!(
            DM_CHANNEL_CONTROL_AAD,
            b"daemonseed/dm/channel/control-aad/v1"
        );
        assert_eq!(
            DM_CHANNEL_OPENING_SIG,
            b"daemonseed/dm/channel/opening-sig/v1"
        );
        assert_eq!(DM_CHANNEL_MSG_AAD, b"daemonseed/dm/channel/msg-aad/v1");
        assert_eq!(DM_CHANNEL_ROOT_SALT, b"daemonseed/dm/channel/root-salt/v1");
        assert_eq!(DM_CHANNEL_ROOT, b"daemonseed/dm/channel/root/v1");
        assert_eq!(
            DM_CHANNEL_CHAIN_SALT,
            b"daemonseed/dm/channel/chain-salt/v1"
        );
        assert_eq!(DM_CHANNEL_CHAIN, b"daemonseed/dm/channel/chain/v1");
        assert_eq!(DM_CHANNEL_STEP_SALT, b"daemonseed/dm/channel/step-salt/v1");
        assert_eq!(DM_CHANNEL_MK, b"daemonseed/dm/channel/mk/v1");
        assert_eq!(DM_CHANNEL_CK, b"daemonseed/dm/channel/ck/v1");
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

    /// The frozen design's requirement: no label may be a prefix of another.
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
    /// It stays afterwards as the change-detector for a FROZEN label set, and a
    /// label declared AFTER the migration is pinned here too — the length assertion
    /// below requires it, and a new label is exactly as frozen as an old one once it
    /// ships. Editing a value here to make a test pass is the one thing this must
    /// never be used for — these strings are on the wire and in derivations shipped
    /// to peers.
    #[test]
    fn every_label_matches_its_pre_migration_value() {
        let pinned: [(&[u8], &[u8]); 28] = [
            (DM_ADVERT_OWNER, b"daemonseed/dm/advert/owner/v1".as_slice()),
            (DM_ADVERT_SALT, b"daemonseed/dm/advert/salt/v1".as_slice()),
            (DM_ADVERT_SIG, b"daemonseed/dm/advert/sig/v1".as_slice()),
            (
                DM_CHANNEL_CHAIN,
                b"daemonseed/dm/channel/chain/v1".as_slice(),
            ),
            (
                DM_CHANNEL_CHAIN_SALT,
                b"daemonseed/dm/channel/chain-salt/v1".as_slice(),
            ),
            (DM_CHANNEL_CK, b"daemonseed/dm/channel/ck/v1".as_slice()),
            (
                DM_CHANNEL_CONTROL,
                b"daemonseed/dm/channel/control/v1".as_slice(),
            ),
            (
                DM_CHANNEL_CONTROL_AAD,
                b"daemonseed/dm/channel/control-aad/v1".as_slice(),
            ),
            (
                DM_CHANNEL_CONTROL_SALT,
                b"daemonseed/dm/channel/control-salt/v1".as_slice(),
            ),
            (DM_CHANNEL_MK, b"daemonseed/dm/channel/mk/v1".as_slice()),
            (
                DM_CHANNEL_MSG_AAD,
                b"daemonseed/dm/channel/msg-aad/v1".as_slice(),
            ),
            (
                DM_CHANNEL_OPENING_SIG,
                b"daemonseed/dm/channel/opening-sig/v1".as_slice(),
            ),
            (
                DM_CHANNEL_OWNER,
                b"daemonseed/dm/channel/owner/v1".as_slice(),
            ),
            (DM_CHANNEL_ROOT, b"daemonseed/dm/channel/root/v1".as_slice()),
            (
                DM_CHANNEL_ROOT_SALT,
                b"daemonseed/dm/channel/root-salt/v1".as_slice(),
            ),
            (DM_CHANNEL_SALT, b"daemonseed/dm/channel/salt/v1".as_slice()),
            (
                DM_CHANNEL_STEP_SALT,
                b"daemonseed/dm/channel/step-salt/v1".as_slice(),
            ),
            (DM_DROP_AAD, b"daemonseed/dm/drop/aad/v1".as_slice()),
            (DM_DROP_HELLO, b"daemonseed/dm/drop/hello/v1".as_slice()),
            (
                DM_DROP_HELLO_SALT,
                b"daemonseed/dm/drop/hello-salt/v1".as_slice(),
            ),
            (DM_DROP_OWNER, b"daemonseed/dm/drop/owner/v1".as_slice()),
            (DM_DROP_POW, b"daemonseed/dm/drop/pow/v1".as_slice()),
            (DM_DROP_SALT, b"daemonseed/dm/drop/salt/v1".as_slice()),
            (DM_DROP_SLOT, b"daemonseed/dm/drop/slot/v1".as_slice()),
            (DM_STORE_AAD, b"daemonseed/dm/store/aad/v1".as_slice()),
            (
                DM_STORE_PROFILE_AAD,
                b"daemonseed/dm/store/profile/aad/v1".as_slice(),
            ),
            (DM_STORE_SALT, b"daemonseed/dm/store/salt/v1".as_slice()),
            (DM_STORE_SEAL, b"daemonseed/dm/store/seal/v1".as_slice()),
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
