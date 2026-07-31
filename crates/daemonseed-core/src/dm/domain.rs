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

/// HKDF-Extract salt for the provisional handshake record's at-rest seal key,
/// rooted in the profile's at-rest key material — **never** in `ss0`, which is
/// what the record holds. Pairs with [`DM_PROVISIONAL_SEAL`] exactly as
/// [`DM_FC_SALT`] pairs with [`DM_FC_SEAL`]. FROZEN.
pub const DM_PROVISIONAL_SALT: &[u8] = b"daemonseed/dm/provisional/salt/v1";

/// HKDF-Expand `info` for the provisional handshake record's AES-256-GCM seal
/// key ([`crate::dm::provisional`]).
///
/// **Its own label rather than the first-contact seal's.** That one is keyed on
/// `ss0` and protects an entry on the wire; this one is keyed on local at-rest
/// material and protects a record on the medium. Deriving both from one label
/// would mean a first-contact entry and a provisional record could open as each
/// other wherever the two key inputs ever coincided. FROZEN.
pub const DM_PROVISIONAL_SEAL: &[u8] = b"daemonseed/dm/provisional/seal/v1";

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
pub const DM_PROVISIONAL_AAD: &[u8] = b"daemonseed/dm/provisional/aad/v1";

/// HKDF-Extract salt for the provisional record's internal binding tag, rooted in
/// `ss0`. Distinct from [`DM_PROVISIONAL_SALT`], which is rooted in the profile's
/// at-rest material: the two extractions must not share a salt. FROZEN.
pub const DM_PROVISIONAL_BIND_SALT: &[u8] = b"daemonseed/dm/provisional/bind-salt/v1";

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
pub const DM_PROVISIONAL_BIND: &[u8] = b"daemonseed/dm/provisional/bind/v1";

/// HKDF-Extract salt for the DM record store's at-rest seal key, rooted in the
/// profile's at-rest key material — the same root [`DM_PROVISIONAL_SALT`] uses,
/// under its own salt so the two extractions over that one input cannot collide.
/// FROZEN.
pub const DM_STORE_SALT: &[u8] = b"daemonseed/dm/store/salt/v1";

/// HKDF-Expand `info` for the DM record store's AES-256-GCM seal key
/// ([`crate::storage::dm_store`]).
///
/// **Its own label rather than [`DM_PROVISIONAL_SEAL`]'s.** That key protects one
/// record kind's contents; this one protects every record's slot in the store,
/// including a provisional record the other key already sealed. One label for
/// both would mean a store blob and a provisional record could open as each other
/// wherever the two key inputs coincided — which, both being derived from the
/// same profile at-rest material, is always. FROZEN.
pub const DM_STORE_SEAL: &[u8] = b"daemonseed/dm/store/seal/v1";

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
pub const DM_STORE_AAD: &[u8] = b"daemonseed/dm/store/aad/v1";

/// Signature domain binding a per-contact pseudonym key to the long-term identity
/// that vouches for it, signed under the LONG-TERM key. FROZEN.
pub const DM_BIND_LT: &[u8] = b"daemonseed/dm/bind/lt/v1";

/// Signature domain for a DM frame's authorship signature, signed under the
/// PSEUDONYM key. The sole proof-of-possession path (the separate `bind_pop` was
/// folded into it), so it binds both public keys as well as the message. FROZEN.
pub const DM_MSG_SIG: &[u8] = b"daemonseed/dm/msg/sig/v6";

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
pub const DM_MSG_AAD: &[u8] = b"daemonseed/dm/msg/aad/v4";

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

/// HKDF-Extract salt for a channel page's owner-seed derivation, rooted in the
/// conversation's secret address root `AR`. FROZEN.
pub const DM_PAGE_SALT: &[u8] = b"daemonseed/dm/page/salt/v1";

/// HKDF-Expand `info` prefix for a channel page's Veilid owner seed. The
/// direction and page number follow it, length-prefixed. Unlike every other DM
/// address this one is **not** world-derivable: it is rooted in a secret only the
/// two parties hold, which is what makes the page owner-write-gated and therefore
/// unforgeable and un-erasable by a third party. FROZEN.
pub const DM_PAGE_ADDR: &[u8] = b"daemonseed/dm/page/addr/v4";

/// HKDF-Extract salt for a direction's delivery-acknowledgement seal key, rooted
/// in the conversation's retained address root `AR`. Distinct from
/// [`DM_PAGE_SALT`] so the two derivations over that same secret cannot collide.
/// FROZEN.
pub const DM_ACK_SALT: &[u8] = b"daemonseed/dm/ack/salt/v1";

/// HKDF-Expand `info` prefix for a direction's delivery-acknowledgement seal key.
/// The direction follows it, length-prefixed.
///
/// **Rooted in `AR`, not in the ratchet root**, which is what the `/v3` in the
/// frozen name records: a ratchet-rooted ack key desyncs the moment the two
/// parties sit at different generations (crypto F-3), and the acknowledgement
/// would go dark exactly when a conversation is busiest. Per-direction for F-6.
/// FROZEN.
pub const DM_ACK_SEAL: &[u8] = b"daemonseed/dm/ack/seal/v3";

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
pub const DM_ACK_SIG: &[u8] = b"daemonseed/dm/ack/sig/v3";

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
    DM_PAGE_SALT,
    DM_PAGE_ADDR,
    DM_ACK_SALT,
    DM_ACK_SEAL,
    DM_ACK_SIG,
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
    DM_PROVISIONAL_SALT,
    DM_PROVISIONAL_SEAL,
    DM_PROVISIONAL_AAD,
    DM_PROVISIONAL_BIND_SALT,
    DM_PROVISIONAL_BIND,
    DM_STORE_SALT,
    DM_STORE_SEAL,
    DM_STORE_AAD,
    DM_BIND_LT,
    DM_MSG_SIG,
    DM_MSG_AAD,
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

    // ---- reading this module's own declarations ------------------------------
    //
    // Three of the guards below hold the hand-maintained registry and the
    // hand-maintained byte pins against the declarations themselves, which means
    // reading this file as text. That parse is a probe, and #283 was the probe
    // going blind: it required a declaration's name and its literal to land on
    // ONE line, so a declaration `rustfmt` had wrapped matched neither half,
    // dropped out of the parsed set, and became silently exempt from the registry
    // check, the byte-pin check and prefix-freeness at once — the registry's
    // `declared.len() == ALL.len()` cross-check included, because the label was
    // then missing from both sides. Nothing enforces the one-line form and the
    // names here are already long, so that was one added label away.
    //
    // The parse now joins each declaration's continuation lines before matching,
    // refuses to skip a `pub const DM_` it cannot read, and is loud when it reads
    // nothing at all. It is also factored out so the fixture tests at the end of
    // this module can drive it over wrapped declarations and prove each guard
    // fails on one — a guard about formatting cannot be trusted on the strength
    // of the formatting that happens to be in the file today.

    /// One `pub const DM_… = b"…";` declaration, as read out of source text.
    #[derive(Debug, PartialEq, Eq)]
    struct Declared {
        name: String,
        value: Vec<u8>,
    }

    /// Read every DM label declaration out of `source`, whatever line it is
    /// wrapped across.
    ///
    /// Anchored at the start of a line, so the `"pub const DM_"` literal that
    /// appears inside this test module's own text is not itself read as a
    /// declaration. A declaration is then taken to run to its terminating `;` —
    /// no DM label contains one, so no literal can end the scan early.
    ///
    /// Panics on a `pub const DM_` whose shape it cannot read rather than
    /// skipping it: skipping is precisely how #283 stayed invisible.
    fn parse_declarations(source: &str) -> Vec<Declared> {
        let mut out = Vec::new();
        let mut lines = source.lines();

        while let Some(line) = lines.next() {
            if !line.trim_start().starts_with("pub const DM_") {
                continue;
            }
            let mut decl = line.trim_start().to_string();
            while !decl.contains(';') {
                let Some(next) = lines.next() else { break };
                decl.push(' ');
                decl.push_str(next.trim());
            }

            let rest = decl
                .strip_prefix("pub const DM_")
                .expect("the line was checked for this prefix");
            let Some((name, tail)) = rest.split_once(':') else {
                panic!("a DM declaration carries no type annotation, so it cannot be read: {decl}");
            };
            let name = format!("DM_{}", name.trim());
            let Some((_, literal)) = tail.split_once("= b\"") else {
                panic!("{name} is declared in a shape this parser cannot read: {decl}");
            };
            let Some((value, _)) = literal.split_once('"') else {
                panic!("{name}'s byte-string literal is unterminated: {decl}");
            };

            out.push(Declared {
                name,
                value: value.as_bytes().to_vec(),
            });
        }

        out
    }

    /// [`parse_declarations`], made loud when it finds nothing.
    ///
    /// A probe whose input goes empty reports success, and every guard built on
    /// this one would then pass vacuously. This is the assertion that turns that
    /// from a pass into a failure.
    fn checked_parse(source: &str) -> Vec<Declared> {
        let declared = parse_declarations(source);
        assert!(
            !declared.is_empty(),
            "the declaration parser read no `pub const DM_…` at all, so every \
             guard built on it would pass while checking nothing"
        );
        declared
    }

    /// This module's own declarations.
    fn declarations() -> Vec<Declared> {
        checked_parse(include_str!("domain.rs"))
    }

    /// The body of the byte-pin tripwire, which the byte-pin guard checks each
    /// declaration appears in.
    fn byte_pin_body(source: &str) -> &str {
        source
            .split_once("fn labels_are_byte_pinned() {")
            .expect("the tripwire test exists")
            .1
            .split_once("\n    }")
            .expect("the tripwire test is a normal block")
            .0
    }

    /// Every declared label is in the registry, and the registry holds nothing
    /// else. Returned rather than asserted so the fixture tests can prove it
    /// fails.
    fn check_registered(declared: &[Declared], registry: &[&[u8]]) -> Result<(), String> {
        for label in declared {
            if !registry.contains(&label.value.as_slice()) {
                return Err(format!(
                    "{} is declared but missing from ALL, so nothing prefix-checks it",
                    String::from_utf8_lossy(&label.value)
                ));
            }
        }
        if declared.len() != registry.len() {
            return Err(format!(
                "ALL holds {} entries but {} labels are declared",
                registry.len(),
                declared.len()
            ));
        }
        Ok(())
    }

    /// Every declared label appears in the byte-pin tripwire's body.
    fn check_byte_pinned(declared: &[Declared], pin_body: &str) -> Result<(), String> {
        for label in declared {
            if !pin_body.contains(&label.name) {
                return Err(format!(
                    "{} is declared but never byte-pinned, so its wire value can \
                     change with the suite still green",
                    label.name
                ));
            }
        }
        Ok(())
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
    /// Run over the declarations as well as over `ALL`. The registry guard makes
    /// the two sets equal, but only while it can see every declaration — so this
    /// checks the labels as *declared*, which is what #283 showed is the set that
    /// can silently shrink.
    #[test]
    fn no_label_is_a_prefix_of_another() {
        check_prefix_free(ALL).unwrap();

        let declared = declarations();
        let values: Vec<&[u8]> = declared.iter().map(|d| d.value.as_slice()).collect();
        check_prefix_free(&values).unwrap();
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

    /// `labels_are_byte_pinned` is hand-maintained too, and it is the tripwire —
    /// so a label that is registered in `ALL` but never pinned can be edited to
    /// anything with the whole suite still green, which is exactly what happened
    /// to `DM_MSG_AAD` when it was added. Registry membership is enforced by the
    /// test below; this one enforces that the tripwire actually covers it.
    #[test]
    fn every_declared_label_is_byte_pinned() {
        // Scoped to the tripwire's own body. An earlier version of this test
        // scanned the whole file for `DM_…` tokens, which the `ALL` registry
        // array satisfies on its own — so it passed while `DM_MSG_AAD` was
        // registered and unpinned, i.e. it tested nothing. Mutation-confirmed.
        let body = byte_pin_body(include_str!("domain.rs"));
        check_byte_pinned(&declarations(), body).unwrap();
    }

    /// `ALL` is hand-maintained, and the two checks above only ever see what is
    /// in it — so a label added without a registry line would be silently exempt
    /// from prefix-freeness forever, and no test would notice. This reads this
    /// module's own source and holds the registry to it in both directions:
    /// every declared label appears in `ALL`, and `ALL` contains nothing else.
    #[test]
    fn every_declared_label_is_registered_for_the_prefix_check() {
        check_registered(&declarations(), ALL).unwrap();
    }

    // ---- positive controls for the guards themselves -------------------------
    //
    // #283's defect was that all three guards reported success on a declaration
    // none of them could see. Proving the fix therefore means proving each guard
    // FAILS on the shape that used to escape it: a guard never observed to fail
    // is indistinguishable from one that cannot.
    //
    // A wrapped label cannot be added to the module just to fail a test, so the
    // fixtures drive the extracted parser and checks over source text instead.
    // They are built with `concat!` and escaped newlines rather than as raw
    // multi-line strings on purpose — a raw string would put a real
    // `pub const DM_…` at the start of a line in THIS file, where the shipped
    // guards would read it as one of this module's own declarations.

    /// A declaration in the shape `rustfmt` produces when the one-line form
    /// exceeds the width. Before #283 it matched neither half of the line-scoped
    /// parse: the first line carries the name but no literal, the second the
    /// literal but no name.
    const WRAPPED: &str = concat!(
        "pub const DM_WRAPPED_LABEL_WITH_A_NAME_LONG_ENOUGH_TO_WRAP: &[u8] =\n",
        "    b\"daemonseed/dm/wrapped/v1\";\n",
    );

    #[test]
    fn the_parser_reads_a_wrapped_declaration() {
        let declared = checked_parse(WRAPPED);
        assert_eq!(declared.len(), 1);
        assert_eq!(
            declared[0].name,
            "DM_WRAPPED_LABEL_WITH_A_NAME_LONG_ENOUGH_TO_WRAP"
        );
        assert_eq!(declared[0].value, b"daemonseed/dm/wrapped/v1".to_vec());
    }

    /// The root of #283 restated as a test: an empty parse must be a failure, not
    /// a silent pass.
    #[test]
    #[should_panic(expected = "read no `pub const DM_")]
    fn a_parse_that_finds_nothing_is_loud() {
        checked_parse("// a source carrying no label declarations at all\n");
    }

    #[test]
    fn a_wrapped_declaration_missing_from_the_registry_is_caught() {
        let err = check_registered(&checked_parse(WRAPPED), ALL).unwrap_err();
        assert!(err.contains("daemonseed/dm/wrapped/v1"), "{err}");
    }

    #[test]
    fn a_wrapped_declaration_without_a_byte_pin_is_caught() {
        let body = "assert_eq!(DM_SOMETHING_ELSE, b\"daemonseed/dm/other/v1\");";
        let err = check_byte_pinned(&checked_parse(WRAPPED), body).unwrap_err();
        assert!(
            err.contains("DM_WRAPPED_LABEL_WITH_A_NAME_LONG_ENOUGH_TO_WRAP"),
            "{err}"
        );
    }

    #[test]
    fn a_wrapped_declaration_that_breaks_prefix_freeness_is_caught() {
        const PAIR: &str = concat!(
            "pub const DM_WRAPPED_LABEL_PREFIXING_THE_ONE_BELOW: &[u8] =\n",
            "    b\"daemonseed/dm/wrapped/v1\";\n",
            "pub const DM_WRAPPED_LABEL_EXTENDING_THE_ONE_ABOVE: &[u8] =\n",
            "    b\"daemonseed/dm/wrapped/v1/more\";\n",
        );
        let declared = checked_parse(PAIR);
        assert_eq!(declared.len(), 2, "both wrapped declarations must be read");
        let values: Vec<&[u8]> = declared.iter().map(|d| d.value.as_slice()).collect();
        let err = check_prefix_free(&values).unwrap_err();
        assert!(err.contains("is a prefix of"), "{err}");
    }

    /// A `pub const DM_` the parser cannot read is a parse failure, not something
    /// to skip past — skipping is how #283 stayed invisible for as long as it did.
    #[test]
    #[should_panic(expected = "cannot read")]
    fn a_declaration_in_an_unreadable_shape_is_loud() {
        parse_declarations("pub const DM_ODD_ONE: &[u8] = SOMETHING_ELSE;\n");
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
