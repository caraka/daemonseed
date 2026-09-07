//! HKDF info-string constants — the load-bearing registry.
//!
//! Every HKDF context used by daemonseed lives here as a `pub const &str`
//! (or as a function emitting a deterministic string from runtime
//! parameters). The byte content of these strings is part of the protocol
//! contract: changing any of them silently breaks identity continuity and
//! cross-version interop. Wire-visible regression tests (M4a / D5 §5)
//! byte-compare these constants against the published spec.
//!
//! Naming convention: `daemonseed/<area>/<subject>[/<discriminator>]`.
//! Every string is `daemonseed/`-prefixed for global namespace isolation
//! (so a daemonseed-derived key cannot collide with the same passphrase
//! used by some other application's HKDF).

// ── Identity (ISC-C1) ──────────────────────────────────────────────────────

/// HKDF salt for the BIP-39 → identity root derivation. Pins the daemonseed
/// usage of the BIP-39 seed apart from any other consumer of the same
/// mnemonic ecosystem (wallets, recovery tools, etc.).
pub const IDENTITY_ROOT_SALT: &[u8] = b"daemonseed/v1/identity-root";

/// Info-string prefix for the **primary** identity (ISC-C1, ISC-C13).
/// Per-domain suffix (`/sign`, `/kem-d`, `/kem-z`) appended at use-site
/// via [`primary`]; do not concatenate this manually.
const PRIMARY_PREFIX: &str = "daemonseed/identity/primary";

/// Info-string prefix template for the **per-device** identity (ISC-C1,
/// ISC-C13). The `<uuid>` placeholder is replaced by a stable
/// device-uuid generated at first enrollment.
const DEVICE_PREFIX_TEMPLATE: &str = "daemonseed/identity/device-{uuid}";

/// Domain separator for the ML-DSA-87 signing keypair seed.
pub const DOMAIN_SIGN: &str = "sign";

/// Domain separator for the ML-KEM-1024 `d` seed (per FIPS 203 keygen).
pub const DOMAIN_KEM_D: &str = "kem-d";

/// Domain separator for the ML-KEM-1024 `z` seed (per FIPS 203 keygen).
pub const DOMAIN_KEM_Z: &str = "kem-z";

/// Domain separator for the Veilid node identity seed (VLD0 = Ed25519), so the
/// transport node key derives from the same mnemonic as the ML-DSA/ML-KEM
/// identity yet shares no key material with it (D3). Content keys NEVER derive
/// from this — it binds only the node/transport identity.
pub const DOMAIN_VEILID_NODE: &str = "veilid-node";

/// Domain separator for the share-root identity IKM (#156). The FOURTH expansion
/// of the identity PRK (sibling of `sign` / `kem-d` / `kem-z` / `veilid-node`),
/// yielding the ONE normative 32-byte secret from which per-share hiding nonces
/// derive (`share_announce::derive_share_root_nonce`). Passed through
/// [`primary`]/[`device`] so the IKM is identity-scoped — a Primary and a Device
/// presentation of the same folder produce different share-id commitments. The
/// ML-DSA secret key is NOT this IKM (an SK-vs-entropy split would fork the nonce
/// and re-mint the id). Content NEVER derives from this — it binds only the
/// share-id commitment nonce.
pub const DOMAIN_SHARE_ROOT_IKM: &str = "share-root-ikm/v2";

/// Domain separator for the DM doorbell slot secret (#233). The FIFTH expansion
/// of the identity PRK (sibling of `sign` / `kem-d` / `kem-z` / `veilid-node` /
/// `share-root-ikm`), yielding the 32-byte secret that picks which of the
/// recipient's 32 doorbell slots this sender knocks on
/// (`dm::doorbell::slot_for`).
///
/// Being an expansion of the mnemonic PRK is the point: the slot survives a
/// reinstall, so a retried first contact overwrites the sender's OWN previous
/// entry instead of orphaning it in a second slot — the `#118` ephemeral-key
/// ring bug class applied in reverse. And because it is a *secret*, a storage
/// node co-hosting the doorbell cannot compute which slot a candidate pubkey
/// maps to, so it cannot learn who is knocking.
///
/// Passed through [`primary`]/[`device`] like `share-root-ikm`, so the secret is
/// identity-scoped. Two presentations of one mnemonic are two identities with
/// different long-term keys, hence two distinct senders to a recipient; giving
/// them one shared slot would make them clobber each other's knocks.
pub const DOMAIN_DM_DOORBELL_SLOT: &str = "dm-doorbell-slot/v1";

/// Build the full HKDF info string for the primary identity's given domain.
/// `domain` is one of `DOMAIN_SIGN`, `DOMAIN_KEM_D`, `DOMAIN_KEM_Z`,
/// `DOMAIN_VEILID_NODE`, `DOMAIN_SHARE_ROOT_IKM`.
pub fn primary(domain: &str) -> String {
    format!("{PRIMARY_PREFIX}/{domain}")
}

/// Build the full HKDF info string for a per-device identity's given
/// domain. `uuid` must be the device's stable UUID, formatted as a 36-char
/// hyphenated string.
pub fn device(uuid: &str, domain: &str) -> String {
    let prefix = DEVICE_PREFIX_TEMPLATE.replace("{uuid}", uuid);
    format!("{prefix}/{domain}")
}

// ── At-rest blob + recovery (ISC-C3, ISC-C30) ──────────────────────────────

/// HKDF info-string template for the at-rest seeds blob key (ISC-C3).
/// `<profile-id>` is substituted by [`at_rest`] at use-site.
const AT_REST_TEMPLATE: &str = "daemonseed/at-rest/{profile_id}";

/// HKDF info-string template for the encrypted recovery file (`.dseed`)
/// key (ISC-C30 / ISC-C32). Distinct from at-rest so the same passphrase
/// produces independent keys for the two artifacts.
const RECOVERY_FILE_TEMPLATE: &str = "daemonseed/recovery-file/{profile_id}";

/// Build the at-rest-blob HKDF info string for a profile.
pub fn at_rest(profile_id: &str) -> String {
    AT_REST_TEMPLATE.replace("{profile_id}", profile_id)
}

/// Build the recovery-file HKDF info string for a profile.
pub fn recovery_file(profile_id: &str) -> String {
    RECOVERY_FILE_TEMPLATE.replace("{profile_id}", profile_id)
}

// ── Profile-scoped auxiliary keys (ISC-A-C6, ISC-C28) ─────────────────────

/// HKDF info-string template for the share-index key (ISC-A-C6).
const SHARE_INDEX_TEMPLATE: &str = "daemonseed/share-index/{profile_id}";

/// HKDF info-string template for the trust-events audit-log key (ISC-C28).
const TRUST_EVENTS_TEMPLATE: &str = "daemonseed/trust-events/{profile_id}";

/// Build the share-index HKDF info string for a profile.
pub fn share_index(profile_id: &str) -> String {
    SHARE_INDEX_TEMPLATE.replace("{profile_id}", profile_id)
}

/// HKDF info-string template for the spent-invite-token set (ISC-C28 / #233).
///
/// Distinct from every other template here for the usual reason — one
/// passphrase must not produce one key for two artifacts — and profile-scoped
/// because the set it protects is profile-scoped: an invite token is redeemed
/// once against this identity, not once per correspondence.
const SPENT_TOKENS_TEMPLATE: &str = "daemonseed/dm-spent-tokens/{profile_id}";

/// Build the trust-events HKDF info string for a profile.
pub fn trust_events(profile_id: &str) -> String {
    TRUST_EVENTS_TEMPLATE.replace("{profile_id}", profile_id)
}

/// Build the spent-invite-token HKDF info string for a profile.
pub fn spent_tokens(profile_id: &str) -> String {
    SPENT_TOKENS_TEMPLATE.replace("{profile_id}", profile_id)
}

// ── Identity-proof channel binding (ISC-S19) ──────────────────────────────

/// HKDF info string for the identity-proof envelope channel-binding
/// (ISC-S19). Combined with the negotiated APP_HELLO version (per
/// ISC-A-S14) at use-site in M4b; this constant alone is the static half.
pub const IDENTITY_PROOF_V1: &str = "daemonseed/identity-proof/v1";

// ── Circle-of-trust key (ISC-C8) ──────────────────────────────────────────

/// HKDF salt for the circle-of-trust key derivation (ISC-C8). A **fixed
/// protocol constant**, never a per-circle value — per-circle uniqueness
/// comes entirely from the shared entropy (the IKM), so two circles differ
/// iff their entropy differs (F16: no per-circle salt, no circle name).
pub const CIRCLE_KEY_SALT: &[u8] = b"daemonseed/v1/circle-key";

/// HKDF info-string template for the circle-of-trust key (ISC-C8). The
/// `<family>` token (per `crypto::suite::Suite::family_token`) anchors the
/// derivation on the crypto family, so within-family suite ratchets leave the
/// key unchanged and a cross-family change yields a cleanly distinct key.
const CIRCLE_TEMPLATE: &str = "daemonseed/circle/{family}";

/// Build the circle-of-trust HKDF info string for a crypto-family token.
pub fn circle(family: &str) -> String {
    CIRCLE_TEMPLATE.replace("{family}", family)
}

/// HKDF info-string template for a circle's **Veilid rendezvous-owner** seed
/// (Phase 2 transport). A sibling of [`CIRCLE_TEMPLATE`]: the same circle PRK is
/// expanded under this distinct label to a VLD0 (Ed25519) owner seed, so the
/// transport rendezvous address is NOT a function of the content `cot_key` —
/// neither key derives from the other. Family-anchored like the content key, so
/// a cross-family rekey moves rendezvous + content together (the circle-rekey
/// event, ISC-A-C8). Content NEVER derives from this — it binds only the DHT
/// record-owner / rendezvous address.
const CIRCLE_VEILID_OWNER_TEMPLATE: &str = "daemonseed/veilid/circle-owner/{family}";

/// Build the circle Veilid rendezvous-owner HKDF info string for a
/// crypto-family token.
pub fn circle_veilid_owner(family: &str) -> String {
    CIRCLE_VEILID_OWNER_TEMPLATE.replace("{family}", family)
}

/// HKDF info-string template for a circle's **presence** Veilid rendezvous-owner
/// seed (Phase 4). A sibling of [`CIRCLE_VEILID_OWNER_TEMPLATE`] under a distinct
/// label, so a circle's presence beacons ride their OWN DHT record — never the
/// chat record's 2-slot append-ring (P1: presence is current-state, chat is
/// event-history; sharing one record would let a ~15 s beacon evict chat
/// backlog). Family-anchored like its siblings; content NEVER derives from this —
/// it binds only the presence rendezvous address.
const CIRCLE_PRESENCE_VEILID_OWNER_TEMPLATE: &str =
    "daemonseed/veilid/circle-presence-owner/{family}";

/// Build the circle presence Veilid rendezvous-owner HKDF info string for a
/// crypto-family token.
pub fn circle_presence_veilid_owner(family: &str) -> String {
    CIRCLE_PRESENCE_VEILID_OWNER_TEMPLATE.replace("{family}", family)
}

// ── Public rooms (ISC-S4 / ISC-S22) ─────────────────────────────────────────

/// HKDF salt for the **global shared** public-room key (ISC-S22). A fixed
/// protocol constant, distinct from [`CIRCLE_KEY_SALT`] so a public-room key
/// can never collide with a circle key even for an identically-named input.
///
/// Unlike a circle, a public room has **no secret IKM**: the room key derives
/// from public, well-known inputs (the crypto family token + the room name), so
/// every client AND the relay derive the byte-identical key. The room is
/// therefore *server-readable by construction* — encrypted in transit but under
/// a key everyone holds (ISC-A-S2: public spaces are the deliberately-readable
/// tier). Per-room uniqueness comes entirely from the room name in the `info`.
pub const PUBLIC_ROOM_KEY_SALT: &[u8] = b"daemonseed/v1/public-room-key";

/// HKDF info-string template for the global public-room key (ISC-S22). The
/// `<family>` token anchors the derivation on the crypto family (mirroring
/// [`CIRCLE_TEMPLATE`]); `<room>` is the public room name, so two rooms differ
/// iff their names differ.
const PUBLIC_ROOM_TEMPLATE: &str = "daemonseed/public-room/{family}/{room}";

/// Build the public-room HKDF info string for a crypto-family token and a
/// public room name.
pub fn public_room(family: &str, room: &str) -> String {
    PUBLIC_ROOM_TEMPLATE
        .replace("{family}", family)
        .replace("{room}", room)
}

/// HKDF info-string template for a public room's **Veilid rendezvous-owner**
/// seed (Phase 3/4 transport). The sibling of [`PUBLIC_ROOM_TEMPLATE`]: the same
/// public-room PRK (the [`PUBLIC_ROOM_KEY_SALT`] extract of the family token) is
/// expanded under this distinct label to a VLD0 (Ed25519) owner seed, so the
/// room's DHT rendezvous address is NOT a function of the room key — neither
/// derives from the other (mirrors [`CIRCLE_VEILID_OWNER_TEMPLATE`]). The inputs
/// are public (family + room name), so every participant derives the same owner
/// and thus the same rendezvous; an operator-owned channel (MOTD/announcements)
/// instead uses a non-derivable owner keypair as its write-gate.
const PUBLIC_ROOM_VEILID_OWNER_TEMPLATE: &str = "daemonseed/veilid/room-owner/{family}/{room}";

/// Build the public-room Veilid rendezvous-owner HKDF info string for a
/// crypto-family token and a public room name.
pub fn public_room_veilid_owner(family: &str, room: &str) -> String {
    PUBLIC_ROOM_VEILID_OWNER_TEMPLATE
        .replace("{family}", family)
        .replace("{room}", room)
}

/// HKDF info-string template for a public room's **presence** Veilid
/// rendezvous-owner seed (Phase 4). A sibling of
/// [`PUBLIC_ROOM_VEILID_OWNER_TEMPLATE`] under a distinct label, so lobby/room
/// presence beacons ride their OWN world-derivable DHT record, separate from the
/// room's chat rendezvous (P1: presence is current-state, chat is event-history).
/// Family- and room-anchored like its sibling; the inputs are public, so every
/// participant derives the same presence rendezvous. Content NEVER derives from
/// this — it binds only the presence rendezvous address.
const PUBLIC_ROOM_PRESENCE_VEILID_OWNER_TEMPLATE: &str =
    "daemonseed/veilid/room-presence-owner/{family}/{room}";

/// Build the public-room presence Veilid rendezvous-owner HKDF info string for a
/// crypto-family token and a public room name.
pub fn public_room_presence_veilid_owner(family: &str, room: &str) -> String {
    PUBLIC_ROOM_PRESENCE_VEILID_OWNER_TEMPLATE
        .replace("{family}", family)
        .replace("{room}", room)
}

/// HKDF info-string template for a public room's **share-discovery** Veilid
/// rendezvous-owner seed (#153). A third sibling of
/// [`PUBLIC_ROOM_VEILID_OWNER_TEMPLATE`] under a distinct label, so public-share
/// announcements ride their OWN world-derivable DHT record, separate from BOTH
/// the room's chat rendezvous ([`PUBLIC_ROOM_VEILID_OWNER_TEMPLATE`]) and its
/// presence record. Chat uses an append-ring subkey scheme and shares use a
/// current-state subkey scheme; co-located on one record they overlapped the same
/// 64-slot space and silently overwrote each other (#153) — a dedicated sibling
/// record removes the collision entirely, exactly as presence was separated (P1).
/// Family- and room-anchored like its siblings; the inputs are public, so every
/// participant derives the same share rendezvous. Content NEVER derives from this.
const PUBLIC_ROOM_SHARE_VEILID_OWNER_TEMPLATE: &str =
    "daemonseed/veilid/room-share-owner/{family}/{room}";

/// Build the public-room share-discovery Veilid rendezvous-owner HKDF info string
/// for a crypto-family token and a public room name.
pub fn public_room_share_veilid_owner(family: &str, room: &str) -> String {
    PUBLIC_ROOM_SHARE_VEILID_OWNER_TEMPLATE
        .replace("{family}", family)
        .replace("{room}", room)
}

// ── Project announce channel (F17 / A0/A1) ──────────────────────────────────

/// HKDF salt for the project-announce Veilid rendezvous-owner seed (Phase 4 A1).
/// A fixed protocol constant. The IKM is the maintainer-held project-announce seed
/// (F17), so the owner keypair — the DHT write-gate for the single project
/// announcements/MOTD channel (A0) — is NON-derivable by clients (they hold only
/// the derived owner pubkey). A distinct salt so the announce owner can never
/// collide with a circle/room owner or the content-signing key.
pub const PROJECT_ANNOUNCE_OWNER_SALT: &[u8] = b"daemonseed/v1/project-announce-owner";

/// HKDF info string for the project-announce Veilid rendezvous-owner seed (Phase 4
/// A1). A **sibling** of the F17 content-signing key: both derive from the one
/// maintainer-held project-announce seed, but the content key uses the seed as an
/// ML-DSA seed directly while this HKDF-expands it under this label — so
/// transport-owner and content-signing material are domain-separated (possessing
/// one never yields the other). A single global channel — no per-room/family
/// distinguisher.
pub const PROJECT_ANNOUNCE_VEILID_OWNER: &str = "daemonseed/veilid/project-announce-owner";

#[cfg(test)]
mod tests {
    use super::*;

    /// **Spec contract** — these byte sequences are protocol-visible and
    /// MUST NOT drift without a coordinated MINOR-version bump on ISC-S14.
    /// If a value changes, an existing daemonseed install loses every
    /// derived key. Edit only after reading ISC-C1 / ISC-C3 / ISC-C30 / etc.
    /// and updating the corresponding spec entry.
    ///
    /// Wire-visible regression test (M4a, D5 §5) will reference these same
    /// expected literals.
    #[test]
    fn identity_info_strings_are_pinned() {
        assert_eq!(primary(DOMAIN_SIGN), "daemonseed/identity/primary/sign");
        assert_eq!(primary(DOMAIN_KEM_D), "daemonseed/identity/primary/kem-d");
        assert_eq!(primary(DOMAIN_KEM_Z), "daemonseed/identity/primary/kem-z");
        // #156: the share-root IKM label (frozen — a second implementation must
        // reproduce it byte-for-byte or every share_id re-mints).
        assert_eq!(
            primary(DOMAIN_SHARE_ROOT_IKM),
            "daemonseed/identity/primary/share-root-ikm/v2"
        );
        // #233: the DM doorbell slot label (frozen — a second implementation must
        // reproduce it byte-for-byte or a reinstalled sender lands on a new slot
        // and orphans its previous knock).
        assert_eq!(
            primary(DOMAIN_DM_DOORBELL_SLOT),
            "daemonseed/identity/primary/dm-doorbell-slot/v1"
        );
        // The device form is asserted too: the slot secret being identity-SCOPED
        // rather than mnemonic-global is a deliberate call (ISA Decisions,
        // 2026-07-28), and this is the string that would silently stop diverging
        // if the derivation were "simplified" back to a bare label.
        assert_eq!(
            device(
                "123e4567-e89b-12d3-a456-426614174000",
                DOMAIN_DM_DOORBELL_SLOT
            ),
            "daemonseed/identity/device-123e4567-e89b-12d3-a456-426614174000/dm-doorbell-slot/v1"
        );
        assert_eq!(
            device("123e4567-e89b-12d3-a456-426614174000", DOMAIN_SIGN),
            "daemonseed/identity/device-123e4567-e89b-12d3-a456-426614174000/sign"
        );
    }

    #[test]
    fn at_rest_info_strings_are_pinned() {
        assert_eq!(
            at_rest("123e4567-e89b-12d3-a456-426614174000"),
            "daemonseed/at-rest/123e4567-e89b-12d3-a456-426614174000"
        );
        assert_eq!(
            recovery_file("123e4567-e89b-12d3-a456-426614174000"),
            "daemonseed/recovery-file/123e4567-e89b-12d3-a456-426614174000"
        );
    }

    #[test]
    fn auxiliary_info_strings_are_pinned() {
        assert_eq!(share_index("uuid"), "daemonseed/share-index/uuid");
        assert_eq!(trust_events("uuid"), "daemonseed/trust-events/uuid");
        assert_eq!(spent_tokens("uuid"), "daemonseed/dm-spent-tokens/uuid");
    }

    /// No auxiliary info string is a prefix of another.
    ///
    /// HKDF's info is length-delimited, so a shared prefix is not itself an
    /// attack — this pins the weaker property that the labels are visibly
    /// distinct, which is what stops a future one being added by copy-edit and
    /// silently colliding with an existing key.
    #[test]
    fn auxiliary_info_strings_are_mutually_distinct() {
        let all = [
            at_rest("uuid"),
            recovery_file("uuid"),
            share_index("uuid"),
            trust_events("uuid"),
            spent_tokens("uuid"),
        ];
        assert_eq!(all.len(), 5, "control: every auxiliary label is listed");
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert!(!a.starts_with(b.as_str()), "{a} starts with {b}");
                }
            }
        }
    }

    #[test]
    fn salt_and_identity_proof_constants() {
        assert_eq!(IDENTITY_ROOT_SALT, b"daemonseed/v1/identity-root");
        assert_eq!(IDENTITY_PROOF_V1, "daemonseed/identity-proof/v1");
    }

    /// **Spec contract (ISC-C8)** — the circle-key salt + info string are
    /// protocol-visible: every member derives the same `cot_key` only if
    /// these bytes match across builds. Drift here silently splits a circle.
    #[test]
    fn circle_info_string_is_pinned() {
        assert_eq!(CIRCLE_KEY_SALT, b"daemonseed/v1/circle-key");
        assert_eq!(circle("hkdf-sha384"), "daemonseed/circle/hkdf-sha384");
    }

    /// **Spec contract (Phase 2 transport)** — the circle Veilid-owner info
    /// string is protocol-visible: every member derives the same rendezvous
    /// address only if these bytes match. It is distinct from [`circle`] so the
    /// rendezvous owner seed and the content `cot_key` never collide.
    #[test]
    fn circle_veilid_owner_info_string_is_pinned() {
        assert_eq!(
            circle_veilid_owner("hkdf-sha384"),
            "daemonseed/veilid/circle-owner/hkdf-sha384"
        );
        assert_ne!(circle_veilid_owner("hkdf-sha384"), circle("hkdf-sha384"));
    }

    /// **Spec contract (Phase 3/4 transport)** — the public-room Veilid-owner
    /// info string is protocol-visible: every participant derives the same lobby
    /// rendezvous only if these bytes match. Distinct from both [`public_room`]
    /// (so the rendezvous owner seed never collides with the room key) and
    /// [`circle_veilid_owner`] (so a public room and a like-named circle never
    /// share a rendezvous owner).
    #[test]
    fn public_room_veilid_owner_info_string_is_pinned() {
        assert_eq!(
            public_room_veilid_owner("hkdf-sha384", "lobby"),
            "daemonseed/veilid/room-owner/hkdf-sha384/lobby"
        );
        assert_ne!(
            public_room_veilid_owner("hkdf-sha384", "lobby"),
            public_room("hkdf-sha384", "lobby")
        );
        assert_ne!(
            public_room_veilid_owner("hkdf-sha384", "lobby"),
            circle_veilid_owner("hkdf-sha384")
        );
    }

    /// **Spec contract (Phase 4 presence)** — the presence rendezvous-owner info
    /// strings are protocol-visible: every participant derives the same presence
    /// record only if these bytes match. Each presence label is distinct from its
    /// chat-record sibling (so presence beacons ride their OWN record, P1) and
    /// from the other tier's presence label (so a public room and a like-named
    /// circle never share a presence rendezvous owner).
    #[test]
    fn presence_veilid_owner_info_strings_are_pinned() {
        assert_eq!(
            circle_presence_veilid_owner("hkdf-sha384"),
            "daemonseed/veilid/circle-presence-owner/hkdf-sha384"
        );
        assert_eq!(
            public_room_presence_veilid_owner("hkdf-sha384", "lobby"),
            "daemonseed/veilid/room-presence-owner/hkdf-sha384/lobby"
        );
        // Presence label ≠ its chat-record sibling (separate records, P1).
        assert_ne!(
            circle_presence_veilid_owner("hkdf-sha384"),
            circle_veilid_owner("hkdf-sha384")
        );
        assert_ne!(
            public_room_presence_veilid_owner("hkdf-sha384", "lobby"),
            public_room_veilid_owner("hkdf-sha384", "lobby")
        );
        // Public-room presence ≠ circle presence (tiers stay disjoint).
        assert_ne!(
            public_room_presence_veilid_owner("hkdf-sha384", "lobby"),
            circle_presence_veilid_owner("hkdf-sha384")
        );
    }

    /// **Spec contract (#153 share-record split)** — the share-discovery
    /// rendezvous-owner info string is protocol-visible: every participant derives
    /// the same share record only if these bytes match. It is distinct from BOTH
    /// the room's chat-record owner and its presence-record owner, so public-share
    /// announcements and lobby chat no longer collide on one record.
    #[test]
    fn public_room_share_veilid_owner_info_string_is_pinned() {
        assert_eq!(
            public_room_share_veilid_owner("hkdf-sha384", "lobby"),
            "daemonseed/veilid/room-share-owner/hkdf-sha384/lobby"
        );
        // Share label ≠ chat-record sibling (the whole point of #153).
        assert_ne!(
            public_room_share_veilid_owner("hkdf-sha384", "lobby"),
            public_room_veilid_owner("hkdf-sha384", "lobby")
        );
        // Share label ≠ presence-record sibling.
        assert_ne!(
            public_room_share_veilid_owner("hkdf-sha384", "lobby"),
            public_room_presence_veilid_owner("hkdf-sha384", "lobby")
        );
    }

    /// **Spec contract (Phase 4 A1)** — the project-announce owner salt + info
    /// string are protocol-visible: every client derives the same announce channel
    /// record address (from the owner pubkey) only if these bytes match. The info
    /// label is distinct from every rendezvous-owner label so the announce owner
    /// never collides with a circle/room/presence owner.
    #[test]
    fn project_announce_owner_constants_are_pinned() {
        assert_eq!(
            PROJECT_ANNOUNCE_OWNER_SALT,
            b"daemonseed/v1/project-announce-owner"
        );
        assert_eq!(
            PROJECT_ANNOUNCE_VEILID_OWNER,
            "daemonseed/veilid/project-announce-owner"
        );
        assert_ne!(
            PROJECT_ANNOUNCE_VEILID_OWNER,
            circle_veilid_owner("hkdf-sha384")
        );
        assert_ne!(
            PROJECT_ANNOUNCE_VEILID_OWNER,
            public_room_veilid_owner("hkdf-sha384", "lobby")
        );
    }
}
