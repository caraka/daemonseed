# Receiver-verifiable `share_id` ↔ publisher binding (#156)

**Status: BUILT — branch `feat/veilid-migration`, gate GREEN (VM-side), RATIFIED + built 2026-07-12.** Design-of-record for the #156 residual of the
#152 pre-cutover review. Scope: v0.33.0 cutover (breaking `daemonseed-proto` change);
not alpha-gating. Companion invariants: ISC-S21, ISC-S30, ISC-A-S2, ISC-A-S22.

## Problem

`share_id` is a plaintext announcement field sealed only under the world-readable
`PublicRoomKey`, so any lobby peer can scrape it. Ingest (`ShareCatalog::apply`)
verifies the announcement's self-signature and — since #152 — binds a **known**
`share_id` to its first-seen `sender_pubkey`. But nothing verifies that an announced
`share_id` is *derivable from* its `sender_pubkey`: an attacker can first-seed a fully
self-consistent announcement (valid self-signature, valid route advert) pairing a
victim's `share_id` with the attacker's own key. Any peer that folds the attacker's
announcement before the victim's genuine one then rejects the real announce as a
"hijack" — content substitution plus per-peer censorship, gated only on winning a race
to cold-joiners.

The root cause is structural: `derive_share_id(sender_pubkey, root)`
(`share_announce.rs`, domain `daemonseed/share-id/v1`) **already commits the id to the
publisher's key** — but `root` (the sharer's local folder path) is a private input the
receiver never sees, so the commitment is unverifiable exactly where it matters.

## Decision

**Option A, refined: carry a root *commitment*; derive its nonce deterministically
from identity secret material — no new persisted state.**

New derivation (v2, domain-separated from v1). Every label AND every variable-length
input is length-prefixed (matching `provenance_input`'s `push_field` discipline — the
v1 sketch's bare-prefix labels are corrected here):

```
nonce           = HKDF-SHA-384(salt = SHARE_NONCE_SALT,          // pinned, non-empty (below)
                               ikm  = IDENTITY_SHARE_ROOT_IKM,   // pinned single IKM (below)
                               info = lp("daemonseed/share-root-nonce/v2") ‖ lp(root))
                  → exactly 32 bytes                              // nonce length is normative
root_commitment = SHA-384(lp("daemonseed/share-root-commitment/v2") ‖ lp(root) ‖ lp(nonce))
                  // 48 bytes
share_id        = SHA-384(lp("daemonseed/share-id/v2") ‖ lp(pk) ‖ lp(root_commitment))[..16]  → 32 hex
```

where `lp(x) = len(x) as u64 big-endian ‖ x`.

**Frozen constants (as-built 2026-07-12 — a second implementation MUST reproduce them byte-for-byte or every `share_id` re-mints):**

- **IKM:** `ShareRootIkm` = HKDF-SHA-384-Expand of the identity PRK under info `daemonseed/identity/{primary|device-<uuid>}/share-root-ikm/v2`, **32 bytes** (`identity::keys`, a fourth sibling of `sign`/`kem-d`/`kem-z`/`veilid-node`; the identity entropy, NOT the ML-DSA-87 SK).
- **`SHARE_NONCE_SALT`** = `b"daemonseed/share-root-nonce-salt/v2"` (non-empty, normative — no implicit zero-salt).
- **nonce** info label `daemonseed/share-root-nonce/v2`, length **32 bytes**.
- **`root_commitment`** domain `daemonseed/share-root-commitment/v2`, length **48 bytes**.
- **`share_id`** domain `daemonseed/share-id/v2`, first **16 bytes** → 32 lowercase-hex.
- **AAD/provenance split:** AEAD AAD `daemonseed/share/announce/aad/v2`; provenance domain `daemonseed/share/announce/provenance/v2` (distinct at v2).

`root_commitment` (48 bytes) travels as a new `ShareAnnouncement` field. A receiver
verifies, before folding **and** on the withdraw branch **and** before importing any
route:

```
announcement.share_id == derive_share_id_v2(announcement.sender_pubkey,
                                            announcement.root_commitment)
```

An attacker cannot pair the victim's `share_id` with any other pubkey: the id bakes
the key in, and occupying a *specific* victim id requires a truncated-SHA-384 second
preimage under the attacker's own fixed key. Both free axes (`pk'`, `rc'`) grind
against a fixed 128-bit target — no birthday shortcut, expected work 2^128 (adversarial
review confirmed: the "attacker grinds `rc'` freely" hypothesis gives no speedup, since
the target id is fixed). Setting `sender_pubkey = victim_pk` needs the victim's secret
key to pass the announcement's own signature check; replaying the victim's genuine
announcement is an idempotent fold, not censorship.

### Why A-refined over B (decouple root, carry salt)

The brief's fork priced A as "smaller change, no new lifecycle" and B as "cleaner but
adds salt-persistence state." Neither price survives inspection:

- A *as briefed* has the same lifecycle problem as B: a hiding commitment needs a
  nonce (folder paths are dictionary-guessable — `H(root)` alone lets any peer confirm
  a guessed path), and that nonce must be republish-stable or the id re-mints (the
  #112/#118 ghost-share class).
- The deterministic-nonce move (`nonce = f(identity secret, root)`) dissolves the
  lifecycle cost for **both** options: re-derivable at every republish from material
  the publisher always holds, never persisted separately, never on the wire.
- With that move A and B converge to the same shape — one carried field, one hash
  check at ingest. **At the verification boundary they are identical** (adversarial
  review, MED-3): `root_commitment` is 48 receiver-*unverifiable* bytes — ingest checks
  only `share_id == derive_v2(pk, rc)`, and `rc` is adversary-chosen free grinding space,
  not a checked binding. The earlier "A carries strictly more structure / can prove
  folder identity" claim is **withdrawn as false** — no ingest check constrains `rc` to
  any root, and a malicious client may reuse one `rc` across folders. Honest description:
  `rc` is an *opaque per-share witness* that keeps `root` off the wire while making
  `share_id` receiver-recomputable. A-refined is chosen because it is the smaller delta
  from the shipped code path (the GUI-veilid publish already computes `derive_share_id`
  from the identity key) and needs no new opaque-salt lifecycle vocabulary — a pragmatic
  tie-break, not a security distinction. **All occupation-resistance comes solely from
  the pk-committed id's second-preimage hardness.**

### Why not C (signature-only)

Already the status quo; proves the announcer owns *their own* key, which is exactly
what the attack satisfies. Rejected as insufficient (per the #156 analysis).

## Specification

1. **Nonce IKM — ONE pinned source, no build-time choice (adversarial HIGH-1).** The
   nonce IKM is a **single normative value protocol-wide**: a dedicated HKDF expansion
   of the profile's identity entropy (the at-rest seeds material), label
   `daemonseed/share-root-ikm/v2`, expanded to a **pinned byte length** recorded in the
   design. The ML-DSA-87 secret-key bytes are **NOT** an acceptable alternative IKM —
   an SK-vs-entropy or GUI-vs-TUI split would derive two different nonces for the same
   `(identity, root)` → two different `share_id`s → the #112/#118 ghost-share bug this
   determinism exists to kill (both crypto reviews flagged this as the top risk). The
   nonce output is **exactly 32 bytes**; the HKDF **salt is a pinned non-empty
   constant** `SHARE_NONCE_SALT` (no implicit zero-salt). The nonce never leaves the
   device and is never persisted (re-derived on demand). The exact IKM bytes, salt,
   and length are frozen constants — a second implementation must reproduce them
   byte-for-byte or it re-mints every id.
2. **Proto — proto3 has no `required`; the reject is a code invariant (adversarial
   HIGH-1).** `ShareAnnouncement` gains `bytes root_commitment`. Because the schema is
   proto3, an omitted field decodes as empty bytes — a structurally valid message. The
   binding therefore rests **entirely** on ingest: **an absent or non-48-byte
   `root_commitment` is hard-rejected before any branch — there is NO legacy /
   owner-binding-only arm for a missing commitment.** Breaking `daemonseed-proto` v1
   change (SemVer MAJOR callout in the commit body; `cargo xtask check-proto` snapshot
   regenerated). Clean cutover break — no live pre-cutover shares exist (alpha testers
   ride the alpha bundle; relay and Veilid populations never meet), so no dual-accept
   window is offered.
3. **Ingest enforcement gates EVERY consumer, not just the catalog fold (adversarial
   HIGH-2).** The check `share_id == derive_share_id_v2(sender_pubkey, root_commitment)`
   runs at three points, each a build ISC — because #152 already shipped route-theater
   once (the fetch path read `discovered`, not the catalog):
   - **`ShareCatalog::apply`** — on the announce fold AND the withdraw branch (today the
     withdraw arm is owner-binding-only; the v2 check must precede it).
   - **Route import** — no route is imported for a `share_id` whose announcement did not
     pass the v2 check. This is a standalone ISC, not a reliance on `apply_discovery`'s
     current wiring.
   - **Circle-share actor** — the same check on the circle path (an insider censoring a
     circle share otherwise survives). Not a parenthetical "verify at build" — a
     build ISC.
4. **Publish-side migration — retire `mint_share_id` from all publish paths (adversarial
   HIGH-2).** The shipped code splits: `daemonseed-gui/src/veilid_net.rs` derives, but
   `gui/src/net.rs`, `tui/src/net.rs`, and `tui/src/veilid_net.rs` mint **random** ids.
   A v2 receiver rejects every randomly-minted share → availability cliff. **All four
   publish sites move to `derive_share_id_v2`; `mint_share_id` is deleted from the
   publish path** (retained only if a non-discovery use survives — none found outside
   tests). A build gate asserts no publish path emits a non-derivable id. Correct the
   catalog comment (`share_catalog.rs:180`) that already falsely claims one derivation
   site.
5. **First-writer-wins demotion.** With the binding checked at every ingest point,
   #152's owner-binding becomes a pure *continuity* rule (a known id keeps its
   first-seen key; a differing key now fails the derivation check regardless) and is no
   longer load-bearing for security. Comment updated at the site; **no
   "id-not-derivable ⇒ accept under owner-binding" escape may be added** (stated as an
   anti-requirement — it is exactly the HIGH-1 reopening).
6. **Id width — ratify 128-bit (both reviews).** `share_id` stays 128-bit / 32-hex.
   Occupying a *specific* victim id is a fixed-target second preimage: 2^128, no
   birthday shortcut (the attacker must hit a chosen id, not any collision). Multi-target
   "any-of-N" is 2^128/N; at a realistic lobby N (~2^12) that is ~2^116 — comfortable.
   Downstream shapes (`current_state_subkey`, rendezvous derivation, UI) unchanged.
7. **Bind `root_commitment` into the provenance signature (adversarial LOW).**
   `provenance_input` (`share_announce.rs:141`) currently omits `root_commitment`. It is
   covered transitively (signed `share_id` + the ingest derive-check pins `rc`) and by
   the AEAD tag on the wire, so this is defense-in-depth, not a break — but since the
   pin rests on the derive-check being present at every (shaky, per HIGH-2) call site,
   add `root_commitment` to the signed input. Cheap; do it.
8. **Split the latent AAD/provenance-domain collision at v2 (adversarial LOW).**
   `SHARE_ANNOUNCE_AAD == SHARE_ANNOUNCE_PROVENANCE_DOMAIN` today (both
   `daemonseed/share/announce/v1`). Harmless now, but the v2 work is the moment to give
   them distinct labels.

## Invariants respected

- **ISC-A-S2 / privacy:** the raw folder path never reaches the wire. The commitment
  is hiding (nonce is secret-derived, unguessable), so dictionary confirmation of a
  guessed path fails. **Pubkey-linkage is unchanged** (the announcement already carries
  `sender_pubkey`), **but a new cross-tier folder-linkage arises and is accepted with
  eyes open (crypto review finding MED-4):** because `share_id`/`root_commitment` are
  deterministic functions of `(identity, root)` and tier-independent, the *same folder*
  shared both publicly and inside a circle yields the *same* `share_id` in both. A peer
  who can open both announcements (a lobby member who is also a circle member) learns
  the public share and the circle share are the same folder — information determinism
  newly grants. **Decision for the freeze:** the nonce `info` is scoped to the
  derivation label only, NOT the tier — mixing tier into the nonce
  (`info = label ‖ tier ‖ root`) would break the cross-relay / cross-tier *portability*
  of a stable id (a deliberate module property, ISC-S21 lineage) to defeat a
  same-folder correlation available only to a dual-membership peer. Cross-relay
  portability is the ratified property; the residual same-folder linkage to a
  dual-member peer is documented, not closed. (If a future product needs per-tier
  unlinkability more than portability, tier-in-nonce is the lever — a genuine design
  fork, not a free fix.)
- **Stable id across republish (#112/#118):** derivation is deterministic from
  `(identity secret, root)`; reconnect/republish re-asserts the same id with no
  persisted nonce state.
- **Discovery vs content identity:** `share_id` remains discovery identity only;
  content addressing stays 1 MiB chunks by SHA-384 (ISC-S28) — no interaction.
- **Route binding (orthogonal):** the `DiscoveryEnvelope` route signature
  (`route_provenance_input`) is untouched; #156 is the identity binding.

## ISC impact (register at the build commit)

- **ISC-S21 revision (drift repair + this design):** the criterion still reads
  "minted client-side from the OS CSPRNG" — stale since #112's deterministic
  derivation, and false for the three `mint_share_id` publish sites. Rewrite to: id =
  v2 derivation above (deterministic from identity + root); unpredictability before
  announcement holds via the secret nonce; receiver-verifiability at ingest is the new
  clause. (Exact wording lands with the build commit's doc-sync.)
- **Ingest derive-check (build ISC):** ingest rejects any announcement (announce OR
  withdraw branch) whose `share_id ≠ derive_share_id_v2(sender_pubkey, root_commitment)`
  (oracle: forged pairing folds nothing on either branch; genuine announce folds).
- **Route-import gate (build ISC):** no route is imported for a `share_id` whose
  announcement did not pass the derive-check — a standalone probe, not a reliance on
  `apply_discovery` wiring (oracle: a route advert for an un-checked `share_id` is
  dropped at import).
- **Circle-path parity (build ISC):** the derive-check runs on the circle-share ingest
  path (oracle: insider forging a circle `share_id` under their own key folds nothing).
- **Unconditional-reject Anti-ISC (build):** an announcement with absent or non-48-byte
  `root_commitment` is rejected with no legacy/owner-binding fallback arm (oracle:
  empty-commitment announcement for a scraped victim id folds nothing).
- **No-random-id-on-publish Anti-ISC (build):** no publish path emits a `share_id` that
  is not `derive_share_id_v2(own_pubkey, root_commitment)` — all four sites migrated,
  `mint_share_id` retired from publish (oracle: grep + a publish round-trip asserting
  the emitted id derives).
- **Path-secrecy Anti-ISC (build):** no wire field contains `root` cleartext, and
  `root_commitment` of a known path is unconfirmable without the identity-derived nonce
  (oracle: commitment differs across identities for identical `root`).

## Residuals (adversary still gets)

- **Denial by non-derivable spam is unchanged** — an attacker can always announce
  garbage ids under their own key; that is ordinary open-post noise, prunable, and
  carries no victim binding.
- **The victim's own id remains scrapeable** (world-readable by design, ISC-A-S2);
  what the attacker can no longer do is *occupy* it.
- **Pre-cutover v1 shares leak the folder path (crypto LOW-1).** v1's
  `derive_share_id(pk, root)` hashes two public/guessable inputs with no secret nonce,
  so any lobby peer can grind candidate paths against an observed v1 `share_id` to
  confirm a victim's folder path — a live confirmation oracle on the GUI-veilid v1 path
  today. v2's secret nonce closes it; this residual drains only when the cutover break
  lands (extra reason the clean break is right).
- **Ephemeral-identity attacker can still announce a *different* id for the same
  content** (their own valid share of pirated bytes) — content-level, out of scope
  (ratings/moderation layer, ISC-A-C5 family).
