# Room ↔ Circle Unification — Design of Record

> Status: ACCEPTED — **Option A (full type-merge) ratified 2026-07-08**; **no cutover gate** (the relay is unused, so the MAJOR wire break breaks no users). Graduated to GitHub issues. Captured 2026-06-28; resolved 2026-07-08. Implementation-ready spec in *Design (A)* below.

## Problem

Public rooms and private circles are parallel, separately-implemented messaging surfaces that have drifted apart on authorship:

- A public-room message (`PublicRoomMessage`) and a `ShareAnnouncement` carry ML-DSA-87 **per-sender provenance** — `sender_pubkey` + a domain-separated signature, verified client-side, with the authoritative handle derived from the key as `SHA-384(sender_pubkey)[:12]` (ISC-S24 / ISC-C57 / ISC-C4); the self-asserted `sender_handle` is never trusted.
- A circle message (`CircleMessage`) carries **only** a self-asserted, spoofable `sender_handle`. Circle membership (holding `cot_key`) authenticates *membership*, not *authorship*.

So any holder of a circle key — an ex-member, an infiltrator, a leaked or compromised key — can post messages and shares attributable to no one and spoofing any handle. For a download-trust decision ("is this binary really from the identity whose shares I trust?"), membership-auth is insufficient. This is a regression from the Demonsaw lineage, which signed circle content. The two surfaces also duplicate seal/open, fan-out, and verification, so they will keep drifting.

## Principle (governing invariant)

**A public room and a private circle behave identically in every respect except how their key is derived (caraka, 2026-06-28).** The sole branch point across the whole stack is the key-derivation function:

- public room → **world-derivable** key (`derive_room_*(room_name, suite)`),
- private circle → **secret-entropy-gated** key (`derive_circle_*(entropy, suite)`).

"Public vs private" reduces to "is the key world-derivable or entropy-gated." Everything downstream — message provenance, the `#12hex` authorship binding, content sealing, fan-out, discovery, share announce/verify, anti-dox — is **one code path parameterized by the room key**, not two parallel implementations. A circle is a public room with a secret key.

## Target end-state

1. **One message type.** Merge `CircleMessage` and `PublicRoomMessage` into a single room message carrying `sender_pubkey` + an ML-DSA-87 signature over a domain-separated input binding the room/circle identifier ‖ `sender_pubkey` ‖ `sent_unix_ms` ‖ `body` (the existing `PublicRoomMessage` pattern; the binding stops cross-room / cross-circle replay).
2. **One seal/open path** parameterized by the room key (`cot_key` and `PublicRoomKey` are both "the room key").
3. **Circle shares** carry the same signed `ShareAnnouncement` provenance as public shares, so a circle download is verifiable by `#12hex` exactly as a public share is.
4. **Identical verification policy** — reject absent/bad signatures; derive the authoritative handle from the key, never trust `sender_handle`.

## Constraints / invariants (must hold)

- **ISC-A-S2 (anti-dox):** the signature + `sender_pubkey` ride **inside** the AEAD seal, so the relay/DHT and any non-key-holder see only ciphertext. Authorship is verifiable only by those who can derive the key. No metadata leak.
- **ISC-C4:** the authoritative handle is `SHA-384(sender_pubkey)[:12]`, never the self-asserted handle.
- Provenance mirrors the existing `PublicRoomMessage` / `ShareAnnouncement` (ISC-S24 / ISC-C57): domain-separated, replay-bound.
- Content keys never derive from Veilid (classical) key material (unchanged).

## Out of scope (orthogonal — not a violation of the principle)

- **The operator write-gate** (the lobby's MOTD / announcements, signed by an operator-only key). This is *also* "differ only by key origin" (member-secret | world-derivable | operator-only), exactly as the Phase-3/4 transport design frames owner derivation, and remains an **orthogonal capability** a room may mount. The base room↔circle equivalence is total; the operator layer is not part of it and is not required to unify here.
- **Deniable / off-the-record mode** — deliberately dropped. Public rooms are not deniable; circles match.

## Approach (sketch — detail at implementation)

1. **Proto** (`daemonseed-proto`): merge into one room-message type (**Option A, ratified** — see *Design (A)*). A type-merge is the faithful expression of the principle; the wire break is free (relay unused).
2. **Core**: collapse the `circle` and `public_room` seal/open + verify into one path parameterized by `RoomKey`; each surface's job shrinks to "supply the key."
3. **Shares**: route circle shares through the signed `ShareAnnouncement` path.
4. **ISCs**: add criteria for circle authorship provenance; revise/merge the diverged criteria; tombstone per the ID-stability rule (never renumber).

## Resolved decisions (2026-07-08 — Option A ratified)

- **Type-merge vs alignment → A (full type-merge).** One `RoomMessage` proto type + one seal/open path. Decisive fact: the field delta between a signed circle message and a `PublicRoomMessage` is only *(seal key, domain tag, identifier content)* — no structural divergence, so a merged type needs no mode-branching. The usual brake on a merge (the wire-break cost) is absent (relay unused). A over alignment because alignment pays the break yet leaves two parallel paths to re-drift.
- **SemVer → MAJOR** (message types merge; wire-breaking).
- **Persisted-data migration → none.** DHT/relay circle content is ephemeral; any unsigned backlog fails the new verify and drops. No durable unsigned circle store.
- **Operator-gate unification → left out** (orthogonal capability; not part of the room↔circle equivalence).
- **`ROADMAP.md` "Sharer identity → handle#hash" → absorbed for circles.** A delivers verifiable `#12hex` authorship for circle messages AND shares (the public side already has it); the ROADMAP entry is removed at graduation.
- **Circle-identifier binding → the member-derivable circle fingerprint `SHA-384(cot_key)[:12]`** (the structural analog of the public room name), NOT the secret `cot_key`. Inside the AEAD seal; one-way (no secret leak); verifier recomputes it from its own key and checks the signature covers *that*.
- **Key rotation → identity is the raw pubkey.** A pre-rotation own-message reads as not-`mine` after a rotation (cosmetic); a stable-ID→current-key mapping is a separate future concern (out of scope).

## Sequencing (REVISED 2026-07-08 — cutover gate dropped)

- **Layer 1 — engine / state / discovery / liveness unification (internal, no wire break)** landed with Veilid **Phase 4** on the one unified rendezvous engine. Design-of-record: `unified-room-model.md`.
- **Layer 2 — the proto message-type merge + signed circle authorship (this document's headline; wire-breaking, MAJOR)** is **no longer gated behind the v0.33.0 cutover.** The gate protected a non-existent user base — the relay is unused (caraka, 2026-07-08), so a wire break breaks no users. Layer 2 is built now, sequenced after the round-2 quick fixes, with its own thorough review (a trust surface) and an adversarial review of the drafted implementation. Graduated to GitHub issues 2026-07-08.

## Design (A) — implementation-ready (ratified 2026-07-08)

**What it fixes (not cosmetic):** the AEAD seal proves only that *a* `cot_key` holder sealed a message — never *which* member. Any holder can post spoofing another member's `sender_handle`. Per-sender ML-DSA-87 signatures close that and make `mine`/authorship key on identity.

**Wire — one `RoomMessage` replaces both `CircleMessage` and `PublicRoomMessage`:**
`RoomMessage { room_id: string, sender_pubkey: bytes, sender_handle: string, body: string, sent_unix_ms: int64, signature: bytes }`. `room_id` holds the public room name (public rooms) or the circle fingerprint `SHA-384(cot_key)[:12]` (circles). `ShareAnnouncement` already has this shape (`room` + `sender_pubkey` + `signature`), so circle shares ride it unchanged with `room` = the circle fingerprint.

**Core — one signed seal/open path** parameterized by `(key, domain_tags, room_id)`; `public_room` and `circle` become thin wrappers that supply the key + their own domain tags. Mirrors `public_room::{seal,open}_room_message`.
- Signature spans `provenance_domain ‖ room_id ‖ sender_pubkey ‖ sent_unix_ms ‖ body`.
- **Distinct domain-separation strings per surface** — `daemonseed/public-room/message/v1` vs a NEW signed `daemonseed/circle/message/v2` (both the AEAD AAD and the provenance domain differ) — the load-bearing detail: one helper is only safe if the two callers pass different domains.
- **Verifier recomputes the circle fingerprint from its own `cot_key`** and checks the signature covers that — never trusts the carried `room_id`.
- **Open verifies fail-closed:** absent/empty `sender_pubkey` or `signature` = hard reject (no "unsigned/unknown sender" surface). An empty pubkey must not equal anyone.

**App (gui + tui):** `mine = (sender_pubkey == my_pubkey)`, evaluated **after** signature verification, replacing handle-keyed own-message suppression — which also **fixes the rename-mid-session dedup break** (#143 root: handle is mutable, pubkey is stable).

**ISCs:** add circle-authorship-provenance criteria mirroring ISC-S24 / ISC-C57; revise the ISC-10..14 "membership ≠ authorship" wording to "signed authorship"; tombstone-not-renumber per the ID-stability rule.

**Migration:** none (ephemeral content). SemVer MAJOR.
