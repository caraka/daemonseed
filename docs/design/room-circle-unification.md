# Room ↔ Circle Unification — Design of Record

> Status: ACCEPTED design; implementation DEFERRED behind a hard sequencing gate (see *Sequencing*). Captured 2026-06-28.

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

1. **Proto** (`daemonseed-proto`): merge into one room-message type (or, fallback, align `CircleMessage` to carry `sender_pubkey` + `signature`). A type-merge is the faithful expression of the principle and the larger wire break.
2. **Core**: collapse the `circle` and `public_room` seal/open + verify into one path parameterized by `RoomKey`; each surface's job shrinks to "supply the key."
3. **Shares**: route circle shares through the signed `ShareAnnouncement` path.
4. **ISCs**: add criteria for circle authorship provenance; revise/merge the diverged criteria; tombstone per the ID-stability rule (never renumber).

## Open questions

- **Type-merge vs alignment** — one proto message (faithful, MAJOR wire break) vs two messages with identical fields (smaller break). Decide at implementation.
- **SemVer** — MAJOR if the message types merge.
- **Persisted-data migration** — confirm no durable unsigned circle data needs migrating (DHT/relay content is ephemeral; expected none).
- **Opportunistic operator-gate unification** — whether to fold the operator-owner parameterization in at the same time, or leave it.
- **Relationship to the existing `ROADMAP.md` Designs entry _"Sharer identity → handle#hash verification"_** — this design delivers that property for circles; reconcile or absorb that entry at scoping.

## Sequencing (hard gate — REVISED 2026-06-29, see `unified-room-model.md`)

Split into two layers (caraka, 2026-06-29):

- **Layer 1 — the engine / state / discovery / liveness unification (internal, no wire break)** is NOT deferred: it is the substance of Veilid **Phase 4** and is built now, on the one unified rendezvous engine (one code path, entropy-source the only variant). The room↔circle storage / discovery / fan-out / share-liveness equivalence lands here. Design-of-record: `unified-room-model.md`.
- **Layer 2 — the proto message-type merge + signed circle authorship (this document's headline; wire-breaking, MAJOR)** rides the **v0.33.0 cutover** clean break, which pays for the wire break once. This is what stays gated: the wire merge waits for the cutover it lands with.

"One major refactor at a time" still holds — there is exactly one cutover and one wire break. This document's Layer-2 content graduates into GitHub issues at the cutover; the Layer-1 engine unification graduates now via `unified-room-model.md`.
