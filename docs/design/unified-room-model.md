# The Unified Room Model — Design of Record

> Status: ACCEPTED (caraka, 2026-06-29). The umbrella that folds the room↔circle
> unification, the Veilid **Phase-4** scope, and the share-liveness model into one
> design. It **revises the sequencing gate** of `room-circle-unification.md` (whose
> provenance/Layer-2 detail stays canonical there) and **realizes the liveness model**
> of `unified-share-model.md`. This is the design-of-record for what closes the Veilid
> migration.

## Problem

We were patching share/discovery bugs in *lobby* code while messaging rode the *circle
backlog* primitive, with the room↔circle unification paused — fixing two faces of one
thing, twice. Two roots:

1. **Bifurcation.** Circles and public rooms are separately implemented, so every fix
   lands once per surface and the two keep drifting.
2. **The engine has only one storage shape.** The rendezvous engine does *backlog*
   (an append-ring keyed on the ephemeral node identity) well — right for messages,
   wrong for shares/presence/MOTD, which are **current state**, not a backlog. #118
   (orphaned stale announcements), #117 (discovery lag / manual refresh), #116 (sharer
   ghost), and #107 (backlog unread freshness) are all symptoms of this missing shape.

## Governing principle

**A public room and a private circle behave identically in every respect except how
their key is derived** (caraka, 2026-06-28). Entropy source is the only variant:
world-derivable (public room / lobby / share-discovery) vs entropy-gated (circle).
Everything downstream — **messaging, sharing, discovery, fan-out, presence, lifecycle,
provenance** — is ONE code path parameterized by the room key (`room-circle-unification.md`
§Principle). caraka, 2026-06-29: this governs *sharing* as much as messaging.

**Corollary (caraka, 2026-06-29):** with a genuinely shared engine, hardening *either*
surface (circle or lobby) completes the other for free — the other side is an
entropy-source swap. This is the litmus test of true unification, and the reason
**engine-unify == Phase 4**.

## Staging (sequencing revision — caraka ratified 2026-06-29)

The unification has two layers with very different costs, so they get different homes:

- **Layer 1 — engine / state / discovery / liveness (internal, NO wire break): unify NOW,
  as the substance of Phase 4.** One rendezvous engine with both storage shapes (below),
  circles and rooms differing only in entropy source. Zero semver cost. This is where
  #115–#118 / #107 live and get fixed *once*, for all room types.
- **Layer 2 — proto message-type merge + signed circle authorship (wire-breaking, MAJOR):
  rides the v0.33.0 cutover** — already a clean MAJOR tree-replacement break
  (`veilid-migration.md` §Cutover). Detail stays in `room-circle-unification.md`.

This **revises** `room-circle-unification.md`'s "implementation deferred *entirely* until
the migration is closed" gate: the *engine* unification is **part of closing** (it is
Phase 4 done right); only the *wire* unification waits, and it waits for the cutover it
rides. "One major refactor at a time" still holds — there is still exactly one cutover and
one wire break. We are only refusing to build Phase 4 against a model we have already
decided to delete.

## The unified engine

One rendezvous module (`crates/daemonseed-veilid-net/src/rendezvous.rs`, already extracted
per D-3.1), parameterized by `(entropy → owner-seed, key-class, payload codec)`. It must
offer **two storage shapes**, both consumed by every room type:

### Shape A — Backlog (exists today)

Append-ring, node-region-keyed (`member_base_subkey(node_pub) + seq % RING_DEPTH`). A
bounded recent backlog from many members. Right for **messages**. Keep as-is.

### Shape B — Current-state (the missing primitive — #118's root)

Last-writer-wins per *logical key*, with freshness + TTL. For **shares** (key = `share_id`),
**presence** (key = member identity), **MOTD** (operator key). Required properties:

- **Stable placement** keyed on the item's STABLE identity (`share_id` / member identity),
  NOT the ephemeral node identity → a republish overwrites in place; a withdraw cancels in
  place. (Removes the node-identity-rotation orphan that is #118.)
- **Freshness** — each item carries `sent_unix_ms` (the deferred red-team residual (f)).
- **Re-announce + TTL aging** — owners periodically re-assert; recipients prune any item
  not refreshed within a prune-TTL (`> ~2` re-announce intervals so one missed cycle does
  not drop a live item). An offline owner's item ages out — owner presence *is* the share
  liveness signal (D-3.6). Realizes `unified-share-model.md` §Liveness.
- **Self-filter** — an item signed by my own key is mine; it is never surfaced as a foreign
  "discovered" item, regardless of local list membership. (Fixes #116.)
- **Discovery = publish-then-find-with-backoff + periodic re-sweep** — given ~14.7 s
  cross-node watch latency, a one-shot sweep can miss; a bounded periodic re-sweep makes
  discovery converge without a manual refresh. (Fixes #117.)

### Presence / roster

Presence is **Shape B over the member key**: on-roster == online (Demonsaw model). Share
freshness and owner presence ride the same room record (D-3.6); the roster removes the
blind node-region hash (`rendezvous.rs` `member_base_subkey` note: "a roster (Phase 4)
removes the blind hash"). Presence convergence is ~tens of seconds — cadence assumes it
(`veilid-migration.md` Phase-0 finding #2).

## Acceptance criteria (engine properties, not lobby patches)

Concrete ISC numbers are minted at cutover (frozen-contract posture). Until then, criteria
are tracked by GitHub issue:

- **#118** → Shape B: two announcements of one `share_id` from different node identities land
  in the *same* slot (last-writer-wins); a republish overwrites a dead-route announcement; a
  withdraw clears the slot; no orphan survives a sharer restart.
- **#117** → discovery converges within a bounded window after (re)connect with no manual
  refresh (periodic re-sweep + freshness).
- **#116** → a withdrawn/own share never reappears as a foreign discovered item (self-filter
  by `sender_pubkey`).
- **#107** → per-room last-seen high-water mark; unread is gated on the transcript's accept
  decision (a rejected/already-seen message never trips unread).
- **#115** → a room-lifecycle op (leave / forget / export-key) that is identical for rooms
  and circles.

## Provenance (Layer 2 — at the cutover)

One signed message/share type; authoritative handle = `SHA-384(sender_pubkey)[:12]`; reject
absent/bad signatures; signature + `sender_pubkey` ride inside the AEAD seal (ISC-A-S2).
Canonical detail: `room-circle-unification.md` §Target end-state / §Constraints. Lands with
the proto merge at v0.33.0 (MAJOR).

## Build plan

1. **Engine:** add Shape B to `rendezvous.rs` alongside Shape A — stable-key placement,
   freshness, TTL aging, self-filter, periodic re-sweep.
2. **Route consumers:** shares (now) and presence/MOTD (Phase-4 back half) through Shape B;
   messages stay Shape A.
3. **Harden on one surface; the other inherits via entropy-swap** (the corollary above).
4. **Phase 5 cutover:** flip Veilid-default, delete the relay, land the Layer-2 wire merge.

## Decisions (resolved 2026-06-29, caraka + Sanjay)

- **Shape A for chat, Shape B for shares (caraka).** Keep the backlog append-ring for
  messages; build the current-state primitive for shares (and later presence/MOTD).
- **Shape B storage mechanism = per-key subkey on the room record (Sanjay's call).** The
  announcement slot is `share-id → subkey` on the rendezvous record (last-writer-wins),
  not a separate per-item record + index. Simplest, fits the existing record. The lobby
  presently holds *only* share announcements (lobby chat is unbuilt), so Shape B can use the
  whole lobby record with no Shape-A contention — another reason public-shares-first is clean.
  Ceiling = `SUBKEY_COUNT` distinct shares before hash-collision; the lobby can take its own
  larger dedicated schema (DHT supports up to 1024 subkeys) if the ceiling ever bites.
- **Cadence / TTL: implement with sane defaults, tunable later (caraka).** Re-announce
  interval + prune-TTL (`> ~2` intervals), tuned against ~14.7 s watch latency. Start
  conservative; tweak from felt-testing.
- **Build surface: public-shares first (Sanjay's call; caraka leaned circles, deferred to
  judgement).** The Shape B *primitive* is built fresh in the engine regardless; its **first
  consumer is the existing public-share path** — repoint publish/withdraw to call Shape B (a
  call-site swap, not a refactor of Shape-A code). This directly fixes the live #116/#117/#118
  bugs, reuses the felt-tested publish/discover/fetch plumbing, and avoids the Shape-A/Shape-B
  slot-contention a circle record (which carries messages) would have. **Circle-shares become
  the second consumer** via the entropy swap — proving the corollary, and adding the feature.
- **Operator write-gate (MOTD/announcements): out for now (caraka).** A third consumer of the
  finished engine; build the engine first, mount MOTD later.

## Reconciliation with existing design docs

- `room-circle-unification.md` — sequencing gate revised here (Layer 1 now / Layer 2 at
  cutover); its provenance/authorship content stays canonical there.
- `unified-share-model.md` — its §Liveness model is realized by Shape B.
- `presence-superstructure.md` — presence is Shape B's first roster consumer.
- `veilid-migration.md` — this doc defines the substance of Phase 4.
