# Design: Phase 4 on Veilid — presence + announcements/MOTD

**Status:** accepted (design-of-record), 2026-07-07. **Single active source of truth for Phase 4.**
Supersedes and folds in two relay-era docs, now archived:
`docs/design/zarchive/presence-superstructure.md` and
`docs/design/zarchive/announcements-motd-admin.md` (both 2026-06-25, written against the
`daemonseed-server` relay). This doc re-grounds their invariants on the Veilid DHT rendezvous
engine per the veilid-migration Phase 3/4 decision (`docs/design/veilid-migration.md`, 2026-06-27).
Component deliverables remain the existing issues (#74/#75/#77 presence; #88/#92/#93/#94
announcements). ISC IDs are minted at the v0.33.0 cutover (frozen-contract posture).

## Problem

Phase 4 (presence + lobby + announcements/MOTD) is the **cutover gate**: at Phase 5 (v0.33.0) the
relay actor and `daemonseed-server` are deleted, and any Phase-4 surface still stubbed on Veilid
goes dark. The two governing design docs were written **before** the Veilid Phase 3/4 re-model and
describe a transport that Phase 5 removes — a server that holds a signer whitelist file, verifies
each post, and answers `UploadPost`/`UploadMotd`/`GetSignerWhitelist` RPCs. They cannot drive the
build as written. This doc re-grounds them on the DHT rendezvous engine and yields a sequenced,
cutover-aware build plan.

The good news, established by a first-hand code survey (2026-07-07): **presence is nearly done and
transport-agnostic; announcements/MOTD needs one genuinely new core primitive.** See the carry-over
map below.

## What carries over, what dies, what is net-new

Class **A** = transport-agnostic core (usable on Veilid unchanged) · **B** = relay-bound (deleted
at cutover) · **C** = Veilid-stubbed today.

| Item | Class | Evidence |
|------|-------|----------|
| `daemonseed_core::heartbeat` (seal/open `MemberHeartbeat`, self-signed, key-class split, distinct AAD/domain) | **A** | `heartbeat.rs` — no relay/tonic imports |
| `daemonseed_core::presence::PresenceTracker` (apply/reap/cadence, #78 replay-freshness) | **A** | `presence.rs` — `std` + proto only |
| `daemonseed_core::public_space` (`verify_artifact`, `Whitelist::authorizes`, `content_address`, `motd_text_is_valid`) | **A** | `public_space.rs` — client-side verify carries over intact |
| `derive_room_veilid_owner_seed` (world-derivable room transport owner) | **A** | `public_room.rs` — the lobby/public-room rendezvous already exists |
| Rendezvous engine `current_state_subkey` (last-writer-wins, one stable slot/member) | **A** (unconsumed) | `rendezvous.rs` — comment: "a `share_id`; later a presence member id" |
| Presence emit-timer + ingest + reap loop | **B** | wired in the **relay** net actor (gui/tui `net.rs`) — dies at cutover |
| `daemonseed-server::public_space` (`load_whitelist`, `verify_stored_post`, `UploadPost`/`UploadMotd`/`DeletePost`/`GetMotd`/`GetSignerWhitelist`) | **B** | server RPC ingestion — deleted at cutover |
| Presence on the Veilid net actor (gui/tui `veilid_net.rs`) | **C** (absent) | `veilid_net.rs` — `EmitHeartbeat`/`ApplyHeartbeat` are silent no-ops |
| `veilid-net actor::presence()` | **C** | `actor.rs` — `Unimplemented("presence — Phase 4")` |
| Announcements/MOTD on the Veilid net actor | **C** | `veilid_net.rs` — `RefreshPublicSpace`/`UploadAnnouncement`/`SetMotd` → `"not yet on Veilid"` |
| **Operator owner-seed (DHT write-gate for announcements/MOTD)** | **missing** | named only in `rendezvous.rs`; no core derivation exists yet |

**Consequence.** Phase-4 presence is a *re-wiring* job (the core is done; only the Veilid net
actor lacks the emit/ingest loop). Phase-4 announcements/MOTD needs one net-new core primitive (an
operator owner-seed), because the whole authorization model was relay-shaped.

## Constraints (must hold — carried from the archived docs, unchanged)

- **ISC-A-S2** — the DHT/relay learns no membership, no participant identity. Member-plane signals
  are AEAD'd under the room key; the wire sees only sealed, shape-identical frames.
- **ISC-S20 live-only** — no store-and-forward, no offline delivery, no reconnect replay. Presence
  *exposes* this usefully (online ⇒ worth sending); it does not change it.
- **Content-key rule** — content keys (and content signatures) never derive from Veilid (classical
  Ed25519/x25519) key material. This is what decouples write-authorization from content-provenance
  (see below).
- **Single-owner DHT record** — a DFLT rendezvous record has exactly one owner keypair; only holders
  of the owner secret write owner-signed subkeys. World-derivable owner ⇒ open rendezvous;
  non-derivable operator owner ⇒ write-gate.
- **~14.7s cross-node DHT watch latency** (Phase-0, public net) — presence convergence is
  tens-of-seconds; cadence must sit at/above this floor.

---

## Part 1 — Presence on Veilid

### The refinement the relay-era doc could not see: separate the presence stock from the chat stock

The archived presence doc decided "**one beacon, share announcements ride it**" and "**rides the
existing stream**." The first half (one liveness mechanism for share-liveness and chat-liveness) is
correct and kept. The second half — putting the heartbeat into the *message* stream — is a
data-type error on the Veilid rendezvous engine: the room record's per-member slots are an
**append-ring** (`RING_DEPTH = 2`), a *history* buffer sized for "a couple of recent messages."
Liveness is **current-state** (you only ever need each member's *latest* beacon), and chat is
**event-history**. Routing a 10–15 s heartbeat into a 2-slot ring evicts the chat backlog within
~2 intervals — worse under the ~14.7 s watch delay, where a slow-joining subscriber can miss a lone
message before it is overwritten. This is a Tragedy-of-the-Commons over the 2 shared slots, not an
inherent limit.

**Decision P1 — presence gets its own record.** Derive a `presence_owner_seed` as a **sibling**
HKDF expansion of the room/circle owner seed (the exact pattern already used:
`derive_circle_veilid_owner_seed` is a sibling of `cot_key`; `derive_room_veilid_owner_seed` a
sibling of the room key). Presence beacons write to `current_state_subkey(member_id)` on that
sibling record — **last-writer-wins, one slot per member** — and receivers keep the
max-`sent_unix_ms` beacon and reap after TTL. **The chat record and its append-ring are never
touched.** Heartbeat cadence can then be as fast as wanted; it can no longer evict a chat message
because they no longer share a buffer. Fallback (only if the extra record/watch cost bites): a
compile-time subkey split inside the single room record (a chat band + a presence band) — rejected
as default because it shrinks chat ring capacity and bakes the split into the record semantics;
kept as a documented fallback.

**Decision P2 — cadence sits above the propagation floor.** Raise the emit interval from the
archived 10–15 s to **~15–20 s** so it sits at/above the ~14.7 s watch floor; keep the 3-miss reap
(TTL ~45–60 s) and the bias-to-forgiveness. Effective presence resolution ≈ interval + ~14.7 s
regardless, and beaconing faster than the channel propagates only adds redundant DHT writes. These
are the values to tune against real-network wobble data once the Lobby increment is live (this is
the archived doc's open question #4, now bounded by the measured floor). `presence.rs` defaults
`HEARTBEAT_INTERVAL_MAX = 15 s`; the cadence is a `PresenceTracker::with_cadence` constructor
argument, and the fixtures are what set it.

### What the relay-plane reaping question resolves to

The archived doc left open "relay-plane vs member-plane convergence for reaping (defense in depth)."
**On Veilid there is no relay refcount plane** — the relay is deleted. The member heartbeat is the
*only* presence/reap signal: a member is on the roster while its beacon is fresh, and a share is
pruned when its sharer's heartbeat lapses (this also finally lands the share-zombie-reaping the
2026-06-13 note deferred — a sharer's liveness and its shares' liveness ride the same beacon,
`docs/design/veilid-migration.md` D-3.6).

### Roster identity and the Lobby-first increment

The roster *is* the signal (Demonsaw model: on the roster = online; no dots/last-seen/typing) —
kept verbatim from the archived doc. **Lobby identity caveat, now concrete:** on Veilid the *node*
identity is ephemeral per launch, and the public Lobby uses an ephemeral per-session content
identity, so Lobby presence shows **"someone is present," not "FAQ is present,"** unless a member
has a persistent identity. The Lobby-first increment is therefore bounded to anonymous presence;
persistent-handle presence follows for circles (#77), where members already carry a stable identity.

### Presence build shape (issues #74 → #75/#77)

- **#74 heartbeat primitive** — the pure-core/veilid-net opener (no GUI): the sibling
  `presence_owner_seed` derivation, `VeilidNetHandle::presence()` (emit-on-timer to
  `current_state_subkey` + subscribe/ingest into `PresenceTracker` + reap), oracle-tested with a
  two-node roster-converges test (`#[ignore]`, live network). This one can run unattended.
- **#75 Lobby roster UI** — the attended follow-on: render the `PresenceTracker` set in the GUI
  (placement — rail vs room section vs pane — is still the archived doc's open UI question).
- **#77 circle presence** — the identical mechanism on circle rendezvous, with persistent handles.

---

## Part 2 — Announcements + MOTD on Veilid

### Decision A0 — MVP scope: ONE project-owned channel; per-community channels (Fork B) deferred

Settle *how many* channels exist and *who owns them* first, because the relay answered this with
`server_id` and Veilid deletes `server_id`.

**Relay-era truth:** MOTD/announcements were **per-server** — each relay had its own, signed by that
server's key, and `server_id` was a `name#hash` (a hash of that key). "The community" was "the relay
you connected to," so multi-community MOTD is not new — it *was* federation. `server_id` did three
jobs for the public space: community **identity**, write **authority**, address **discovery**. On
Veilid the operator-owned record covers authority (owner secret) and discovery (address from owner
pubkey); community identity has no automatic successor — the owner **pubkey** becomes the identity (a
human name is a local label, as with circles/rooms — ISC-C8).

**Decision (caraka, 2026-07-07): MVP ships Fork A only — a single PROJECT-owned channel.** Owner =
the maintainer-held project key (the existing F17 `project_announce` anchor, ISC-15): a maintainer-held
**offline** seed derives both the ML-DSA content-signing key (F17, already present) and a sibling
Veilid owner keypair (the DHT write-gate); **only the two public keys are baked into clients** — the
exact F17 model already in code ("the placeholder is replaced by a baked-in real release public key
whose secret stays offline"; the operator instance loads that seed at runtime and it is not in the
tree). Clients derive
the record address from the baked owner pubkey, read/watch/verify, and cannot write. MVP
"MOTD/announcements" = **maintainers → all users** ("v0.34 shipped, here's what's new") — exactly what
#88 asked for. The relay-era *per-server operator* MOTD retires with the relay (no host to own it).

**Fork B — mintable per-community channels — is deferred as a deliberate future feature, not smuggled
in.** B is "federation reborn without a server": anyone mints a channel (keypair + record), distributes
the owner pubkey like a circle phrase, optionally binds it to a public room. It fits daemonseed's
community-revival mission but is deeper than it looks: the moment a channel attaches to a **circle** it
reintroduces an **owner/originator** onto circles, which are deliberately **ownerless** (ISC-C8:
shared-owner, no founder — every member equal). "Who owns this circle / who may speak for it" is an
unsolved governance problem the circle model was built to avoid. B therefore needs its own design pass
(community identity, pubkey distribution/trust, room↔channel binding, the circle-ownership question) —
NOT the cutover. A0's operator-only decisions below (A1–A4) all hold for the one project channel and
are the reusable substrate a future B would parameterize.

**Seed for a future B (caraka, 2026-07-07) — the crux is first-contact key distribution, not the DHT.**
Owned channels are the *inverse* of circles: an abandoned circle self-purges (ownerless + live-only
DHT = natural GC), but an owned channel persists exactly as long as someone keeps writing it — so a
persistent adversary can keep a *squatted* look-alike channel alive and divert trust/traffic to it.
Persistence is what makes an owned channel useful AND is exactly what an adversary can buy. The defense
is already in daemonseed's DNA: trust binds to the **`name#hash`** (the key fingerprint), never the
human label — an impostor can take the name but never the hash, so a client that knows the real hash
never resolves to the impostor no matter how alive it is kept. That reduces B's security to **how a
user learns the right hash at first contact** (the petname / Zooko's-triangle problem) — solved for
circles by out-of-band phrases and for the app by baked keys, unsolved for open community discovery.
Any B design starts here, not at the DHT mechanics.

### The decoupling the relay collapsed: write-gate ≠ content-provenance

On the relay these were one thing (the server sat on both). On Veilid they are two independent
layers, and the design must keep them separate:

1. **Write authorization** — who may place an owner-signed subkey on the DHT record. This is a
   *Veilid owner key*. The single-owner constraint forces this to **one holder** at MVP.
2. **Content provenance** — who signed the announcement/MOTD *content*. This is a *classical
   ML-DSA-87 key* (content-key rule), verified **client-side** by `verify_artifact` against the
   `Whitelist` — carries over from the relay **unchanged**.

**Decision A1 — operator-owned rendezvous slot is the sole write-gate (MVP).** Announcements and
MOTD live on an **operator-owned** rendezvous record: a *non-derivable* operator owner keypair (the
one piece of net-new core — an operator owner-seed, held by the operator, NOT derived from any
public input) is the write-gate. MOTD is a single last-writer-wins slot (`current_state_subkey`);
announcements are content-addressed items on the record. Clients subscribe, fetch, and re-verify
with the carried-over `verify_artifact` + `Whitelist` + MOTD plaintext rule (ISC-A-S3 — trust
nothing the transport asserts). The relay's `UploadPost`/`UploadMotd`/`GetSignerWhitelist` RPCs are
**moot** (no server); their client-side authoring/verify helpers (`daemonseed_cli::public_space`)
re-target the operator record.

**Decision A2 — the whitelist degrades from a security boundary to a documentary roster (named,
accepted).** On the relay, the whitelist was an *enforcement boundary the server applied per post*.
On Veilid the operator *is* the writer, so **no independent party enforces the whitelist against the
writer** — a compromised operator can publish content signed by a non-whitelisted key, or rewrite
the roster. For MVP the operator is a trusted principal; the whitelist the operator publishes on the
record is a **client-verified documentary roster** (provenance + transparency), not an enforcement
boundary. This is the real, honest cost of the re-grounding — stated as accepted, not left implicit.

**Decision A3 — multi-author is quarantined behind a post-MVP out-of-band submission channel.**
A shared-owner (circle-style) model was rejected: revocation = rotate the owner keypair = new DHT
record key = re-advertise rendezvous = every client re-resolves — the disaster-recovery cost paid on
*every* personnel change, strictly worse than out-of-band submit-to-operator for an operator
function. MVP is **operator = sole author AND sole writer** (whitelist has one entry, near-vestigial).
If a future increment wants >1 content author, it defines an out-of-band submission channel (the
signer hands a signed artifact to the operator, who writes it) — the whitelist can already carry
N entries and `verify_artifact` already verifies N signers; only server-enforced *ingestion* died.

**Decision A4 — keep MOTD and announcements separable.** MOTD is inherently operator-scoped (a
single server-wide message) — operator-only fits perfectly and permanently. Announcements are the
surface a future multi-author increment touches. Both are operator-only for MVP, but the doc and
code keep them separable so the fork stays quarantined to announcements.

### Gaps closed before this became design-of-record

- **Roster/announcement freshness (rollback guard).** Live-only DHT + no store-and-forward means a
  client reading a stale subkey sees an old roster/MOTD; an untrusted transport could serve a stale
  slot to roll back a revocation. Apply the **#78 replay-freshness pattern** to the operator record:
  a monotonic version/`sent_unix_ms` guard so a client never accepts an older roster/MOTD than one
  it has seen. This closes a silent-rollback surface the archived doc did not have (it had a server
  enforcing freshness).
- **Subkey size does not force the split-hash.** Phase-0 measured the per-subkey cap at 32768 B with
  ~7× headroom over the ~4.6 KB ML-DSA-87 signed object, so a signed announcement fits in one
  subkey and the unread-landing hash can stay the **single combined** MVP hash (archived doc's
  open question resolved by measurement, not taste). The client computes the combined hash over the
  *verified* view exactly as the relay-path #93 already does (`combined_content_hash`).
- **Operator signer-key stability (#94).** The composer gates on, and signs with, the **stable
  profile ML-DSA key** (`derive_identity_keys(...).signing`) — independent of the ephemeral
  per-launch Veilid node identity. On Veilid this becomes: the operator holds the operator owner
  secret (write-gate) *and* their stable signing key is on the published roster (provenance). #94's
  "surface the stable, not the ephemeral, identity" is the composer-gate answer for the operator-only
  model.
- **Owner-key loss = unrecoverable record (accepted MVP risk, named).** A non-derivable single owner
  means losing the operator owner secret loses the announcements rendezvous permanently. Out of scope
  to solve at MVP; named as an accepted risk (mitigation — operator key backup — is operator
  procedure, not app scope).

### Announcements/MOTD build shape (issues #88 epic → #92/#93/#94)

- **[core]** operator owner-seed derivation (the net-new primitive) + the monotonic freshness guard.
- **[veilid-net]** operator-owned rendezvous publish/subscribe for MOTD (single slot) + announcements
  (content-addressed items); re-target the `daemonseed_cli::public_space` authoring/verify helpers.
- **[gui/tui] #92** signer-gated composer — gate on the stable key (#94) + operator-owner possession.
- **[gui] #93** unread-gated landing — reuse the client-derived combined-hash + `landing_decision`
  (already built relay-side; transport-swap only).

---

## Build plan (sequenced, cutover-aware)

Presence and announcements are independent tracks; presence is further along and lower-risk.
Order within each track is dependency-driven. "Unattended" = oracle-gated core/veilid-net, no GUI;
"attended" = has a GUI surface / manual test.

**Track P — presence (lower risk, mostly re-wiring):**
1. **P-a (#74, unattended)** — sibling `presence_owner_seed` + `VeilidNetHandle::presence()`
   emit/ingest/reap on a current-state sibling record; cadence via `with_cadence`; two-node
   roster-converge oracle (`#[ignore]`, live network). *Depends on:* nothing new (core is done).
2. **P-b (#75, attended)** — GUI Lobby roster render; manual test on a real-network host (two clients see each
   other appear/disappear). *Depends on:* P-a.
3. **P-c (#77, attended)** — circle presence (persistent handles) on the same mechanism.
   *Depends on:* P-a, P-b proven.

**Track A — announcements/MOTD (needs the net-new core primitive):**
1. **A-a (core, unattended)** — operator owner-seed derivation + monotonic freshness guard; unit
   oracles. *Depends on:* nothing.
2. **A-b (veilid-net, unattended)** — operator-owned MOTD slot + announcement items publish/subscribe;
   re-target cli authoring/verify; in-process oracle + two-node (`#[ignore]`, live network).
   *Depends on:* A-a.
3. **A-c (#92, attended)** — signer-gated composer on the stable key (#94). *Depends on:* A-b.
4. **A-d (#93, attended)** — unread-gated landing (hash + `landing_decision` transport-swap).
   *Depends on:* A-b.

**Lobby-transcript hardening (rides the Lobby increment, not new design):** #126/#131 (lobby
sender-timestamp ordering/high-water is forgeable on the open room), #100 (message age), #107
(per-circle high-water). These are transport-quality items the presence roster work touches; fold
their fixes into P-b/the Lobby increment rather than deferring.

## Cutover-gate coverage (what Phase 5 requires)

Phase 4 is the gate: at v0.33.0 the relay actor is deleted, so **every surface a daemon relies on
must be non-stubbed on Veilid, or it goes dark.** Required before Phase 5:

- **MUST (gates cutover):** presence P-a/P-b (Lobby roster) — the motivating "is X online to ping?"
  need; announcements/MOTD A-a/A-b (the project channel, A0) — so the maintainers can still post
  "what's new" after the relay is gone. Without these, the app loses presence and the update channel at
  cutover.
- **SHOULD (strongly wanted, small):** #92 composer, #93 landing, #77 circle presence — complete the
  experience but a daemon is not *broken* without them at the instant of cutover.
- **MAY (post-cutover):** multi-author announcements (A3 fork), roster-placement UI polish, the
  compile-time subkey-split fallback (only if the sibling record proves too costly).

Per the project cutover-gate decisions (2026-07-07): TUI parity does **not** gate (GUI primary);
this Phase-4 gate composes with the transport-quality bugs (#113/#123/#112/#121/#128) and a
whole-branch review already named as the full cutover gate.

## Open questions (residual)

- **Roster UI placement** — rail vs active-room section vs separate pane (archived doc's open item;
  a UI call, deferred to #75).
- **Final presence cadence/TTL/jitter** — the ~15–20 s / 3-miss / ~45–60 s starting point tunes
  against real-network wobble once the Lobby increment is live.
- **Server-wide-key MOTD** — the relay allowed a server-wide key (not just whitelist signers) to set
  MOTD; on Veilid this is subsumed by "operator owns the record" (the operator IS the server-wide
  authority). Confirm no separate affordance is wanted.

## Cross-references

`docs/design/veilid-migration.md` (Phase 3/4 decision, D-3.1/D-3.2 rendezvous engine + owner-class
model, D-3.6 liveness), `docs/design/unified-room-model.md` (presence is the roster consumer of
Shape B), `docs/design/unified-share-model.md` (share-liveness rides the same beacon). Archived
originals: `docs/design/zarchive/{presence-superstructure,announcements-motd-admin}.md`.
ISA invariants: ISC-S4/S7/S8/S9 (public space, announcements, whitelist, MOTD), ISC-S20/A-S2
(live-only, relay-blind), ISC-S17/A-S12 (constant-time presence). Issues: #74/#75/#77 (presence),
#88/#92/#93/#94 (announcements/MOTD). Code pointers still naming the archived paths
(`presence.rs`, `heartbeat.rs`, `cot.proto` design-of-record comments) repoint to this doc during
the Phase-4 build that edits them.
