# Direct Messaging — Design of Record

> Status: **ADJUDICATED — NOT FROZEN (2026-07-27).** The design space was mapped and the forks were adjudicated (Option C over A, schema sizing, keep-alive, WriteClass — all below and mostly surviving). Then an adversarial panel (erasure/availability — run twice, the second code-grounded — correlation/metadata, crypto/replay) **refuted the frozen candidate**: all three lenses returned BLOCKER-class findings that trace to one root — the design priced *write authority* (who can forge, who can erase) but never *retention* (what the network keeps) or *read observability* (which records an adversary can choose to watch). Fork 1C's decisive argument, the stop-on-presence stopping condition, and the Fork-3 spam bound all rest on "no third party can erase the outbox," which is true of authorization and false of the other two. **This document is therefore an adjudication record, not a ratified freeze.** The § Adversarial-pass findings section is authoritative and SUPERSEDES any in-body claim it contradicts; the § Revised direction section (added after the findings, with caraka) supersedes the three-record mechanics on the identity/metadata axis and **dissolves reopened decision #1**; § Decision #2 *proposed* an `ss`-channel-as-ack + A+B+C model — but the round-2 re-panel (§ Re-panel round 2) **refuted it**: all three lenses returned BLOCKER-class findings against the revised direction too. The `ss`-gated ongoing channel is a genuine banked win, but #1 is only *capped* (lobby rhythm side-channel), #2 is reopened (the ack is itself evictable), and #3 is not mechanical (no real FS from a static KEM key; unwritten nonce/AAD spec). **This is the second refutation. The next step is scope/ambition calls that are above a build (best-effort delivery vs a pinning node; no-PFS vs a key-layer redesign; unlinkability-vs-lobby vs cover traffic) — caraka's call — then a written crypto construction, then a third panel.** Re-cuts the relay-era DM ISC family (ISC-C38–C46 / ISC-A-C20–A-C25) in `ISA.md` to the Veilid *direction* (the relay-era `server_id`/no-offline content was unambiguously wrong); the specific three-record mechanics remain under the reopened questions. Partial progress on #177. Couples: #134 (presence slot ceiling — the schema-sizing answer below serves both), #136 (monotonic version), #225 (OS notifications).

> **The valuable, durable output of this pass** (independent of the reopen): the schema-sizing facts (§ Schema sizing — answers #134 too), the fork *verdicts* that survive review (C over A; static-KEM over handshake; the WriteClass classification; the keep-alive/stopping-condition *shape*), the crypto-primitive sizing, and — above all — the enumerated adversarial findings that any next iteration must answer. The design was not ready to freeze; the pass is exactly what surfaced that, cheaply, before a build.

## The design, in one sentence

**A DM is a circle with one other person, where their published identity key replaces the shared phrase.**

Every addition below was tested against whether that sentence survives it. The sender encapsulates to the recipient's published static ML-KEM-1024 key, seals the message under the encapsulated secret, and publishes it; the recipient decapsulates whenever they next come online. There is no handshake, no session, no ack, and no new transport — the same rendezvous engine, sealed frames, transcript, and rail carry it.

## Problem

There is no way to hand someone circle entropy privately inside daemonseed — private contact is currently bootstrapped by an *external* private channel. The fix is first-contact-capable, offline-capable direct messaging: A can message B without B being online, without prior arrangement, and without either party revealing the correspondence to the network.

## Constraints (must hold)

- **ISC-A-S2 posture** — DHT and storage nodes see only sealed frames; no content, no forgeable authorship.
- **WB-2 write ceiling + WB-3 scheduler invariants** (`docs/design/veilid-write-budget.md`, FROZEN) — DM writes classify into the existing scheduler; **nothing here amends WB-3** (see § Write classification for the explicit statement).
- **Frozen wire contract** — v0.36.2 is released to testers; the proto delta is strictly additive (see § Wire delta).
- **No DHT TTL** — retention is capacity-eviction only (`RecordStoreLimits` has no expiration field; `remote_max_records` 64/128, `remote_max_storage_space_mb` 128/256). A stored value survives exactly as long as someone re-seeds it. Store-and-forward is something the **sender performs**, not something the network provides.
- **Veilid write authority is all-or-nothing per DFLT record** — `value_data.writer() == owner` for every subkey; the subkey index takes no part in authorization (`veilid-core-0.5.7 src/storage_manager/schema.rs:48-88`). An inbox anyone can write is an inbox anyone can erase.

## Schema sizing — the fact that shapes every record here (answers #134's blocking unknown too)

Veilid's DFLT schema permits **`o_cnt` up to 1024** (`DHTSchema::MAX_SUBKEY_COUNT`, `veilid_api/types/dht/schema/mod.rs:24`; validated `dflt.rs:30-34`). But the per-subkey value cap is **not** a flat 32 KiB:

```
max_value_len = min(MAX_SUBKEY_SIZE = 32768, MAX_RECORD_DATA_SIZE = 1 MiB / o_cnt)
```

(`storage_manager/schema.rs:61-63`; constants `storage_manager/types/mod.rs:14-16`.) Slot count trades directly against slot capacity:

| o_cnt | per-subkey cap |
|---|---|
| 1 | 32 KiB |
| 32 | 32 KiB |
| 64 (today's `dflt(64)`) | **16 KiB** |
| 128 | 8 KiB |
| 256 | 4 KiB |
| 512 | 2 KiB |
| 1024 | 1 KiB |

Consequences:

1. **Latent guard defect (pre-existing, file as its own issue):** `APP_MESSAGE_CAP = 32768` is used as the subkey-write guard (`rendezvous.rs:258-260`), but the true cap on the production `dflt(64)` records is **16384**. A sealed value of 16385–32768 bytes passes the local guard and is rejected by Veilid (`"value too big"`). Nothing ships that big today (share adverts ~12 KiB are the closest), but the guard should be schema-derived, not constant. The Phase-0 "32768 accepted" live probe used a smaller-`o_cnt` record and does not contradict this.
2. **#134 (presence ceiling) is answered by formula, not by a number:** a dedicated presence schema takes `o_cnt ≤ 1 MiB / padded_beacon_size`. At the current `MemberHeartbeat` shape (~7.4 KiB unpadded: pubkey 2592 + sig 4627 + fields), padding to 8 KiB bounds presence at **o_cnt = 128**. Shrinking the beacon buys slots linearly. The #77/#134 build picks the padding constant first, then the count — in that order.
3. **PQ signatures dominate every payload.** ML-DSA-87 signature = 4627 B, pubkey = 2592 B, ML-KEM-1024 ciphertext = 1568 B. Any schema past o_cnt ≈ 150 cannot carry a signed message at all. Big-slot-count schemas are for small unsigned-inside pointers only.

## The three records

DM delivery uses three record types. Only one of them is world-writable, and it carries pointers, not messages.

### 1. The key record — one per identity, `dflt(1)`

Publishes the identity's **static ML-KEM-1024 encapsulation key**. The keypair already exists on every identity, derived deterministically from the recovery phrase (`daemonseed-core/src/identity/keys.rs:267,280,307-320`; determinism test-locked) — only the public half is new to the wire.

- **Address (world-derivable — that is the point):** owner seed = HKDF-SHA384 over the identity's full ML-DSA-87 public key, domain-separated (`daemonseed/dm/keyrec/v1/owner`, suite-family-anchored like the lobby derivation). Anyone holding the full pubkey computes the record key. The full pubkey is already carried by every provenance-signed artifact — chat/room messages (`cot.proto` `sender_pubkey`), share announcements, and presence beacons (`MemberHeartbeat.sender_pubkey`) — so **anyone visible on a roster or in a transcript is DM-able with zero new discovery surface.**
- **Content:** `DmKeyRecord { version (u64, monotonic), kem_ek (1568 B), signature (ML-DSA-87 over domain ‖ identity_pubkey ‖ version ‖ kem_ek) }` ≈ 6.2 KiB — fits the 32 KiB `dflt(1)` subkey with 5× headroom.
- **Write authority:** world-derivable owner (unavoidable — a discoverable address under DFLT is a derivable owner). Accepted: forgery is impossible (signature under the identity key; readers verify), so erasure is the only attack, and it is DoS-only. The owner keeps the record alive operator-style while online. The **monotonic `version`** exists so a future key rotation cannot be reverted by replaying an old signed blob — same newer-wins pattern as #136; readers cache the highest verified version and never regress.
- **Residual (named):** an attacker can wipe the key record while the owner is offline, blocking **new** first contacts to that identity until they return (established correspondents cache the EK forever, per the contact cache). Eviction does the same thing without an attacker. The sender-side outbox therefore has an *awaiting-key* state with retry (below).

### 2. The doorbell — one per identity, world-writable, `dflt(256)`

The only unauthenticated write surface, and it carries only sealed fixed-size pointers.

- **Address:** owner seed = HKDF over the recipient's identity pubkey (`daemonseed/dm/doorbell/v1/owner`) — lobby-parity world-writable, deliberately.
- **Entry:** `kem_ct (1568 B) ‖ AEAD-sealed { outbox_record_key, sender_pubkey_hash (SHA-384, 48 B), proto_version }`, sealed under the encapsulated secret with AAD `daemonseed/dm/doorbell/v1`, **padded to one constant length ≤ 2 KiB** (WB-1.4 discipline: fixed-size or it becomes a metadata oracle). Fits the 4 KiB cap of `dflt(256)` with headroom. No signature inside — it wouldn't fit and isn't needed: a forged pointer costs the recipient one dead outbox fetch that fails verification there. The sender's *full* identity is proven at the outbox, not at the doorbell.
- **Slot discipline — current-state, stable, blind:** `slot = HKDF(sender_dm_slot_secret, recipient_identity_pubkey) % 256`, where `sender_dm_slot_secret` is an HKDF expansion of the sender's own seed (`daemonseed/dm/doorbell/v1/slot`). Properties, each load-bearing:
  - **Stable across restarts** — a re-seed overwrites the sender's own previous entry, never orphans it. This is #118's fix direction applied from birth: last-writer-wins surfaces key off stable ids; the ephemeral-node-key ring bug class cannot occur here.
  - **Not observer-computable** — the slot derives from a sender *secret*, so a storage node co-hosting the doorbell cannot run a candidate-set attack ("slot 14 is active, and slot 14 is what pubkey X would map to") to learn who is knocking. The recipient doesn't need to compute it either: readers sweep the whole record (WB-4.L1).
  - The #118 asymmetry it must not disturb is *preserved*: chat rings keep ephemeral node-key regions (that ephemerality is what prevents cross-session linkage of lobby writes); the doorbell gets stability without linkage by rooting in a secret instead of a public stable id.
- **Collision math:** birthday over 256 slots is material around ~20 *concurrent unknown* first-contact senders. Colliders overwrite each other last-writer-wins; keep-alive alternation plus whole-record sweeps deliver both eventually; established correspondents leave the doorbell entirely (below), so steady-state occupancy stays low. Accepted for v1.
- **Erasure:** anyone can wipe the doorbell. Cost: a *notification*, never a message — content lives elsewhere, and the sender's keep-alive restores the pointer. First-contact suppression residual is handled by the stopping-condition split (below).

### 3. The outbox — one per (sender → recipient) pair, sender-owned, `dflt(64)`

Where messages actually live. **No third party can write or erase it.**

- **Address:** owner seed = HKDF expansion of the **sender's identity seed** with the recipient's identity pubkey folded into the info (`daemonseed/dm/outbox/v1/owner` ‖ recipient pubkey) — the sibling-expansion pattern of `circle/key.rs`. Only the sender can derive the owner secret; the record key is not computable by observers (it reaches the recipient only inside the sealed doorbell pointer, and the recipient caches it).
- **Slot discipline:** single writer, so no member regions — a plain append ring, `slot = seq % 64`, seq persisted in the outbox state. Retention = the sender's last 64 messages to that correspondent (vs `RING_DEPTH = 2` on chat rings — "your third message overwrites your first" is not acceptable for offline delivery; 64 pending messages per correspondent is).
- **Message:** `DmMessage { kem_ct (1568 B), sealed { sender_pubkey, sent_unix_ms, body, signature } }`, AAD `daemonseed/dm/msg/v1`. Fresh encapsulation per message. Seal key = HKDF-SHA384(ss, `daemonseed/dm/msg/v1` ‖ sender_pubkey ‖ recipient_pubkey) — binding both identities into the KDF info kills cross-pair replay by construction. Signature over domain ‖ recipient_pubkey ‖ sent_unix_ms ‖ body proves authorship inside the seal (relay-blind, ISC-A-S2 intact). Size arithmetic: 1568 + 16 (tag) + 4627 (sig) + 2592 (pubkey) + fields ≈ 8.9 KiB of overhead against the 16 KiB `dflt(64)` cap → **body cap ≈ 7 KiB; the build sets `DM_BODY_CAP` from this arithmetic and the compose UI enforces it.**
- **Recipient dedup** is by content address of the sealed value — a message republished after reading is wasteful, not wrong (this is what makes the ack unnecessary at v1).

### How the pieces meet

**First contact:** sender fetches recipient's key record (address derived from their pubkey, learned from any signed artifact) → encapsulates → writes the message into the (new) outbox record → writes the sealed doorbell pointer. Recipient, next time online, sweeps their doorbell → decapsulates the pointer → fetches the outbox record → decapsulates messages → surfaces as a **contact request** (Fork 3, below).

**Established contact:** the recipient's contact cache holds the correspondent's outbox record key (and EK). Their client sweeps/watches cached outbox records directly — **the doorbell is not consulted after first contact**, which is what makes doorbell erasure a first-contact-only nuisance. Outbox records join the steady-resweep rotation (WB-4.L2 — watches are lossy; sweep is the guarantee); per-record resweep latency grows linearly with record count, which at contact scale is the #171 tail-sweep's problem, named here as a scaling consideration, not a v1 blocker.

## Fork 1 — write authority: adjudicated for Option C (doorbell + sender-owned content)

**Option A (world-writable inbox, lobby parity) is REJECTED**, and the decisive argument is the interaction the brief flagged: under A, the erasure primitive **composes with the stopping condition into silent, targeted, cheap suppression at exactly the attacker's best moment.** The recipient comes online → the sender's stop-on-presence rule fires and re-seeding stops forever → the attacker's sustained wipe (trivial: they hold the owner key) wins the race against the recipient's sweep → the message is gone, the sender's UI honestly believes "they've been online, it's delivered," and neither party ever learns otherwise. Lobby parity does not transfer: the lobby is an ephemeral broadcast surface where erasure costs recent chatter; a DM inbox is targeted store-and-forward where erasure is a *silent, per-victim censorship primitive* whose worst case is invisible. A also has no answer that isn't an ack (ruled out) or a tombstone (an ack in a different hat).

**Option C accepts A's only real advantage was fewer records, and buys:** content that cannot be erased by anyone but the sender; an unauthenticated write surface bounded to fixed-size sealed pointers (which is also the spam bound); and a stopping condition that is actually sound for established contacts (below). Costs, priced: two records per new correspondence, one extra fetch hop at first contact, and outbox-record count growing with correspondents (swept round-robin — linear, bounded by contact count).

**Option B (SMPL) for the post-first-contact channel — structurally sound, deliberately deferred.** Verified against veilid-core: in SMPL, member-range writes are authorized against the *member's* key — the owner cannot write (hence cannot erase) member subkeys (`storage_manager/schema.rs:99-135`). A per-pair SMPL record (2 fixed members, writer set never changes — the open-membership objection from `veilid-migration.md:103` does not apply to a pair) would give a true single-record two-writer channel with erasure-proof member ranges: the closest literal realization of "a circle with one other person." It is not v1 because it needs machinery that doesn't exist in the workspace (an SMPL create/open path; stable per-identity DM writer keys, derived and exchanged) while Option C reuses the DFLT engine as-is. **Recorded as the v2 consolidation target** if the two-records-per-pair overhead ever bites.

## Fork 3 — the spam surface: bounded, not designed away

Anyone who can derive your doorbell address can knock. The bounds, ranked by where they bite:

1. **The unauthenticated surface is pointer-sized and fixed-size.** Content never lands unbidden; the recipient fetches it by choice. A garbage entry costs one decapsulation (constant-time, cheap) and is dropped on AEAD failure.
2. **One slot per sender.** A spammer's re-writes land on their own slot — volume does not spread across the record.
3. **ISC-C45's explicit-accept SURVIVES the re-cut, demoted from wire handshake to local UI gate.** A first contact from an unknown sender surfaces as a **contact request**; the thread renders only on accept. Decline discards. This is the relay-era answer with the HELLO/ACCEPT machinery deleted — the *UX* was right, the wire protocol was the complexity this design exists to remove.
4. **The block list (re-cut ISC-C46) drops a blocked sender's doorbell entries at sweep** (matched on the sealed `sender_pubkey_hash`) and stops sweeping their outbox. Silent and unilateral; the blocked sender's view is byte-identical to "never came online" — the old C46 goal now falls out of the sender-abandons-on-schedule structure for free.
5. **Named residual, accepted at v1:** a Sybil flooder minting fresh identities can occupy many doorbell slots (each costs a sustained keep-alive to hold against eviction and real-sender overwrites). This degrades *first-contact* delivery under active attack; established contacts are untouched. Rate/PoW bounds are v2-if-ever; at alpha scale the fixed-size surface plus per-sender slots suffice.

## Task 2 — the keep-alive (ratified, with one split)

**Mechanism (ratified as stated):** no TTL, eviction-only retention → a message survives exactly as long as the sender re-seeds it. The sender performs store-and-forward.

**Schedule (ratified):** geometric backoff per pending message — `1 min → 2 → 4 → 8 → 16 → 32 → 64 → hourly → daily` (~20 writes over a week vs ~5,000 at the operator's flat 120 s). Hard give-up at **7 days**; the message is marked **undelivered** in the UI, never silently abandoned.

**Stopping condition (ratified for established contacts; split for first contact):**

- **Established contact:** stop re-seeding once the recipient has been seen present (lobby roster, already swept continuously — a free local lookup) at any point after the publish. Sound *because of Fork 1C*: the recipient holds the outbox record key, their client sweeps it, the content cannot have been erased — presence-after-publish plus on-DHT genuinely exhausts the failure modes. Presence is a **stopping** condition, never a sending gate (the earlier draft that gated sending on presence reproduced the constraint this design removes).
- **First contact:** presence does **not** stop re-seeding — the doorbell is erasable, so "they were online" does not imply "they saw the pointer." First-contact messages re-seed on the full schedule until either **evidence of establishment** (any inbound traffic from the recipient on this pair — a reply, or their doorbell entry to us) or the 7-day give-up. Cost of this insurance: ~20 writes over the week. This is the residual of the erasure attack under C, priced at almost nothing.
- Dependency, named: presence is lobby-only today (#77 extends it to circles); everyone is in the pinned lobby by default, so it holds in practice.
- Leak, named and accepted: an observer co-hosting an outbox record who watches re-seeding stop learns "the recipient appeared in the lobby" — information the lobby record already publishes.

**Persisted outbox (ratified as a hard storage requirement):** pending DMs and their backoff position survive restart. The operator keep-alive tolerates in-memory state because it re-folds from the DHT; a DM has no such source — a restart before collection would silently lose the message from the sender's side. States: **awaiting-key** (recipient's key record unfetchable — evicted or wiped; retry key fetch on the same backoff), **awaiting-collection** (sealed, published, re-seeding), **presumed-delivered** (stopped on presence / establishment), **undelivered** (7-day give-up, surfaced). Ring seq per correspondent persists with it.

## Fork 4 — write classification (uses WB-3; amends nothing)

- **First dispatch of a user send is `Chat` (rank 1)** — the outbox write, plus the doorbell write when the send is a first contact. It is a user action wanting user-action latency (I4's 2-permit chat lane, never coalesced). This is one write (two at first contact) per user action — exactly what the chat lane is for.
- **Every scheduler-driven re-dispatch is `Keepalive` (rank 4):** outbox re-seeds, doorbell keep-alive, key-record keep-alive. They compete in the non-chat window against presence and advert refreshes, coalesce per I3 on `(record, logical id)` — the logical id is the *message* (slot), so a superseded re-seed of the same message coalesces and distinct messages never do — and reach the floor lane via `FLOOR_AGE(4)` like any class-4 write.
- **I6b does not apply.** There is no hard DHT expiry anywhere in the DM path — only eviction pressure — so no DM write carries a deadline. I6b stays scoped to the operator-TTL case it was built for.
- **The retry loop lives in the persisted outbox, above the scheduler.** The scheduler has no retry machinery (verified: zero `retry`/`repeat` hits in `schedule.rs`) and **gains none**: the outbox owns the backoff timers and enqueues each re-seed as a fresh, ordinary write into the I1 funnel. **Explicit statement, as the freeze requires: WB-3 is not amended by this design.** New writers classified into existing classes is *use* of the scheduler; the one thing that would have been an amendment — scheduler-resident retries — is placed outside it by construction.
- **WB-0 conformance:** DM sends and their re-seeds are chat-class consented emissions — the activity *is* the payload — not presence/discovery-class, so WB-0's activity-independence rule does not govern them. The two DM keep-alives that are *not* content (doorbell, key record) take no input from user activity: they run on their own cadence while pending/online. Budget: a pending message costs ~20 writes/week; steady-state DM keep-alives are noise under the WB-2 4/min ceiling.

## Wire delta (additive; back-compat posture explicit)

Three new `daemonseed.v1` messages — `DmKeyRecord`, `DmDoorbellEntry`, `DmMessage` — plus the three new record derivations. **No existing message, field, or record changes.** This is a green-field additive MINOR on the frozen wire: v0.36.2 clients never derive or sweep DM records, so they neither see nor break on any of it (contrast #136, which mutates an existing record's semantics — the expensive kind). Compatibility rule: DM requires both ends ≥ the shipping version; a DM sent to an old client simply ages to *undelivered* — indistinguishable from never-came-online, which is the honest answer. `cargo xtask check-proto` snapshot updates ride the build commits.

## Out of scope (unchanged from the pre-freeze decisions, recorded so they are not re-litigated)

- **Acks / delivery receipts** — dedup-by-content-address makes them an optimization; block semantics fall out of their absence.
- **Forward secrecy** — the system has none anywhere; a static-KEM DM is *stronger* than a phrase-shared circle, not weaker. DHT decay is not PFS (a recording adversary keeps the ciphertext). If PFS ever becomes a requirement it is a whole-system conversation.
- **Key agreement from ML-DSA keys** — no such operation exists; the Ed25519→X25519 intuition does not transfer to lattice schemes. Recorded so it is not re-proposed.
- **Read-before-write as a stop condition** — "collected" and "evicted" are indistinguishable without a tombstone, and a tombstone is an ack.
- **SMPL for open rendezvous** — rejected with structural reason at `veilid-migration.md:103`; only the per-pair post-contact case is live, and it is deferred (Fork 1B above).

## UI

Discord-style **DM overlay on the rail, sorted by recency** (ratified). The rail already carries unread dots (#64); recency-sort suits DMs where circles want stable ordering; #225 (OS notifications) gets its obvious home. Unknown-sender first contacts render as requests (Fork 3), with accept / decline / block.

## Spawned work (build slices, in dependency order)

1. **Key publication:** `DmKeyRecord` + derivations + keep-alive + fetch/verify/cache path (includes the schema-derived write guard fixing the `APP_MESSAGE_CAP` latency noted above, or that lands as its own prior fix).
2. **Outbox + doorbell:** records, derivations, sealed formats, persisted outbox with backoff states, WriteClass wiring.
3. **Collection path:** doorbell sweep, pointer decapsulation, outbox sweep/watch + steady-resweep registration, dedup, contact cache extension (re-cut C44).
4. **UI:** rail overlay, requests, block list wiring (re-cut C45/C46).

Each slice registers its ISCs in `crates/daemonseed-isc` at its build commit, per the WB pattern.

**These slices do not proceed until the reopened decisions below are resolved** — several would build a refuted construction.

## Adversarial-pass findings (2026-07-27, 3 independent lenses — authoritative; supersedes contradicted in-body claims)

The one-line root, stated by all three lenses: **the design analyzes each record for write authority and never asks the prior questions — what does the network retain, and which records can an adversary choose to watch and at what cost.** Two of the three records are world-addressable from a stable identity for free.

### BLOCKERs (freeze cannot stand)

- **B1 (crypto) — the message seal key is underivable; first contact cannot decrypt.** The seal key binds `sender_pubkey` into its HKDF info, but `sender_pubkey` (2592 B) is placed *inside* the seal and cannot be moved into the doorbell pointer (over the 2 KiB pad and the 4 KiB `dflt(256)` cap). At first contact the recipient holds only the 48-B `sender_pubkey_hash`, a preimage-resistant hash. The construction does not close. *Likely-but-wrong build fix (silently dropping `sender_pubkey` from the KDF) deletes the property the doc calls load-bearing.* **Fix direction:** carry `sender_pubkey` as a cleartext envelope field (the `cot.proto` provenance pattern — see B8), sign over it, and let cross-pair replay resistance rest on `recipient_pubkey` in the KDF info alone (sufficient).
- **B2 (crypto) — authentic messages replay from an attacker-owned outbox.** Nothing binds a sealed `DmMessage` to its carrier record/slot/seq. Anyone who scrapes a sealed message re-publishes it into their *own* outbox with a doorbell pointer carrying the real sender's hash; it AEAD-opens and the ML-DSA signature verifies — a genuine-looking message at an attacker-chosen time. The sole defence, dedup-by-content-address, is soft local state, empty on reinstall / recovery-from-mnemonic / second device. **Fix direction:** bind a per-conversation/outbox identifier (and ideally a monotonic counter) into the signed input; specify dedup durability.
- **B3 (metadata) — world-derivable addresses are a targetable, stable-identity presence oracle. [DOWNGRADED + ADDRESSED — see § Revised direction.]** Harvest any identity pubkey, derive its key-record/doorbell addresses, `watch_dht_values`, and read the key-record `seq` cadence as a sleep/wake time series bound to a *permanent* ML-DSA identity, plus doorbell in-degree. **Correction (code-verified 2026-07-27):** the finding's premise "lobby identity is ephemeral, so this is the *first* stable-identity surface" is **wrong** — the lobby already broadcasts every member's full stable pubkey (sealed under a world-derivable key; `veilid_net.rs:339`, `public_room.rs:12,119,129`). So DM is not a novel exposure of *who exists*; what remained genuinely new was a *targeted, room-independent, always-on* presence probe on a stable identity. The **Revised direction closes even that**: presence rides the lobby (no DM presence advertisement), the key record demotes to a presence-independent static publish, and all post-first-contact addressing is `ss`-derived and pseudonymous. Residual: first-contact key-record *existence* is discoverable — accepted for alpha.
- **B4 (erasure) — the doorbell is a pre-consent read-amplification primitive.** Because identity is proven at the outbox (not the doorbell), collection is forced before the accept/decline gate: an attacker fills all 256 doorbell subkeys with *correctly-sealed* pointers to noise records for ~512 writes; the victim's first sweep then does 256 × (`open_or_create` ~6–10 s, inline-serial under the margin-2 limiter) ≈ 25–43 min of wedged actor loop + 16 k gated GETs — the exact read-lane starvation WB-5.1 exists to prevent, reachable unauthenticated. Fork 3.1's "one cheap decapsulation" bound is inverted (only AEAD-*failing* entries are cheap).
- **B5 (erasure) — stop-on-presence certifies delivery on record B from liveness on record A.** Presence is observed in the *lobby*; the message lives in the *outbox*. Between re-seeds the outbox value can evict (no TTL, capacity-only), the record session can go dead-silent, or a GET can be lossy — and the sender, seeing lobby presence, stops re-seeding and marks `presumed-delivered`. This reintroduces the exact silent-loss-with-false-delivered failure Fork 1C rejected A to avoid, one layer down. Probability rises with recipient offline duration — the design's target case.

### MAJORs

- **M1 (crypto) — key-record rollback by re-writing an older *authentic* record.** World-*derivable* owner means anyone can *write*, not only erase. Replaying a correctly-signed `version:1` blob with a higher subkey `seq` downgrades every cold reader (new senders, reinstalls, second devices) — the highest-verified cache defends only warm readers. "Forgery impossible, erasure is DoS-only" is false; replacement-with-older-authentic is a third option. (BLOCKER if rotation is ever a compromise response.)
- **M2 (crypto/erasure) — a losing `set_dht_value` re-propagates the attacker's value and returns `Ok(Some)`.** Verified in veilid-core 0.5.7 (`set_value.rs:487-497,637-641`): on a contested subkey the honest sender abandons its own bytes, fans out the attacker's value, stores it locally, and returns success. The keep-alive *repairs the erasure in the attacker's favour*, and the outbox state machine has no "my write lost the race" state and consumes no return value. Also: `Ok(None)`/`allow_offline` ≠ network-durable (WB-5 §evidence, not carried here).
- **M3 (crypto/erasure) — "one slot per sender" is client convention, zero enforcement.** Every reader holds the world-derived doorbell owner secret, which under DFLT authorizes writing *every* subkey. An attacker writes 0..255 directly — whole-doorbell wipe/fill at 256 writes/cycle, no Sybil. Fork 3.2's spam bound holds only against conforming clients.
- **M4 (crypto) — `sender_pubkey_hash` is attacker-chosen (unsigned doorbell): block bypass + cache poisoning.** Block matches a field the writer controls → set it to a non-blocked hash and blocking is defeated at zero cost; or name a *trusted* correspondent's hash with an attacker outbox key to redirect the victim's resweep. No rule is given for a known-hash pointer with a different outbox key. Plus resweep amplification if a record registers before verification.
- **M5 (crypto/erasure) — doorbell pointer replay (no signature/timestamp/counter).** A scraped entry re-written verbatim is byte-identical to the sender's keep-alive (stable slot), resurrecting a declined request, defeating the 7-day give-up, and enabling a selective-freeze pin. Cross-recipient replay is correctly prevented (encapsulated to the EK); same-doorbell replay is not.
- **M6 (crypto) — UKS on the doorbell.** `DmKeyRecord` proves no possession of the DK for its published EK. An attacker signs a record advertising a *victim's* EK under the attacker's own identity; a sender's ciphertext then decapsulates for both. The message seal absorbs it (identities in the KDF), the doorbell seal (bare `ss`, constant AAD, no recipient binding) does not.
- **M7 (metadata) — the geometric backoff phase-locks the doorbell to the opaque outbox and violates WB-3 I6.** The schedule is deterministic and *unjittered*, so the two records fire in lockstep from one t0 — collapsing the outbox's address secrecy into a timing derivation, and creating exactly the stable cross-record phase relationship WB-3 I6 forbids. So "WB-3 not amended" is false in effect. **Fix:** per-emission jitter (WB-1.2 pattern), independent per-record.
- **M8 (metadata) — outbox messages are unpadded.** Padding is specified for the doorbell and forgotten for the message; body length, message count, and inter-message intervals leak to any outbox co-host. WB-0's length-oracle rationale applies. **Fix:** pad `DmMessage` to a bucketed constant.
- **M9 (metadata) — sender-secret slot is a durable per-correspondent pseudonym.** The secret defeats the *candidate-set naming* attack (correct, load-bearing) but not *tracking*: a co-host logs `(slot, seq, timestamp)` over months → a stable partition of R's unknown-correspondent set with first-seen, cadence, cessation — a contact graph in shape. Named for presence in the WB doc; not carried here.
- **M10 (metadata) — the first/established stopping split timestamps tie-formation.** First contact re-seeds through presence events; established stops at the first — the transition is observable as an edge-creation event with timestamp, key-free.
- **M11 (erasure) — recipient-side state loss permanently orphans every established correspondence, silently.** The outbox owner is derivable only by the sender; the recipient learns it only from the (now-evicted) doorbell pointer. Reinstall/second-device/recovery re-derives identity but not reachability; senders keep stopping on presence and reporting delivered. A supported user action → permanent one-way silent loss; the sender-side loss is fine (re-derives from its own seed) — an asymmetry the design never states.
- **M12 (erasure) — WB-2 breach on the happy path.** 30 pending messages (10 each to 3 offline correspondents) ≈ 1.75/min of DM re-seeds in the dense backoff head, plus keep-alives → ~3.75–4+/min against the 4/min ceiling, from one ordinary session. Breaching WB-2 is what caused the write storm that starves the re-seeds themselves — self-amplifying.
- **M13 (erasure) — WB-5.1 floor-lane census silently invalidated.** Up to 64 pending logical ids per correspondent vs the frozen "~12 total" premise → floor-lane worst-case drain rises from ~40 min to ~35 h in a 200 s regime; in the daily tail, re-seeds enqueue faster than the capacity-1 floor drains. Classification is unchanged but a frozen *quantitative* premise is not. (Also: the doc says logical id = "the message (slot)" — those differ under `seq % 64`; taking message-identity breaks I3 supersession.)
- **M14 (erasure) — key-record eviction probability is monotone in recipient offline duration, and >7 days first contact is structurally impossible.** The `dflt(1)` key record's only keeper is the offline party; retention is capacity-only; `awaiting-key` gives up at 7 days. The identities most needing offline delivery have the least-refreshed key records. The design hands every reader the ability to keep the record alive (world-derivable owner, self-verifying blob) and uses none of it.
- **M16 (erasure, code-verified — NEW) — stop-on-presence is trippable by presence *replay*, so the DM design silently inherits the un-ratified #78 anti-replay gap.** Presence has no nonce/sequence anti-replay — only a 300 s freshness *window* (`presence.rs:135` `REPLAY_FRESHNESS_PAST`, and `:133` flags the nonce scheme as "an OPEN design call flagged for ratification", #78). The lobby record is world-writable (world-derivable owner). So an attacker captures one recent recipient beacon (broadcast, world-readable) and replays it after the sender publishes → the sender's stop-on-presence fires → re-seeding stops → the (actually-offline) recipient never collects → the outbox evicts → undelivered, sender believes delivered. No signature forgery. **The DM design makes presence a load-bearing delivery-correctness signal while the presence layer treats replay-hardening as unfinished** — at minimum a declared hard dependency on #78, more likely a different collection signal.
- **M11 code-grounding (erasure, verified):** the contact cache is not derivable from the mnemonic (`storage/seeds.rs:329-342` initializes every collection empty; `first_start/orchestrator.rs:275-279` mints a fresh `profile_id` so even a copied blob is unreadable). ISC-C44 is `[ ]` unbuilt. After a legitimate recovery the recipient holds zero outbox keys, established senders have stopped writing/re-seeding the doorbell, and there is no re-bootstrap path — permanent silent one-way loss on the identity model's own advertised flow. This is the sharpest instance of the write-authority-vs-availability root.
- **M15 (erasure) — empty outbox records enter the CRSH health-tracked resweep and may self-DoS.** An idle outbox gets no re-seed → goes network-absent → the consumer-route-self-heal detector may fire repair (`close`+`open`+`watch`+64-GET) on records healthy-by-design. Benign vs self-inflicted turns on whether a force-refresh GET against an absent record returns `Ok(None)` (no repair) or `Err` (repair) — unspecified; population scales with contact count.

### MINORs (recorded)

- **m1 (crypto) — DM signature drops `sender_pubkey`**, the sole departure from the repo's provenance pattern (`cot.proto` `RoomMessage`/`ShareAnnouncement`/`MemberHeartbeat` all bind it) — DSKS setup; fix with B1.
- **m2 (crypto) — `sent_unix_ms` is advisory, nothing enforces freshness**; amplifies B2/M5. Recency-sort UI surfaces a replayed old message at top.
- **m3 (crypto) — `version` rotation is currently underivable**: `kem_ek` derivation is KAT-pinned with no rotation index (`keys.rs:307-320`), so one mnemonic → one EK forever; the newer-wins machinery is inert until a rotation counter is added to the HKDF info (a pre-freeze protocol-string decision).
- **m4 (crypto) — domain-string hygiene**: `daemonseed/dm/*` is a clean namespace (no collision/shadow — verified against the full registry), but `daemonseed/dm/msg/v1` triples as HKDF-info + AAD + signature-domain (the repo splits these; e.g. `.../aad/v2` vs `.../provenance/v2`), and the doorbell AAD binds neither recipient nor record (the M6 gap). **State a nonce-derivation rule for all three seals** — ML-KEM implicit rejection means garbage never fails decap (B4 cost), and a cached-`ss` doorbell rewrite risks AES-GCM nonce reuse.
- **m5 (metadata) — block is third-party-detectable** (writes continue, resweep GETs cease); **schema fingerprints are role-revealing** (`dflt(256)`~2 KiB = doorbell, `dflt(1)`~6.2 KiB = key record — enables B3 over a random sample with zero targeting); **key rotations are publicly timestamped**.
- **m6 (erasure) — false `undelivered`** on the modal read-but-quiet first contact, and `undelivered` conflates five distinct facts (suppression / eviction / declined / read-quiet / old-build) into the one availability signal.
- **m7 (erasure, NEW correctness) — the re-seed vs "fresh encapsulation per message" clauses are in tension.** Content-address dedup (the reason no ack is needed) requires every re-seed of a pending message to emit *byte-identical* sealed bytes; "fresh encapsulation per message" + a signature over `sent_unix_ms` means a re-seed that re-encapsulates produces a new content address → the recipient sees a duplicate, not an idempotent re-seed. **Resolve by stating explicitly: encapsulate + seal once at compose, persist the sealed frame in the outbox state, re-seed byte-identically** (never re-seal per re-seed).
- **m8 (erasure) — the schema-derived guard fix (§Schema-sizing #1) must cover every new schema, not just the chat ring:** the constant `APP_MESSAGE_CAP=32768` guard is wrong for the doorbell (`dflt(256)`, cap 4096) and any `dflt(128)` presence record (cap 8192) too; a copied constant guard lets an oversized write pass locally and be silently rejected by Veilid ("value too big") — presenting as nondelivery.
- **Aside:** `keys.rs:90,95` doc-comments state ML-DSA-87 sizes wrong (pk listed 4896 — real 2592); the DM doc used the correct figures, but a builder sizing from those comments will err. Fix the comments.

### What the panels tried and could NOT break (the surviving core)

Cross-pair `DmMessage` replay resistance (both identities in the KDF info — holds, it was just mistaken for general anti-replay); outbox authorized-*erasure* resistance (sender-only owner derivation genuinely holds — it just doesn't imply availability or insertion resistance); key-record *forgery* under another identity (signature covers `domain‖pubkey‖version‖ek`, fixed-length, unambiguous); schema-squatting (schema binds into the record key); doorbell slot enumeration by a co-host (sender-secret rooting defeats candidate-set naming — correct and load-bearing); domain-string cross-lifting (no collision with any existing label); false-dedup on repeated text (fresh encapsulation per message). The **fork verdicts** — C over A on the *authorization* axis, static-KEM over handshake, the WriteClass classification, offline store-and-forward as the shape — survive; what fails is the *mechanism* built under them.

## Revised direction (2026-07-27, post-adjudication — caraka + Sanjay) — pseudonymous ratchet + lobby presence

> This is the iteration *after* the adjudication. It **supersedes the § The three records model on the identity/metadata axis** and **largely dissolves reopened decision #1.** It is a design *direction*, not a re-freeze — it wants its own panel re-run. Decisions #2 (first-contact availability) and #3 (crypto construction) remain; #3 now interacts favorably.

**The reframe (code-verified).** A user's long-term pubkey has no net privacy — the lobby already broadcasts it. Lobby presence beacons and lobby chat are sealed and signed with the **stable** identity key (`crates/daemonseed-gui/src/veilid_net.rs:339` "the stable identity key"; `MemberHeartbeat.sender_pubkey` / `RoomMessage.sender_pubkey` = the full ML-DSA-87 key), under a content key derived from **public inputs only** (`crates/daemonseed-core/src/public_room.rs:12,119,129` — family token + room name, "PUBLIC, not secret"). So anyone can derive the lobby key and read every member's full stable identity. The Veilid *node* key is ephemeral per launch; the *content-plane identity* is not. The privacy goal is therefore not to hide the key — it is to stop a third party from **linking a DM address or DM-channel identity to that key.** (This corrects finding B3, which inherited the write-budget doc's mistaken "lobby is ephemeral.")

**Identity layer — per-contact pseudonym, mandatory in-seal binding.** At first contact A presents a per-correspondent pseudonym key `P_A` and, *inside the KEM-sealed first-contact message* (openable only by B), a signature by A's long-term identity key over `P_A ‖ A's long-term pubkey`. B verifies the binding and learns `P_A ↔ A`; no third party sees inside the seal, so `P_A` is unlinkable to A for everyone but B. The binding is **mandatory, not optional** — an unbound pseudonym is unauthenticated and reopens impersonation/UKS, and the binding is what keeps the block list and the "known handle, new key" trust event working on the real identity behind the pseudonym. Scope, stated deliberately: this is unlinkability to **third parties**, not to correspondents — two people you DM each legitimately learn `↔ A`, so colluding correspondents can link you to yourself. That is unavoidable under mandatory binding and is the correct trade (the target is the uninvited observer).

**Address layer — shared-secret rendezvous, epoch-ratcheted.** After first contact both parties hold the KEM shared secret `ss`. The ongoing rendezvous address is `H(ss ‖ epoch)` — derivable only by the two of them, computable by no third party, not a function of either long-term identity in any observer-visible way. A co-hosting storage node sees an opaque address it cannot link to either party. **This improves on the relay-era RESUME** (`resume_addr = f(sort(both KEM pubkey hashes))`), which was derivable by anyone who fetched both key records — rooting the address in the *secret* `ss` instead of the public pubkey hashes closes that hole.

**Epoch ratchet — slow, forgiving, wide window (caraka).** `epoch` advances on a slow schedule, so the rendezvous address walks over time: an observer who correlated the pair at one epoch loses them at the next — transport/metadata **forward-unlinkability**. Optionally chain the *seal* key per epoch (`ss_{n+1} = KDF(ss_n)`, delete `ss_n` after the window) for approximate content forward secrecy — not hard PFS (each party retains the current window's key), but close enough: messages older than the retained window are unrecoverable on later compromise. The window is deliberately **wide and forgiving** — keep several epochs of keys live so a late-delivered (offline store-and-forward) message still opens; the ratchet trades a slice of PFS for delivery robustness, the right call for a store-and-forward medium. Epoch cadence and window depth are the two knobs, both generous by default.

**Presence — reuse the lobby, add nothing (caraka).** The stopping condition needs "has my correspondent been present since I published?" Both parties are in the default-pinned lobby, which already publishes each member's stable pubkey; each DM party learned the other's long-term identity at binding, so each recognizes the other in the lobby roster it *already sweeps* — a purely local lookup, no new record/write/watch. This **eliminates the DM-specific presence advertisement and the key-record presence oracle**: the key record demotes to a static publish (written once, cached forever after one fetch, re-seeded rarely on a fixed, presence-*independent* schedule against eviction), so polling it reveals at most "this identity is DM-capable," never an online/offline rhythm. Dependency: lobby presence (#77 generalizes it to circles); everyone is pinned to the lobby by default. Caveat: this picks a cleaner *source* for the stopping signal — it does not by itself make presence-based stopping *sound*; decision #2 replaces the guess with a real collection signal.

**What survives of the three-record model:** the **key record** (static, first-contact-only, long-term-identity-keyed — the irreducible cold-contact surface); a **first-contact channel** (doorbell-like, still world-writable/derivable — the residual of decision #2); and the **`ss`-ratcheted pseudonymous channel** replaces the per-pair sender-owned outbox for all post-first-contact traffic. The crypto construction B1 is *helped* — the pseudonym + binding ride inside the roomy first-contact seal, exactly where the identity material needed to move.

**Net on decision #1:** dissolved to a single residual — the first-contact key record is keyed on your long-term identity and its *existence* is discoverable ("X runs DM"). Everything after first contact is pseudonymous on both layers, ratcheting, and presence-free. Accepting the first-contact existence leak for alpha is now reasonable, not a blocker.

## What must be resolved before this can freeze (updated after the revised direction)

1. **~~The world-derivable-address oracle~~ — LARGELY DISSOLVED by the revised direction.** Reduced to accepting that a long-term identity's *DM-capability and first-contact address* are discoverable — nearly unavoidable for cold contact, and its steady-state activity oracle is closed (key record demoted to a presence-independent static publish; ongoing traffic pseudonymous). Residual sub-decision only: is the first-contact *existence* leak acceptable for alpha (yes, recommended), and does the first-contact record itself want slow epoch rotation (see decision #2's replay defense).
2. **Availability erasure of first contact — STILL OPEN (round-2 re-panel reopened it; the "resolved" claim was premature).** The `ss`-channel-as-ack relocates the eviction race onto the ack rather than dissolving it (E1), "any peer write" is not collection proof (E2), and A+B+C bound spam/CPU, not the world-writable wipe (E5/E6). See § Re-panel round 2. The honest floor: reliable collection confirmation is impossible on a no-TTL eviction-only substrate — the design must adopt best-effort delivery with truthful advisory states and never claim "delivered."
3. **The crypto construction — OPEN and NOT "mechanical."** Round 2 showed the framing was wrong. Beyond B1/B2/M4/M6: (a) **no forward secrecy is achievable with a static mnemonic-locked KEM key** — one `ss` forever, regenerable from harvested `kem_ct` + DK compromise, and raw `ss` must be retained for addressing, so the "delete after window" ratchet is theatre against harvest-now-decrypt-later (crypto F1); (b) **no nonce/AAD rule is stated for any seal** — AES-GCM nonce reuse is catastrophic and there are now ≥4 seal kinds (F9/F10); (c) key-record UKS enables confidentiality misdirection (F4), and the pseudonym binding lacks proof-of-possession of `P_A` (F5). Getting FS at all requires a rotating/ephemeral-KEM key layer (Signal-style PQ ratchet), which reintroduces machinery this design deleted — a scope decision, not a mechanical fix.
4. **Budget conformance (M7, M8, M12, M13).** Jitter the schedule (M7), pad the message (M8), re-derive the WB-2/WB-5.1 arithmetic against realistic pending-message counts (M12, M13); if the arithmetic doesn't close, the backoff schedule or a per-user pending cap is the lever.
5. **Recovery / multi-device reachability (M11).** The recovery-phrase model recovers identity but not DM reachability. Decide: accepted alpha limit (documented), or a re-bootstrap signal. (The revised direction does not fix this — the ongoing `ss`/pseudonym/contact state is still at-rest-only and lost on restore.)

## Decision #2 exploration — first-contact availability (the residual defensive work)

Decision #1 shrank to first contact; decision #2 is *also* concentrated there. The first-contact channel is irreducibly world-derivable (cold contact needs an address derivable from your public identity) **and** world-writable (a stranger with no prior shared secret must be able to write it), so it inherits: read-amplification flooding (B4), erasure/wipe (M3), pointer replay (M5), and an unsound stopping condition (B5, M16). The ongoing channel is now safe (pseudonymous, `ss`-derived); the whole fight is first contact.

**The load-bearing structural fix — the `ss`-channel IS the collection signal, so stop guessing from presence.** The ongoing pseudonymous channel is a shared rendezvous both parties write to. So "did they collect M?" is answerable directly: A watches the shared channel for B's next write — the accept, a reply, an epoch advance, or a minimal high-water "seen" marker. This is a **real** ack, not a presence guess, and — because it rides the unlinkable `ss` address — it leaks nothing to third parties, which is exactly why the earlier "an ack is a tombstone in a different hat" objection dissolves *here*: on the pseudonymous channel there is no third-party-visible tombstone. Adopting it:

- **Replaces presence-based stopping entirely**, which **dissolves B5 (eviction race), M16 (presence-replay trip), and the presence-soundness hole in one move** — the sender stops on a real collection signal, not a lobby guess.
- **Reduces the state model to three truthful states** — *on-DHT* (published, re-seeding), *peer-reachable* (seen in lobby — advisory only, never "delivered"), *confirmed-collected* (peer wrote back on the shared channel). "Delivered" is asserted only on the third. This fixes M6/m6 (five-facts-collapsed-to-one).

That leaves only *first-contact* flooding/erasure/replay. Graded options, cheapest to most restrictive:

- **A. Self-contained first-contact entry — kills the read-amplification (B4).** B4 exists only because identity is proven at the *outbox*, forcing a fetch before the accept/decline decision. Put the whole first-contact payload — `kem_ct` + sealed{ pseudonym, long-term binding sig, first message body } — **in the entry itself**, so accept/decline is decided from that one entry with no forced second fetch; a garbage entry then costs one decap + one AEAD attempt, full stop. Sizing: the binding sig (4627 B) + pubkeys dominate (~8–11 KB), over the `dflt(256)` 4 KB cap — so the first-contact record is a larger schema (`dflt(64)` = 16 KB/subkey, 64 concurrent unknown senders), fewer slots but no amplification; slot count is bounded by B anyway.
- **B. Proof-of-work filter on first-contact writes — bounds flooding.** Honest recipients ignore any first-contact entry lacking a valid PoW bound to `(recipient_id, epoch, entry-hash)`. Veilid can't enforce it, but the DoS bites at the *recipient's* processing, and a client-side filter puts the cost there: an attacker must burn PoW *per entry* to make the recipient consider it — free flooding becomes CPU-bounded flooding. Cheap, no product-claim change, composes with A (PoW-gate the 64 slots).
- **C. Capability-token first contact — closes the open flood, changes the product claim.** Cold contact already has an out-of-band step (you learned the pubkey *somewhere*). Fold a recipient-issued token into it: a first-contact write must carry a token the recipient handed out (card, QR, existing channel) to be processed. Only token-holders can knock — *eliminates* open flooding and is arguably better spam control, at the cost of "anyone with my pubkey can DM me cold" becoming "anyone I gave a token." The high-assurance end; likely a per-identity policy knob.

**Replay + wipe of the first-contact entry (M3/M5):**
- *Replay:* bind the recipient's current first-contact **epoch** + a timestamp into the entry's signed input; the recipient rotates its first-contact record slowly and ignores stale-epoch entries — a replayed old entry is rejected. (Same epoch primitive as the `ss`-ratchet, reused.)
- *Wipe:* a sustained wiper still wins against re-seeding, but the window the entry must survive is now just "one recipient sweep," because the `ss`-channel ack ends re-seeding the instant the recipient collects. With PoW/token bounding the attacker's write rate and the honest state model never falsely reporting "delivered," a wipe degrades first contact to "not yet delivered" (true) rather than "silently lost while showing delivered" (the failure that mattered).

**Irreducible:** cold first contact from a bare public identity is floodable to *some* degree — the lever is cost (PoW) or admission (token), never elimination. Honest posture: first contact is best-effort under active attack, the system *says so* rather than faking delivery, and the ongoing channel — where real conversations live — is exposed to none of it.

### Decision #2 — ~~RESOLVED~~ REOPENED by the round-2 re-panel (see § Re-panel round 2). Adopt A + B + C together, on three axes

A, B, and C are not alternatives — they are three orthogonal axes and all three ship:

- **C = admission** (who may *start* a conversation), **B = rate** (how fast anyone admitted may knock, PoW), **A = shape** (each knock is single-fetch, no amplification). C-on does not make A/B redundant: a regretted token-holder is still rate-bounded by B, and every valid knock is still single-fetch by A.

**Two orthogonal controls — do not conflate them:**
- **C (admission policy)** gates *new first contacts* only. On establishment an `ss` exists and C is forever irrelevant to that channel.
- **The block list** governs *existing channels*. Turning C back on after an open period stops new strangers; blocking cuts off specific past contacts. (Affordance: a "block everyone who contacted me during [window]" bulk action for the open-then-swarmed case, so cleanup isn't one-by-one.)

**Token design (concrete):** the invite token is `Sign_recipient(grantee_long-term_pubkey ‖ nonce ‖ expiry)` — **grantee-bound, one-time, expiring**, NOT a bearer secret (a bearer token posted in a semi-public lobby is interceptable and shareable, defeating the wall). It composes for free with the mandatory pseudonym binding: the first-contact entry proves its pseudonym is bound to a long-term identity, so the recipient's admission check is "is there a valid unspent token I issued to *that* identity?" The grantee is present under their long-term key in the lobby when they ask, so the recipient knows exactly whom to bind it to. Verifiable offline (signed by the recipient's own key), consumed by the first successful first-contact (after which the `ss` channel takes over and the token is never needed again).

**Grant delivery — not circular.** The token is sealed to the requester's *published key record* and dropped (lobby message or a one-shot sealed drop) — the recipient can always reach a requester whose key record is public, so granting a DM invite does not itself require an existing DM channel.

**Posture is a first-run choice, not a silent default.** At setup the user picks "Open to DMs from anyone" or "Invite-only" — respecting both the paranoid and the wild-guy consciously, and teaching the admission control at the one moment attention is on it. (A silent invite-only default risks reading as "the app is broken — I typed their handle, why can't I message them"; a silent open default gives away the protection the ethos wants. A conscious choice avoids both.) Changeable any time; the two-control model above governs what a later change does and does not reach.

**Advertise the policy in the key record.** One bit in the already-static key record — "invite-only" — lets a sender's UI say *"this user requires an invite"* upfront instead of the DM silently ageing to `undelivered`. Leaks the *policy* (low-sensitivity, not activity); converts a confusing silent failure into a clear next step.

**Make-or-break: the grant UX must be one tap.** C-on protects only if granting is frictionless — someone asks in the lobby, one tap seals + drops the token. If the flow is clunky, paranoid users disable C to make the app usable and lose the protection entirely. The security lives on that interaction, not on the crypto.

**Interop is per-recipient by construction:** each client enforces its *own* admission policy (who reaches *me*), so an open user and an invite-only user interoperate cleanly — a sender to an invite-only user without a token sees "requires an invite," never a silent drop.

**Net decision #2 status: the panel re-run REFUTED this "resolved" claim — see § Re-panel round 2.** The `ss`-channel-as-ack is not a reliable ack (its own value evicts, E1; "any peer write" ≠ collection, E2), and A+B+C bound spam/CPU but not availability (the world-writable first-contact record is wipeable regardless of posture, E5/E6). Decision #2 is reopened, not resolved. What the re-run confirmed *does* hold is recorded below.

## Re-panel round 2 (2026-07-27) — the revised direction is ALSO not freezable

The revised direction was re-run through the same 3-lens panel (the check that should have run *before* marking anything resolved). All three lenses returned BLOCKER-class findings. The direction is a **real improvement** with a confirmed surviving core, but decisions #1 and #2 are *not* resolved and #3 is not "mechanical."

**Surviving core the re-panel could NOT break (genuine wins, banked):**
- **`ss`-gated write authority on the ongoing channel.** The `ss`-derived rendezvous owner secret is held only by the two parties, so a third party cannot write, forge, or replay messages *or* acks there — a real improvement over the world-derivable doorbell (M5) and world-writable presence (M16). *This is the load-bearing win and it holds.*
- **Grantee-bound invite token** resists forgery/interception/transplant/DSKS (ML-DSA folds signer+verifier keys into `mu`); bearer-in-lobby interception correctly defeated.
- **Pseudonym third-party unlinkability + M9 (per-correspondent tracking) dissolved + M10 (tie-formation) closed + lobby-recognition emission-free (F6)** — all hold *for the ongoing channel in isolation*.
- **Presence-replay false-delivery (M16)** genuinely closed against third-party forgery.

**BLOCKER-class findings (why it can't freeze):**

*Metadata — the address-unlinkability claim is capped, not achieved (the world-readable lobby is a free side channel):*
- **F1 (MAJOR/BLOCKER-of-claim) — rhythm intersection.** A Level-C node hosting `H(ss‖epoch)` reads the world-readable lobby (which publishes every member's online windows) and intersects the channel's activity-timed writes against lobby members' online windows → de-anonymizes *both* opaque endpoints to real identities. Pseudonym/ratchet protects the address in isolation; it doesn't stop joining it to the lobby's identity-plane by timing.
- **F2/F3** — the first-contact→`ss` handoff binds the channel to B's identity at birth; the epoch ratchet doesn't defeat a Sybil observer matching old→new addresses by traffic-shape (my wide window makes it worse by keeping epochs concurrently active). **F5** — the key-record demotion doesn't remove the presence oracle (an offline process can't re-seed, so re-seed clustering is still an online rhythm). **F7** — invite-only leaks the contact edge *in the clear* via the lobby grant handshake (the paranoid posture leaks a graph edge that open mode doesn't).

*Erasure — the ack is not an ack; the adjudication's own root (retention, not authority) is still unpaid:*
- **E1 (BLOCKER)** — the ack has its own eviction race: the recipient writes it once and goes offline, nobody re-seeds it, it evicts before the offline sender reads it → the sender re-seeds a *collected* message to give-up.
- **E2 (BLOCKER)** — "any peer write" ≠ collection: the shared channel carries the peer's own pending traffic / keepalives / epoch advances, none of which mean they surfaced my message → false "confirmed-collected."
- **E5/E6/E7** — A+B+C bound spam/CPU, not availability: the world-writable first-contact record is wipeable/floodable from the target's pubkey alone regardless of open/invite-only (PoW gates the recipient's CPU, not the Veilid-level write authority; the token check runs *after* the expensive decap+verify). C, the "high-assurance" control, buys zero availability. **E8** — the epoch is reused for opposite-cadence purposes (slow for robustness, fast for anti-flood) → precomputable PoW flood. **E9** — epoch/offline desync → permanent silent channel loss on the *established* channel (no re-bootstrap).

*Crypto — no real FS, and the seal spec is unwritten:*
- **F1 (BLOCKER of the FS claim)** — the epoch ratchet gives NO forward secrecy. A static mnemonic-locked KEM key means one `ss` forever, regenerable from a harvested `kem_ct` + a future DK compromise; and raw `ss` must be *retained* for addressing, so "delete after a window" cannot delete the secret that matters. Harvest-now-decrypt-later — the project's entire PQ raison d'être — fully recovers a "ratcheted" channel on endpoint/DK compromise. Real FS needs a rotating/ephemeral-KEM ratchet, which reintroduces deleted machinery.
- **F2** — "epoch advance = ack" is unsound (a time-driven roll is not evidence of reading); stale-read false-stop. **F4** — key-record UKS enables a first-contact confidentiality misdirection. **F5** — the pseudonym binding proves possession of the *long-term* key but not of `P_A` → authorship transplant. **F9 (BLOCKER-adjacent)** — no nonce-derivation rule for ANY of the ≥4 new seal kinds (AES-GCM nonce reuse is catastrophic). **F10** — AAD separation not carried to the new seal kinds. **F11** — `H(ss‖epoch)` written as a bare hash where the codebase always uses domain-labelled HKDF.

**The two hard structural truths the re-panel forced out (substrate properties, not design bugs):**
1. **Reliable collection confirmation is impossible on a no-TTL, eviction-only DHT with no always-on node.** Every stop-signal (presence, ack) is a heuristic that can be wrong, because any confirmation record is itself evictable. The honest posture is **best-effort delivery with truthful advisory states — never claim "delivered."** A guaranteed-delivery story needs a pinning/availability node (out of MVP, D1).
2. **No PFS is achievable with a static per-identity KEM key.** The ratchet was theatre. Real forward secrecy requires a rotating/ephemeral-KEM key layer (a PQ double-ratchet), which is a substantial redesign of the key layer, not a bolt-on.

**Round-2 verdict:** the revised direction is the right *direction* — `ss`-gated ongoing-channel authority is a genuine, banked win — but it is not a freeze. #1 is capped by the lobby side-channel (F1), #2 is reopened by the ack's non-durability (E1/E2) and the unaddressed world-writable wipe (E5/E6), and #3 is not mechanical (no-FS F1, unwritten nonce/AAD spec F9/F10, binding gaps F4/F5). The next iteration must first make **scope/ambition calls** that are above a build — best-effort delivery vs a pinning node; no-PFS vs a key-layer redesign; unlinkability-vs-lobby vs cover traffic — and only then write the concrete crypto construction before a third panel. Fork verdicts and schema facts still carry forward unchanged.

## Committed decisions (2026-07-27, caraka — post round-2) — the ambition line

The round-2 scope/ambition calls are made. These convert two of the three "hard limits" into committed work.

### D-PFS — take on a post-quantum ratchet key-layer redesign (committed)

"No PFS" is the wrong landing for a pure-PQ project, so the static-KEM key layer is replaced by a PQ ratchet. Shape:

- **Two chains.** A per-message **symmetric chain** (`CK_{n+1} = HKDF(CK_n)`, message key `MK_n = HKDF(CK_n)`, **delete `CK_n`/`MK_n` after use**) gives forward secrecy cheaply, every message. An **asymmetric KEM ratchet** advances on each round-trip: the replying party ships a fresh **ephemeral ML-KEM-1024** public key, the peer encapsulates to it → new root secret → new sending chain — giving post-compromise healing. Async degradation is the standard double-ratchet one: per-message FS is immediate; post-compromise recovery lags until the next reply.
- **The F1 fix — decouple addressing from the deletable seal-key chain.** The rendezvous **address chain** derives from a retained **address root `AR`** (`addr_epoch = HKDF("…/dm/addr/v1", AR ‖ epoch)`); the **seal keys** derive from the ratcheted, forward-deleted chain. Both are seeded from the initial `ss0` at channel start, but only `AR` is retained. Compromise of current state then reveals addresses (metadata — past+future) and the *current* message chain (current message + until the next KEM-ratchet heals), but **not deleted past message keys**. Honest property: **content forward secrecy holds; address-linkability is not forward-secret** (addresses are metadata, and no ratchet hides metadata from an endpoint compromise). State exactly this — no overclaim.
- **The cost to design around:** ML-KEM EK/CT are ~1568 B each, so every KEM-ratchet step is kilobytes on a 16 KB-subkey DHT under a tight write budget. Ratchet cadence vs write budget is the tuning axis (symmetric steps are cheap; KEM steps are the expensive ones, so heal on round-trips, not per message).
- **Frontier note:** a fully-PQ *continuous* ratchet is not widely deployed (Signal's PQXDH is PQ only on the initial handshake; its ongoing ratchet is still classical). This is real design work, appropriate to the project's thesis.

### D-DELIV — fail-safe ack handshake + generous ignorant hosting; pinning node rejected; overlay deferred (committed)

Corrects the round-2 overclaim that "reliable collection confirmation is impossible" — it is impossible only if you *stop on a weak positive signal*. Fail-safe fixes it:

- **Default not-delivered; confirm only on a genuine ack.** The sender keeps best-effort re-seeding and flips a message to *confirmed* only on an **authenticated monotonic high-water** ("I have collected up to seq S"), written on the `ss`-channel — unforgeable because only the two parties hold the channel owner secret (verified: Veilid rejects any write where `writer != owner`, `schema.rs:60,83`). This converts E1/E2 from *silent loss + false-delivered* into *extra re-seeding until convergence* — an eviction now only **delays and costs writes, never loses and never shows a false "delivered."** The one true-loss case (message evicts AND sender gone forever before recipient ever collects) is reported honestly as "not confirmed," so the UI is never *wrong*.
- **Two-sided re-seed, self-terminating.** Sender re-seeds a message until high-water ≥ its seq; recipient re-seeds its high-water while it still sees unacked messages; when the sender stops (ack seen), the message evicts, the recipient stops seeing it, and stops acking. Fixes the E3 ack-of-ack regress by mutual observation. Epoch advance is **never** an ack (F2).
- **Availability = generous ignorant hosting, no dedicated node.** Every Veilid node already stores records near its key ID; clients simply become **more generous storage nodes** (raise the remote-record-store limits — the `remote_max_records=64` dial). Sealed content, opaque keys, proximity-selected → zero-knowledge, no chokepoint, no permanent infra (dodges the pinning-node surveillance/coercion concerns). **Bound (verified):** a non-owner cannot *refresh* a record (`writer != owner` rejected), so generous hosts *lengthen* the eviction window but do not *guarantee* retention once the owner stops re-seeding — which is why the ack handshake, not the swarm, provides correctness.
- **Rejected: a dedicated pinning/availability node** — it walks back the Veilid migration's no-always-on-dependency win and concentrates metadata into a single surveillance/coercion vantage.
- **Deferred: a daemonseed replication *overlay*** (clients store + re-serve sealed blobs outside the owner-write DHT) — it could both refresh and echo, but it is a new subsystem ("distributed relay reborn") with its own reduced-but-real surface. Only if the retention window proves too short in practice.
- **Not obtained: decorrelation cover from the swarm.** The owner-write rule that makes the ack unforgeable also blocks third parties from injecting write-timing cover on a channel they don't own — so F1 decorrelation must come from endpoint cover traffic (expensive) or stay an accepted cap. This stays under the unlinkability posture (decision #1's residual), NOT solved here.

### The residual ambition call still open

- **Unlinkability vs the lobby (F1).** Still capped: activity-timed DM writes are rhythm-correlatable to lobby-published online windows. Options remain: accept-and-document for alpha (recommended given the ongoing channel is otherwise pseudonymous), endpoint constant-cadence cover traffic (expensive, WB-budget hit), or reduce lobby co-residence. **Not yet decided.**

## Concrete crypto construction (DRAFT v1 — 2026-07-27, for the third panel; NOT frozen)

> First concrete pass, written so a panel has a fixed target instead of a direction. Every seal names its key, nonce, and AAD; every signature names its signed input; every derivation is a domain-labelled HKDF, never a bare hash/concat. **Sub-decisions flagged `‹OPEN›` need caraka or a panel.** This supersedes the sketch-level derivations scattered above.

### Primitives & identities

- **Primitives:** ML-KEM-1024 (KEM; EK/CT 1568 B), ML-DSA-87 (sig 4627 B, pk 2592 B), AES-256-GCM (96-bit nonce), HKDF-SHA384, SHA-384. All from oxicrypt.
- **Long-term identity (mnemonic-derived, static):** ML-DSA sign keypair `(S_lt, PK_lt)`; ML-KEM keypair `(DK_lt, EK_lt)`. Both already exist (`keys.rs`).
- **Per-contact pseudonym (random per correspondent, at-rest only):** a fresh ML-DSA sign keypair `(S_pc, PK_pc)` per correspondent — signs ongoing DM messages so wire authorship is not the long-term key. **Not** mnemonic-derived (so it is unlinkable and unrecoverable — accepted, tied to the M11 recovery limit).
- **Ephemeral ratchet keys:** fresh ML-KEM keypairs generated per KEM-ratchet step (D-PFS).
- **Domain-label namespace:** all HKDF `info` / AAD strings live under `daemonseed/dm/…`, length-prefixed, one distinct label per purpose (owner-seed ≠ seal-key ≠ addr-chain ≠ ratchet-KDF ≠ nonce ≠ each signature-domain ≠ each AAD). No label is a prefix of another. (F11)

### Nonce rule (global — closes F9)

Every AES-256-GCM seal carries its **96-bit nonce explicitly** in the envelope. Message keys are unique by construction (`MK_n` from a forward-advancing chain; `ss0`/ephemeral-KEM roots are single-use), so `(key, nonce)` never repeats. **Re-seed re-emits the byte-identical stored frame** (encapsulate+seal **once** at compose, persist the frame, re-seed verbatim) — never re-seals under the same key → no reuse, and it satisfies content-address dedup (closes the m7 tension). AAD is distinct per seal kind (closes F10).

### Key record (per long-term identity, `dflt(1)`, world-derivable)

```
DmKeyRecord {
  version:  u64                       // monotonic
  ek_lt:    [1568]                    // long-term ML-KEM EK
  invite_only: bool                   // admission policy advert (F7 leak accepted)
  sig:      ML-DSA_{S_lt}( "daemonseed/dm/keyrec/sig/v1" ‖ PK_lt ‖ LE64(version) ‖ ek_lt ‖ invite_only )
}
```
- Address owner seed = `HKDF("daemonseed/dm/keyrec/owner/v1", ikm = PK_lt)`. Readers cache highest verified `version`, never regress (rollback M1 = a cold reader accepts an old authentic record; residual accepted for alpha, or ‹OPEN› pin a floor via a second channel).
- **UKS fix (F4) is at the message layer, not here:** rather than prove DK possession (hard for KEM non-interactively), the first-contact body binds the *intended recipient* (below), so a misdirected ciphertext is rejected by the wrong recipient.

### First-contact entry (self-contained — option A; `dflt(64)`, 16 KB; world-writable)

```
FirstContactEntry {
  pow:      [..]                      // PoW over ("daemonseed/dm/fc/pow/v1" ‖ recipient_keyrec_addr ‖ LE64(epoch) ‖ SHA384(ct0 ‖ sealed))  (option B)
  ct0:      [1568]                    // ML-KEM.encaps(EK_lt_B) → (ct0, ss0)
  nonce:    [12]
  sealed:   AES-256-GCM(
              key = HKDF("daemonseed/dm/fc/seal/v1", ikm = ss0),
              nonce, aad = "daemonseed/dm/fc/aad/v1" ‖ recipient_keyrec_addr ‖ LE64(epoch),
              plaintext = FirstContactBody )
}
FirstContactBody {
  intended_recipient: PK_lt_B         // F4: B rejects if != own PK_lt
  PK_lt_A, PK_pc_A
  bind_lt:  ML-DSA_{S_lt_A}("daemonseed/dm/bind/lt/v1" ‖ PK_lt_A ‖ PK_pc_A)   // pseudonym↔identity
  bind_pop: ML-DSA_{S_pc_A}("daemonseed/dm/bind/pop/v1" ‖ PK_pc_A ‖ PK_lt_A)  // F5: PoP of P_A
  token?:   ML-DSA_{S_lt_B}("daemonseed/dm/token/v1" ‖ PK_lt_A ‖ nonce_t ‖ LE64(expiry))  // option C, if B invite-only
  ar_seed:  [32]                      // address-root contribution (see channel)
  eph_ek_A: [1568]                    // A's first ratchet ephemeral EK (so B can heal on its reply)
  seq: u64 = 0, sent_ms, body
  msg_sig:  ML-DSA_{S_pc_A}("daemonseed/dm/msg/v1" ‖ chan_id ‖ LE64(epoch) ‖ LE64(seq) ‖ sent_ms ‖ body)  // authorship under pseudonym; binds channel+epoch+seq (B2/F5)
}
```
- **Replay:** PoW binds `epoch`; recipient persists seen `SHA384(entry)` for the current epoch (within-epoch dedup, F8); the slow first-contact epoch rotation rejects cross-epoch replay.
- **Token one-time:** B persists spent `nonce_t` (residual: lost on recovery, F7/M11 — accepted).

### The ongoing channel & ratchet

- `ss0` (from first contact) seeds two independent roots: **`AR = HKDF("daemonseed/dm/addr/root/v1", ss0 ‖ ar_seed_A ‖ ar_seed_B)`** (retained) and the **send-chain root `RK0 = HKDF("daemonseed/dm/ratchet/root/v1", ss0)`** (ratcheted + deleted forward).
- **Address per epoch:** `chan_addr(epoch) = HKDF("daemonseed/dm/addr/v1", AR ‖ LE64(epoch))` → Veilid owner keypair for a `dflt(N)` shared record. Both parties derive it; both are owners (owner-write ⇒ third parties can't forge/erase — the banked win). `chan_id = HKDF("daemonseed/dm/chanid/v1", AR)`.
- **‹OPEN› epoch driver.** Wall-clock (`epoch = floor(now/period)`) → resync after any offline gap but a global synchronized reshuffle (metadata F3/F4) and a permanent-loss risk beyond the retained window (E9); interaction-counter → desync/no-passive-advance. Leaning wall-clock with a **wide window + several concurrent live epochs** for the store-and-forward tolerance, and accept the synchronized-reshuffle metadata cost. Needs a panel.
- **Message:** per message advance the symmetric chain (`CK_{n+1}=HKDF("daemonseed/dm/chain/v1",CK_n)`, `MK_n=HKDF("daemonseed/dm/mk/v1",CK_n)`, delete). Optionally carry `eph_ek` to advance the KEM ratchet on a reply. Seal under `MK_n`, explicit nonce, AAD `"daemonseed/dm/msg/aad/v1" ‖ chan_id ‖ LE64(epoch)`; `msg_sig` as above (binds `chan_id‖epoch‖seq` — kills carrier/cross-epoch replay B2/F2).
- **Ack (high-water):** `AckMarker { high_water: u64, sig = ML-DSA_{S_pc}("daemonseed/dm/ack/v1" ‖ chan_id ‖ LE64(epoch) ‖ LE64(high_water)) }`, sealed on the channel. Sender advances a message to *confirmed* only on a verified `high_water ≥ seq` (monotonic; a stale lower marker never regresses — F2). Epoch advance is not an ack.

### What this construction still does NOT resolve (for the panel)

- **Metadata F1** (lobby rhythm-intersection) — architectural, not a crypto-spec fix; stays the open unlinkability call.
- **Rollback M1** (cold reader accepts an old authentic key record) — accepted for alpha or needs a second-channel version floor ‹OPEN›.
- **Recovery M11** — pseudonym/`ss`/spent-token state is at-rest-only, lost on restore; `ss ∉ f(mnemonic)` by design, so only a re-bootstrap or re-first-contact restores reachability. Accepted-for-alpha or needs a re-bootstrap signal ‹OPEN›.
- **Epoch driver ‹OPEN›** and the **wide-window metadata cost** (F3) — panel input wanted.
- **Budget** — the two-sided ack handshake + KEM-ratchet kilobytes + generous hosting must be re-derived against WB-2/WB-5.1 (decision #4).

**Status: DRAFT — not frozen.** Next: caraka's calls on the `‹OPEN›` items + the unlinkability residual, then a third 3-lens panel against this construction, then (if it survives) the WB budget arithmetic, then freeze.
