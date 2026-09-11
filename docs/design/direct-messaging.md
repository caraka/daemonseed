# Direct messaging

## What the layer does

Direct messaging lets two daemonseed users who know each other's published identity hold a private conversation without ever being online at the same time. All traffic rides on records in the Veilid distributed hash table (DHT), the key-value store the application already uses. Each user publishes an **advert**, a signed record holding a current ML-KEM-1024 public key, and has a **drop**, a record anyone can write into, used only for first contact. A conversation is two **channel** records, one per direction, each written only by its owner and read by the other party. A sender writes a message into its own channel, keeps the ciphertext on disk, and rewrites it whenever the network loses it, until the recipient's collection cursor, published in the reverse channel, passes it. Message keys come from per-direction symmetric chains re-keyed by an ML-KEM encapsulation at the start of every conversational turn; every message key is deleted once used. A conversation's state is a few kilobytes on disk under the application's at-rest encryption.

## Founding claims

Each claim is an outcome, closed only by its own probe. Every component of the layer names the claim it serves; a component that names none is deleted.

- **FC1 Asynchronous.** Two people who are never online at the same time can hold a conversation. Probe: on the live network, A runs, sends, stops. B runs, collects, replies, stops. A runs, collects. At no moment do both processes exist. Refuted if any message fails to open on the other side.
- **FC2 Restart-safe.** A restart on either side, at any moment, loses no message and shows nothing false. Probe: FC1's run with a kill at every step boundary, resumed from the state left on disk. Refuted if a message fails to open, or a message shows as collected that was not.
- **FC3 Forward secrecy against a clone.** Someone who copies a user's device at time T reads nothing that user collected before T, nothing they sent before T, and nothing after their next reset. Probe: snapshot A's state directory mid-conversation and run it as an attacker against every record captured from the DHT. Pre-T and post-reset messages must fail to open. Control: the current-turn message before any reset must open.
- **FC4 First contact.** Knowing only someone's published identity, a user can start a conversation while they are offline, they find it when they return, and nobody can make the user accept a request under a name that is not theirs. Probe: A writes a first-contact request with B off. B starts later and sees the request attributed to A's verified identity. A request under a different key is not shown as A.
- **FC5 The network learns nothing.** Storage nodes holding every record of a conversation cannot read a message, cannot forge one, and cannot tell which two identities are talking. Probe: capture every record. Opening without keys fails. A slot write from a non-owner key is rejected. The identity public keys of both parties appear in zero bytes of any channel or drop record. Control: they do appear in the advert.
- **FC6 Small enough to hold in one head.** The layer is readable end to end by one person in a day. Probe: a line ceiling of 6,000 including tests, checked at every commit, and a check that every component names a founding claim. Crossing the ceiling stops the work until the ceiling is re-ratified with the reason written down, or the layer is cut back under it.

Inherited from the project rather than restated: no message content survives client closure (`ISA.md` ISC-C30). Probe: search the profile directory for any sent or received body after close; control: the ciphertext outbox is present.

## Substrate facts

Facts about Veilid the design rests on. File references are to `veilid-core` 0.5.7.

- A record is a set of numbered **subkeys** under one **owner keypair**. Only the owner key may write any subkey; anyone who can compute the record's **lookup key** can read it. The lookup key is a hash of the record kind, the owner public key and the schema (`storage_manager/record_key.rs:69-78`). An owner keypair may be derived deterministically from a secret or from a public hash and used as the writer; opening with that keypair suffices, and creation is needed only when the open reports the key unknown.
- An owner key derivable from public information means anyone can write, and therefore anyone can erase.
- There is no time-to-live. A storage node keeps at most 64 to 128 remote records and 128 to 256 MB and evicts the least recently touched; a read is a touch (`record_index.rs`). A value survives exactly as long as someone re-writes it.
- A record has up to 1024 subkeys; per-subkey size is min(32 KiB, 1 MiB / subkey count): 64 subkeys gives 16 KiB each, 256 gives 4 KiB.
- An ML-DSA-87 signature is 4627 bytes and its public key 2592; an ML-KEM-1024 ciphertext and public key are 1568 each.
- A plain read (`get_dht_value`) returns the same absent result for a never-written and an evicted subkey (`routing_context.rs:614`, `get_value.rs:538`). A writer reading its own record is served the local copy without the network being asked (`get_value.rs:78-86`), even on a forced refresh (`get_value.rs:274-278`). `inspect_dht_record` with `DHTReportScope::SyncSet` returns each subkey's local and network sequence numbers as if the local copy did not exist (`dht_record_report.rs:132-150`).
- Watch notifications are best-effort for readers who are not the writer (`routing_context.rs:722-729`). The design relies only on polling.
- Reads and writes go through safety routing by default (`routing_context.rs:49-61`, `get_value.rs:60-71`, `set_value.rs:62-78`), so a storage node does not see the originating node.
- A node sustains about 4 DHT writes per minute across everything the application does, a measured ceiling rather than an enforced limit. The application's write scheduler delays rather than drops and never coalesces or sheds chat-class writes; every write this layer makes is chat-class.
- Storage nodes may read, retain, replay or erase anything they hold.
- A full drop poll, measured on one desktop-class x86 core with oxicrypt 0.24.0 in a release build: 256 ML-KEM-1024 decapsulations in 26 to 29 ms and 256 ML-DSA-87 verifications in 77 to 83 ms. The verify count is an upper bound, since a hello that does not decapsulate is discarded before any signature check. On a mid-range mobile core the same work is estimated at three to six times slower, unmeasured.

## Records

### DHT records

| Record | Owner keypair | Written by | Layout |
|---|---|---|---|
| **ADVERT(B)** | derived by HKDF from B's identity public key, so anyone can compute it and write; readers accept only content signed by B's identity key | B, on weekly rotation and when the record is found missing or wrong | 64 × 16 KiB; subkey 0 holds the advert; subkeys 1 to 63 reserved for per-device keys |
| **DROP(B)** | derived by HKDF from B's identity public key; anyone can write or erase | each sender rewrites its own hello until collected; B erases collected hellos | 256 × 4 KiB; one hello per slot; an index parameter is reserved for more drops per identity |
| **CHAN(A→B)** | derived by HKDF from A's identity secret, B's identity public key and a conversation generation number; recomputable by any device holding A's recovery phrase | A | 64 × 16 KiB; subkey 0 control, subkeys 1 to 63 the message ring |
| **CHAN(B→A)** | the same derivation from B's side | B | same |

A channel's lookup key is disclosed only inside a hello, so its readers are the two parties and the storage nodes holding it.

- **ADVERT.0** — `serial ‖ not_before ‖ kem_pk (1568) ‖ ML-DSA-87 signature (4627)` over all of it with B's identity key, about 6.3 KB. The KEM keypair rotates weekly; B keeps the previous secret for one rotation period only.
- **DROP.slot** — `kem_ct (1568) ‖ AEAD_{k_hello}(lookup_key(CHAN) ‖ r) ‖ pow_tag`, about 1.7 KB, where `ss0` is the shared secret from encapsulating to the recipient's advert key and `k_hello = HKDF(ss0, "hello")`. Slot index is `H(r) mod 256`. `pow_tag` is a proof-of-work tag over `kem_ct ‖ r ‖ recipient identity` at difficulty zero: present and checked, free to produce.
- **CHAN.0 (control)** — from the writer, encrypted: the **channel opening** and the writer's `collected_cursor`. The opening is written once and holds the writer's identity public key (2592), its first ratchet KEM public key (1568), the advert serial it encapsulated to, and an ML-DSA-87 signature (4627) over the whole, about 9 KB.
- **CHAN.k, k = 1..63** — message `seq` lives in slot `1 + (seq mod 63)`: `header(n, m, seq, device_id, optional kem_ct 1568, optional kem_pk 1568) ‖ AEAD_{mk}(body)`. `n` and `m` are turn numbers; `device_id` is a reserved device identifier. Header up to about 3.2 KB, body up to about 12 KB.

### On-disk records

All under the application's at-rest AEAD.

- **SELF** — the current and previous advert KEM secret keys and the advert serial. Derived owner keypairs are recomputed from the identity, never stored.
- **CONV(peer)** — the peer's identity public key, both channel lookup keys, the conversation generation, ratchet state (chain roots, the two most recent own ratchet KEM secrets, the peer's latest ratchet public key), `send_seq`, `peer_collected` (their cursor over my messages), `my_collected` (mine over theirs), and the hello slot and `r` while a hello is outstanding.
- **OUTBOX(peer, seq)** — the exact ciphertext written to the slot. Deleted once the peer's cursor passes `seq`.

There is no message store. A received message is held in memory only while the application runs; a sent message persists only as the ciphertext in the outbox. On startup the user sees unread messages only.

## Keys and forward secrecy

```
identity ML-DSA-87 (long-term; signs adverts and channel openings)
 ├─ advert, drop and channel owner keypairs   (derived; DHT write authority only)
 └─ [nothing that decrypts]

advert ML-KEM-1024 keypair (weekly, independent random)  ── hello ──▶ ss0
ss0 ─▶ k_hello, R_A^0 (root of A's direction)

per conversation, per direction X→Y:
 R_X^n  = HKDF(R_X^{n-1}, ss_Y^m, ss_X^n)      root for X's turn n
 CK_X   = HKDF(R_X^n, "chain")                  sending chain
 CK_X, mk_seq = HKDF(CK_X, "step")              per-message key; CK advances, mk deleted after use
```

A **turn** is the first message X writes after having read a turn of Y's that X had not seen before, or X's first message ever. At turn start X generates a fresh KEM keypair `pk_X^n`, encapsulates to the latest `pk_Y^m` it has read, giving `ss_X^n` and `kem_ct`, derives `R_X^n`, and puts `n, m, kem_ct, pk_X^n` in that message's header. Later messages in the turn carry only `n, m, seq`. Y, on reading, decapsulates with `sk_Y^m`, recomputes `R_X^n` from its stored `R_X^{n-1}` and its own `ss_Y^m`, and runs the chain forward. A's root starts from `ss0`; B's root starts from B's first turn, encapsulated to A's first ratchet key as read from A's channel opening. The per-turn step is present from the first release.

Within a direction messages are totally ordered by `seq`, so there is no out-of-order delivery and no store of skipped keys. Across directions there is no shared root to disagree about, and every header pins the `(n, m)` pair it was derived from. When turns cross, both messages open, because each side keeps its two most recent KEM secrets until a message encapsulated to the newer one arrives.

Key deletion is strict: every per-message key is deleted after use, by the sender at write time and by the reader at read time. A retention window could later be added as a key-deletion policy alone, with no record change; it is not part of this design.

What the end state guarantees, by compromise event:

- **Identity key, at any time.** No message content is revealed, past or future; the identity key never derives a decryption key. The attacker can sign and write a forged advert and so impersonate the victim for new first contacts until the identity is revoked, which is out of scope here. Established conversations are unaffected.
- **At-rest state at time T, with a storage node retaining every ciphertext forever.** Messages the compromised party collected before T stay secret: their keys are gone. Messages it sent before T stay secret: only ciphertext is kept. Necessarily revealed: messages addressed to it and not yet collected at T, and the current advert KEM secret, hence any hello and first turn still on the DHT encapsulated to it, bounded by the weekly rotation.
- **After the compromise.** Once each party has completed one turn the other has read, later messages are secret again.
- **Reset, user-triggered.** Forces a new turn on the next send in every conversation and rotates the advert immediately. It does not cover the identity key.
- **Not protected:** live compromise of a running process.

## Flows

**First contact (A → B, B offline).**

1. A computes ADVERT(B)'s lookup key from B's identity public key, reads subkey 0 and verifies the signature.
2. A derives its owner keypair for CHAN(A→B), generates a ratchet keypair `pk_A^0`, encapsulates to B's advert key to get `ss0`, and persists CONV(B) before any DHT write.
3. A writes CHAN(A→B).0 (the opening) and CHAN(A→B).1 (message `seq` 0), and persists OUTBOX(B, 0).
4. A writes the hello to DROP(B) at `H(r) mod 256` and reads it back once; if another value is there, A picks a new `r` and rewrites.
5. A polls the hello slot and its own drop on its normal schedule and rewrites anything found evicted. If B's advert key changes before the hello is collected, A re-encapsulates to the new key and rewrites the hello and the first-turn slots.

**Collection (B, whenever it next runs).**

1. B reads DROP(B). For each non-empty slot B checks the tag and tries decapsulation with the current and the previous advert secret. Failures are discarded silently.
2. Success yields the CHAN(A→B) lookup key. B reads subkey 0 and verifies A's signature over the opening, which binds B's advert serial, so the hello cannot be redirected. B now knows A's identity and applies the rule under *A hello from a known identity* below; the steps that follow are for an unknown identity the user accepts.
3. B persists CONV(A), reads the ring, decrypts from `seq` 0, advances `my_collected`, and deletes each `mk` as it is used.
4. B erases the hello slot. One write; hygiene, not the acknowledgement.
5. B accepts by writing a hello back: B derives its own owner keypair for CHAN(B→A), writes CHAN(B→A).0 with its opening and cursor, and writes a hello naming CHAN(B→A) into DROP(A), encapsulated to A's advert key. If B replies at once, the reply is turn 0 of B's direction and carries the cursor, so the control write is skipped.

**A hello from a known identity.** A verified hello is handled by the identity that signed its channel opening:

- From a blocked identity: dropped silently.
- From an identity with which the reader has an outstanding first contact of its own: it is the acceptance. The reader records the lookup key in its CONV record for that peer, reads the peer's cursor and any reply, and erases the slot.
- From an identity with which an established conversation already exists: surfaced to the user as that correspondent having started over, for explicit accept. On accept the reader tears down the old conversation by the delete flow under *Delivery*, and every message still outstanding to that identity ends in a distinct "correspondent started over" state.
- From an unknown identity: a contact request, for explicit accept.

**Ordinary message, recipient offline for a week.** Sender: derive `mk`, persist OUTBOX and the advanced `send_seq`, write the slot, delete `mk`. One write. The sender's poller rewrites from OUTBOX if the slot is evicted. Recipient, whenever it next runs: reads the ring, decrypts, and writes its cursor, inside a reply or as one control write per collection batch.

**Reply.** B's first message after reading A's turn starts a new turn: fresh `pk_B^1`, `kem_ct` to `pk_A^n`, new `R_B`, written to CHAN(B→A). A, later, reads it, updates `R_B`, and deletes `sk_A^{n-1}` once a message encapsulated to `pk_A^n` has been seen.

**Restart at any point.** Every step above persists state before the DHT write it enables and never mutates ratchet state after a write. On launch the layer reloads CONV and OUTBOX and rewrites any outstanding slot that differs from OUTBOX; rewrites are byte-identical, so a crash between "write" and "persist" is harmless, and a crash between "persist CONV" and "write hello" resumes at step 3. Reader-side chain keys are derived on read, so a crash mid-read re-derives the same `mk`.

## Delivery

The **cursor** a reader publishes is the count of messages it has collected contiguously from `seq` 0. A message is **collected** when the peer's cursor, read from the reverse channel's control subkey or from any message header, exceeds its `seq`. Until then the sender rewrites the slot whenever it detects eviction.

The ring holds 63 slots. If `send_seq − peer_collected ≥ 63` the API refuses new messages with a distinct backpressure error rather than overwriting an uncollected slot.

The protocol never gives up: a message is outstanding until the recipient's cursor passes it. Polling of an outstanding slot backs off to daily after seven days. The user interface shows how long a message has been uncollected and nudges at a configurable threshold; nothing is torn down automatically, because the protocol cannot distinguish a dead identity from a long absence.

Deleting a conversation is the sender-side teardown: erase the own channel record, optionally after writing a "closed" marker in its control subkey, drop local state, stop polling. Re-establishment happens only by a fresh hello, which the deleting side treats as a new first contact under the next conversation generation.

## Eviction detection

A plain read cannot detect eviction: it returns the same absent result for a never-written and an evicted subkey, and a writer reading its own record is served the local copy without the network being asked, even on a forced refresh. The poller therefore uses `inspect_dht_record(key, subkeys, DHTReportScope::SyncSet)`, which reports the network's sequence number for each subkey as if the local copy did not exist. A network sequence number that is absent, or below the local one, is an eviction and triggers the rewrite from OUTBOX.

Because eviction is least-recently-touched per storage node and a read is a touch, the daily poll is itself the keep-alive; a write happens only on a day a node has dropped the record.

## Abuse

**Drop spam.** Cost to B per poll: up to 256 tag checks and up to 512 KEM decapsulations, tens of milliseconds on a desktop. The rate at which one node can fill anyone's drop is bounded by the 4-writes-per-minute ceiling and the fixed 256 slots, which is why the proof-of-work difficulty is zero: below about fifteen seconds of work it binds nothing those two do not already bind. Residual: a pool of attackers can keep DROP(B) full of junk; legitimate hellos then contend for slots and are rewritten after the read-back check. Established conversations never touch the drop again.

**Drop and advert erasure.** Both owner keys are public, so anyone can zero either record. The owner rewrites on detected loss, so the attacker must out-write every legitimate writer continuously at about 4 writes per minute per attacking node. Residual: a persistent attacker denies first contact to B. Any hardening of the drop, such as the reserved multiple-drop index, applies to the advert at the same time or not at all.

**Channel erasure by storage nodes.** The sender rewrites. Storage nodes cannot forge, lacking the owner key and the AEAD keys, and replay of an old slot is detected by `seq` in the associated data against the reader's cursor.

**Redirect and impersonation.** The opening's signature binds the writer's identity, its first ratchet key and the recipient's advert serial; a relayed hello lands in a channel whose signature names the wrong advert.

**Linkability.** Storage nodes holding DROP(B) learn that someone sent B a hello, not who; those holding a channel learn nothing about either identity. Safety routing hides the originating node of every read and write. Hiding that B receives hellos at all is impossible without prior arrangement, because a sender must compute a location B reads, and that computation is public.

## Write budget

First contact: at most 4 writes per side. Message: 1. Cursor: at most 1 per collection batch, usually 0 because it rides inside a reply. Advert: 1 per week, plus a rewrite only when the hourly jittered poll finds the record missing or wrong. Evicted slot: a rewrite only on detected eviction, rate-limited by the application's shared write scheduler. Well inside the 4-per-minute ceiling.

## Wire changes

The change is additive. The records above are new message types in the existing envelope, and the header fields for the KEM step and the device identifier are optional from the first release. The published identity does not change: the advert and the drop are located from the identity public key already published.

## Multi-device foundations

Three properties are in place now so that a second device can be added later without changing any record: channel owner keypairs are derived, never random, so any device holding the recovery phrase recomputes its own channels; first contact is symmetric, so no party ever holds another's owner secret; and the message header carries a device identifier while the advert's subkeys 1 to 63 are reserved for per-device keys.

Deferred, and addable without record changes: an encrypted self-record on the DHT holding the contact list and peer channel lookup keys; per-device fan-out at turn start wrapping one body key; visibility of sent messages on a user's other devices. A second device can never read messages in flight before it existed; that is FC3 holding. Until then conversation state lives on one disk, and a second device is a new identity to correspondents.

## Later message types

Three features are message types over the existing channel, with no record or key change, built after the core conversation is proven: **withdraw before collection**, a marker in the control subkey after which the recipient steps its chain past the withdrawn number; **edit**, a message naming the sequence number it replaces; and **remove for both**, cooperative and marked as such in the user interface.

## Size rule

The layer is at most 6,000 lines of Rust including tests, checked at every commit. Every component names the founding claim it serves.

## Open questions

- Which key encrypts the channel control subkey, and does it change per turn?
- Does the root of B's direction also mix in the shared secret of B's hello written back, or only the encapsulation of B's first turn?
- How wide is the device identifier, and what value does a single-device installation write?
- What is the shape of the "closed" marker, and does a peer's client surface it?
- What does a full drop poll cost on a mobile-class CPU? The mobile figure is an estimate until a native benchmark of 256 ML-KEM-1024 decapsulations plus 256 ML-DSA-87 verifications runs on a device.
- Does `inspect_dht_record` with `SyncSet` report an eviction on the live network? The probe is to evict or zero a record from another node and confirm the report.
- What is the default threshold for the uncollected-age nudge?
