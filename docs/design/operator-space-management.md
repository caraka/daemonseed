# Operator space management — design pass (OPEN, pre-design)

> **Status: OPEN — this is not a design-of-record.** It is the problem statement, the
> verified ground truth, and the unresolved forks for a design pass that has not yet run.
> Nothing here is ratified. When the pass runs, its output replaces this document's
> § Approach and § Open questions; § Ground truth is intended to survive so the pass does
> not re-derive facts that are already established.

## Problem

The operator space — MOTD plus announcements, the one project-owned channel that reaches
every user — has accumulated a cluster of issues that share a root and keep being
addressed one at a time. Each fix is locally correct and globally uninformed, so the next
one reopens the previous one's assumptions.

The shared root: **the operator record's authority model was never finished.** The record
is world-writable by construction (its owner seed is a world-derivable derivation), its
content authority is a signer whitelist that no party enforces against the writer, and the
key custody design of record has been overtaken. Retention, ordering, revocation, and
limits all sit downstream of that unfinished model, so each is being solved against an
assumption the next issue contradicts.

### The cluster

| Issue | What it is | Which axis |
|---|---|---|
| #141 | Announcements/MOTD expire from the DHT — no keep-alive | retention |
| #238 | Keep-alive was gated on "subscribed", not "is operator"; fixed cadence | authority, retention |
| #166 | WB-3 I6b deadline-override dead in production — MOTD can expire under congestion | retention |
| #136 | Record needs a monotonic version to wire the `AnnounceFreshness` rollback guard | freshness, revocation |
| #191 | Operator delete/tombstone posts — compose is insert-only | revocation, limits |
| #237 | Announcements render in content-hash order, not by time | ordering |
| #158, #239 | Unread indicator re-fires on already-read content | read state |
| #192, #139, #142 | Timezone, composer layout, unread indicator behaviour | presentation |
| ISC-15 | The write-gate / key custody model itself | authority |
| #177 | Client ISC reconciliation after the Veilid cutover | contract |

Ordering (#237) and revocation (#191) in particular cannot be settled independently:
content-addressed slots have no intrinsic order and no delete, so both want a record
structure decision, and that decision wants the authority model first.

## Announcements and MOTD — how much are they actually separate?

Less than the code's shape suggests, and the answer matters because it decides whether
this pass designs one mechanism or two.

**At the storage layer they are not separated at all.** Both are values on the same
64-subkey DFLT record, placed by the same hash function: `current_state_subkey(stable_id)`
= FNV-1a mod `SUBKEY_COUNT`. The MOTD's slot id is the literal string `"motd"`;
an announcement's is `hex(content_address)`. The only structural difference between the
two is a one-byte KIND tag inside the value and the slot-id convention. They draw on one
shared pool of 64 subkeys.

**Which means they can collide with each other.** `current_state_subkey("motd")` is
**subkey 21**. Any announcement whose content address hashes to 21 lands on the same
subkey, and `publish_at_subkey` is last-writer-wins — so one silently replaces the other,
and the loser is simply gone from the record. This is not MOTD-specific: announcements
collide with each other on the same birthday curve.

| standing items on the record | P(at least one collision) |
|---|---|
| 3 | 4.6% |
| 5 | 14.5% |
| 10 | 50.5% |
| 20 | 94.9% |

**This, not the write budget, is the real limit on announcement count** — and it is
silent content loss, not degradation. The placement rustdoc calls collision "slot-sharing,
bounded by `SUBKEY_COUNT`; a larger dedicated schema lifts the ceiling if it ever bites",
which is a fair trade for ephemeral share adverts that get re-announced, and a much worse
one for durable operator posts that do not. Note also that colliding slots cannot both
survive *whatever* the keep-alive cadence is: re-publishing each in turn just alternates
which one exists.

**The mechanism is already filed — #134** — with the same function, the same 64-slot
ceiling, and the same birthday arithmetic. Two gaps for this pass rather than a new issue:

- **#134 is scoped to presence.** Its problem statement is the unbounded lobby roster and
  its stated decision is "how large a dedicated presence schema"; the operator record
  appears only in the list of records sharing `SUBKEY_COUNT`. A dedicated presence schema
  fixes presence and leaves the announce record on 64. The operator-record instance —
  announcements colliding with each other, and with the MOTD at subkey 21 — is not
  covered by any open issue, and there is no announcement-limit issue at all.
- **#191 reads the MOTD as safe, and it is only half safe.** It notes "the MOTD is fine —
  it lives in the single mutable `motd` slot, last-writer-wins". True for the MOTD's own
  updates; not true against a colliding announcement, which overwrites it from outside.
  Worth carrying into whatever #191 becomes, since a tombstone design that assumes the
  MOTD slot is private to the MOTD inherits the same blind spot.

The remedy direction is shared with #134 (a larger or dedicated schema lifts the ceiling)
but the sizing question is per-consumer, which is why this belongs in the pass rather than
folded into a presence issue.

**The one genuine difference is mutability, and it has a real driver.** A MOTD is a
singleton updated arbitrarily often; an announcement is an accumulating log. Storing each
MOTD revision as a fresh content-addressed slot would burn the shared 64-slot pool that
announcements also draw from, so the MOTD gets one overwritable slot costing exactly 1
forever. That is an engineering trade against the slot budget, not a style choice.

**But the price of that trade is the entire MOTD problem class.** A mutable slot with no
newer-wins in the fold is unsafe to re-publish, which is why the MOTD has no keep-alive,
why #136 blocks it, and why #166's expiry has no mitigation. And #136 dissolves the
distinction: give the mutable slot a monotonic version and it becomes safely refreshable
while staying a singleton. After that, the remaining difference between MOTD and
announcements really is mostly semantic — "the current thing" versus "the accumulated
things" — and one retention mechanism covers both.

So: design one mechanism, not two, and treat #136 as the thing that makes that possible.
Until it lands the two behave differently, but that difference is a temporary property of
an unfinished record format rather than a fact about the content.

The table below is therefore the *current* state, not a target:

| | Announcements | MOTD |
|---|---|---|
| Slot | one per post, `hex(content_address)` | the single mutable `"motd"` slot |
| Slot count | grows without bound | exactly one, forever |
| Re-publish | idempotent — same bytes, same key, cannot revert anything | **can revert**: no newer-wins in the fold, so a stale re-publish propagates backwards |
| Keep-alive today | operator-only, one slot per emission (#238) | **none, from anyone** — deliberately excluded |
| Delete | no primitive; needs tombstones (#191) | overwrite is the delete |
| Order | none intrinsic; renders by content hash today (#237) | not applicable |
| Blocked on #136 | for tombstone rollback resistance | for **any** keep-alive at all |

The consequence worth stating plainly: **the MOTD is the most visible piece of operator
content and it is the one thing nothing refreshes.** It survives only from the operator's
last explicit `set_motd` until capacity eviction takes it, and #166 (the dead WB-3 I6b
deadline override) means congestion can take it sooner. #141 is titled for both halves;
only the announcements half is addressed, and the MOTD half is blocked on #136.

This asymmetry is not new, but #238 widens it: announcements now have a working retention
story and the MOTD still has none.

## Ground truth (verified, do not re-derive)

Each of these was checked against the tree at the time of writing; the citation is where
to re-check it, not a claim that it is permanent.

**Two different keys get called "the operator key", and conflating them is what stalled
this.**

- **Authorship authority** — who may *sign* announcements and MOTD. This is the signer
  whitelist, ISC-S8 (`ISA.md`): a flat list of ML-DSA-87 public keys or `name#hash`
  handles; "revocation is immediate on the next published whitelist", i.e. enforced by
  readers at verification time.
- **Write authority** — who may *set a value* on the Veilid record. Today this is the
  world-derivable `dev_project_announce_veilid_owner_seed`
  (`crates/daemonseed-core/src/public_space.rs`), computed by every client at connect in
  `subscribe_operator_space` (`crates/daemonseed-gui/src/veilid_net.rs`).

**A whitelist cannot stop republication.** A republisher re-emits already-signed operator
bytes unchanged; the whitelist verifies them and accepts, correctly — they are authentic.
So authorship authority does not constrain write volume, and #238's class of defect is not
closed by any whitelist. `docs/design/phase4-veilid-presence-announcements.md` Decision A2
already reached this: on Veilid "the operator *is* the writer, so no independent party
enforces the whitelist against the writer" — the whitelist "degrades from a security
boundary to a documentary roster", near-vestigial with one entry.

**Announce record mechanics.**

- Rendezvous records are DFLT schema, fixed `SUBKEY_COUNT = 64`
  (`crates/daemonseed-veilid-net/src/rendezvous.rs`).
- The record key is a function of **schema + owner public key**
  (`get_dht_record_key`, same file). A schema change therefore changes the record
  *address*.
- Announcements live in content-addressed slots, `hex(content_address)` — idempotent under
  re-publish, no intrinsic ordering, no delete primitive.
- MOTD lives in the single mutable `"motd"` slot, which has no newer-wins in the fold, so
  re-publishing a stale MOTD can revert a newer one fleet-wide. This is why the keep-alive
  excludes it, pending #136.
- `AnnounceFreshness` (`public_space.rs`) already exists as the monotonic rollback guard;
  #136 is the wire field to feed it.
- The sweep discards `ValueData.seq`, so "was this slot recently refreshed?" is **not
  observable** to a client today.

**No operator marker exists on any roster.** `MemberHeartbeat` carries `room`,
`sender_pubkey`, `sender_handle`, and an advisory timestamp; the string `operator` appears
in no `.proto` in the tree. Any design that wants clients to detect operator presence or
absence needs a new wire field — the same cost class as #136, on a frozen wire contract
with testers on a released build.

**SMPL is the obvious primitive and it does not fit.** Veilid's SMPL schema takes a set of
designated member public keys and enforces writes against them — exactly "a whitelist of
keys that may publish, using their own private keys", at the transport, with no custody
infrastructure. `rendezvous.rs` records SMPL's rejection for the rendezvous engine, and
that reasoning is sound there (circles and the lobby have open, unknowable membership).
Announcements are the opposite case and would fit. It still fails: because the schema binds
into the record key, **changing the member set moves the record**, so every roster change
would relocate the announcements channel and force every client to rediscover it. SMPL
makes enforcement free and updates impossible.

**Retention is far cheaper than assumed.** Veilid has no TTL; retention is capacity
eviction only. Measured in early felt testing: announcement values survived **more than 24
hours with nobody re-seeding them at all**. Caveat: eviction is capacity-driven, so that
figure is a property of DHT load during that test, not a constant.

**Write budget anchors** (`docs/design/veilid-write-budget.md`, WB-2): ~4 writes/min
non-chat ceiling per client with ~2.0/min already spoken for; ~6 writes/min was the
empirical DHT saturation point in testing, ~2/min ran healthy.

## Settled by #238 (already landed, stated so the pass does not reopen it)

- **Non-operators do not re-seed.** Generous hosting by the fleet is rejected on
  principle: content evicting while no operator runs is a *signal* that no operator is
  running, and a fleet-wide write subsidy makes that operational failure invisible. This
  forecloses nothing — the owner seed remains world-derivable, so fleet hosting can be
  reinstated later with no wire change.
- **Cadence is damped hard**: one slot per emission, jittered 45–75 min band drawn per
  emission, giving the whole fleet ~1 write/hour on the record and refreshing each slot
  every `N` hours for `N` standing announcements. The session's *first* emission uses a
  short jittered 2–5 min band, because the steady band would mean an operator session
  shorter than 45 min refreshed nothing at all.
- **Four costs surfaced by the #238 review, accepted-and-recorded rather than fixed.**
  These are the pass's most concrete inputs:
  1. **Rotation latency has an attacker-influenced denominator.** `OperatorSpace.posts` is
     an unbounded, insert-only map, and the F17 signing seed is in-source, so anyone can
     mint verifying announcements. Per-slot refresh period is `|posts| × band`: publish
     enough announcements and the operator's genuine posts refresh slower than they
     evict. This is the *limits* question with a sharp edge on it — and note the old
     batch design failed the same attack differently (an unbounded write storm rather
     than dilution).
  2. **Adversarial overwrite is now permanent.** `posts` is rebuilt each session from the
     DHT sweep with no persistence, so content overwritten while the operator is offline
     is never re-learned and never re-seeded. Fleet re-publication used to restore it.
     The decision to drop fleet hosting priced capacity eviction; it did not price
     adversarial overwrite. **A local persisted copy of the operator's own published
     posts would close this far better than fleet hosting did** — worth its own issue.
  3. **The damping was not required by WB-2.** The gate plus one-slot-per-emission at the
     old 120 s period already lands on WB-2's 0.5/min operator allocation. The further
     ~30x came from the measured >24 h retention, not from the budget. Both are
     defensible; they are separate decisions and should be re-priced separately.
  4. **The record leaks operator liveness, and the first emission marks session start.**
     Under operator-only every write on the record is by definition the operator's, so
     write timing is an online/offline signal to any observer. The 2-5 min first band is
     disjoint from the 45-75 min steady band, so any short gap identifies a session
     start. Collapsing to a single wide band (e.g. `[2, 75] min`) removes the marker but
     gives up the guarantee that a short session refreshes anything.
- **Operator uptime is now load-bearing**, which is new. Announcement retention is a
  function of how often an operator actually runs the client: a session of roughly `N`
  hours cycles all `N` slots once. This is the intended consequence of rejecting fleet
  hosting — retention now tracks operator presence, visibly — but it is a real operational
  dependency the pass should price, especially against #191 (limits/tombstones) and the
  margin analysis above.
- **The band is a tunable**, named in `daemonseed_core::public_space`, expected to move
  when the design pass has better numbers.

The margin analysis the pass should carry forward: ~8× over the observed 24 h survival
floor at `N = 3`, ~4× at `N = 6`, and the margin is gone around `N ≈ 24`. That is the
quantitative link between the retention design and the *limits* question below — it is a
visible, tunable edge rather than a cliff, but it is the reason announcement count cannot
grow unbounded.

## The unresolved fork — key custody

This is the decision the rest waits on, and the two candidates are genuinely different.

**Candidate A — the recorded design (ISC-15 / Fork A).** A maintainer-held **offline**
seed derives both the ML-DSA content-signing key and a sibling Veilid owner keypair; only
the two public keys are baked into clients, which "read/watch/verify, and cannot write"
(`docs/design/phase4-veilid-presence-announcements.md`; `ISA.md` Decisions 2026-07-07 and
2026-07-22). Under A the offline key sits in the **publishing path**: every announcement
needs it. There is no middle tier, and the whitelist stays vestigial.

**Candidate B — root-signed whitelist (maintainer's stated intent; NOT yet recorded as a
decision).** A baked-in root public key whose secret signs **the whitelist only**. Listed
individuals sign announcements with their **existing identity keys**. The root key comes
out for roster changes and nothing else.

B is a conventional two-tier structure and is operationally much cheaper: the high-value
key leaves storage rarely, day-to-day publishing uses ordinary online keys, and revocation
is a roster publication rather than a key rotation. **B is also very close to what ISC-S8
already specifies** — the whitelist criterion was written for exactly this shape; it was
Fork A's record-ownership answer that fused the roles.

**The hole B leaves.** B answers authorship and says nothing about *writes*. Remove the
offline Veilid owner keypair from the publishing path and the write credential is unowned:
either shared among operators (a revoked operator retains write access until the record
rotates) or left world-derivable (today's state, i.e. #238's precondition).

**A candidate resolution worth evaluating in the pass — per-operator records.** Give each
whitelist entry two fields: the operator's ML-DSA identity pubkey *and* a Veilid owner
pubkey. Each operator publishes to its **own** announce record, deriving that record's
owner secret from its own identity secret; readers compute the address from the published
owner pubkey (the record key is a function of schema + owner *public* key). Then:

- A client cannot write another operator's record — the #238 class becomes structurally
  impossible rather than gated.
- Revocation is clean: drop the entry, clients stop sweeping that record. No rotation, no
  shared secret, no residual write access.
- Each operator re-seeds only its own record, which is the #238 model enforced rather than
  requested.

Costs: clients sweep `N` records instead of one (`N` small and known); the whitelist
becomes load-bearing for *discovery* as well as authorization; and the record address is a
public function of a published key, so which identity owns which announce record is
visible — fine for named operators on a public roster, but it should be a stated property
rather than a later surprise. Note the project deliberately chose the *opposite* for the DM
key record (owner seed derived from the identity's **public** key, world-derivable on
purpose, integrity resting on the inner signature) — same primitive, opposite choice, for
different reasons; announcements would want the secret-derived variant.

**Whichever candidate wins, two problems remain and are the genuinely hard part:**

1. **Bootstrap.** Clients must learn the first whitelist without trusting the record that
   carries it, or anyone with write access installs their own roster. That needs at least
   one root public key baked into the client — a much smaller commitment than an offline
   seed: a pubkey, no custody ceremony.
2. **Freshness / rollback.** A signed whitelist is replayable: anyone with write access can
   re-publish an older version and restore a revoked signer. The fix is a monotonic version
   bound into the signature — **the same primitive #136 already scopes** for the MOTD slot,
   and `AnnounceFreshness` is already written to consume it. One mechanism unblocks the
   MOTD keep-alive, whitelist updates, and #191's tombstones.

## Open questions for the pass

1. **Custody fork** — A or B (or per-operator records under B)? Everything below inherits
   from this. It also needs recording: the offline-seed design is currently the design of
   record in three places and the maintainer's stated intent differs, so the tree is
   misleading until this is settled and written down.
2. **Is the `operator_write_enabled()` gate permanent?** Under A it eventually becomes
   redundant (the crypto enforces it); under B and per-operator records it stays load-bearing
   or becomes structurally unnecessary respectively. Cheap either way — keep as
   defence-in-depth, since it stops the *attempt* and not merely the effect.
3. **Limits on announcements.** What bounds `N`? The margin analysis above says retention
   safety degrades as `N` grows. Candidates: a hard cap, operator-driven tombstones (#191),
   age-based expiry, or paging. Interacts with ordering (#237) — a cap needs an eviction
   order, which needs a time order, which content-addressed slots do not provide.
4. **Ordering (#237).** Announcements sort by content hash today. A signed timestamp exists
   in the artifact; is the fix presentation-only (sort on the signed timestamp at render)
   or does the record structure need to change? Presentation-only is far cheaper and
   probably right, but it should be confirmed against the limits decision, not assumed.
5. **Revocation of content (#191).** Tombstones on a record with no delete primitive.
   ISC-S7 already grants the operator power to delete any post and a signer power to delete
   their own; wiring it needs the monotonic version (#136) so a tombstone cannot be rolled
   back by a replayed older record.
6. **MOTD keep-alive.** Blocked on #136. Once the version lands, does the MOTD join the
   same rotation, or does it want its own cadence given it is a single mutable slot?
7. **Retention under congestion (#166).** The WB-3 I6b deadline override is dead in
   production, so MOTD can expire under congestion. Does the damped #238 cadence make this
   better or worse, and does the keep-alive need a congestion-aware floor?
8. **Should fleet hosting ever return?** If it does, Trickle-style suppression (RFC 6206 —
   listen for others' refreshes, restart your own countdown, total load flat in fleet size)
   is the principled mechanism, and it requires plumbing `ValueData.seq` through the sweep.
   Recorded as the upgrade path; not proposed.

## Cross-references

- `ISA.md` — ISC-S4 / S7 / S8 / S9 (public space, announcements, whitelist, MOTD),
  ISC-15, and the Decisions entries dated 2026-07-07, 2026-07-22, and 2026-07-28.
- `docs/design/phase4-veilid-presence-announcements.md` — the Veilid cutover design,
  Decisions A1–A4 and Fork A/B.
- `docs/design/veilid-write-budget.md` — WB-1.2, WB-2, WB-3 I6.
