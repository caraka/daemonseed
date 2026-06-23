# Design: presence superstructure (member-visible connected-presence)

**Status:** accepted (design-of-record) — resolves the draft seed's open questions; component
deliverables filed as #74 (heartbeat primitive), #75 (Lobby increment), #76 (share unification),
#77 (circle presence). Removed from the ROADMAP `Designs` list; this doc stays as the rationale.

## Problem

Members need to know whether another member's client is online *before* reaching out. Today there is
no member-visible signal: the relay tracks subscription liveness (ISC-S20) but, by design, members
cannot see who is present. Concretely — a tester connected from Slovenia pinged the maintainer
overnight; the maintainer had no way to see the tester was online to reply. And because messages are
**live-only** (held in RAM, gone on relaunch; ISC-S20: "a frame sent while a daemon is absent is
never delivered"), a reply sent into a room the recipient has left is simply lost. Presence is the
affordance that tells a sender whether a message is worth sending at all.

## Two presence planes

Presence already exists at one layer; this design adds the other.

- **Relay plane (built — ISC-S20, ISC-A-S2, ISC-S17/A-S12).** A subscription stream's lifetime *is*
  presence-at-hash: the relay knows a rendezvous address has N live subscribers (refcount),
  constant-time, with no identity, no membership, no enumeration. This is the liveness the relay
  needs to reap dead assets — deliberately **not** member-visible identity.
- **Member plane (this design).** Members want to see *which handles* are present in a room. That
  requires a signal the relay cannot read but members can — i.e. carried *inside* the room's
  encryption.

## Constraints (must hold)

- **ISC-A-S2** — the relay learns no membership and no participant identity. The member-plane signal
  is AEAD'd under the room key; the relay sees only sealed frames + presence-at-hash + refcount.
- **ISC-S20 live-only** — no store-and-forward, no offline delivery, no reconnect replay. Presence
  does not change this; it *exposes* it usefully (online ⇒ worth sending; offline ⇒ don't bother).
- **ISC-S17 / ISC-A-S12** — relay-side presence detection stays constant-time and abuse-state-free.
  The member heartbeat adds no relay-readable per-identity signal.
- **Connected-only semantics** — client running / subscribed. NOT typing, read-receipts, or activity
  state. AFK-but-running counts as present.
- **Wire indistinguishability** — the member-plane beacon is shape-identical to other sealed room
  frames, adding no new distinguishable flow (ISC-A-S2 traffic-shape).

## Decision: one beacon

Resolves the seed's three open questions.

1. **Derived-from-shares vs independent → unify (do not distinguish).** A `ShareAnnouncement` is
   already a heartbeat that happens to carry a payload. Building "presence derived from live shares"
   *and* "an independent heartbeat for chat-only members" means two liveness sources to reconcile,
   with edge cases (a member who shares *and* chats; one who stops sharing but stays in chat; a
   chat-only lurker with no signal at all). Instead: **one uniform AEAD'd member heartbeat is the
   member-plane liveness substrate, and share announcements ride it** — a share announcement is
   "heartbeat + share payload."
2. **Rides the existing stream.** The heartbeat travels as a sealed room frame over the existing
   CoT/room subscription (the same surface share announcements use), not a separate asset — keeping
   it one indistinguishable flow.
3. **Cadence / window → fast beacon, multi-miss reap, decoupled knobs.** The heartbeat *interval*
   sets presence resolution; the *miss-count × interval* sets the liveness TTL — keep them separate.
   Default: a fast jittered interval (~10–15 s) with reap only after ~3 consecutive misses
   (TTL ~30–45 s), so a brief connection wobble (≤ ~2 missed beacons) never reaps a live share, while
   a genuine departure clears within ~TTL. **Bias to forgiveness:** briefly over-showing a crashed
   client as present is far cheaper than share-availability churn or a false reap that wastes the
   sharer's re-announce. A slow beacon where a *single* miss reaps is the brittle opposite — it both
   reaps on the first wobble and gives sluggish presence. This composes with auto-reconnect (#71/#72):
   a wobbling client re-connects within the 2–30 s backoff and resumes beaconing well inside the TTL,
   so the share rides through the wobble rather than flapping out and back.

### Payoffs of unifying

- **Presence for everyone** — sharers and chat-only members, one mechanism.
- **Faster share-staleness** — a share is pruned the moment its sharer's heartbeat lapses, without
  attempting (and failing) a fetch. This closes the 2026-06-13 deferral that zombie-reaping "belongs
  on a sharer heartbeat", and complements the relay-plane refcount reap.
- **Lighter reconcile** — the heartbeat can carry a compact live-share digest (share-ids / a rolling
  hash); a full `ShareAnnouncement` fires only on change, not every interval.
- **One sealed beacon** on the wire instead of two flows — better for ISC-A-S2.

## Ethos — why the lag is fine

The heartbeat **opens the gate to reaching out**, nothing more. It does not guarantee anyone is at
the keyboard, nor that a message will ever be read: messages are live-only, and a recipient who
disconnects loses whatever was in flight. The few-seconds presence lag (see-online → they-drop →
ping-lost) is known and **accepted as part of the no-logs ethos** — the cost of a relay that
remembers nothing. Daemons understand this contract: presence says "worth a try," never "delivered."
This is deliberately *less* than a traditional chat app, and that restraint is the point.

## First increment: the public Lobby

Land presence in the public Lobby first. The Lobby is a public room (membership open, server is a
member — ISC-A-S2), so member-visible presence there is the lowest-privacy-sensitivity case, and it
directly answers the motivating need ("is the tester online to ping?"). Circle presence follows on
the identical mechanism once the Lobby increment is proven.

## Open questions

- **Heartbeat digest format** — what the live-share digest carries (share-ids vs a rolling hash) and
  how a receiver diffs it against its last view.
- **Lobby identity** — the public Lobby currently uses an ephemeral per-session identity, so presence
  there shows ephemeral handles unless a member has a persistent identity. How is "that's FAQ"
  recognized across sessions in a public room? (May bound the Lobby-first increment to "someone is
  present" rather than "FAQ is present".)
- **Relay-plane vs member-plane convergence for reaping** — does the member heartbeat subsume the
  relay's sharer-reap signal, or do both run (defense in depth)?
- **Final cadence / jitter / TTL values** — the ~10–15 s interval / 3-miss / ~30–45 s TTL default
  above is the starting point; tune against the censorship traffic-analysis budget and real wobble
  data once the Lobby increment is live.

## Cross-references

ISC-S20 (subscription-lifetime presence, live-only), ISC-A-S2 (relay learns no membership/identity),
ISC-S17 / ISC-A-S12 (constant-time, abuse-state-free relay presence), ISC-S21 (`share_id` →
unpredictable rendezvous), ISC-S27 (share content serving); `docs/design/unified-share-model.md`
(the in-band sealed announcement + roll-call + two-speed liveness this rides on).
