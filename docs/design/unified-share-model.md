# Design: unified share model — sealed content + relay-blind in-band discovery

**Status:** draft — design-first; gates the share-discovery rework and the
public-share content seal.

## Problem

Shares are the lone exception to daemonseed's "everything sealed, relay never
reads anything" model. Two specific gaps:

1. **Content rides cleartext on the public tier.** A public share's `ShareFrame`
   (`daemonseed-core::share_envelope`) is carried in `CotFrame.payload`
   **unencrypted**, while every chat payload — circle *and* public room — is
   AES-256-GCM-sealed (`circle::message`, `public_room`). So on the wire the
   relay (and any observer) can structurally distinguish public-share traffic
   from circle traffic: a metadata leak, and the one place A-S2 opacity is not
   uniform.
2. **Discovery is relay-mediated.** Public-share discovery uses a relay-held RAM
   registry (`daemonseed-server::share::SharePublishRegistry`) and a unary
   `ListPublicShares` RPC. This is the only role in which the relay is **not** a
   pure blind forwarder — it aggregates a queryable who-published-what directory,
   lets any client build a publisher/timing map, and is an exception that has to
   be explained ("the relay is blind *except* for the share list").

Circle shares cannot reuse either gap's mechanism: a relay-visible circle
directory would leak circle existence/activity (A-S2), and circle content must be
sealed under the secret `cot_key`. So today's path forces a public/private split
in code and a "*everything is E2EE except public share files*" caveat in the
product story. The first testers should receive the **intended** model, not the
caveated one.

## Vision

Public and circle shares are byte-identical except **which key seals them and
which room they announce into**. The relay is a pure blind forwarder for
*everything* — chat and shares, public and private. "Always end-to-end
encrypted; the relay never reads your content; public vs private is only whether
the key is shared with everyone or just your circle" becomes the literal spec,
not a marketing simplification.

## Constraints / invariants (must hold)

- **A-S2** — relay learns no membership, no participant identity, and (the new
  bar) holds **no share directory**. No relay-side share state of any kind.
- **A-S16** — only the sealed form ever rides the wire; share content included.
- **A-S1** — ephemerality: no persisted share state anywhere, relay or otherwise.
- **S21** — a share's rendezvous address stays unpredictable (CSPRNG-drawn,
  not enumerable); it is what the announcement hands out.
- **S22 / S24 / C57** — the public tier seals under the public room key and
  every posted message is ML-DSA self-signed for provenance; the announcement is
  no exception. Circle tier seals under `cot_key`.
- **Key-class separation (new, hard).** Once everything is sealed, *which key*
  is the sole thing separating public from circle. A share-seal API must be
  **incapable of accepting the wrong key class** — a `PublicRoomKey` and a
  `CircleKey` must not be substitutable, so a circle share can never be silently
  sealed under the public key (a silent, total confidentiality failure with zero
  structural signal). Uniformity concentrates all risk into one key choice; make
  that choice un-mistakable at the type level.
- **Honest labeling.** Sealing public content buys **structural
  indistinguishability**, not confidentiality (the public key is derivable by
  anyone, including the relay — `public_room`). The UI still labels public shares
  "anyone can read." We never imply public content is private.

## Approach

Adopt the `public_room` model wholesale for shares. Two separable workstreams.

### A. Seal share content

Seal each `ShareFrame` (manifest/chunk frames) before it enters
`CotFrame.payload`, reusing the existing envelope:

- Public-tier shares → sealed under the **public room key**
  (`public_room::seal_room_message`'s envelope shape / a share-specific AAD).
- Circle shares → sealed under `cot_key` (`circle::message`).

This closes gap (1): public-share frames stop riding cleartext, so they are
structurally indistinguishable from circle frames. A distinct AAD
(`daemonseed/share/frame/v1`) keeps a share frame from being confused with a chat
message even under an equal key, mirroring `ROOM_MESSAGE_AAD` vs `MESSAGE_AAD`.
The per-chunk SHA-384 integrity check (`share_envelope`) is unchanged — it sits
inside the seal.

### B. Relay-blind in-band discovery

Replace the relay registry with a **signed, sealed share-announcement payload**
carried on the existing `CircleOfTrust.Subscribe` stream — the same transport
chat already uses.

- A new application payload type (e.g. `ShareAnnouncement`) sealed + ML-DSA
  self-signed exactly like `PublicRoomMessage`, carried in `CotFrame.payload` at
  the **room's rendezvous address** (`public_room::room_asset_address` for
  public; `cot::asset_address` for a circle). It carries: the share's
  rendezvous address (what `ListPublicShares` used to hand back), name, rating,
  the sharer handle + `sender_pubkey` (provenance, C57), and a withdraw flag.
- **Discovery = listening to the stream**, identical to receiving chat. Publish =
  post an announcement; unpublish = post a withdraw. Public shares announce into
  the **lobby**; circle shares announce into the **circle**. Same code, same
  envelope, only the key/room differ.
- **Delete** `SharePublishRegistry`, `ListPublicShares`, `PublishShare`,
  `UnpublishShare` from the relay surface. The relay becomes a pure blind
  forwarder; the proto loses the share-registry RPCs.

### One discovery entry point (late-join + liveness)

There is a single late-join hook; **startup discovery, the refresh button, and a
background timer all call it.** It is a *roll-call*: post a sealed roll-call
request into the room; every currently-connected sharer re-announces. This needs
**no new relay capability** — it fits the relay's existing live-only,
no-retention posture (a late chat joiner already sees no history).

Liveness is a **two-speed** model:

- **Fast push (primary):** live publish/withdraw announcements reach everyone
  currently subscribed in real time.
- **Slow reconcile (the timer):** a long, jittered roll-call that self-heals
  missed announcements and **ages out** anything not re-announced within a TTL.
  Prune-TTL must exceed ~2 re-announce intervals so one missed cycle does not
  drop a live share. Backstop: clients prune on fetch-failure (a crashed sharer
  cannot send a withdraw).

This replaces the relay's connection-scoped auto-reap
(`share::ShareReapGuard`) with an in-band, relay-blind equivalent.

### Relationship to presence

This is the share-side of the same mechanism `presence-superstructure.md`
describes: presence is emergent from who is announcing/heartbeating inside a
sealed room. The roll-call/announce stream here and the AEAD heartbeat there
converge on one in-band signal — they should be designed as one mechanism, not
two. (See open questions: derive presence from share announcements, or a
dedicated heartbeat?)

## Open questions

- **Scope of the first cut:** ship A + B together (the asterisk-free "always
  E2EE" claim needs the content seal), or B first (discovery) then A? They are
  separable but the product claim wants both.
- **Sequencing:** build the unified model and point *public* at it now (no
  testers are on the registry path yet), then circle reuses it — vs keep the
  registry for the current alpha and migrate later. Circles need in-band
  discovery regardless, so building it once is the lower-total-work path.
- **Roll-call storms:** how do sharers coalesce re-announce responses so N
  joiners × M sharers in a busy lobby doesn't melt? (jitter; cap; lean on live
  broadcasts as primary.) Is the roll-call request a distinct payload kind, or
  implicit in subscribing?
- **Announcement message shape:** new `ShareAnnouncement` payload vs extending an
  existing type. TTL / sequence / withdraw field design.
- **Relay replay buffer:** an *opaque* sealed recent-message buffer the relay
  re-forwards blind would solve late-join without roll-call — but it adds relay
  state (A-S1 tension). Currently rejected in favour of a stateless relay; record
  the tradeoff.
- **Presence convergence:** does presence derive from share announcements
  (one mechanism, Demonsaw-style) or ride a dedicated heartbeat (decouples
  presence from whether a member is sharing)? Resolve jointly with
  `presence-superstructure.md`.

## ISC impact (flag — resolved when this graduates to issues)

Likely touches `ISA.md` `## Criteria`: a new in-band-discovery ISC; a
public-share-content-seal ISC that revises the current "public-share content is
server-visible / cleartext" stance (the seal makes it server-*readable* via the
public key, never wire-cleartext — aligning shares with S22/A-S16); and a
key-class-separation ISC. IDs are permanent — additions/splits only, no renumber.

## Cross-references

`public_room` (the template: `derive_room_key`, `room_asset_address`,
`seal_room_message`/`open_room_message`), `circle::message`, `share_envelope`,
`cot.proto` (`CotFrame`, `PublicRoomMessage`, `CircleMessage`),
`daemonseed-server::share`. ISC anchors: A-S1, A-S2, A-S16, S4, S21, S22, S24,
C19, C57. Sibling design: `presence-superstructure.md`.
