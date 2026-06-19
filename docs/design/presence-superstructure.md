# Design: circle share/chat presence superstructure

**Status:** draft — design-first; gates any circle-presence work.

## Problem

"Presence" in a circle is *emergent*, not a bolt-on feature: it falls out of the
share-announcement path. Public shares publish a connection **through the relay**
(`server/src/share.rs` keys live listings by `(owner, name)` — the relay sees the
owner), so the set of live shares ⇒ who is online. This is exactly how Demonsaw's
online-list worked: who's sharing ⇒ who's in the chat, members coming and going
with their shares.

## Constraints (must hold)

- **ISC-A-S2** — the relay learns no membership and no participant identity.
  Circle shares must **not** reuse the public publish path naively: if the relay
  can tie publishers to a circle's rendezvous, that leaks membership/presence to
  the relay, a direct ISC-A-S2 violation.
- Presence-to-**members** is wanted (the Demonsaw behavior); presence-to-**relay**
  is forbidden.
- **Connected-only** semantics — client running / subscribed. NOT activity or
  typing indicators: AFK-but-running counts as present.

## Proposed seed

An AEAD'd member **heartbeat** *inside* the sealed circle: the relay sees only
ciphertext (ISC-A-S2 holds), while members learn each other's connected-presence.
This mirrors the public online-list behavior but with the circle's encryption
layer over it.

## Cross-references

ISC-A-S2, ISC-S4, ISC-S27 (share content serving), ISC-S21 (`share_id` →
unpredictable rendezvous).

## Open questions

- Heartbeat cadence and liveness window — when is a silent member considered gone?
- Does presence ride the existing CoT subscription, or a dedicated heartbeat asset?
- Is presence *derived from* circle shares (Demonsaw-style), or an independent
  signal? (Derived keeps one mechanism; independent decouples presence from
  whether a member happens to be sharing.)
