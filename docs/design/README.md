# Design docs

Design-first work for daemonseed: epics too large or too uncertain to be a
single issue, written up before any code. Lightweight RFC style — rationale, not
ceremony.

## How it works

1. A design starts as an entry under `## Designs` in the repo [`ROADMAP.md`](../../ROADMAP.md)
   and a doc here (`docs/design/<slug>.md`).
2. The doc states the **problem**, the **constraints** it must hold (especially
   the security / ISC invariants), the **proposed approach**, and the **open
   questions**.
3. When the design is **accepted**, its concrete deliverables are filed as GitHub
   issues and the `ROADMAP.md` entry is removed. **The doc stays** — it is the
   design-of-record, the rationale future contributors need.

A doc here is *design rationale*, not status or history: status is the issues it
spawned, and history is git tags + `CHANGELOG.md`.

## Vocabulary

These docs use a few ordinary words in a fixed technical sense. Read them as
defined here wherever they appear.

- **seal / sealed** — encrypt with the authenticated cipher (AES-256-GCM under a
  derived key); *open* is the inverse. A sealed frame is ciphertext plus its tag.
- **sweep** — read every slot of a DHT record once, in bounded parallel batches,
  to pick up anything a watch missed.
- **fold** — merge an item that arrived from the network into local state, after
  verifying it.
- **advert** — an advertisement: a signed announcement of a route or a share,
  published to a shared record so peers can find it.
- **knock** — a first-contact request written to a peer's doorbell record.
- **rung** — one level of a write-budget ladder; the budget steps up and down a
  rung at a time.
- **rendezvous record** — the shared DHT record a group meets on; its address is
  derived from the group's owner key.
