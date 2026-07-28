# daemonseed — roadmap

Forward-looking only. This file holds work that is **not yet a concrete, scoped
deliverable**: speculative ideas, and design-first epics still being worked out.
The moment an item is decomposed into actionable work, that work becomes a
**GitHub issue** and the item is removed from here.

Same rules as the issue tracker: no status, no history (those live in git tags +
`CHANGELOG.md`), no planning of *when* (that is the maintainer's call at scoping
time). This is a queue of *what might come*, not a plan.

## Ideas

Speculative, unvetted — captured so they aren't lost. Promote to a Design (or
straight to a GitHub issue) once vetted.

*(none captured yet)*

## Designs

Design-first epics: too large or too uncertain to be a single issue, needing a
fleshed design before any code. Each entry is a one-line pointer to its design
doc under `docs/design/`. When a design is accepted, its component deliverables
become GitHub issues and the entry here is removed — but the design doc stays as
the design-of-record.

- **Direct messaging** — offline-capable, first-contact-capable 1:1 private messaging with a static ML-KEM key replacing the shared phrase. Design-of-record: [`docs/design/direct-messaging.md`](docs/design/direct-messaging.md) — **ADJUDICATED, not yet frozen** (2026-07-27): a 3-lens adversarial panel reopened the three-record candidate; the doc records the findings and the structural decisions to resolve. Needs a second design iteration + panel re-run before build slices graduate into issues. DM ISC family (ISC-C38–C46 / ISC-A-C20–A-C25) re-cut to the direction.


## Features

Wanted, shaped enough to describe, but deliberately deferred (no decision on
*when*). Promote to a GitHub issue when picked up.

- **(Conditional) reap reason-code + do-not-resurrect** — only needed *if* the
  relay ever gains a durable/policy/TTL reap. Today every reap is a disconnect
  (shares should always come back), so this is deferred until such a reap exists.
