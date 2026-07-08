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


## Features

Wanted, shaped enough to describe, but deliberately deferred (no decision on
*when*). Promote to a GitHub issue when picked up.

- **(Conditional) reap reason-code + do-not-resurrect** — only needed *if* the
  relay ever gains a durable/policy/TTL reap. Today every reap is a disconnect
  (shares should always come back), so this is deferred until such a reap exists.
