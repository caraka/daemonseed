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
