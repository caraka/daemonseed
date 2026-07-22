# Project instructions — daemonseed

Standing rules for any AI assistant working in this repository. These are loaded automatically at the start of every session by any agent or assistant that respects `AGENTS.md`. The file is intentionally model-agnostic — phrase everything in terms of "the assistant" or imperative; do not assume a specific tool or vendor.

## Project context

Daemonseed is a federated, end-to-end-encrypted communication and file-sharing protocol — a Rust-native successor to Demonsaw, informed by lineage but built clean (zero lines of Demonsaw code). Backend is pure Rust, no C dependencies. Crypto stack is CNSA 2.0 via the oxicrypt crate + rustls. Wire is gRPC-over-h2 (prost / tonic). Storage is a three-layer split: encrypted seeds file + redb indexed state + content-addressed chunk filesystem. Threat model is Level-C adversarial; the censorship-survivability bar is "survive the GFW" per Wu et al., USENIX Security 2023. License: AGPL-3.0-or-later on code crates; Apache-2.0 OR MIT dual on the `daemonseed-proto` schema crate.

## Key paths

- **Repo:** this repository — <https://github.com/caraka/daemonseed>
- **Sibling crypto foundation:** <https://github.com/oxiforge/oxicrypt> — currently private; goes public before daemonseed does. daemonseed depends on it for CNSA 2.0 primitives, AEAD, and KDF.
- **Sibling TLS-stack glue:** <https://github.com/oxiforge/oxitls> — currently private; goes public before daemonseed does. Provides the rustls `CryptoProvider` and the ML-DSA webpki verifier (`oxitls-rustls-provider`, `oxitls-webpki-mldsa`); consumed by daemonseed-cli and -tui.
- **LAMA spec (API-manifest format):** <https://github.com/lamaspec/lama> — the specification (`SPEC.md`) that this repo's `lama.yaml` and `docs/llm-api-manifest/*-api.yaml` MUST conform to. Re-checked at every doc-sync.

## Session bootstrap

At the start of every session — or after a context reset — read these in order before doing anything else:

1. **`ISA.md`** (in this repo) — the Ideal State Artifact: the **authoritative** design contract and system of record. Read its Problem / Vision / Principles / Constraints / Out of Scope before changing any boundary. Each ISC is a verifiable end-state; each `ISC-A-*` is a forbidden state; IDs are permanent (never renumbered, vacated IDs stay reserved). The full ISC inventory is `ISA.md` `## Criteria`; the live count and coverage come from `cargo xtask isc-coverage` — neither is hand-written here or anywhere else (see **Canonical homes** for why no surface carries a duplicate count). The client surface is intentionally the larger side because daemonseed's complexity lives at the client (identity, federation trust, suite agility, first-start, trust-event taxonomy).
2. **`docs/llm-api-manifest/` in this repo** — LAMA manifests describing the public API surfaces of each crate. AI agents helping cross-language client implementers consume these. Stubbed at repo creation; grows as the API grows.

## Canonical homes

Every kind of project fact has exactly **one** canonical home. Do not duplicate a fact across surfaces — copies drift, and a drifted copy is worse than no copy. To read a fact, read its canonical home; to change a fact, update only its canonical home (and any *pointer* that names it — never a second copy of the value). If the right home for something isn't obvious — or doesn't exist yet — propose one (with your reasoning) and raise it, rather than silently picking a home or copying the fact into several places.

| Fact | Canonical home | Everything else |
|------|----------------|-----------------|
| **Design contract** — Problem, Vision, Principles, Constraints, Criteria (ISC IDs + end-states), Out of Scope | **`ISA.md`** (this repo) | nowhere else. It is a PAI-Algorithm artifact and may be regenerated — keep it to what must *always* hold, never history or status |
| **Milestone / release history** — what shipped, when, under which tag | **SSH-signed git tags + `CHANGELOG.md`** (root) | ISA / `lama.yaml` / `README.md` carry a *pointer*, never a milestone table |
| **Live ISC coverage / count** | **`cargo xtask isc-coverage`** (registry `isc_coverage::TOTAL`) | never hand-write an ISC count anywhere; cite the command |
| **Pending work — actionable, scoped** | **GitHub Issues** — type label (`bug` / `enhancement` / `documentation`) + tier label (`tier:punchlist` / `tier:candidate` / `tier:backlog`; unlabeled tier = needs triage) | closed the ordinary way (`Closes #N` in a PR/commit); never duplicated in-tree |
| **Forward-looking — speculative ideas + design-first epics (not yet actionable)** | **`ROADMAP.md`** (root) — `Ideas` / `Designs` / `Features`, forward-only, no status/history | an item graduates into GitHub issue(s) and is removed; a Design points at its `docs/design/` doc |
| **Design-of-record** — rationale for a design-first epic | **`docs/design/*.md`** (RFC-lite) | persists after spawning issues; it is rationale, not status or history |
| **Cross-project / night-run orchestration** | **maintainer-held, out of tree** (vault) — intentionally not in this repo | the repo carries no cross-project planning |
| **Public API surface** (per crate) | **`docs/llm-api-manifest/*-api.yaml`** | the full LAMA manifests |
| **API-discovery summary** | **`lama.yaml`** (root) — concise capabilities + manifest pointer | no milestone / coverage / status state in this file |
| **Crypto suites** (current + deprecated) | **`daemonseed_core::crypto::suite::Registry`** — supported set, enforced at runtime (`Registry::lookup`); wire tags are `SuiteId` in `daemonseed_proto::v1` | ISC-S15/S16/A-S10/A-S11/C24/C25 (`ISA.md`) govern the rules; never hand-copy the suite list elsewhere |
| **Release version** | **git tags** (Cargo is tag-driven, stays `0.1.0`) | `lama.yaml` `version` + `README.md` `## Status` + `daemonseed-gui`'s `APP_VERSION` (`crates/daemonseed-gui/src/main.rs`) — all three stamped at release from the tag |

## Issue tracking, roadmap & design docs

Three surfaces, one direction of flow — speculative → designed → actionable:

- **GitHub Issues** hold every *concrete, scoped deliverable* (bugs, enhancements, tasks). Type label (`bug`/`enhancement`/`documentation`) + tier label (`tier:punchlist` hot → `tier:candidate` warm → `tier:backlog` cold; **unlabeled tier = needs triage**). A PR closes its issue the ordinary way — `Closes #N` / `Fixes #N` in the PR or commit, auto-closing on merge to `main`.
- **`ROADMAP.md`** (root) holds *forward-looking work that is not yet a deliverable*: `Ideas` (speculative), `Designs` (design-first epics, one-line pointers to `docs/design/`), `Features` (wanted-but-deferred). Forward-only, no status/history. When an item is decomposed into actionable work it **becomes GitHub issue(s) and is removed** from `ROADMAP.md`.
- **`docs/design/*.md`** hold the *design-of-record* for design-first epics (RFC-lite: problem → constraints/ISC invariants → approach → open questions). An accepted design spawns issues; the doc **persists** as rationale.

So: an idea enters `ROADMAP.md`; if it needs design, it gets a `docs/design/` doc; once actionable, it graduates into GitHub issues (the roadmap entry is removed, the design doc stays). Nothing here records *status* or *history* — that is issues + git tags + `CHANGELOG.md`.

**Cross-references are hard-bounded to repo-canonical artifacts.** An issue, `ROADMAP.md` entry, or `docs/design/` doc may freely cite the repo `ISA.md`'s `ISC-N` / `ISC-A-N` IDs and repo paths/docs — they are permanent, shared, and authoritative. It must **never** cite a contributor's own local / working-draft / PRD language or its private ISC numbering: those are personal scratch, may diverge from the repo, and mean nothing (or mislead) to anyone else. The test: **if a reference resolves inside the repo, it belongs; if it only resolves in someone's local notes, it does not.**

## Branch & merge workflow

Every change lands on `main` through a **pull request** — never a direct push or a local fast-forward to `main`, even for a single-author or trivial change.

1. Branch from `main`; push the branch and open a PR (`gh pr create`).
2. Review before merge. A trust-surface change — crypto, the signer whitelist / announce write-gate, provenance, identity/key derivation — warrants a thorough review pass called out in the PR.
3. Merge by a **signature-preserving** path (this repo signs commits): a local fast-forward of the PR branch, or `gh pr merge --merge`. Never `--rebase` / `--squash` — they re-create the commits server-side and drop the SSH signature, landing an unsigned commit on `main`.
4. The **release-chore** — version stamps (`lama.yaml`, `README.md` `## Status`, `daemonseed-gui`'s `APP_VERSION`) and the `CHANGELOG.md` `[Unreleased]` → `[vX.Y.Z]` rename — plus the signed tag are a **separate post-merge** step, never bundled into a feature PR (see *Cutting a release tag* below).

## Definition of done

Every task is incomplete until all of these pass:

1. `cargo fmt --all --check` — no unformatted code
2. `cargo clippy --workspace --all-targets -- -D warnings` — no warnings
3. `cargo test --workspace` — all tests pass
4. `cargo xtask check-proto` — generated protobuf code matches the committed snapshot (per the hybrid codegen decision: `build.rs` regenerates each build; CI verifies the committed snapshot)
5. **Doc-sync** — the commit is the gate: every commit that changed tracked state landed with its documentation already true (see **Doc-sync reconciliation**). This is the judgment gate alongside the four mechanical checks.

Run checks 1–4 as the last step before handing control back to the user, and re-run after any post-review fix-ups; check 5 (doc-sync) is applied per-commit as you go, not deferred to handback. If `cargo fmt --all --check` reports diffs, run `cargo fmt --all` to fix them before the clippy step — clippy output is easier to read on formatted code.

**Cutting a release tag:** run `cargo xtask release-gate` before `git tag`. It runs the full DoD gate (fmt · clippy workspace + `daemonseed-gui --features desktop` · `test --workspace` · check-proto · isc-coverage) and exits non-zero naming any red step, so a tag is never created on a red tree — the v0.29.0 slip, where a tag was cut while `test --workspace` was red. The pre-push hook is the backstop on push; the release-gate stops the tag being created in the first place.

## Documentation sync at every commit point

At each commit boundary, refresh documentation while the context is fresh. For any commit that touches a crate — directly or by reference — do all of:

1. **Rustdoc.** Update the `lib.rs` header and any affected item docs of every crate changed or referenced. Run `cargo doc --workspace --no-deps` and resolve any new warnings in crates the commit touched.
2. **ISC alignment.** Confirm the change is consistent with the design contract. If it requires a new or modified ISC, update **`ISA.md`** `## Criteria` in this repo in the same commit. IDs are permanent: never renumber; splits become `ISC-N.M`; drops leave a reserved tombstone. If the change is wire-visible, also confirm the SemVer impact (PATCH / MINOR / MAJOR) and call it out in the commit body.
3. **README.** Update `README.md` if the commit changes user-facing status — crate added / removed, build instructions, project phase, supported platforms.
4. **LAMA manifests.** Update `lama.yaml` (root, concise capabilities + pointer summary) and the relevant `docs/llm-api-manifest/*-api.yaml` if the commit adds, removes, renames, or changes the signature of any public function, type, trait, RPC service, message type, CLI subcommand, or server-config field. The manifests are how AI agents discover the project surface; they must stay in sync with the code **and with the LAMA spec (`SPEC.md`)** at <https://github.com/lamaspec/lama> — the root `lama.yaml` stays a concise capabilities + manifest pointer (SPEC § "Repository discovery"), never a milestone / coverage / status board (see **Canonical homes**); re-read `SPEC.md` against it at every commit that touches it so it doesn't re-accrete that cruft. A pre-commit hook enforces this for Rust public signatures once it lands (`scripts/git-hooks/pre-commit`). **No human names in LAMA.** The manifests are AI-reference only — names of developers, daemons, maintainers, or testers are not relevant to an agent implementing against the API and do not belong here. Upstream organization or project names (e.g., the `friendly-words` source attribution) are acceptable when they carry licensing or provenance information; personal names are not.

**Reference docs state bare present-tense facts, not prose or history.** The LAMA manifests and `CHANGELOG.md` exist to reduce a contributor-LLM's inference friction, so keep them to the fact: a manifest `description:` is a one-line statement of *what the thing is and does now* (the SPEC's "one-line purpose"); a changelog entry is a terse catalog line of *what changed*, citing `(#N)` where an issue/PR exists. Keep OUT of both: history ("replaces X", "was cleartext", "the alpha shipped…"), rationale or mechanism ("so that…", "because the relay…"), and compares-to narrative ("mirrors Y", "the request half of…"). Those live elsewhere and are reached by pointer — history via the git tag + changelog, rationale via `docs/design/*.md`, the contract via `ISA.md`. If an entry reads like a paragraph, it has drifted; cut it to the fact. (The full crate surface — signatures, parameters, errors, sequencing — still belongs in the manifest; it is the *narrative* that does not.)

Run `cargo fmt --all` before staging the commit so formatting is always clean. These doc updates ship **in the same commit** as the code change — not as a follow-up — so reviewers always see the code and its documentation evolve together.

## Doc-sync reconciliation — the commit IS the gate

There is no separate, deferrable gate. **The commit is the doc-sync gate.** Every commit lands with its documentation already true — the same discipline for a feature, a refactor, a manifest-only fix, or a release. Leaving the gate undefined (a PR? a batch? a milestone? a handoff?) is exactly how doc-sync slips and debt accumulates: each undefined gate becomes an excuse to defer to the next one, and deferred doc-sync is usually *lost* doc-sync. Making every commit the gate closes that gap permanently — including the API manifests, which are the surface most often left stale by a "later" that never comes.

**This is a deliberate trade, and we carry the extra per-commit work gladly:** it is far cheaper than reconstructing cold, and it means a session can stop, restart, or hand off at *any* commit with the repo and project state already correct — nothing to catch up on. A commit's documentation is not a follow-up to its code; it is part of the same unit of work. **For contributors: your doc-sync is as much a part of the commit as the code — a reviewer blocks on a commit whose docs are stale exactly as they would on a failing test. The doc work matters as much as the code it documents.**

**Why this is enforced:** stale docs and stale project context burn inference. Every fact a future session or contributor must reconstruct — because it was true and known *now* but never written down — is paid for again later, at higher cost and lower fidelity. Capture-while-hot is near-zero cost; reconstruct-when-cold compounds.

At every commit, reconcile every one of the following that the change affects — do not stop at the one or two surfaces you happened to touch. A `CHANGELOG.md` entry under `## [Unreleased]` is added on **every** PR / notable / issue-fixing commit, at the moment it lands — entries accumulate there between releases. Only the **signed tag** and the **`version` stamps** are release-tied (they fire on the commit that ships a release). Everything else is kept current on **every** commit:

1. **`CHANGELOG.md`** (canonical change history) — a changelog entry is part of **every** change-bearing PR / commit, NOT deferred to a release tag. Add the change under `## [Unreleased]` in Keep-a-Changelog form (`### Added` / `### Changed` / `### Fixed` / `### Removed`) at the moment it lands; entries pile up there until a release. **At release**, rename the `## [Unreleased]` block to `## [vX.Y.Z] — <date>` matching the SSH-signed tag (`git tag --verify vX.Y.Z`) and open a fresh empty `## [Unreleased]`. The tag is the durable anchor; the changelog is its human/agent-readable rendering. This is the ONLY place change/milestone history is recorded — do not re-list it elsewhere. (Planning for *unstarted* work stays in the vault manifest, never here — `[Unreleased]` is for changes that have *landed*.)
2. **`ISA.md`** — frozen contract only: add `## Decisions` entries for boundary-level design calls, `## Verification` evidence, and any new/changed `## Criteria`. Principles, Constraints, Criteria wording, and Out of Scope change only here, deliberately, in the PR. **Do NOT add milestone rows or release narrative** — history is git tags + `CHANGELOG.md` (see **Canonical homes**).
3. **`README.md` `## Status`** — the current-release line only (the version + a one-line "what it is now"), with a pointer to `CHANGELOG.md` for the per-release detail. Do not grow a multi-release narrative here; that duplicates the changelog and is the surface most prone to silent drift.
4. **`lama.yaml` (root) + `docs/llm-api-manifest/*-api.yaml`** — bump the `version` field to the release; conform both to the LAMA spec, `SPEC.md` at <https://github.com/lamaspec/lama> (root stays a concise capabilities + manifest pointer, **no** milestone/coverage/status); update the per-crate manifests for any crate whose surface the batch changed. **Also stamp `daemonseed-gui`'s `APP_VERSION` (`crates/daemonseed-gui/src/main.rs`) to the release version** — it is the in-app version label and drifts silently if forgotten (it read `v0.32.0` through the v0.33.0 release). All three version surfaces — `lama.yaml`, `README.md` `## Status`, and `APP_VERSION` — move together at the tag.

**Every item above is a contributor requirement** — a PR is incomplete without them, and a reviewer should block on stale repo docs exactly as on a failing test.

**Completion gate (per commit):** a commit is not done until every applicable item above is either updated or explicitly confirmed unaffected — and that reconciliation ships *in the commit*, not as a later pass. State it in the commit body when it's substantive (e.g. "doc-sync: CHANGELOG [Unreleased] + ISA Decisions/Verification + tui/core API manifests + README Status"). A change-bearing commit adds its `CHANGELOG.md` `[Unreleased]` entry as part of the commit; at a release, rename `[Unreleased]` → `[vX.Y.Z]` and add the signed-tag + version-stamp line. Because every commit honors this, stopping / handing off / refreshing context requires no catch-up: the state of the world is already true. If you ever find a doc surface stale at a boundary, a prior commit skipped its gate — fix it in the next commit, hot, rather than letting it ride.

## License posture

- **Code crates** (`daemonseed-core`, `daemonseed-cli`, `daemonseed-tui`, `daemonseed-veilid-net`, `xtask`): **AGPL-3.0-or-later**.
- **Schema crate** (`daemonseed-proto`): **Apache-2.0 OR MIT dual** (Rust-ecosystem default).

When adding a new crate, set its `Cargo.toml` `license` field per this split. The schema carve-out exists so cross-language client implementations can exist freely without copyleft viral concerns. Repo root carries three LICENSE files (`LICENSE-AGPL`, `LICENSE-APACHE`, `LICENSE-MIT`); per-crate `license` fields select the correct one(s) for each crate.
