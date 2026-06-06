# Project instructions — daemonseed

Standing rules for any AI assistant working in this repository. These are loaded automatically at the start of every session by any agent or assistant that respects `AGENTS.md`. The file is intentionally model-agnostic — phrase everything in terms of "the assistant" or imperative; do not assume a specific tool or vendor.

## Project context

Daemonseed is a federated, end-to-end-encrypted communication and file-sharing protocol — a Rust-native successor to Demonsaw, informed by lineage but built clean (zero lines of Demonsaw code). Backend is pure Rust, no C dependencies. Crypto stack is CNSA 2.0 via the oxicrypt crate + rustls. Wire is gRPC-over-h2 (prost / tonic). Storage is a three-layer split: encrypted seeds file + redb indexed state + content-addressed chunk filesystem. Threat model is Level-C adversarial; the censorship-survivability bar is "survive the GFW" per Wu et al., USENIX Security 2023. License: AGPL-3.0-or-later on code crates; Apache-2.0 OR MIT dual on the `daemonseed-proto` schema crate.

## Key paths

- **Repo:** `~/repos/daemonseed` (this repository)
- **Sibling crypto/TLS foundation:** `~/repos/oxicrypt` — currently private; goes public before daemonseed does. daemonseed depends on it for CNSA 2.0 primitives, AEAD, KDF, and TLS 1.3 glue.
- **Project folder (internal to project lead):** `~/carakastan/Projects/DaemonSeed/` — design docs, ISCs, suite registry, working notes. **Internal to caraka during the private phase**; selected artifacts will be promoted to this repo before the repo opens publicly.

## Session bootstrap

At the start of every session — or after a context reset — read these in order before doing anything else:

1. **`~/carakastan/Projects/DaemonSeed/llm-project-manifest.yaml`** — current state of the world. What exists, what's complete vs partial vs stub. No plans, no priorities; just facts. Outside this repo because it references internal paths.
2. **`ISA.md`** (in this repo) — the Ideal State Artifact: the **authoritative** design contract and system of record. Read its Problem / Vision / Principles / Constraints / Out of Scope before changing any boundary. Each ISC is a verifiable end-state; each `ISC-A-*` is a forbidden state; IDs are permanent (never renumbered, vacated IDs stay reserved). The full ISC inventory is `ISA.md` `## Criteria`; the live count and coverage come from `cargo xtask isc-coverage` — neither is hand-written here or anywhere else (see **Canonical homes** above for why no surface carries a duplicate count). The client surface is intentionally the larger side because daemonseed's complexity lives at the client (identity, federation trust, suite agility, first-start, trust-event taxonomy).
3. **`~/carakastan/Projects/DaemonSeed/ds-suite-registry.md`** — current and deprecated cryptographic suite definitions. Companion to ISC-S15 / S16 / A-S10 / A-S11 / C24 / C25 / A-C8 / A-C9.
4. **`docs/llm-api-manifest/` in this repo** — LAMA manifests describing the public API surfaces of each crate. AI agents helping cross-language client implementers consume these. Stubbed at repo creation; grows as the API grows.

The manifest at #1 and the suite registry at #3 live **outside this repo** because they contain internal paths and working-draft notes that should not be committed to version control. Update them as part of doc-sync (below) when commits change tracked state. **Do not commit them.** The ISA at #2 *is* in this repo and is authoritative — update it here, in the same commit batch as any code change that moves a boundary.

The ISC document has been promoted into this repo as the sanitized **`ISA.md`** (2026-05-29). The suite registry promotion is still pending — decide at its own PR whether `ds-suite-registry.md` follows the ISA into the repo or stays vault-side.

## Canonical homes

Every kind of project fact has exactly **one** canonical home. Do not duplicate a fact across surfaces — copies drift, and a drifted copy is worse than no copy. To read a fact, read its canonical home; to change a fact, update only its canonical home (and any *pointer* that names it — never a second copy of the value).

| Fact | Canonical home | Everything else |
|------|----------------|-----------------|
| **Design contract** — Problem, Vision, Principles, Constraints, Criteria (ISC IDs + end-states), Out of Scope | **`ISA.md`** (this repo) | nowhere else. It is a PAI-Algorithm artifact and may be regenerated — keep it to what must *always* hold, never history or status |
| **Milestone / release history** — what shipped, when, under which tag | **SSH-signed git tags + `CHANGELOG.md`** (root) | ISA / `lama.yaml` / `README.md` carry a *pointer*, never a milestone table |
| **Live ISC coverage / count** | **`cargo xtask isc-coverage`** (registry `isc_coverage::TOTAL`) | never hand-write an ISC count anywhere; cite the command |
| **In-progress / next milestone / state-of-world** | **vault `llm-project-manifest.yaml`** (uncommitted; project-lead) | the repo carries no "in-progress / pending / planned" status |
| **Public API surface** (per crate) | **`docs/llm-api-manifest/*-api.yaml`** | the full LAMA manifests |
| **API-discovery summary** | **`lama.yaml`** (root) — concise capabilities + manifest pointer | no milestone / coverage / status state in this file |
| **Crypto suites** (current + deprecated) | **vault `ds-suite-registry.md`** (uncommitted) | companion to ISC-S15/S16/A-S10/A-S11/C24/C25 |
| **Release version** | **git tags** (Cargo is tag-driven, stays `0.1.0`) | `lama.yaml` `version` + `README.md` stamped at release from the tag |

**LAMA conformance is a standing rule, checked at every doc-sync.** `lama.yaml` and every `docs/llm-api-manifest/*-api.yaml` MUST conform to the LAMA specification at **`~/repos/lama/SPEC.md`** (canonical: <https://github.com/lamaspec/lama>). In particular, the root `lama.yaml` is a *concise capabilities + manifest pointer* for fast agent triage (SPEC § "Repository discovery"; target ~30–60 lines) — **not** a status board. Re-read SPEC.md against `lama.yaml` at every commit that touches it so the file does not re-accrete milestone / coverage / planning cruft. (It did once — a 559-line `lama.yaml` stuffed with `milestones_complete` / `milestones_planned` / `isc_reference` — which is exactly why this rule is written down.)

## Standards target

- **Crypto bundle:** CNSA 2.0 (ML-DSA-87 + ML-KEM-1024 + AES-256-GCM + SHA-384). The suite registry tracks current + deprecated suites. CNSA 2.1 is anticipated within ~12 months; the architecture is designed to absorb it via additive MINOR bumps — see ISC-S14 wire-protocol versioning and the BIP-39 + HKDF root-of-derivation rationale (ISC-C1 / ISC-C2).
- **Censorship-survivability bar:** Wu et al., USENIX Security 2023 (negative-allowlist GFW detection). ALPN is set to a generic value (`h2`); application-protocol identification happens after TLS handshake; first TLS record on :443 satisfies GFW Ex5 by construction.
- **Wire protocol versioning:** SemVer 2.0. MINOR bumps MUST be additive-only (per ISC-S14 / A-S9 / C23). MAJOR bumps may break wire compatibility but are the last resort.

## Definition of done

Every task is incomplete until all of these pass:

1. `cargo fmt --all --check` — no unformatted code
2. `cargo clippy --workspace --all-targets -- -D warnings` — no warnings
3. `cargo test --workspace` — all tests pass
4. `cargo xtask check-proto` — generated protobuf code matches the committed snapshot (per the hybrid codegen decision: `build.rs` regenerates each build; CI verifies the committed snapshot)

Run all four as the last step before handing control back to the user, and re-run after any post-review fix-ups. If `cargo fmt --all --check` reports diffs, run `cargo fmt --all` to fix them before the clippy step — clippy output is easier to read on formatted code.

## Documentation sync at every commit point

At each commit boundary, refresh documentation while the context is fresh. For any commit that touches a crate — directly or by reference — do all of:

1. **Rustdoc.** Update the `lib.rs` header and any affected item docs of every crate changed or referenced. Run `cargo doc --workspace --no-deps` and resolve any new warnings in crates the commit touched.
2. **ISC alignment.** Confirm the change is consistent with the design contract. If it requires a new or modified ISC, update **`ISA.md`** `## Criteria` in this repo in the same commit (the ISC document was promoted in-repo on 2026-05-29 — there is no longer a vault `ds-isc-draft.md`; the ISA is the single home, see **Canonical homes**). IDs are permanent: never renumber; splits become `ISC-N.M`; drops leave a reserved tombstone. If the change is wire-visible, also confirm the SemVer impact (PATCH / MINOR / MAJOR) and call it out in the commit body.
3. **README.** Update `README.md` if the commit changes user-facing status — crate added / removed, build instructions, project phase, supported platforms.
4. **LAMA manifests.** Update `lama.yaml` (root, concise capabilities + pointer summary) and the relevant `docs/llm-api-manifest/*-api.yaml` if the commit adds, removes, renames, or changes the signature of any public function, type, trait, RPC service, message type, CLI subcommand, or server-config field. The manifests are how AI agents discover the project surface; they must stay in sync with the code **and with the LAMA spec at `~/repos/lama/SPEC.md`** (canonical: <https://github.com/lamaspec/lama>) — the root `lama.yaml` stays a concise capabilities + manifest pointer (SPEC § "Repository discovery"), never a milestone / coverage / status board (see **Canonical homes**). A pre-commit hook enforces this for Rust public signatures once it lands (`scripts/git-hooks/pre-commit`). **No human names in LAMA.** The manifests are AI-reference only — names of developers, daemons, maintainers, or testers are not relevant to an agent implementing against the API and do not belong here. Upstream organization or project names (e.g., the `friendly-words` source attribution) are acceptable when they carry licensing or provenance information; personal names are not. The vault-side project manifest follows the same rule.
5. **Project manifest.** Update `~/carakastan/Projects/DaemonSeed/llm-project-manifest.yaml` if the commit changes the status of any tracked item — new crate, doc completion, milestone close, release bump, external dependency update, etc. Lives outside this repo; **do not commit**. **Do this in the same work batch as the commit, while the context is fresh — NOT deferred to a milestone-end or post-merge pass.** It can't ship *in* the commit (it's vault-local), but it must be refreshed at the same moment, not afterwards: the manifest is the project's state-of-the-world, and a stale manifest misleads the next session. Deferring it is how it rots.
6. **User / operator manual gem check.** Pause and ask: *did this commit, or the conversation that produced it, surface anything a future user or operator would want explained in their voice — privacy claims they can rely on, OPSEC choices they need to make, what doxes them and what doesn't, what an operator sees vs doesn't see, governance commitments, recovery-failure modes, censorship-survivability guarantees?* The check is both **reactive** (a real question was asked we should write the answer down) and **proactive** (an explanation emerged in implementation that a user would benefit from even though nobody asked — capture it before it cools). If yes, append a dated Q&A or topic block to the appropriate vault scratch file:
    - Client-facing material → `~/carakastan/Projects/DaemonSeed/docs-draft/user-manual-scratch.md`
    - Operator-facing material → `~/carakastan/Projects/DaemonSeed/docs-draft/operator-manual-scratch.md`

    Both files are vault-local and append-only during the private phase. No polish, no reorganization — just capture explanations as-given with date + topic. Polish + organization happen as a dedicated pass at the MVP gate when scratch becomes `docs/user/` and `docs/operator/` in the repo. The discipline is the same as the implementer-facing insight capture below: forcing the thought at each commit gate, not producing a gem on every commit. The cost of capture-while-warm is near-zero; the cost of skip-and-reconstruct compounds.

Run `cargo fmt --all` before staging the commit so formatting is always clean. These doc updates ship **in the same commit** as the code change — not as a follow-up — so reviewers always see the code and its documentation evolve together.

## Insight capture at every commit

Before staging any commit — not only commits that touch documentation — pause and ask: *did this session surface any mechanistic insight — about why a design choice is correct, how a security or federation property is guaranteed, what structural constraint prevents a class of bug, or why an interoperability property holds — that a community contributor, security researcher, or future implementer would need to understand?*

If yes, write it into the relevant documentation (rustdoc, README, or a `docs/` markdown file) in the same commit. Good candidates:

- Language/compiler guarantees that enforce a security property (e.g., the type-state pattern preventing pre-HELLO traffic per ISC-C23; `Drop` ordering ensuring zeroization; `forbid(unsafe_code)` as a build-time control).
- Composition patterns that extend coverage transitively (e.g., the no-keys-in-introducer invariant per ISC-S6 preventing transitive-trust collapse; constant-time CoT-hash presence-detection per ISC-S17 closing the timing-side-channel against ISC-A-S2).
- Rationale for why a design approach is complete — especially when completeness is non-obvious.
- Federation properties where two components intentionally diverge because they implement different invariants, and where the divergence would otherwise look like a bug.

Insights surface during code work, not during doc work. A manifest-only commit or a refactor commit is just as likely to expose a gem as a feature commit — so this check runs at **every** commit gate. Capture every gem while the context is warm; a gem deferred is usually a gem lost. When no gem applies, that is a valid outcome — many commits legitimately surface none. The discipline is forcing the thought at each commit gate, not producing a gem on every commit.

## Doc-sync reconciliation — the boundary IS the commit

There is no separate, deferrable "boundary." **The boundary is the commit.** Every commit lands with its documentation already true — the same discipline for a feature, a refactor, a manifest-only fix, or a release. Leaving "boundary" undefined (a PR? a batch? a milestone? a handoff?) is exactly how doc-sync slips and debt accumulates: each undefined boundary becomes an excuse to defer to the next one, and deferred doc-sync is usually *lost* doc-sync. Defining the boundary as the commit closes that gap permanently — including the API manifests, which are the surface most often left stale by a "later" that never comes.

**This is a deliberate trade, and we carry the extra per-commit work gladly:** it is far cheaper than reconstructing cold, and it means a session can stop, restart, or hand off at *any* commit with the repo and project state already correct — nothing to catch up on. A commit's documentation is not a follow-up to its code; it is part of the same unit of work. **For contributors: your doc-sync is as much a part of the commit as the code — a reviewer blocks on a commit whose docs are stale exactly as they would on a failing test. The doc work matters as much as the code it documents.**

**Why this is enforced:** stale docs and stale project context burn inference. Every fact a future session or contributor must reconstruct — because it was true and known *now* but never written down — is paid for again later, at higher cost and lower fidelity. Capture-while-hot is near-zero cost; reconstruct-when-cold compounds.

At every commit, reconcile every one of the following that the change affects — do not stop at the one or two surfaces you happened to touch. The release-tied items (the `CHANGELOG.md` entry + signed tag, and the `version` stamps) fire on the commit that ships a release; everything else is kept current on **every** commit:

1. **`CHANGELOG.md` + the git tag** (canonical milestone history) — when a release is tagged, add exactly one `CHANGELOG.md` entry for it, matching the SSH-signed tag (`git tag --verify vX.Y.Z`). The tag is the durable anchor; the entry is its human/agent-readable rendering. No release ships without its entry. This is the ONLY place shipped milestone history is recorded — do not re-list it elsewhere.
2. **`ISA.md`** — frozen contract only: add `## Decisions` entries for boundary-level design calls, `## Verification` evidence, and any new/changed `## Criteria`. Principles, Constraints, Criteria wording, and Out of Scope change only here, deliberately, in the PR. **Do NOT add milestone rows or release narrative** — history is git tags + `CHANGELOG.md` (see **Canonical homes**).
3. **`README.md` `## Status`** — the current-release line only (the version + a one-line "what it is now"), with a pointer to `CHANGELOG.md` for the per-release detail. Do not grow a multi-release narrative here; that duplicates the changelog and is the surface most prone to silent drift.
4. **`lama.yaml` (root) + `docs/llm-api-manifest/*-api.yaml`** — bump the `version` field to the release; conform both to `~/repos/lama/SPEC.md` (root stays a concise capabilities + manifest pointer, **no** milestone/coverage/status); update the per-crate manifests for any crate whose surface the batch changed.
5. **Vault project manifest** (`~/carakastan/Projects/DaemonSeed/llm-project-manifest.yaml`, **do not commit**) — `current_release`, `milestones_in_progress`, and `next_milestone` (planning only). Shipped history is **not** re-listed here — point it at `CHANGELOG.md` + git tags. Never leave "in progress" / "kicked off" framing on completed work.
6. **Suite registry** (`~/carakastan/Projects/DaemonSeed/ds-suite-registry.md`, **do not commit**) — if the boundary touched cryptographic suites.
7. **Gem capture.** Sweep the whole batch's conversation for (a) user/operator-facing explanations → append to the manual scratch files (per the gem check above), and (b) implementer/security insights → rustdoc/README/`docs/`. The boundary is the highest-yield capture moment because the entire batch's reasoning is still in context; once it cools the gem is usually lost.

**Repo docs vs. vault docs — contributor scope.** Items 1–4 and the in-repo half of 7 (rustdoc / README / `docs/`) are **required of every contributor** as part of the PR — a PR is incomplete without them, and a reviewer should block on stale repo docs. Items 5, 6, and the scratch-file half of 7 are **vault-local** (`~/carakastan/Projects/DaemonSeed/`) and require project-folder access: they are the **project lead's responsibility**, reconciled at the same boundary by whoever holds that access. An outside contributor neither can nor must update them — their doc-sync obligation is fully discharged by keeping the in-repo docs current, and the vault docs are never a blocker on an external PR.

**Completion gate (per commit):** a commit is not done until every applicable item above is either updated or explicitly confirmed unaffected — and that reconciliation ships *in the commit*, not as a later pass. State it in the commit body when it's substantive (e.g. "doc-sync: ISA Decisions/Verification + tui/core API manifests + README Status; manifest refreshed in vault"), and at a release add the CHANGELOG-entry + signed-tag + version-stamp line. Because every commit honors this, stopping / handing off / refreshing context requires no catch-up: the state of the world is already true. If you ever find a doc surface stale at a boundary, a prior commit skipped its gate — fix it in the next commit, hot, rather than letting it ride.

## License posture

- **Code crates** (`daemonseed-core`, `daemonseed-server`, `daemonseed-cli`, `daemonseed-tui`, `xtask`): **AGPL-3.0-or-later**.
- **Schema crate** (`daemonseed-proto`): **Apache-2.0 OR MIT dual** (Rust-ecosystem default).

When adding a new crate, set its `Cargo.toml` `license` field per this split. The schema carve-out exists so cross-language client implementations can exist freely without copyleft viral concerns. Repo root carries three LICENSE files (`LICENSE-AGPL`, `LICENSE-APACHE`, `LICENSE-MIT`); per-crate `license` fields select the correct one(s) for each crate.

## Workspace hygiene — worktree placement

When creating a git worktree (`git worktree add` or any tool that initiates one), place it inside **the directory the current session was launched from** (the session's CWD), not unconditionally inside this repo. Worktree path: `<session-cwd>/.worktrees/<branch-name>/`.

- **Bare-repo case** — session launched in this repo (e.g. `cd ~/repos/daemonseed && claude`). CWD == repo root. Worktree at `~/repos/daemonseed/.worktrees/<branch-name>/`. `.worktrees/` is already in `.gitignore`.
- **Meta-project case** — session launched in the project folder (`~/carakastan/Projects/DaemonSeed/`) while doing work on this repo. CWD != repo root. Worktree at `~/carakastan/Projects/DaemonSeed/.worktrees/<branch-name>/`. The project folder is the vault — not a git repo — and is already excluded from version control by being outside this repo, so no gitignore entry is required there.

**Why:** Claude Code (and equivalent assistants) scope filesystem permissions to the session's CWD. Worktrees inside that directory get implicit Read / Write / Edit / Bash access without per-operation permission prompts. Worktrees outside it require explicit allowlisting per access pattern, which does not scale across subagent dispatches. The rule is permission-driven, not repo-location-driven — "put it where the session is rooted" beats the naive "put it where the source repo lives".

For Rust workspace path-dependencies that expect a sibling crate (notably `daemonseed`'s dependency on `oxicrypt`), create a symlink inside the worktree's parent pointing at the source repo: `ln -s ~/repos/oxicrypt <worktree-parent>/oxicrypt`. Worktrees are ephemeral — created for the feature, removed after merge. Branches and commits persist in the source repo's `.git/`.

## Working style — check in at batch boundaries

Sessions may run on a laptop or a workstation; sessions often run for hours. Long sessions are fine — but **check in before starting a new batch of work** so the user is not forced to interrupt a running batch with a shutdown or context switch.

A "batch" is any unit that will run for more than a few minutes without a natural break. Before starting one, state what's in it and roughly how long it'll take, so the user can say "go" or "not now". This applies equally to refactor passes, multi-crate cargo runs, and exploratory code-spelunking sessions.
