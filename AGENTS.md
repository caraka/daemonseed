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
2. **`~/carakastan/Projects/DaemonSeed/ds-isc-draft.md`** — the working Ideal State Criteria document. Authoritative design source during the private phase. Each ISC is a verifiable end-state; each ISC-A is a forbidden state. Currently 96 ISCs (60 server-side + 36 client-side).
3. **`~/carakastan/Projects/DaemonSeed/ds-suite-registry.md`** — current and deprecated cryptographic suite definitions. Companion to ISC-S15 / S16 / A-S10 / A-S11 / C24 / C25 / A-C8 / A-C9.
4. **`docs/llm-api-manifest/` in this repo** — LAMA manifests describing the public API surfaces of each crate. AI agents helping cross-language client implementers consume these. Stubbed at repo creation; grows as the API grows.

The manifest at #1, the ISC draft at #2, and the suite registry at #3 live **outside this repo** because they contain internal paths and working-draft notes that should not be committed to version control. Update them as part of doc-sync (below) when commits change tracked state. **Do not commit them.**

When the repo opens publicly, caraka will promote sanitized versions of the ISC document and suite registry into this repo and rewrite this section to point at the in-repo locations.

## Standards target

- **Crypto bundle:** CNSA 2.0 (ML-DSA-87 + ML-KEM-1024 + AES-256-GCM + SHA-256). The suite registry tracks current + deprecated suites. CNSA 2.1 is anticipated within ~12 months; the architecture is designed to absorb it via additive MINOR bumps — see ISC-S14 wire-protocol versioning and the BIP-39 + HKDF root-of-derivation rationale (ISC-C1 / ISC-C2).
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
2. **ISC alignment.** Confirm the change is consistent with the ISC document. If the change requires a new or modified ISC, update the ISC draft in the project folder in the same logical batch — commit the code in this repo; update the ISC draft in `~/carakastan/Projects/DaemonSeed/ds-isc-draft.md`. If the change is wire-visible, also confirm the SemVer impact (PATCH / MINOR / MAJOR) and call it out in the commit body.
3. **README.** Update `README.md` if the commit changes user-facing status — crate added / removed, build instructions, project phase, supported platforms.
4. **LAMA manifests.** Update `lama.yaml` (root, quick-triage summary) and the relevant `docs/llm-api-manifest/*-api.yaml` if the commit adds, removes, renames, or changes the signature of any public function, type, trait, RPC service, message type, CLI subcommand, or server-config field. The manifests are how AI agents discover the project surface; they must stay in sync with the code. A pre-commit hook enforces this for Rust public signatures once it lands (`scripts/git-hooks/pre-commit`).
5. **Project manifest.** Update `~/carakastan/Projects/DaemonSeed/llm-project-manifest.yaml` if the commit changes the status of any tracked item — new crate, doc completion, external dependency update, etc. Lives outside this repo; **do not commit**.

Run `cargo fmt --all` before staging the commit so formatting is always clean. These doc updates ship **in the same commit** as the code change — not as a follow-up — so reviewers always see the code and its documentation evolve together.

## Insight capture at every commit

Before staging any commit — not only commits that touch documentation — pause and ask: *did this session surface any mechanistic insight — about why a design choice is correct, how a security or federation property is guaranteed, what structural constraint prevents a class of bug, or why an interoperability property holds — that a community contributor, security researcher, or future implementer would need to understand?*

If yes, write it into the relevant documentation (rustdoc, README, or a `docs/` markdown file) in the same commit. Good candidates:

- Language/compiler guarantees that enforce a security property (e.g., the type-state pattern preventing pre-HELLO traffic per ISC-C23; `Drop` ordering ensuring zeroization; `forbid(unsafe_code)` as a build-time control).
- Composition patterns that extend coverage transitively (e.g., the no-keys-in-introducer invariant per ISC-S6 preventing transitive-trust collapse; constant-time CoT-hash presence-detection per ISC-S17 closing the timing-side-channel against ISC-A-S2).
- Rationale for why a design approach is complete — especially when completeness is non-obvious.
- Federation properties where two components intentionally diverge because they implement different invariants, and where the divergence would otherwise look like a bug.

Insights surface during code work, not during doc work. A manifest-only commit or a refactor commit is just as likely to expose a gem as a feature commit — so this check runs at **every** commit gate. Capture every gem while the context is warm; a gem deferred is usually a gem lost. When no gem applies, that is a valid outcome — many commits legitimately surface none. The discipline is forcing the thought at each commit gate, not producing a gem on every commit.

## License posture

- **Code crates** (`daemonseed-core`, `daemonseed-server`, `daemonseed-cli`, `daemonseed-tui`, `xtask`): **AGPL-3.0-or-later**.
- **Schema crate** (`daemonseed-proto`): **Apache-2.0 OR MIT dual** (Rust-ecosystem default).

When adding a new crate, set its `Cargo.toml` `license` field per this split. The schema carve-out exists so cross-language client implementations can exist freely without copyleft viral concerns. Repo root carries three LICENSE files (`LICENSE-AGPL`, `LICENSE-APACHE`, `LICENSE-MIT`); per-crate `license` fields select the correct one(s) for each crate.

## Working style — check in at batch boundaries

Sessions may run on a laptop or a workstation; sessions often run for hours. Long sessions are fine — but **check in before starting a new batch of work** so the user is not forced to interrupt a running batch with a shutdown or context switch.

A "batch" is any unit that will run for more than a few minutes without a natural break. Before starting one, state what's in it and roughly how long it'll take, so the user can say "go" or "not now". This applies equally to refactor passes, multi-crate cargo runs, and exploratory code-spelunking sessions.
