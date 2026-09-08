# Contributing

`AGENTS.md` at the repository root is the contract for any change to this repository, whether a person or an assistant makes it. This file is the short version; where they differ, `AGENTS.md` wins.

## Before you start

- Work is tracked in GitHub Issues. Pick an issue, or open one first for anything beyond a one-line fix, so the scope is agreed before the code exists.
- Read `ISA.md` before changing a boundary. It is the design contract; a change that alters what the system promises updates `ISA.md` in the same pull request.

## Making a change

1. Branch from `main`.
2. Sign your commits. Every commit on `main` is signed and a pull request is merged by a path that keeps your signatures, so an unsigned commit will be sent back for signing. GitHub documents SSH commit signing at <https://docs.github.com/authentication/managing-commit-signature-verification>.
3. Run the gate before pushing: `cargo xtask gate`. `cargo xtask install-hooks` installs a pre-push hook that runs the `preflight` group automatically. Continuous integration runs `preflight` and `dev-suite` on every pull request; `release-suite` runs on `main`.
4. Keep documentation true in the same commit as the code: a `CHANGELOG.md` entry under `[Unreleased]`, rustdoc for anything touched, `ISA.md` if the contract changed, the `## Status` section of `README.md` if the user-facing status changed, and the API manifests under `docs/llm-api-manifest/` for any public-surface change. `AGENTS.md` lists every surface and what each one holds.
5. Open a pull request against `main`. Name the issue it closes with `Closes #N` on its own line, or say which part of an issue it covers with `Covers <the part> of issue #N`.

## Licensing

Code crates are AGPL-3.0-or-later; the `daemonseed-proto` schema crate is Apache-2.0 OR MIT. Each crate's `Cargo.toml` names its license.
