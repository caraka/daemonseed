# daemonseed

Federated end-to-end-encrypted communication and file-sharing protocol. Pure Rust.

Private phase. See [`AGENTS.md`](AGENTS.md) for the working context, conventions, and per-commit discipline. AI agents discovering the project surface should start at [`lama.yaml`](lama.yaml) at the repository root.

## Workspace layout

```
daemonseed/
├── Cargo.toml                              workspace root (resolver = "2", edition = 2024, MSRV 1.95)
├── lama.yaml                               LAMA discovery entry point — AI agent quick triage
├── AGENTS.md                               canonical working rules (referenced by CLAUDE.md)
│
├── crates/
│   ├── daemonseed-core/                    protocol library — identity, 3-layer storage (seeds /
│   │                                       redb share index / chunk CAS), crypto-agility, first-start,
│   │                                       bootstrap, flat circle-of-trust keys, rendezvous addressing, indexer,
│   │                                       reconnect backoff, mute/hide lists, @-mention logic (M9),
│   │                                       release trust anchor + multi-sig verify + update-lifecycle FSM (M10)
│   ├── daemonseed-proto/                   wire schema (Protocol Buffers, prost + tonic)
│   ├── daemonseed-server/                  relay daemon: TLS 1.3 + APP_HELLO + identity-proof → Authenticated (M4b); federation peer table + introducer (M5); public-space service (M6); circle-of-trust live relay (M8); RAM-only rate limiting (M9); release boot-gate (M10)
│   ├── daemonseed-cli/                     scriptable client: `connect <server-id>` with identity-proof (M4b) + C22 trust slider (M5)
│   ├── daemonseed-tui/                     interactive ratatui client — the MVP product surface (M11)
│   └── daemonseed-integration-tests/       cross-crate integration tests + ISC coverage registry
│
├── docs/
│   └── llm-api-manifest/                   per-crate LAMA API manifests referenced by lama.yaml
│       ├── daemonseed-core-api.yaml
│       ├── daemonseed-proto-protocol.yaml
│       ├── daemonseed-server-api.yaml
│       ├── daemonseed-cli-api.yaml
│       └── daemonseed-tui-api.yaml
│
└── xtask/                                  workspace task runner: gen-proto, check-proto,
                                            isc-coverage, findings-resolved, install-hooks
```

Substantive code lives in `daemonseed-core`, `daemonseed-proto`, `daemonseed-server`, and `daemonseed-cli` as of M10. The `tui` crate begins filling in at M11 (the MVP gate): a ratatui client whose interactive logic is a terminal-free, unit-testable screen state machine reused over the proven cli client stack.

## Status

Current release: **v0.11.0** (M9 closed); **v0.12.0-pre** cuts at the **M10 verifiable-core** close — the pure-Rust, test-driven half of release distribution. `daemonseed-core::release` adds a binary-bound release trust anchor (an N-of-M ML-DSA-87 key set) and an N-of-M multi-sig verify that accepts only when enough *distinct* anchor keys have signed; `daemonseed-server::boot_gate` refuses to boot on a failed release-signature verify, with no "boot anyway with a warning" path; and the client update-lifecycle state machine verifies before applying, never auto-installs (even for emergency updates), refuses silent downgrades, and wipes-and-logs on verification failure. This milestone ships the **verifiable core only** — the release-signing *infrastructure* (real signing keys, Sigstore co-signature, reproducible builds, store / F-Droid / package-manager channels, the optional update-relay role) and the platform features (biometric login, OS-native autostart) are deferred to a follow-up "M10-infra" track that needs a key ceremony, accounts, and platform integration rather than pure logic. Promotion to a public repository is gated on the `oxicrypt` sibling crate going public.

## License

- Code crates: **AGPL-3.0-or-later** (`LICENSE-AGPL`).
- `daemonseed-proto` (wire schema): **Apache-2.0 OR MIT** (`LICENSE-APACHE`, `LICENSE-MIT`). Schema is dual-licensed so cross-language client implementations are free of copyleft drag.

## Quickstart for contributors

```bash
cargo build --workspace                                          # build everything
cargo test --workspace                                           # run all tests
cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings
cargo xtask check-proto                                          # verify committed proto snapshot matches .proto sources
cargo xtask isc-coverage                                         # report ISC coverage against the spec
```

See `AGENTS.md` for the full definition-of-done, the doc-sync ritual at every commit boundary, and the worktree placement convention.
