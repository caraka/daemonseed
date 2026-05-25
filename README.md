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
│   ├── daemonseed-core/                    protocol library — identity, storage, crypto-agility,
│   │                                       first-start orchestrator, bootstrap, circle metadata
│   ├── daemonseed-proto/                   wire schema (Protocol Buffers, prost + tonic)
│   ├── daemonseed-server/                  relay daemon: TLS 1.3 + APP_HELLO + identity-proof → Authenticated (M4b)
│   ├── daemonseed-cli/                     scriptable client: `connect <server-id>` with identity-proof (M4b)
│   ├── daemonseed-tui/                     interactive ratatui client (placeholder until M11)
│   └── daemonseed-integration-tests/       cross-crate integration tests + ISC coverage registry
│
├── docs/
│   └── llm-api-manifest/                   per-crate LAMA API manifests referenced by lama.yaml
│       ├── daemonseed-core-api.yaml
│       ├── daemonseed-proto-protocol.yaml
│       ├── daemonseed-server-api.yaml
│       └── daemonseed-cli-api.yaml
│
└── xtask/                                  workspace task runner: gen-proto, check-proto,
                                            isc-coverage, findings-resolved, install-hooks
```

Substantive code lives in `daemonseed-core`, `daemonseed-proto`, `daemonseed-server`, and `daemonseed-cli` as of M4b. The `tui` crate is still a placeholder; it fills in at M11.

## Status

Current release: **v0.5.0** (M4a closed); **v0.6.0-pre** cuts at M4b close — the post-HELLO identity-proof exchange now lands a connection at `Authenticated` (mutual ML-DSA-87 envelopes, TLS channel binding, ±5min freshness, per-key replay counters). ISC coverage 48/93 (51.6% of MVP) after M4b. Promotion to a public repository is gated on the `oxicrypt` sibling crate going public.

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
