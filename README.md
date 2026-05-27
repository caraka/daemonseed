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
│   │                                       reconnect backoff, mute/hide lists, @-mention logic (M9)
│   ├── daemonseed-proto/                   wire schema (Protocol Buffers, prost + tonic)
│   ├── daemonseed-server/                  relay daemon: TLS 1.3 + APP_HELLO + identity-proof → Authenticated (M4b); federation peer table + introducer (M5); public-space service (M6); circle-of-trust live relay (M8); RAM-only rate limiting (M9)
│   ├── daemonseed-cli/                     scriptable client: `connect <server-id>` with identity-proof (M4b) + C22 trust slider (M5)
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

Substantive code lives in `daemonseed-core`, `daemonseed-proto`, `daemonseed-server`, and `daemonseed-cli` as of M9. The `tui` crate is still a placeholder; it fills in at M11.

## Status

Current release: **v0.10.0** (M8 closed); **v0.11.0-pre** cuts at M9 close — abuse-resilience and chat affordances. Server: multi-granularity, RAM-only rate limits — a per-connection request token bucket plus subscription/verify caps, and a per-identity-key connection table GC'd on disconnect, all enforced through the same uniform silent close as an identity-proof failure (no wire reason). Client: an exponential+jitter reconnect backoff with an 8-retry budget and layer-based close-cause messages that never speculate about which limit was hit; mute and hide-shares lists persisted in the encrypted seeds blob and never sent on the wire; and @-mention recognition + autocomplete resolution as pure post-decrypt/pre-send functions that add no new server-visible distinction. TUI rendering of mute/mention lands at M11. The per-milestone ISC-coverage convention, dormant across M7–M8, is re-instated this milestone. Promotion to a public repository is gated on the `oxicrypt` sibling crate going public.

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
