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
│   ├── daemonseed-server/                  relay daemon: TLS 1.3 + APP_HELLO + identity-proof → Authenticated (M4b); federation peer table + introducer endpoint (M5/M12); public-space service (M6); circle-of-trust live relay (M8); RAM-only rate limiting (M9); release boot-gate (M10); user-publish share registry, reaped on disconnect (M12)
│   ├── daemonseed-cli/                     scriptable client: `connect <server-id>` with identity-proof (M4b) + C22 trust slider (M5); `publish` / `unpublish` / `list-shares` (M12)
│   ├── daemonseed-tui/                     interactive ratatui client — the MVP product surface (M11); Servers-pane introducer discovery (M12)
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

All six crates are substantive as of the alpha1 MVP (M12). The `tui` crate — the MVP product surface — is a ratatui client whose interactive logic is a terminal-free, unit-testable screen state machine reused over the proven cli client stack, exercised end-to-end by the 4-daemon PTY gate.

## Status

Current release: **v0.14.0 — alpha1 MVP**. The full 4-daemon end-to-end gate (`cargo xtask mvp-gate`) passes 10/10: cold first-start, mutual Authenticated, public-space view, circle-of-trust chat with mute/@mentions, user-publish file sharing, federation introducer discovery, suite-deprecation surfacing, and clean-device recovery from a 24-word mnemonic. M12 — the milestone that reaches MVP — adds the last two gate steps under one additive wire bump: **user-publish file sharing** (the `daemonseed-cli publish` / `unpublish` / `list-shares` commands; a published share is RAM-only and stays live only while you stay online — the relay reaps it the instant your connection drops) and the **federation introducer endpoint** (the TUI Servers pane now surfaces relay-discovered candidate servers read-only — never auto-trusted, promotion is always your explicit action). Earlier milestones delivered the interactive TUI and client surfaces (M11, v0.13.0) and the verifiable-core release machinery (M10, v0.12.1). The release-signing *infrastructure* (real keys, Sigstore co-signature, reproducible builds, store / package-manager channels) and the platform features (biometric login, OS-native autostart) remain on a follow-up "M10-infra" track; direct messaging is alpha2. Promotion to a public repository is gated on the `oxicrypt` sibling crate going public.

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
