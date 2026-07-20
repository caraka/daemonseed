# daemonseed

Federated end-to-end-encrypted communication and file-sharing protocol. Pure Rust.

Private phase. See [`AGENTS.md`](AGENTS.md) for the working context, conventions, and per-commit discipline. AI agents discovering the project surface should start at [`lama.yaml`](lama.yaml) at the repository root.

## Project map

Each kind of fact has one home — to avoid the drift that comes from duplicating state. Where to look:

- **What shipped, when** → [`CHANGELOG.md`](CHANGELOG.md) (one entry per SSH-signed git tag).
- **The design contract** (problem, principles, boundaries, every ISC) → [`ISA.md`](ISA.md).
- **Live ISC coverage** → `cargo xtask isc-coverage`.
- **The full canonical-homes map** (authoritative; what lives where and why) → the *Canonical homes* table in [`AGENTS.md`](AGENTS.md#canonical-homes).
- **Per-crate API surface** (for client implementers) → [`docs/llm-api-manifest/`](docs/llm-api-manifest/), indexed from [`lama.yaml`](lama.yaml).

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
│   │                                       release trust anchor + multi-sig verify + update-lifecycle FSM (M10),
│   │                                       at-rest persistence of display-name / mute / hide / circle membership
│   │                                       via a cached SealingKey re-seal (M13); fetched-download CAS + manifest
│   │                                       store (storage::fetched, M15)
│   ├── daemonseed-proto/                   wire schema (Protocol Buffers, prost + tonic)
│   ├── daemonseed-veilid-net/              Veilid transport: identity-bound node, sealed 1:1 + circle/lobby/public-room rendezvous, signed share-discovery route adverts, owner-on-demand share content transfer
│   ├── daemonseed-cli/                     library-only client: Veilid route-advert signer (`route_signer`) + announcements/MOTD authoring & render helpers (`public_space`)
│   ├── daemonseed-tui/                     interactive ratatui client — the MVP product surface (M11); Servers-pane introducer discovery (M12); multi-circle carousel (v0.16); session write-through + silent circle rejoin from the at-rest blob (M13); define-share + indexer (M14); publish/serve/unpublish + fetched-download browse/extract (M15)
│   ├── daemonseed-gui/                     Slint GUI client (round-1 scaffold) — software-renderer shell; `--features desktop` opens a real window
│   ├── daemonseed-isc/                      ISC registry leaf crate (zero deps): the single source of
│   │                                       TOTAL / COVERED, read by both the integration tests and xtask
│   └── daemonseed-integration-tests/       cross-crate integration tests (re-exports daemonseed-isc)
│
├── docs/
│   └── llm-api-manifest/                   per-crate LAMA API manifests referenced by lama.yaml
│       ├── daemonseed-core-api.yaml
│       ├── daemonseed-proto-protocol.yaml
│       ├── daemonseed-veilid-net-api.yaml
│       ├── daemonseed-cli-api.yaml
│       ├── daemonseed-tui-api.yaml
│       └── daemonseed-gui-api.yaml
│
└── xtask/                                  workspace task runner: gen-proto, check-proto,
                                            isc-coverage, findings-resolved, install-hooks, release-gate
```

The `tui` (ratatui) and `gui` (Slint) crates are the product surfaces; their interactive logic is a terminal-free / RAM-only, unit-testable screen state machine over the shared authoring library (`cli`) and the Veilid DHT transport (`daemonseed-veilid-net`). There is no relay — every client is a Veilid node.

## Status

Current release: **v0.35.1** — alpha (post-MVP). The transport is now the Veilid DHT: the relay server is retired and daemonseed runs fully serverless, peer-to-peer — the public Lobby and circle chat, member presence, in-band share discovery/transfer, and operator announcements/MOTD all ride the DHT, end-to-end sealed. See `CHANGELOG.md` for per-release detail.

The per-release history lives in **[`CHANGELOG.md`](CHANGELOG.md)** (one entry per SSH-signed tag) — this section is intentionally kept to the current release so it can't silently drift. The release-signing *infrastructure* (real keys, Sigstore co-signature, reproducible builds, store / package-manager channels) and the platform features (biometric login, OS-native autostart) remain on a follow-up track; direct messaging is planned. Promotion to a public repository is gated on the `oxicrypt` sibling crate going public.

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

## Running the GUI

```bash
cargo run -p daemonseed-gui --features desktop          # opens a real window
```

**Wayland input note.** Under some Wayland compositors — most reliably reproduced when running **more than one client in the same session** — winit 0.30's Wayland pointer path can stop delivering input, leaving the window non-responsive (the process stays healthy; it is a dead surface, not a hang). Force XWayland with `--x11` or `DAEMONSEED_X11=1` to work around it:

```bash
DAEMONSEED_X11=1 cargo run -p daemonseed-gui --features desktop
./daemonseed-gui --x11                                  # equivalent, for a built binary
```

## Packaging

A reproducible AppImage recipe for the desktop GUI lives in
[`packaging/appimage/`](packaging/appimage/):

```bash
packaging/appimage/build-appimage.sh        # → dist/daemonseed-gui-x86_64.AppImage
```

It builds `daemonseed-gui --release --features desktop` against a glibc 2.35 floor
via `cargo-zigbuild` and bundles it with `appimagetool`. See
[`packaging/appimage/README.md`](packaging/appimage/README.md) for requirements and knobs.

A self-contained Windows build (no MSVC, no Windows host needed) lives in
[`packaging/windows/`](packaging/windows/):

```bash
packaging/windows/build-windows.sh          # → dist/daemonseed-gui.exe
```

It cross-compiles `daemonseed-gui --release --features desktop` for
`x86_64-pc-windows-gnu` via `cargo-zigbuild`; zig static-links the mingw runtime, so the
`.exe` depends only on stock Windows 10+ system DLLs (nothing to ship alongside it).
Requires the target: `rustup target add x86_64-pc-windows-gnu`.
