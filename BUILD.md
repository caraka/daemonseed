# Building daemonseed

How to produce every artifact — dev binaries, the Linux AppImage, the Windows
`.exe`, and glibc-portable server binaries. The CI *gate* (fmt/clippy/test/…) is
separate and lives in [AGENTS.md → Definition of done](AGENTS.md#definition-of-done);
this file is about producing runnable and distributable binaries.

## Repository layout — clone the sibling first

During the pre-1.0 private phase daemonseed **path-depends** on one sibling repo,
so it must be checked out **next to** the daemonseed directory (`../oxicrypt`):

```
somedir/
├── oxicrypt/     # CNSA 2.0 primitives, AEAD, KDF
└── daemonseed/
```

`Cargo.toml` references it as `../oxicrypt/crates/...`, so a daemonseed-only clone
fails at the first `cargo build`. **It is required to build any crate — the GUI
included** — because `daemonseed-core` (which every crate depends on) hard-depends
on it.

## Toolchain

- Rust is pinned by `rust-toolchain.toml` (channel `1.96`, with `rustfmt` +
  `clippy`) — rustup selects it automatically. Workspace MSRV is `1.95`.
- Distributable / portable builds also need **`cargo-zigbuild` + `zig`** (the
  cross-linker that pins the glibc floor): `cargo install cargo-zigbuild` and a
  `zig` on `PATH`.
- The AppImage build also needs **`appimagetool`** on `PATH`.
- The Windows build also needs the target: `rustup target add x86_64-pc-windows-gnu`.

## Dev builds (fast, local run)

| Artifact | Command | Output |
|----------|---------|--------|
| TUI | `cargo build -p daemonseed-tui` | `target/debug/daemonseed-tui` |
| GUI | `cargo build -p daemonseed-gui --features desktop` | `target/debug/daemonseed-gui` |

The GUI **requires `--features desktop`** to build the windowed app (Veilid is the
unconditional transport since the v0.33.0 cutover — there is no `veilid` feature).
Add `--release` for an optimized build under `target/release/`.

## Distributable builds

Both scripts default their output to `./dist`, take an optional `[OUTPUT_DIR]`, and
cross-link against an old glibc floor via `cargo-zigbuild`, so the result runs on
machines older than the build host.

| Artifact | Command | Output |
|----------|---------|--------|
| Linux AppImage | `packaging/appimage/build-appimage.sh [OUTPUT_DIR]` | `<dir>/daemonseed-gui-x86_64.AppImage` |
| Windows `.exe` | `packaging/windows/build-windows.sh [OUTPUT_DIR]` | `<dir>/daemonseed-gui.exe` |

Under the hood both run `cargo zigbuild --release --features desktop` — the AppImage
against `x86_64-unknown-linux-gnu.<glibc-floor>` (the floor is set in the script),
the Windows build against `x86_64-pc-windows-gnu`.

To rebuild the AppImage while an old copy is still running (an in-place overwrite
fails with `Text file busy`), build to a temp dir and atomically rename onto the
canonical name — a rename over a running executable is safe on Linux:

```sh
packaging/appimage/build-appimage.sh dist/.build \
  && mv -f dist/.build/daemonseed-gui-x86_64.AppImage dist/daemonseed-gui-x86_64.AppImage \
  && rm -rf dist/.build
```

## Portable Linux binary for a different-glibc host (server / seed node)

A plain `cargo build` links against the **build host's** glibc. If the run host has
an **older** glibc it fails to load (`libm.so.6: version 'GLIBC_2.XX' not found`). Any
binary that leaves the build host must be built with a pinned glibc floor:

```sh
cargo zigbuild -p daemonseed-tui --release --target x86_64-unknown-linux-gnu.2.34
```

- Pick a floor `≤` the oldest run host's glibc (`2.34` is broadly safe; the AppImage
  uses the floor set in its script).
- **The output path differs** — zigbuild emits under the triple dir:
  `target/x86_64-unknown-linux-gnu/release/daemonseed-tui`.
- **Verify before shipping:**
  `objdump -T <bin> | grep -oE 'GLIBC_[0-9.]+' | sort -V | tail -1` — the max must be
  `≤` your floor; `file <bin>` confirms the architecture.

The same recipe with `-p daemonseed-gui --features desktop` produces a portable GUI
binary at `target/x86_64-unknown-linux-gnu/release/daemonseed-gui`.

## Running two clients locally

For peer-to-peer testing, run two (or more) clients side by side, each from its own
persistent `--portable` profile directory with a **distinct `DAEMONSEED_VEILID_PORT`**
so the nodes don't collide on one machine. `DAEMONSEED_VEILID_TRACE=1` adds transport
probes to a client's output, and `--x11` forces the software renderer (needed on some
Wayland setups).

## Gate before you commit / tag

Building is not the gate. Before committing, run the
[Definition of done](AGENTS.md#definition-of-done) checks; before cutting a release
tag, run `cargo xtask release-gate` (fmt · clippy workspace + `daemonseed-gui
--features desktop` · test · check-proto · isc-coverage), which refuses to let a tag
be created on a red tree.
