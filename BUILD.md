# Building daemonseed

How to produce every artifact — dev binaries, the Linux AppImage, the Windows
`.exe`, and glibc-portable server binaries. The CI *gate* (fmt/clippy/test/…) is
separate and lives in [AGENTS.md → Definition of done](AGENTS.md#definition-of-done);
this file is about producing runnable and distributable binaries.

## Repository layout — a daemonseed clone is enough

daemonseed takes its crypto from **oxicrypt, pinned to a published version on
crates.io**. A plain `git clone` of this repo builds; no sibling checkout is
needed, and the packaging scripts fetch the integrity signer from the registry at
the same pin.

To work across both repos at once, uncomment the `[patch.crates-io]` block at the
foot of the workspace `Cargo.toml`, which redirects every oxicrypt dependency to a
local `../oxicrypt` without changing a version. **Re-comment it before pushing** —
a patched build is not the build anyone else gets, so a green gate under a patch
says nothing about the pinned version.

## Toolchain

- Rust is pinned by `rust-toolchain.toml` (channel `1.96`, with `rustfmt` +
  `clippy`) — rustup selects it automatically. Workspace MSRV is `1.95`.
- Distributable / portable builds also need **`cargo-zigbuild` + `zig`** (the
  cross-linker that pins the glibc floor): `cargo install cargo-zigbuild` and a
  `zig` on `PATH`.
- The AppImage build also needs **`appimagetool`** on `PATH`.
- The Windows build also needs the target: `rustup target add x86_64-pc-windows-gnu`.
- System packages are build prerequisites: **`protoc`** (the protobuf compiler,
  invoked by `daemonseed-proto/build.rs`), the **wayland client development
  headers** (probed by `wayland-sys`'s build script, reached through
  `daemonseed-gui` → `rfd` → `ashpd`), and **pkg-config**, which that probe
  uses. dbus is vendored and sqlite is bundled by their crates, so neither needs
  a package. On Debian/Ubuntu: `protobuf-compiler libwayland-dev pkg-config`.

## Dev builds (fast, local run)

| Artifact | Command | Output |
|----------|---------|--------|
| TUI | `cargo build -p daemonseed-tui` | `target/debug/daemonseed-tui` |
| GUI | `cargo build -p daemonseed-gui --features desktop` | `target/debug/daemonseed-gui` |

The GUI **requires `--features desktop`** to build the windowed app (Veilid is the
unconditional transport since the v0.33.0 cutover — there is no `veilid` feature).
Add `--release` for an optimized build under `target/release/`.

## Signing: a build you intend to run must carry an integrity slot

The oxicrypt module verifies its own image before it will do any work, so **a
binary you have just compiled refuses to start**:

```
daemonseed-tui: crypto module init failed: FIPS power-up self-test failed:
Module image integrity (HMAC-SHA-256 over the loader-invariant image)
```

That is the expected result, not a fault. `oxicrypt-integrity-sign` computes
HMAC-SHA-256 over the artifact's loader-invariant extent and writes the range
table and MAC into a reserved slot inside the file:

```sh
# Resolve the signer the same way the packaging scripts do, then use it. Sourcing
# the helper is the point: it picks the signer matching this workspace's pin, and
# under `[patch.crates-io]` it builds from the patched checkout rather than
# installing a same-numbered release.
. packaging/lib/sign.sh
SIGNER="$(resolve_signer "$PWD")"
sign_artifact "$SIGNER" <artifact>
```

**Sign last.** Anything that rewrites the artifact afterwards invalidates the
slot — stripping, compression, a platform signing tool. Both distributable
scripts below already do this as their final step; a hand-built binary you mean
to run needs it done by hand.

**Test binaries are never signed and do not need to be.** `cargo test` targets
initialize the module through
`daemonseed_core::kats::initialize_module_unsigned_test_binary`, behind the
`testing` feature, which substitutes a named stub for the image check. The
feature is reached only through a dev-dependency edge, and the release command
carries none — so no shipped artifact links a `testing`-enabled core. (It is on
under `--all-targets`, which is why that is scoped to the build that ships rather
than claimed of every build.)

## Distributable builds

Both scripts default their output to `./dist`, take an optional `[OUTPUT_DIR]`, and
cross-link against an old glibc floor via `cargo-zigbuild`, so the result runs on
machines older than the build host.

| Artifact | Command | Output |
|----------|---------|--------|
| Linux AppImage | `packaging/appimage/build-appimage.sh [OUTPUT_DIR]` | `<dir>/daemonseed-gui-x86_64.AppImage` |
| Windows `.exe` | `packaging/windows/build-windows.sh [OUTPUT_DIR]` | `<dir>/daemonseed-gui.exe` |
| Linux TUI | `packaging/tui/build-tui.sh [OUTPUT_DIR]` | `<dir>/daemonseed-tui-x86_64` |

All three sign the artifact as their last step and read the slot back with
`--verify`, so a build that reaches the end is one that will start.

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

**For the TUI, use `packaging/tui/build-tui.sh`** — it does everything below, plus
the floor check and the signing, and fails rather than handing you a binary that
will not start. The manual recipe is kept for a target the script does not cover.

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
- **Sign it** (see *Signing* above) — this recipe produces a runnable artifact and no
  script does it for you. Sign after the glibc check, since signing is last.

The same recipe with `-p daemonseed-gui --features desktop` produces a portable GUI
binary at `target/x86_64-unknown-linux-gnu/release/daemonseed-gui`.

## Running two clients locally

**Sign the binaries first** (see *Signing* above), or use the packaging scripts,
which sign for you. A `cargo build` / `cargo run` binary is unsigned and exits at
startup with `Module image integrity` before it reaches any of the below.

For peer-to-peer testing, run two (or more) clients side by side, each from its own
persistent `--portable` profile directory with a **distinct `DAEMONSEED_VEILID_PORT`**
so the nodes don't collide on one machine. `DAEMONSEED_VEILID_TRACE=1` adds transport
probes to a client's output, and `--x11` forces the software renderer (needed on some
Wayland setups).

## Gate before you commit / tag

Building is not the gate. Before committing, run the
[Definition of done](AGENTS.md#definition-of-done) checks; before cutting a release
tag, run `cargo xtask release-gate`, which runs every group of that gate and refuses
to let a tag be created on a red tree. `cargo xtask gate --list` prints the step
table; `cargo xtask gate --group preflight` runs the group the pre-push hook runs.
