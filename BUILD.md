# Building daemonseed

How to produce every artifact — dev binaries, the Linux AppImage, the Linux TUI,
the Windows GUI, and glibc-portable binaries — and how a release is built and
staged. The CI *gate* (fmt/clippy/test/…) is separate and lives in
[AGENTS.md → Definition of done](AGENTS.md#definition-of-done); this file is about
producing runnable and distributable binaries.

## The oxicrypt library

daemonseed takes its crypto from the **`oxicrypt` crate, pinned to a published
version on crates.io**. The crate holds no cryptographic code: it links the
program to **`liboxicrypt_ffi`**, oxicrypt's separately built shared library,
which oxicrypt signs at release and which verifies its own signature and runs its
self-tests when it is initialised. daemonseed's own binaries carry no signature.

The build needs the library before it can link anything, and a program needs it
at run time:

```sh
scripts/fetch-oxicrypt-ffi.sh                  # linux-x86_64 (default)
scripts/fetch-oxicrypt-ffi.sh windows-x86_64   # the Windows library and import library
```

The script downloads oxicrypt's release tarball, refuses it unless it matches the
sha256 pinned in the script, and unpacks it under
`target/oxicrypt-ffi/v<version>/<platform>`. `.cargo/config.toml` points
`OXICRYPT_LIB_DIR` at the Linux directory and pins `OXICRYPT_LIB_FINGERPRINT`, the
fingerprint of oxicrypt's release key; the library is refused at start-up if it
reports any other. Set either variable in the environment to override it.
`cargo clean` removes the library; fetch it again afterwards.

On Linux, `.cargo/config.toml` also gives cargo a runner that puts
`OXICRYPT_LIB_DIR` on `LD_LIBRARY_PATH`, so `cargo test` and `cargo run` find the
library with no further setup. A binary run directly from `target/` does not:
start it with `LD_LIBRARY_PATH` set to that directory, or use the packaged builds
below, which carry the library beside the binary.

To work on both repositories at once, uncomment the `[patch.crates-io]` block at
the foot of the workspace `Cargo.toml`, which redirects the `oxicrypt` crate to a
local `../oxicrypt` without changing its version. **Re-comment it before
pushing** — a patched build is not the build anyone else gets, so a green gate
under a patch says nothing about the pinned version.

## Toolchain

- Rust is pinned by `rust-toolchain.toml` (channel `1.99.1`, with `rustfmt` +
  `clippy`) — rustup selects it automatically. Workspace MSRV is `1.95`.
- The Linux distributable builds also need **`cargo-zigbuild` + `zig`** (the
  cross-linker that pins the glibc floor): `cargo install cargo-zigbuild` and a
  `zig` on `PATH`.
- The AppImage build also needs **`appimagetool`** on `PATH`.
- The Windows build runs on Windows with the MSVC toolchain:
  `rustup target add x86_64-pc-windows-msvc`.
- System packages are build prerequisites: **`protoc`** (the protobuf compiler,
  invoked by `daemonseed-proto/build.rs`), the **wayland client development
  headers** (probed by `wayland-sys`'s build script, reached through
  `daemonseed-gui` → `rfd` → `ashpd`), and **pkg-config**, which that probe
  uses. dbus is vendored and sqlite is bundled by their crates, so neither needs
  a package. On Debian/Ubuntu: `protobuf-compiler libwayland-dev pkg-config`.
- The `xtask` tests of `scripts/ci/already-passed.sh` also need **`jq`** on `PATH`.

## Dev builds (fast, local run)

| Artifact | Command | Output |
|----------|---------|--------|
| TUI | `cargo build -p daemonseed-tui` | `target/debug/daemonseed-tui` |
| GUI | `cargo build -p daemonseed-gui --features desktop` | `target/debug/daemonseed-gui` |

The GUI **requires `--features desktop`** to build the windowed app (Veilid is the
unconditional transport since the v0.33.0 cutover — there is no `veilid` feature).
Add `--release` for an optimized build under `target/release/`. Run either with
`cargo run`, or see *The oxicrypt library* above for running the binary directly.

## Distributable builds (Linux)

Both scripts default their output to `./dist`, take an optional `[OUTPUT_DIR]`,
fetch the oxicrypt library themselves, and cross-link against an old glibc floor
via `cargo-zigbuild`, so the result runs on machines older than the build host.

| Artifact | Command | Output |
|----------|---------|--------|
| Linux AppImage | `packaging/appimage/build-appimage.sh [OUTPUT_DIR]` | `<dir>/daemonseed-gui-x86_64.AppImage` |
| Linux TUI | `packaging/tui/build-tui.sh [OUTPUT_DIR]` | `<dir>/daemonseed-tui-x86_64` and `<dir>/liboxicrypt_ffi.so.1` |

Each script checks that the unpacked library is byte-identical to the copy in the
pinned tarball and ships it unchanged: inside the AppImage as
`usr/lib/liboxicrypt_ffi.so.1`, and beside the TUI binary, which must be shipped
with it. The binaries are linked with the RUNPATH `$ORIGIN:$ORIGIN/../lib`, so
they find the library with no absolute path and no `LD_LIBRARY_PATH`. Both scripts
fail when the binary or the library needs a glibc symbol version above the floor
(`GLIBC_FLOOR`, default `2.35`). `packaging/lib/oxicrypt-ffi.sh` holds the steps
both share.

To rebuild the AppImage while an old copy is still running (an in-place overwrite
fails with `Text file busy`), build to a temp dir and atomically rename onto the
canonical name — a rename over a running executable is safe on Linux:

```sh
packaging/appimage/build-appimage.sh dist/.build \
  && mv -f dist/.build/daemonseed-gui-x86_64.AppImage dist/daemonseed-gui-x86_64.AppImage \
  && rm -rf dist/.build
```

## Windows GUI

The Windows GUI is built as `x86_64-pc-windows-msvc` on Windows, linked through
the import library `oxicrypt_ffi.dll.lib` that oxicrypt's Windows tarball ships:

```sh
dir="$(scripts/fetch-oxicrypt-ffi.sh windows-x86_64)"
OXICRYPT_LIB_DIR="$(cygpath -w "$dir")" \
  cargo build --release --locked -p daemonseed-gui --features desktop --target x86_64-pc-windows-msvc
```

`target/x86_64-pc-windows-msvc/release/daemonseed-gui.exe` loads `oxicrypt_ffi.dll`
and `vcruntime140.dll` at start-up: ship both beside the exe, the first unchanged
from the tarball and the second from the Visual C++ redistributable. The release
workflow below does exactly this.

## Portable Linux binary for a different-glibc host

**For the TUI, use `packaging/tui/build-tui.sh`** — it does everything below, plus
the floor check, and fails rather than handing you a binary that will not start.
The manual recipe is kept for a target the script does not cover.

A plain `cargo build` links against the **build host's** glibc. If the run host has
an **older** glibc it fails to load (`libm.so.6: version 'GLIBC_2.XX' not found`). Any
binary that leaves the build host must be built with a pinned glibc floor, and
linked with a RUNPATH that finds the library shipped beside it:

```sh
RUSTFLAGS='-C link-arg=-Wl,--enable-new-dtags -C link-arg=-Wl,-rpath,$ORIGIN' \
  cargo zigbuild -p daemonseed-tui --release --target x86_64-unknown-linux-gnu.2.35
```

- Pick a floor `≤` the oldest run host's glibc.
- **The output path differs** — zigbuild emits under the triple dir:
  `target/x86_64-unknown-linux-gnu/release/daemonseed-tui`.
- **Ship `liboxicrypt_ffi.so.1` beside the binary**, copied unchanged from
  `OXICRYPT_LIB_DIR`.
- **Verify before shipping:**
  `objdump -T <bin> | grep -oE 'GLIBC_[0-9.]+' | sort -V | tail -1` — the max must be
  `≤` your floor; `readelf -d <bin>` shows the RUNPATH; `file <bin>` confirms the
  architecture.

The same recipe with `-p daemonseed-gui --features desktop` produces a portable GUI
binary at `target/x86_64-unknown-linux-gnu/release/daemonseed-gui`.

## Running two clients locally

For peer-to-peer testing, run two (or more) clients side by side, each from its own
persistent `--portable` profile directory with a **distinct `DAEMONSEED_VEILID_PORT`**
so the nodes don't collide on one machine. Use `cargo run` or the packaged builds,
which find the oxicrypt library on their own. `DAEMONSEED_VEILID_TRACE=1` adds
transport probes to a client's output, and `--x11` forces the software renderer
(needed on some Wayland setups).

## Releases

Releases are built on GitHub runners by `.github/workflows/release.yml`, never on a
developer's machine. One matrix row per artifact: the Linux AppImage, the Linux TUI
and the Windows GUI.

- **Pushing a signed annotated `v*` tag stages a release.** The `guard` job runs
  `scripts/release-guard.sh`, which runs `scripts/check-release-tag.sh` against
  `keys/allowed-signers`, all three taken from `main`. The tag must be signed by a
  key that file names, carry its own name in the signed tag object, name the
  workspace version as `v` plus a SemVer version, and point at a commit on
  `main`. The build legs then run in the `release` environment, which holds them
  for approval only when the repository configures that environment with
  required reviewers, as it must for a release.
- **The first release tag can be pushed only once this workflow is on `main`**,
  because the guard reads `keys/allowed-signers` and its scripts from `main`.
- **Each leg builds its artifact, loads it on the runner that built it, and
  records its provenance.** The GUI runs `--self-check`, a headless path that
  initialises the oxicrypt library, joins a circle from a fixed phrase (deriving
  the circle's key) and checks that a draft survives switching circles; the TUI
  must draw its first-start screen in a pseudo-terminal. A copy of the binary without the
  library beside it must fail to start (`scripts/release-load-check.sh`). Each
  leg ships one archive, `daemonseed-<tag>-<leg>.tar.gz` for the Linux legs and
  `daemonseed-<tag>-windows-x86_64-gui.zip` for Windows, with a `.sha256`
  beside it. Each archive carries a `BUILD-PROVENANCE.txt` naming the target triple, the commit,
  the toolchain, the run, the oxicrypt library's sha256, the oxicrypt release-key
  fingerprint and the load check; the Windows one also names the
  `vcruntime140.dll` version and sha256.
- **`verify` checks every archive** against the target triple of the matrix row
  that built it, which also fixes its format (`.zip` for Windows, `.tar.gz`
  otherwise), and against `packaging/release/import-allow-list.txt`: every ELF
  `NEEDED` entry and every PE import of every shipped binary, including the files
  inside the AppImage, must be on that list (`scripts/verify-release-rows.sh`,
  `scripts/check-release-artifact.py`).
- **`attach` puts the archives and their checksums on a draft release** for the
  tag (`scripts/attach-draft.sh`). The draft's files are downloaded and tested,
  and the draft is then published by hand, so the bytes tested are the bytes
  published. The workflow never publishes a release or changes a published one.
- **A dry run builds every leg without staging anything.** Add the
  `release-dry-run` label to a pull request to dry-run the release legs on it;
  once the workflow is on `main`, `workflow_dispatch` on any branch does the
  same. A dry run builds, loads and checks every leg exactly as a release does
  and uploads the archives as workflow artifacts. It never enters the `release`
  environment and never creates or changes a release or a tag. Without the
  label a pull request's runs build nothing: a new commit, a reopen or an added
  label still starts a run, its `guard` job finds no `release-dry-run` label,
  and every leg is skipped. The label decides whether the legs run, not what a
  run may do: that is bounded outside the pull request, since GitHub gives a
  fork's pull request a read-only token and no secrets, the `release`
  environment admits only `v*` tags and holds runs for approval when the
  repository configures it with required reviewers, and a first-time
  contributor's runs wait for approval.

`scripts/test-release-scripts.sh` tests the guard, the tag check, the draft
upload, the fingerprint read, the staging and the artifact check against
fixtures; the `preflight` gate group runs it as `cargo xtask release-scripts`,
beside `cargo xtask check-crypto-deps`, which fails when `Cargo.lock` holds any
`oxicrypt` package but the binding crate.

## Gate before you commit / tag

Building is not the gate. Before committing, run the
[Definition of done](AGENTS.md#definition-of-done) checks. On `main`, CI does not re-run
a group of that gate when the newest pull-request run of the same commit ID passed it on the
same tree. Any doubt runs the gate. Before cutting a release tag, the tagged commit needs green CI in
all three groups, which a pull request from a `release/` branch runs. When CI cannot run,
`cargo xtask release-gate` runs every group locally and exits non-zero naming any red
step; run it before `git tag`.
`cargo xtask gate --list` prints the step table; `cargo xtask gate --group preflight` runs
the group the pre-push hook runs.
