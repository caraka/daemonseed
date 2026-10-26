# AppImage packaging — `daemonseed-gui`

A reproducible recipe that bundles the desktop GUI into a single portable
`daemonseed-gui-x86_64.AppImage` that runs on any reasonably recent x86_64 Linux
desktop without a Rust toolchain.

## Build

```sh
packaging/appimage/build-appimage.sh [OUTPUT_DIR]   # default OUTPUT_DIR = ./dist
```

Output: `<OUTPUT_DIR>/daemonseed-gui-x86_64.AppImage`.

The script builds `daemonseed-gui --release --features desktop` with
[`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild), targeting
`x86_64-unknown-linux-gnu.2.35` so the binary links against the **glibc 2.35**
floor (Ubuntu 22.04 "Jammy"). It then assembles an AppDir from the templates in
this directory, bundles oxicrypt's signed shared library, and runs `appimagetool`.

## The oxicrypt library

The binary links oxicrypt's separately built and signed shared library,
`liboxicrypt_ffi.so.1`, which verifies its own signature when it is initialised.
The script fetches the pinned release with `scripts/fetch-oxicrypt-ffi.sh` (which
checks the tarball's sha256), confirms the unpacked library is byte-identical to the
tarball's copy, and installs it unchanged as `usr/lib/liboxicrypt_ffi.so.1`. The
binary is linked with the RUNPATH `$ORIGIN:$ORIGIN/../lib`, so it finds the library
from `usr/bin` with no absolute path and no `LD_LIBRARY_PATH`. The daemonseed binary
itself carries no signature. The script fails if the binary or the library needs a
glibc symbol version above the floor.

## Requirements (must be present on the build host)

- `rustup` with the `x86_64-unknown-linux-gnu` target
- `cargo-zigbuild` + `zig` (the cross-linker that pins the glibc floor)
- `appimagetool` on `PATH`
- network access on the first build, to fetch the pinned oxicrypt library (cached after)

No imagemagick is needed — the app icon is a scalable SVG.

> On first use, `appimagetool` downloads the AppImage type-2 runtime from GitHub
> (one network fetch, then cached). Subsequent builds are offline.

## Knobs

| Env | Default | Meaning |
|-----|---------|---------|
| `GLIBC_FLOOR` | `2.35` | glibc version suffix on the target triple |
| `APPIMAGETOOL` | first on `PATH` | path to `appimagetool` |

## Runtime

`AppRun` defaults `DAEMONSEED_X11=1`, launching the GUI on XWayland (winit 0.30's
Wayland software-render path drops pointer input in some compositors/VMs). Override
with `DAEMONSEED_X11=0` for native Wayland.

## Files

| File | Role |
|------|------|
| `build-appimage.sh` | the recipe |
| `../lib/oxicrypt-ffi.sh` | fetches, checks and bundles the oxicrypt library; shared with the TUI recipe |
| `AppRun` | AppImage entry point (sets `DAEMONSEED_X11=1`, execs the binary) |
| `daemonseed-gui.desktop` | desktop entry template |
| `daemonseed-gui.svg` | scalable placeholder icon (replace with the real brand icon) |
