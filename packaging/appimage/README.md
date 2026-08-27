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
this directory, **signs the binary's integrity slot**, and runs `appimagetool`.

## Signing

The oxicrypt module verifies its own image before doing any work, so an unsigned
binary exits at startup with `Module image integrity`. The script runs
`oxicrypt-integrity-sign --sign` on the AppDir binary and reads the slot back with
`--verify`, as its **last** step before packaging — anything that rewrites the
artifact after signing invalidates the MAC. `appimagetool` stores the ELF verbatim,
so the slot survives into the AppImage.

The signer is fetched from crates.io at the version this workspace pins, so the tool
that writes the slot and the runtime that reads it cannot drift. It is a build tool,
outside the cryptographic boundary, and is linked into nothing that ships.

## Requirements (must be present on the build host)

- `rustup` with the `x86_64-unknown-linux-gnu` target
- `cargo-zigbuild` + `zig` (the cross-linker that pins the glibc floor)
- `appimagetool` on `PATH`
- network access on the first build, to fetch the pinned integrity signer (cached after)

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
| `AppRun` | AppImage entry point (sets `DAEMONSEED_X11=1`, execs the binary) |
| `daemonseed-gui.desktop` | desktop entry template |
| `daemonseed-gui.svg` | scalable placeholder icon (replace with the real brand icon) |
