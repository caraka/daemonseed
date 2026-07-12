#!/usr/bin/env bash
#
# build-windows.sh — cross-compile daemonseed-gui.exe for Windows, from Linux.
#
# Produces a self-contained x86_64 Windows GUI binary via cargo-zigbuild (zig as the
# cross-linker). The result depends only on DLLs present on a stock Windows 10+ install
# (system DLLs + the Universal CRT api-sets) — zig statically links the mingw runtime, so
# there is NO libwinpthread / libgcc / libstdc++ to ship. No Windows host, no MSVC toolchain.
#
# Requirements (all present on the build VM):
#   - rustup with the windows-gnu target:  rustup target add x86_64-pc-windows-gnu
#   - cargo-zigbuild + zig                  (the same toolchain the AppImage recipe uses)
#
# Usage:
#   packaging/windows/build-windows.sh [OUTPUT_DIR]
# OUTPUT_DIR defaults to ./dist. The resulting file is <OUTPUT_DIR>/daemonseed-gui.exe.
#
# Note: the binary is built with the default (console) subsystem, so a console window
# opens alongside the GUI and carries stdout/stderr — deliberately kept for the alpha so
# testers can capture panics/logs in reports.

set -euo pipefail

TARGET="x86_64-pc-windows-gnu"
BIN="daemonseed-gui.exe"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="${1:-$REPO_ROOT/dist}"

echo "[windows] cross-building $BIN for $TARGET …"
cargo zigbuild --manifest-path "$REPO_ROOT/Cargo.toml" \
  -p daemonseed-gui --release --features "desktop veilid" --target "$TARGET"

SRC="$REPO_ROOT/target/$TARGET/release/$BIN"
mkdir -p "$OUTPUT_DIR"
cp -f "$SRC" "$OUTPUT_DIR/$BIN"

echo "[windows] done: $OUTPUT_DIR/$BIN"
file "$OUTPUT_DIR/$BIN"
