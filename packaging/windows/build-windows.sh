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
  -p daemonseed-gui --release --features "desktop" --target "$TARGET"

SRC="$REPO_ROOT/target/$TARGET/release/$BIN"
mkdir -p "$OUTPUT_DIR"
cp -f "$SRC" "$OUTPUT_DIR/$BIN"

# The oxicrypt module verifies its own image before doing any work, so an
# unsigned artifact never reaches `Operational`. Signed on the copy in
# OUTPUT_DIR, last, because anything that rewrites the file afterwards
# invalidates the slot. Same step and same reasoning as the AppImage recipe;
# the signer classifies PE as well as ELF.
SIGNER_DIR="$REPO_ROOT/../oxicrypt/tools/oxicrypt-integrity-sign"
[ -f "$SIGNER_DIR/Cargo.toml" ] || { echo "[windows] integrity signer not found at $SIGNER_DIR" >&2; exit 1; }
echo "[windows] building the integrity signer …"
cargo build --release --locked --manifest-path "$SIGNER_DIR/Cargo.toml"
SIGNER_BIN="$REPO_ROOT/../oxicrypt/target/release/oxicrypt-integrity-sign"
[ -x "$SIGNER_BIN" ] || { echo "[windows] integrity signer not built at $SIGNER_BIN" >&2; exit 1; }

echo "[windows] signing the module image …"
"$SIGNER_BIN" --sign "$OUTPUT_DIR/$BIN"
# Read the slot back rather than trusting the signer's exit — a signer that
# wrote nothing exits the same way as one that worked.
"$SIGNER_BIN" --verify "$OUTPUT_DIR/$BIN"

echo "[windows] done: $OUTPUT_DIR/$BIN"
file "$OUTPUT_DIR/$BIN"
