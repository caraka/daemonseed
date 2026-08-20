#!/usr/bin/env bash
#
# build-tui.sh — portable, signed build of the daemonseed TUI.
#
# Produces a single x86_64 binary linked against an old glibc floor (Ubuntu
# 22.04 "Jammy", glibc 2.35) via cargo-zigbuild, so it runs on a host older
# than the build machine — and signs it, because since oxicrypt 0.24.0 the
# module verifies its own image before doing any work and an unsigned binary
# dies at startup with "Module image integrity".
#
# The TUI is a shipped artifact and had no script: the recipe lived in BUILD.md
# as instructions to follow by hand. A signing step that only a human performs
# is the one step nothing can fail on, so it lives here instead.
#
# Requirements:
#   - rustup with the x86_64-unknown-linux-gnu target
#   - cargo-zigbuild + zig   (the cross-linker that pins the glibc floor)
#   - the oxicrypt sibling checkout at ../oxicrypt (the signer builds from it)
#
# Usage:
#   packaging/tui/build-tui.sh [OUTPUT_DIR]
# OUTPUT_DIR defaults to ./dist. The resulting file is
#   <OUTPUT_DIR>/daemonseed-tui-x86_64
#
# Knobs (env):
#   GLIBC_FLOOR   glibc version suffix for the target triple (default 2.35)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"
OUT_DIR="${1:-${REPO_ROOT}/dist}"
GLIBC_FLOOR="${GLIBC_FLOOR:-2.35}"
TARGET="x86_64-unknown-linux-gnu"
ZIG_TARGET="${TARGET}.${GLIBC_FLOOR}"
BIN="daemonseed-tui"
OUT_BIN="${OUT_DIR}/${BIN}-x86_64"

log() { printf '\033[1;32m[tui]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[tui] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

command -v cargo-zigbuild >/dev/null || die "cargo-zigbuild not found (cargo install cargo-zigbuild + zig)"
command -v zig >/dev/null || die "zig not found"
rustup target list --installed 2>/dev/null | grep -qx "${TARGET}" || die "rust target ${TARGET} not installed (rustup target add ${TARGET})"

# No `--features desktop`: that is the GUI's slint flag and means nothing here.
log "building ${BIN} (release) for ${ZIG_TARGET}"
cargo zigbuild --release --locked -p "${BIN}" --target "${ZIG_TARGET}"

# cargo-zigbuild emits under the base triple directory (no glibc suffix), which
# is also why this never collides with a native `target/release` build.
BIN_PATH="${REPO_ROOT}/target/${TARGET}/release/${BIN}"
[ -x "${BIN_PATH}" ] || die "built binary not found at ${BIN_PATH}"

mkdir -p "${OUT_DIR}"
cp -f "${BIN_PATH}" "${OUT_BIN}"

# Assert the floor rather than trusting the flag: a zigbuild that silently fell
# back to the host linker produces a binary that loads here and nowhere older,
# and the only symptom is a tester reporting a GLIBC version error.
log "checking the glibc floor"
MAX_GLIBC="$(objdump -T "${OUT_BIN}" | grep -oE 'GLIBC_[0-9.]+' | sort -u -V | tail -1 | sed 's/^GLIBC_//')"
[ -n "${MAX_GLIBC}" ] || die "no GLIBC version symbols found in ${OUT_BIN} — objdump read nothing, so this check proved nothing"
# Sort -V puts the higher version last; if that is the floor, nothing exceeds it.
[ "$(printf '%s\n%s\n' "${MAX_GLIBC}" "${GLIBC_FLOOR}" | sort -V | tail -1)" = "${GLIBC_FLOOR}" ] \
  || die "binary requires GLIBC_${MAX_GLIBC}, above the ${GLIBC_FLOOR} floor"
log "glibc floor ok (max symbol GLIBC_${MAX_GLIBC} <= ${GLIBC_FLOOR})"

# Signed LAST, after the copy and after the floor check, because the MAC covers
# the artifact's loader-invariant extent and anything that rewrites the file
# invalidates the slot. The signer is a build tool from oxicrypt's own tree,
# outside the cryptographic boundary; nothing here links it.
SIGNER_DIR="${REPO_ROOT}/../oxicrypt/tools/oxicrypt-integrity-sign"
[ -f "${SIGNER_DIR}/Cargo.toml" ] || die "integrity signer not found at ${SIGNER_DIR}"
log "building the integrity signer"
cargo build --release --locked --manifest-path "${SIGNER_DIR}/Cargo.toml"
SIGNER_BIN="${REPO_ROOT}/../oxicrypt/target/release/oxicrypt-integrity-sign"
[ -x "${SIGNER_BIN}" ] || die "integrity signer not built at ${SIGNER_BIN}"

log "signing the module image"
"${SIGNER_BIN}" --sign "${OUT_BIN}" || die "integrity signing failed"
# Read the slot back rather than trusting the signer's exit: a signer that wrote
# nothing exits the same way as one that worked, and the only symptom would be a
# tester reporting that the app refuses to start.
"${SIGNER_BIN}" --verify "${OUT_BIN}" || die "integrity slot did not verify after signing"

log "done: ${OUT_BIN}"
file "${OUT_BIN}"
