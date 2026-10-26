#!/usr/bin/env bash
#
# build-tui.sh — portable build of the daemonseed TUI.
#
# Produces an x86_64 binary linked against an old glibc floor (Ubuntu 22.04
# "Jammy", glibc 2.35) via cargo-zigbuild, so it runs on a host older than the
# build machine, and places oxicrypt's signed shared library beside it, where
# the binary's $ORIGIN RUNPATH finds it. Ship the two files together.
#
# Requirements:
#   - rustup with the x86_64-unknown-linux-gnu target
#   - cargo-zigbuild + zig   (the cross-linker that pins the glibc floor)
#   - network access on the first build, to fetch the pinned oxicrypt library
#     (cached under target/oxicrypt-ffi/ afterwards)
#
# Usage:
#   packaging/tui/build-tui.sh [OUTPUT_DIR]
# OUTPUT_DIR defaults to ./dist. The resulting files are
#   <OUTPUT_DIR>/daemonseed-tui-x86_64
#   <OUTPUT_DIR>/liboxicrypt_ffi.so.1
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

# The signed oxicrypt library the binary links, fetched at the pinned release.
# shellcheck source=../lib/oxicrypt-ffi.sh
. "${HERE}/../lib/oxicrypt-ffi.sh"
oxicrypt_prepare "${REPO_ROOT}" || die "could not prepare the oxicrypt library"

# No `--features desktop`: that is the GUI's slint flag and means nothing here.
log "building ${BIN} (release) for ${ZIG_TARGET}"
RUSTFLAGS="$(oxicrypt_rustflags)" cargo zigbuild --release --locked -p "${BIN}" --target "${ZIG_TARGET}"

# cargo-zigbuild emits under the base triple directory (no glibc suffix), which
# is also why this never collides with a native `target/release` build.
BIN_PATH="${REPO_ROOT}/target/${TARGET}/release/${BIN}"
[ -x "${BIN_PATH}" ] || die "built binary not found at ${BIN_PATH}"

mkdir -p "${OUT_DIR}"
cp -f "${BIN_PATH}" "${OUT_BIN}"
oxicrypt_bundle "${OUT_DIR}" || die "could not bundle ${OXICRYPT_SONAME}"

# Assert the floor rather than trusting the flag: a zigbuild that silently fell
# back to the host linker produces a binary that loads here and nowhere older,
# and the only symptom is a tester reporting a GLIBC version error.
log "checking the glibc floor"
MAX_GLIBC="$(oxicrypt_check_glibc "${GLIBC_FLOOR}" "${OUT_BIN}" "${OUT_DIR}/${OXICRYPT_SONAME}")" \
  || die "glibc floor check failed"
log "glibc floor ok (max symbol GLIBC_${MAX_GLIBC} <= ${GLIBC_FLOOR})"

log "done: ${OUT_BIN}"
file "${OUT_BIN}" "${OUT_DIR}/${OXICRYPT_SONAME}"
