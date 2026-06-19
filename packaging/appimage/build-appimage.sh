#!/usr/bin/env bash
#
# build-appimage.sh — reproducible AppImage build for daemonseed-gui.
#
# Produces a portable, single-file x86_64 AppImage of the desktop GUI, linked
# against an old glibc floor (Ubuntu 22.04 "Jammy", glibc 2.35) via cargo-zigbuild
# so it runs on any reasonably recent Linux desktop without a local Rust toolchain.
#
# Requirements (all already present on the build VM):
#   - rustup with the x86_64-unknown-linux-gnu target
#   - cargo-zigbuild + zig   (the cross-linker that pins the glibc floor)
#   - appimagetool           (on PATH; assembles the AppDir into the .AppImage)
# No imagemagick is needed: the app icon is a scalable SVG.
#
# Usage:
#   packaging/appimage/build-appimage.sh [OUTPUT_DIR]
# OUTPUT_DIR defaults to ./dist. The resulting file is
#   <OUTPUT_DIR>/daemonseed-gui-x86_64.AppImage
#
# Knobs (env):
#   GLIBC_FLOOR   glibc version suffix for the target triple (default 2.35)
#   APPIMAGETOOL  path to appimagetool (default: first on PATH)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"
OUT_DIR="${1:-${REPO_ROOT}/dist}"
GLIBC_FLOOR="${GLIBC_FLOOR:-2.35}"
TARGET="x86_64-unknown-linux-gnu"
ZIG_TARGET="${TARGET}.${GLIBC_FLOOR}"
BIN="daemonseed-gui"
APPIMAGETOOL="${APPIMAGETOOL:-$(command -v appimagetool || true)}"

log() { printf '\033[1;32m[appimage]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[appimage] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

command -v cargo-zigbuild >/dev/null || die "cargo-zigbuild not found (cargo install cargo-zigbuild + zig)"
command -v zig >/dev/null || die "zig not found"
[ -n "${APPIMAGETOOL}" ] || die "appimagetool not found on PATH (set APPIMAGETOOL=...)"
rustup target list --installed 2>/dev/null | grep -qx "${TARGET}" || die "rust target ${TARGET} not installed (rustup target add ${TARGET})"

log "building ${BIN} (release, --features desktop) for ${ZIG_TARGET}"
cargo zigbuild --release --locked \
  -p "${BIN}" --features desktop \
  --target "${ZIG_TARGET}"

# cargo-zigbuild emits artifacts under the base triple directory (no glibc suffix).
BIN_PATH="${REPO_ROOT}/target/${TARGET}/release/${BIN}"
[ -x "${BIN_PATH}" ] || die "built binary not found at ${BIN_PATH}"

log "assembling AppDir"
APPDIR="$(mktemp -d)"
trap 'rm -rf "${APPDIR}"' EXIT
mkdir -p "${APPDIR}/usr/bin" \
         "${APPDIR}/usr/share/applications" \
         "${APPDIR}/usr/share/icons/hicolor/scalable/apps"

install -m 0755 "${BIN_PATH}"                       "${APPDIR}/usr/bin/${BIN}"
install -m 0755 "${HERE}/AppRun"                    "${APPDIR}/AppRun"
install -m 0644 "${HERE}/${BIN}.desktop"            "${APPDIR}/${BIN}.desktop"
install -m 0644 "${HERE}/${BIN}.desktop"            "${APPDIR}/usr/share/applications/${BIN}.desktop"
install -m 0644 "${HERE}/${BIN}.svg"                "${APPDIR}/${BIN}.svg"
install -m 0644 "${HERE}/${BIN}.svg"                "${APPDIR}/usr/share/icons/hicolor/scalable/apps/${BIN}.svg"

mkdir -p "${OUT_DIR}"
OUT_FILE="${OUT_DIR}/${BIN}-x86_64.AppImage"
log "packaging → ${OUT_FILE}"
# ARCH is required by appimagetool when it cannot infer it; --no-appstream keeps
# the build offline (no network validation of an AppStream feed).
ARCH=x86_64 "${APPIMAGETOOL}" --no-appstream "${APPDIR}" "${OUT_FILE}"

log "done: ${OUT_FILE}"
