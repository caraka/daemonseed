#!/usr/bin/env bash
# Fetch the signed oxicrypt shared library (liboxicrypt_ffi) that daemonseed
# links through the `oxicrypt` crate, and check it against the pinned digest.
#
# Usage: scripts/fetch-oxicrypt-ffi.sh [PLATFORM] [DEST]
#   PLATFORM  linux-x86_64 (default) or windows-x86_64
#   DEST      directory to unpack into
#             (default target/oxicrypt-ffi/v<VERSION>/<PLATFORM>)
#
# The version and each tarball's sha256 are pinned here and change together
# with the `oxicrypt` version in the workspace Cargo.toml. The default DEST is
# the directory `.cargo/config.toml` points OXICRYPT_LIB_DIR at, and which its
# Linux runner puts on the library search path of the programs cargo runs
# (`cargo test`, `cargo run`), so no run-time path is needed for development.
# It lies inside `target/`, so `cargo clean` removes it; run this script again
# afterwards.
#
# Prints the absolute path of the unpacked library directory on stdout.
set -euo pipefail

VERSION="0.26.0"
PLATFORM="${1:-linux-x86_64}"

case "${PLATFORM}" in
  linux-x86_64)   SHA256="3570545f66a2d2945a2fd1f14cc09641e6c651cbe8cdd83f4d2add59f5cd857f" ;;
  windows-x86_64) SHA256="1815c11f46e964a6a5e10b1a526dfcce390b776a6171cf885792cadb2debb961" ;;
  *) echo "fetch-oxicrypt-ffi: unsupported platform ${PLATFORM}" >&2; exit 2 ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${2:-${ROOT}/target/oxicrypt-ffi/v${VERSION}/${PLATFORM}}"
NAME="oxicrypt-ffi-v${VERSION}-${PLATFORM}"
URL="https://github.com/oxiforge/oxicrypt/releases/download/v${VERSION}/${NAME}.tar.gz"

mkdir -p "${DEST}"
TARBALL="${DEST}/${NAME}.tar.gz"

if [ ! -f "${TARBALL}" ] || ! echo "${SHA256}  ${TARBALL}" | sha256sum --check --status; then
  curl --fail --location --silent --show-error --max-time 300 --output "${TARBALL}.part" "${URL}"
  mv -f "${TARBALL}.part" "${TARBALL}"
fi
echo "${SHA256}  ${TARBALL}" | sha256sum --check --quiet \
  || { echo "fetch-oxicrypt-ffi: ${TARBALL} does not match the pinned sha256" >&2; exit 1; }

tar -xzf "${TARBALL}" -C "${DEST}" --strip-components=1
echo "${DEST}"
