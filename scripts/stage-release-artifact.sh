#!/usr/bin/env bash
# Packs one leg's release files with their provenance.
#
#   stage-release-artifact.sh <label> <leg> <triple> <load-check> <out-dir> <file> [<file> ...]
#
#   <label>       the release tag, or the dry run's label
#   <leg>         the matrix row's name, e.g. linux-x86_64-appimage
#   <triple>      the target triple the leg built for
#   <load-check>  one line saying how the artifact was loaded and what it showed
#   <out-dir>     where the archive and its checksum are written
#   <file>        the files the artifact ships
#
# Reads OXICRYPT_LIB_DIR (the fetched oxicrypt release directory, holding the
# library, its tarball and oxicrypt's own BUILD-PROVENANCE.txt),
# OXICRYPT_LIB_FILE (the library's file name in that directory) and
# OXICRYPT_LIB_FINGERPRINT (the release-key fingerprint the build pinned, as
# scripts/oxicrypt-fingerprint.sh prints it).
# Optional: RUN_URL (the run that built the files), RELEASE_PROVENANCE_EXTRA
# (a file whose lines are appended to the provenance) and RELEASE_ARCHIVE
# (`zip` or `tar.gz`, overriding the format the triple selects).
#
# Writes <out-dir>/daemonseed-<label>-<leg>.<format>, holding a directory of
# the same name with the files and BUILD-PROVENANCE.txt, and its .sha256 beside
# it, and prints the archive's file name last. The format is `zip` for a
# Windows triple and `tar.gz` for any other, as check-release-artifact.py
# requires.
# Refuses when the fingerprint oxicrypt's provenance names is not the pinned
# one. Exits 0 when staged, 1 on a refusal, 2 on a usage error.
set -euo pipefail

[ $# -ge 6 ] || { echo "usage: $0 <label> <leg> <triple> <load-check> <out-dir> <file> [<file> ...]" >&2; exit 2; }
LABEL="$1" LEG="$2" TRIPLE="$3" LOADED="$4" OUT="$5"
shift 5
fail() { echo "stage-release-artifact: $*" >&2; exit 1; }
for v in OXICRYPT_LIB_DIR OXICRYPT_LIB_FILE OXICRYPT_LIB_FINGERPRINT; do
    [ -n "${!v:-}" ] || { echo "stage-release-artifact: ${v} is not set" >&2; exit 2; }
done
for f in "$@"; do [ -f "${f}" ] || { echo "not a file: ${f}" >&2; exit 2; }; done

lib="${OXICRYPT_LIB_DIR}/${OXICRYPT_LIB_FILE}"
[ -f "${lib}" ] || fail "no oxicrypt library at ${lib}"
lib_sha="$(sha256sum "${lib}" | cut -d' ' -f1)"
upstream="$(sed -n 's/^  verify key: //p' "${OXICRYPT_LIB_DIR}/BUILD-PROVENANCE.txt")" \
    || fail "could not read oxicrypt's provenance"
[ "${upstream}" = "${OXICRYPT_LIB_FINGERPRINT}" ] \
    || fail "oxicrypt's provenance names verify key '${upstream}', not the pinned ${OXICRYPT_LIB_FINGERPRINT}"

commit="$(git rev-parse HEAD)" || fail "could not read the commit"
rustc_version="$(rustc --version)" || fail "could not read the rustc version"
[ -n "${commit}" ] && [ -n "${rustc_version}" ] || fail "the commit or the rustc version is empty"

NAME="daemonseed-${LABEL}-${LEG}"
mkdir -p "${OUT}"
STAGE="$(mktemp -d)"
trap 'rm -rf "${STAGE}"' EXIT
mkdir "${STAGE}/${NAME}"
cp "$@" "${STAGE}/${NAME}/"
{
    echo "daemonseed ${LABEL} — ${LEG}"
    echo ""
    echo "target triple        : ${TRIPLE}"
    echo "commit               : ${commit}"
    echo "rustc                : ${rustc_version}"
    echo "built by             : ${RUN_URL:-a local build}"
    echo "oxicrypt library     : ${OXICRYPT_LIB_FILE} sha256:${lib_sha}"
    echo "oxicrypt release key : ${OXICRYPT_LIB_FINGERPRINT}"
    echo "load check           : ${LOADED}"
    if [ -n "${RELEASE_PROVENANCE_EXTRA:-}" ]; then cat "${RELEASE_PROVENANCE_EXTRA}"; fi
    echo ""
    echo "daemonseed binaries carry no signature of their own. The oxicrypt"
    echo "library is oxicrypt's release file, unchanged; it verifies its own"
    echo "signature against the release key above when it is initialised."
} > "${STAGE}/${NAME}/BUILD-PROVENANCE.txt"

case "${RELEASE_ARCHIVE:-${TRIPLE}}" in
    zip | *-windows-*) FORMAT=zip ;;
    *) FORMAT=tar.gz ;;
esac
ARCHIVE="${NAME}.${FORMAT}"
if [ "${FORMAT}" = zip ]; then
    PY="$(command -v python3 || command -v python)" || fail "no python to write the zip with"
    out_abs="$(cd "${OUT}" && pwd)"
    # A native Windows python reads a Windows path, not the shell's.
    if command -v cygpath >/dev/null; then out_abs="$(cygpath -w "${out_abs}")"; fi
    (cd "${STAGE}" && "${PY}" -c '
import os, sys, zipfile
name, out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for d, _, fs in os.walk(name):
        for f in sorted(fs):
            z.write(os.path.join(d, f))
' "${NAME}" "${out_abs}/${ARCHIVE}") || fail "could not write ${ARCHIVE}"
else
    tar -C "${STAGE}" -czf "${OUT}/${ARCHIVE}" "${NAME}"
fi
(cd "${OUT}" && sha256sum "${ARCHIVE}" > "${ARCHIVE}.sha256")
cat "${OUT}/${ARCHIVE}.sha256"
echo "${ARCHIVE}"
