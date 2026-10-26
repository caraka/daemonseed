#!/usr/bin/env bash
# Checks every leg's staged archive against the matrix row that built it.
#
#   verify-release-rows.sh <records-dir> <allow-list> <count>
#
#   <records-dir>  the downloaded workflow artifacts: one directory per leg,
#                  holding `row.txt` and `dist/`
#   <allow-list>   packaging/release/import-allow-list.txt
#   <count>        how many legs the matrix has
#
# Each `row.txt` is one line, `<archive> <triple>`: the archive the leg's
# stage step wrote and the target triple of its matrix row. Each leg's `dist/`
# must hold exactly that archive and its `.sha256`, the checksum must verify,
# and scripts/check-release-artifact.py must accept the archive for that
# triple, which requires a `.zip` for a Windows triple and a `.tar.gz` for any
# other. Exits 0 when every leg passes, 1 otherwise, 2 on a usage error.
set -euo pipefail

[ $# -eq 3 ] || { echo "usage: $0 <records-dir> <allow-list> <count>" >&2; exit 2; }
RECORDS="$1" ALLOW="$2" COUNT="$3"
HERE="$(cd "$(dirname "$0")" && pwd)"
fail() { echo "verify-release-rows: $*" >&2; exit 1; }

listing="$(find "${RECORDS}" -name row.txt -type f)"
mapfile -t rows < <(sort <<<"${listing}" | grep . || true)
[ "${#rows[@]}" -eq "${COUNT}" ] || fail "expected ${COUNT} legs, found ${#rows[@]}"
for row in "${rows[@]}"; do
    read -r archive triple rest < "${row}" || fail "${row} is empty"
    [ -n "${archive}" ] && [ -n "${triple}" ] && [ -z "${rest:-}" ] \
        || fail "${row} is not '<archive> <triple>'"
    dist="$(dirname "${row}")/dist"
    have="$(cd "${dist}" && find . -type f | sed 's#^\./##' | sort)"
    want="$(printf '%s\n%s.sha256\n' "${archive}" "${archive}" | sort)"
    [ "${have}" = "${want}" ] || fail "${dist} holds ${have//$'\n'/, }, not ${archive} and its checksum"
    (cd "${dist}" && sha256sum -c "${archive}.sha256" >/dev/null) || fail "${archive}.sha256 does not verify"
    PYTHONDONTWRITEBYTECODE=1 python3 "${HERE}/check-release-artifact.py" \
        --triple "${triple}" --allow-list "${ALLOW}" "${dist}/${archive}" \
        || fail "${archive} fails its check for ${triple}"
done
echo "verify-release-rows: ${COUNT} legs checked"
