#!/usr/bin/env bash
# Prints the oxicrypt release-key fingerprint the build pins.
#
#   oxicrypt-fingerprint.sh [<cargo-config>]
#
# The pin is defined once, as OXICRYPT_LIB_FINGERPRINT in the `[env]` table of
# `.cargo/config.toml` (or <cargo-config>), which cargo hands to the `oxicrypt`
# crate's build. Cargo lets the environment override that value, so an
# OXICRYPT_LIB_FINGERPRINT already set in the environment is what the build
# used, and is printed instead.
#
# Exits 0 printing `sha256:<64 hex digits>`, 1 when the file does not hold
# exactly one such line, 2 on a usage error.
set -euo pipefail

[ $# -le 1 ] || { echo "usage: $0 [<cargo-config>]" >&2; exit 2; }
if [ -n "${OXICRYPT_LIB_FINGERPRINT:-}" ]; then
    value="${OXICRYPT_LIB_FINGERPRINT}"
else
    CONFIG="${1:-$(cd "$(dirname "$0")/.." && pwd)/.cargo/config.toml}"
    [ -f "${CONFIG}" ] || { echo "oxicrypt-fingerprint: no ${CONFIG}" >&2; exit 1; }
    matches="$(sed -n 's/^OXICRYPT_LIB_FINGERPRINT *= *"\([^"]*\)" *$/\1/p' "${CONFIG}")"
    [ "$(printf '%s' "${matches}" | grep -c '^')" -eq 1 ] \
        || { echo "oxicrypt-fingerprint: ${CONFIG} does not set OXICRYPT_LIB_FINGERPRINT exactly once" >&2; exit 1; }
    value="${matches}"
fi
[[ "${value}" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || { echo "oxicrypt-fingerprint: '${value}' is not sha256:<64 hex digits>" >&2; exit 1; }
echo "${value}"
