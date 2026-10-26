#!/usr/bin/env bash
# Loads a built release binary on the machine that built it, far enough that
# the oxicrypt module must initialise, and checks what it shows.
#
#   release-load-check.sh gui <executable>
#   release-load-check.sh tui <executable>
#   release-load-check.sh missing-library <executable>
#
# gui              runs `<executable> --self-check`, the GUI's headless path
#                  that initialises the module, joins a circle from a fixed
#                  phrase (deriving the circle's key) and checks that a draft
#                  survives switching circles; joining fails unless the module
#                  is operational. Requires exit 0 and
#                  `SELF-CHECK PASS`. An AppImage runs with
#                  APPIMAGE_EXTRACT_AND_RUN=1, so it needs no FUSE.
# tui              runs `<executable> --portable` in a 120x40 pseudo-terminal
#                  from an empty directory for a few seconds; the TUI
#                  initialises the module before it draws anything and exits
#                  with `crypto module init failed` when that fails, so the
#                  first-start screen is the evidence. Needs `script`.
# missing-library  the control: a copy of <executable> alone in an empty
#                  directory must fail to start, because the loader cannot
#                  find the oxicrypt library beside it.
#
# Each run starts in a fresh empty directory. Prints one `load check: ...`
# line on success. Exits 0 when the check passes, 1 when it fails, 2 on a
# usage error.
set -euo pipefail

[ $# -eq 2 ] || { echo "usage: $0 <gui|tui|missing-library> <executable>" >&2; exit 2; }
MODE="$1" EXE="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
[ -f "${EXE}" ] || { echo "not a file: $2" >&2; exit 2; }
fail() { echo "release-load-check: $*" >&2; exit 1; }
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
cd "${WORK}"

case "${MODE}" in
    gui)
        status=0
        APPIMAGE_EXTRACT_AND_RUN=1 timeout 300 "${EXE}" --self-check > out.txt 2>&1 || status=$?
        tail -n 20 out.txt
        [ "${status}" -eq 0 ] || fail "the GUI self-check exited ${status}"
        grep -q 'SELF-CHECK PASS' out.txt || fail "the GUI self-check did not report a pass"
        echo "load check: daemonseed-gui --self-check initialised the oxicrypt module and passed"
        ;;
    tui)
        command -v script >/dev/null || fail "script(1) is not available"
        status=0
        TERM=xterm-256color timeout 8 script -qec "stty cols 120 rows 40; '${EXE}' --portable" /dev/null \
            > screen.raw 2>&1 || status=$?
        [ "${status}" -eq 124 ] || fail "the TUI exited ${status} before the timeout"
        ! grep -q 'init failed' screen.raw || fail "the TUI reported a crypto module init failure"
        grep -q 'identity' screen.raw || fail "the TUI did not draw its first-start screen"
        echo "load check: daemonseed-tui initialised the oxicrypt module and drew its first-start screen"
        ;;
    missing-library)
        mkdir alone
        cp "${EXE}" alone/
        status=0
        "./alone/$(basename "${EXE}")" --self-check > out.txt 2>&1 || status=$?
        cat out.txt
        [ "${status}" -ne 0 ] || fail "a copy without the oxicrypt library beside it started"
        case "$(uname -s)" in
            MINGW* | MSYS* | CYGWIN*) ;;
            *) grep -q 'oxicrypt_ffi' out.txt || fail "the failure did not name the oxicrypt library" ;;
        esac
        echo "control: a copy without the library fails to start (exit ${status})"
        ;;
    *) echo "unknown mode: ${MODE}" >&2; exit 2 ;;
esac
