#!/usr/bin/env bash
#
# build-oracle.sh — portable build of a two-node network oracle as a runnable binary.
#
# `crates/daemonseed-veilid-net/tests/` holds eleven `#[ignore]`d two-node tests.
# Each needs a host that can attach to the public Veilid network, and the usual
# way to run one is `cargo test --test <name> -- --ignored` from a checkout on
# that host.
#
# That requires a full toolchain and a build directory wherever the test runs,
# which is not always where the network is. This does for the oracles what
# build-tui.sh does for the TUI: cross-links against an old glibc floor via
# cargo-zigbuild and emits ONE executable to copy and run.
#
# NOT SIGNED, unlike every other packaging script here, and that is deliberate.
# A shipped artifact must be signed or oxicrypt refuses to start; these oracles
# call `kats::initialize_module_unsigned_test_binary`, the test-only init that
# does the power-up self-tests without the image check — because a test binary's
# bytes are not a shipped module image. Signing one would be theatre. If you ever
# see `Module image integrity` from one of these, something else is wrong.
#
# Requirements:
#   - rustup with the x86_64-unknown-linux-gnu target
#   - cargo-zigbuild + zig   (the cross-linker that pins the glibc floor)
#
# Usage:
#   packaging/oracles/build-oracle.sh [TEST_NAME] [OUTPUT_DIR]
#
# TEST_NAME defaults to two_node_doorbell; it is the file stem under
# crates/daemonseed-veilid-net/tests/. OUTPUT_DIR defaults to ./dist/oracles.
# The resulting file is <OUTPUT_DIR>/<TEST_NAME>-x86_64.
#
# Knobs (env):
#   GLIBC_FLOOR   glibc version suffix for the target triple (default 2.35)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"
TEST_NAME="${1:-two_node_doorbell}"
OUT_DIR="${2:-${REPO_ROOT}/dist/oracles}"
GLIBC_FLOOR="${GLIBC_FLOOR:-2.35}"
TARGET="x86_64-unknown-linux-gnu"
ZIG_TARGET="${TARGET}.${GLIBC_FLOOR}"
CRATE="daemonseed-veilid-net"
OUT_BIN="${OUT_DIR}/${TEST_NAME}-x86_64"

log() { printf '\033[1;32m[oracle]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[oracle] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

command -v cargo-zigbuild >/dev/null || die "cargo-zigbuild not found (cargo install cargo-zigbuild + zig)"
command -v zig >/dev/null || die "zig not found"
command -v objdump >/dev/null || die "objdump not found (binutils) — the glibc floor check needs it"
rustup target list --installed 2>/dev/null | grep -qx "${TARGET}" || die "rust target ${TARGET} not installed (rustup target add ${TARGET})"

SRC="${REPO_ROOT}/crates/${CRATE}/tests/${TEST_NAME}.rs"
[ -f "${SRC}" ] || die "no such oracle: ${SRC}
available: $(cd "${REPO_ROOT}/crates/${CRATE}/tests" && ls *.rs | sed 's/\.rs$//' | tr '\n' ' ')"

# Release, not debug, and this is not a preference. These oracles mint a real
# proof of work at production difficulty; an unoptimised SHA-384 turns a couple
# of seconds into minutes and the run reads as a hang.
log "building oracle ${TEST_NAME} (release) for ${ZIG_TARGET}"
BUILD_JSON="$(mktemp)"
trap 'rm -f "${BUILD_JSON}"' EXIT
# `cargo-zigbuild test`, NOT `cargo zigbuild test`. `cargo zigbuild` dispatches to
# the `zigbuild` subcommand, which builds and does not take `test` — it fails with
# "unexpected argument 'test' found". `test` is a sibling subcommand of `zigbuild`,
# reachable only by invoking the binary directly. build-tui.sh uses the `cargo
# zigbuild` form correctly because it really is building, not testing.
cargo-zigbuild test --release --locked \
  -p "${CRATE}" --test "${TEST_NAME}" --no-run \
  --target "${ZIG_TARGET}" --message-format=json > "${BUILD_JSON}"

# A test binary carries a content hash in its filename, so the path cannot be
# constructed — it is read from cargo's own JSON. Taking the LAST executable
# emitted would be a guess; filter to this crate's test target by name.
BIN_PATH="$(python3 - "${BUILD_JSON}" "${TEST_NAME}" <<'PY'
import json, sys
path, want = sys.argv[1], sys.argv[2]
hits = []
for line in open(path):
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        continue
    exe = msg.get("executable")
    tgt = msg.get("target") or {}
    if exe and tgt.get("name") == want and "test" in (tgt.get("kind") or []):
        hits.append(exe)
# Exactly one match is the expected case. More than one would mean two test
# targets share a name, which cargo does not allow — so if it ever happens,
# say so rather than silently picking.
if len(hits) > 1:
    sys.exit(f"ambiguous: {len(hits)} test targets named {want}")
print(hits[0] if hits else "")
PY
)"
[ -n "${BIN_PATH}" ] || die "cargo emitted no executable for test target '${TEST_NAME}' — read ${BUILD_JSON}"
[ -x "${BIN_PATH}" ] || die "built binary not found or not executable at ${BIN_PATH}"

mkdir -p "${OUT_DIR}"
cp -f "${BIN_PATH}" "${OUT_BIN}"

# Assert the floor rather than trusting the flag: a zigbuild that silently fell
# back to the host linker produces a binary that loads here and nowhere older,
# and the only symptom is a tester reporting a GLIBC version error.
log "checking the glibc floor"
MAX_GLIBC="$(objdump -T "${OUT_BIN}" | grep -oE 'GLIBC_[0-9.]+' | sort -u -V | tail -1 | sed 's/^GLIBC_//')"
[ -n "${MAX_GLIBC}" ] || die "no GLIBC version symbols found in ${OUT_BIN} — objdump read nothing, so this check proved nothing"
[ "$(printf '%s\n%s\n' "${MAX_GLIBC}" "${GLIBC_FLOOR}" | sort -V | tail -1)" = "${GLIBC_FLOOR}" ] \
  || die "binary requires GLIBC_${MAX_GLIBC}, above the ${GLIBC_FLOOR} floor"
log "glibc floor ok (max symbol GLIBC_${MAX_GLIBC} <= ${GLIBC_FLOOR})"

# Prove the binary is the oracle we asked for and that it actually holds the
# ignored test — a test target that compiled to zero tests would run clean and
# mean nothing, which is the failure mode these scripts exist to prevent.
log "listing what the binary contains"
LISTED="$("${OUT_BIN}" --list --ignored 2>/dev/null || true)"
COUNT="$(printf '%s\n' "${LISTED}" | grep -c ': test$' || true)"
[ "${COUNT}" -ge 1 ] || die "the built binary lists ${COUNT} ignored tests — it would run clean and prove nothing"
printf '%s\n' "${LISTED}" | sed 's/^/    /'

log "done: ${OUT_BIN}"
file "${OUT_BIN}"
cat <<EOF

Run it on a host that can reach the public Veilid network:

    ${OUT_BIN} --ignored --nocapture

Nothing else is needed — no profile, no environment, no working directory. It
brings up two nodes in one process, attaches both, and tears them down. Expect
it to take a few minutes: each knock mints a real proof of work at production
difficulty before anything reaches the network, and both nodes wait on DHT
propagation.

A pass prints "test result: ok." with a non-zero count. A run that prints
0 passed has tested nothing.
EOF
