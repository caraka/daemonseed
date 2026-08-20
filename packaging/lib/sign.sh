#!/usr/bin/env bash
#
# sign.sh — resolve the integrity signer and sign a built artifact.
#
# Sourced by every packaging script. The oxicrypt module verifies its own image
# before doing any work, so an unsigned artifact exits at startup with
# "Module image integrity"; this is the step that stops that reaching a user.
#
# ── The contract this exists to keep ─────────────────────────────────────────
# The slot format and the integrity key are a contract between two halves: the
# `oxicrypt-integrity` a binary LINKS, and the `oxicrypt-integrity-sign` that
# writes its slot. If they disagree, the signer writes a slot the runtime cannot
# verify and the app refuses to start — so the two must come from the same
# source, not merely the same version number.
#
# That distinction is load-bearing under `[patch.crates-io]`. With the patch on,
# the runtime is a local checkout whose `version` still reads `0.24.0` while its
# HEAD may be several commits past the tag. Installing "0.24.0" from the registry
# there would pair a published signer with an unpublished runtime — version-
# identical, materially different. So the source is read from cargo, not assumed:
# a path source builds the signer from that same tree, a registry source installs
# the pinned release.

# Resolve (building or installing as needed) the signer matching this workspace's
# `oxicrypt-integrity-sign`, and echo its path. Takes the repo root.
resolve_signer() {
    local repo_root="$1"
    local meta version source prefix bin

    # `--locked` first, on purpose: without it this is a resolver run that can
    # rewrite `Cargo.lock` as a side effect of packaging, which would let an
    # artifact be built against a dependency set nobody reviewed.
    #
    # It legitimately fails under an active `[patch.crates-io]`, because a patched
    # build genuinely resolves to something the pinned lockfile does not describe.
    # So the fallback is allowed — but only loudly, and only after saying which
    # build this is. On the pinned path that warning never prints; if it ever does
    # print there, the lockfile and the manifests have diverged and the artifact is
    # not the reviewed one.
    meta="$(cargo metadata --format-version 1 --locked --manifest-path "${repo_root}/Cargo.toml" 2>/dev/null)"
    if [ -z "${meta}" ]; then
        echo "[sign] cargo metadata --locked failed — resolving unlocked." >&2
        echo "[sign] EXPECTED under [patch.crates-io]; anywhere else it means the" >&2
        echo "[sign] lockfile disagrees with the manifests and this artifact is not" >&2
        echo "[sign] the pinned build." >&2
        meta="$(cargo metadata --format-version 1 --manifest-path "${repo_root}/Cargo.toml" 2>/dev/null)" \
            || { echo "[sign] cargo metadata failed outright" >&2; return 1; }
    fi

    # Version AND source together, and exactly one match: a graph resolving two
    # versions of the signer would otherwise pick whichever came first.
    local resolved
    resolved="$(printf '%s' "${meta}" | python3 -c '
import json, sys
m = json.load(sys.stdin)
hits = [p for p in m["packages"] if p["name"] == "oxicrypt-integrity-sign"]
if len(hits) != 1:
    print("AMBIGUOUS", len(hits))
else:
    p = hits[0]
    # `source` is null for a path/patched package and a registry URL otherwise.
    print("PATH" if p.get("source") is None else "REGISTRY", p["version"], p["manifest_path"])
')" || { echo "[sign] could not read the signer from cargo metadata" >&2; return 1; }

    read -r source version manifest <<<"${resolved}"
    case "${source}" in
        AMBIGUOUS)
            echo "[sign] ${version} versions of oxicrypt-integrity-sign in the graph; refusing to guess" >&2
            return 1 ;;
        PATH|REGISTRY) ;;
        *)
            echo "[sign] unexpected signer resolution: ${resolved}" >&2
            return 1 ;;
    esac

    prefix="${repo_root}/target/signer/${source}-${version}"
    bin="${prefix}/bin/oxicrypt-integrity-sign"

    if ! signer_is_usable "${bin}"; then
        rm -rf "${prefix}"
        if [ "${source}" = "PATH" ]; then
            # Patched build: the runtime is that checkout, so the signer must be
            # too. Building from the same manifest is the only way the two agree
            # when the version number cannot tell them apart.
            echo "[sign] building oxicrypt-integrity-sign from ${manifest} (patched runtime)" >&2
            cargo install --path "$(dirname "${manifest}")" --root "${prefix}" --locked >&2 || return 1
        else
            echo "[sign] installing oxicrypt-integrity-sign ${version} from the registry" >&2
            cargo install oxicrypt-integrity-sign --version "${version}" --root "${prefix}" --locked >&2 || return 1
        fi
    fi

    signer_is_usable "${bin}" || { echo "[sign] signer at ${bin} is not usable after install" >&2; return 1; }
    echo "${bin}"
}

# Is this a signer that actually runs, and is it the right program?
#
# `[ -x ]` is not enough and the gap is not academic: a ZERO-BYTE file with the
# execute bit set is run by bash as an empty script and exits 0, so every later
# `--sign` and `--verify` "succeeds" while nothing is written.
#
# The probe is the OUTPUT, not the exit status — this tool prints its usage and
# exits 1, so a check written `--help >/dev/null` refuses a perfectly good
# signer. (Found by running the fix against the real binary, which is the only
# reason it is not still here: a fix that over-refuses looks exactly like a fix
# that works until the day it blocks a release.) Requiring the usage text to name
# `--sign` also distinguishes this program from any other executable that
# happens to sit at the path.
signer_is_usable() {
    local bin="$1" usage
    [ -s "${bin}" ] && [ -x "${bin}" ] || return 1
    # Captured, not piped. Under the `set -o pipefail` every caller sets, a
    # pipeline inherits this tool's exit 1 even when the grep matches — so the
    # obvious `--help | grep -q` form refuses every working signer, and does it
    # only inside the scripts, never in an interactive shell where one would
    # test it. Substitution with `|| true` takes the OUTPUT and discards the
    # status, which is the thing actually being examined.
    usage="$("${bin}" --help 2>&1 || true)"
    case "${usage}" in
        *--sign*) return 0 ;;
        *) return 1 ;;
    esac
}

# Sign an artifact, and prove the bytes changed.
#
# `--verify` alone is not an independent oracle: it runs the same binary that did
# the signing, so a signer that no-ops both verbs passes. Hashing the artifact
# either side of the sign is a check the signer cannot satisfy by doing nothing.
sign_artifact() {
    local signer="$1" artifact="$2" before after
    before="$(sha256sum "${artifact}" | cut -d' ' -f1)" || return 1
    "${signer}" --sign "${artifact}" || return 1
    after="$(sha256sum "${artifact}" | cut -d' ' -f1)" || return 1
    if [ "${before}" = "${after}" ]; then
        echo "[sign] the artifact is byte-identical after signing — no slot was written" >&2
        return 1
    fi
    "${signer}" --verify "${artifact}" || return 1
}
