#!/usr/bin/env bash
# Tests check-release-tag.sh, release-guard.sh, attach-draft.sh,
# oxicrypt-fingerprint.sh, stage-release-artifact.sh,
# check-release-artifact.py and verify-release-rows.sh against fixtures.
#
#   test-release-scripts.sh
#
# check-release-tag.sh runs in scratch repositories whose tags are signed with
# ssh keys generated here: one named in the allowed-signers file, one not.
# attach-draft.sh runs against a stub `gh` that keeps the repository's
# releases as JSON and answers the calls the script makes, applying each
# `--jq` filter with jq, so the filters the script sends are the ones tested.
# The stub records the bytes, content type and path of every upload, refuses
# a second asset of the same name as GitHub does, fails a named call on
# request, and can leave a just-created draft out of the next few lists, as
# GitHub's list lags a draft created a moment earlier.
# release-guard.sh runs against the same scratch repositories, with a stub
# checker that records whether it was called.
#
# The staging and artifact checks run on fixture tarballs holding a small
# executable and shared object built here with `cc`, standing in for a release
# binary and the oxicrypt library.
#
# Every case asserts the exit status and a line of the output. Needs git,
# ssh-keygen, python3, jq, rustc, cc, readelf and objdump. Exits 0 when every case passes, 1 otherwise.
set -euo pipefail

# The fixtures below create, commit to and tag repositories of their own. A git
# hook exports GIT_DIR and its relatives to everything it runs, and with them
# set every git command here would act on the repository the hook runs for
# instead. Clear git's repository-local variables before anything calls git;
# the list comes from git itself and needs no repository.
# shellcheck disable=SC2046
unset $(git rev-parse --local-env-vars)

HERE="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
pass=0 failed=0

# expect <name> <status> <needle> <command...>
expect() {
    local name="$1" want="$2" needle="$3" out status=0
    shift 3
    out="$("$@" 2>&1)" || status=$?
    if [ "$status" = "$want" ] && grep -qF -- "$needle" <<<"$out"; then
        pass=$((pass + 1))
    else
        failed=$((failed + 1))
        echo "FAIL $name: exit $status (want $want), output:" >&2
        printf '    %s\n' "${out//$'\n'/$'\n'    }" >&2
    fi
}

# check <name> <condition...>
check() {
    local name="$1"
    shift
    if "$@"; then pass=$((pass + 1)); else failed=$((failed + 1)); echo "FAIL $name" >&2; fi
}

# --- check-release-tag.sh -------------------------------------------------

ssh-keygen -q -t ed25519 -N '' -C allowed -f "$T/allowed-key"
ssh-keygen -q -t ed25519 -N '' -C other -f "$T/other-key"
echo "release@example.org $(cat "$T/allowed-key.pub")" > "$T/allowed-signers"

# repo <dir> <workspace version>: a repository with `main` and a side branch.
repo() {
    git init -q -b main "$1"
    printf '[workspace.package]\nversion = "%s"\n' "$2" > "$1/Cargo.toml"
    G="$1"
    g add Cargo.toml
    g commit -q -m base
    g switch -q -c side
    g commit -q --allow-empty -m side
    g switch -q main
}
g() { git -C "$G" -c user.name=Test -c user.email=tagger@example.org -c commit.gpgsign=false \
    -c tag.gpgsign=false -c gpg.format=ssh "$@"; }

# tag <name> <commit> <signed-with: allowed|other|none|lightweight>
tag() {
    g tag -d "$1" >/dev/null 2>&1 || true
    case "$3" in
        allowed) g -c user.signingkey="$T/allowed-key" tag -s -m "$1" "$1" "$2" ;;
        other) g -c user.signingkey="$T/other-key" tag -s -m "$1" "$1" "$2" ;;
        none) g tag -a -m "$1" "$1" "$2" ;;
        lightweight) g tag "$1" "$2" ;;
    esac
}
run_check() { (cd "$G" && "$HERE/check-release-tag.sh" "$1" "$2" "$T/allowed-signers" main); }

repo "$T/repo" 1.2.3
MAIN="$(g rev-parse main)"
SIDE="$(g rev-parse side)"

tag v1.2.3 "$MAIN" allowed
expect "signed release tag accepted" 0 "accepted: v1.2.3" run_check v1.2.3 "$MAIN"
tag v1.2.3-rc.1 "$MAIN" allowed
expect "signed pre-release tag accepted" 0 "accepted: v1.2.3-rc.1" run_check v1.2.3-rc.1 "$MAIN"
tag v1.2.3-rc-1.x "$MAIN" allowed
expect "hyphenated pre-release tag accepted" 0 "accepted: v1.2.3-rc-1.x" run_check v1.2.3-rc-1.x "$MAIN"
tag v1.2.4 "$MAIN" allowed
expect "other version refused" 1 "does not name the workspace version 1.2.3" run_check v1.2.4 "$MAIN"
expect "build metadata refused" 1 "is not v followed by a SemVer" run_check v1.2.3+build "$MAIN"
expect "leading zero refused" 1 "is not v followed by a SemVer" run_check v01.2.3 "$MAIN"
expect "numeric pre-release leading zero refused" 1 "is not v followed by a SemVer" run_check v1.2.3-01 "$MAIN"
expect "empty pre-release identifier refused" 1 "is not v followed by a SemVer" run_check v1.2.3-rc..1 "$MAIN"
expect "empty pre-release refused" 1 "is not v followed by a SemVer" run_check v1.2.3- "$MAIN"
tag v1.2.3 "$MAIN" lightweight
expect "lightweight tag refused" 1 "is not an annotated tag" run_check v1.2.3 "$MAIN"
tag v1.2.3 "$MAIN" none
expect "unsigned annotated tag refused" 1 "does not carry a valid signature" run_check v1.2.3 "$MAIN"
tag v1.2.3 "$MAIN" other
expect "tag signed by an unlisted key refused" 1 "does not carry a valid signature" run_check v1.2.3 "$MAIN"
tag v1.2.3 "$SIDE" allowed
expect "tag off main refused" 1 "is not on main" run_check v1.2.3 "$SIDE"
tag v1.2.3 "$MAIN" allowed
expect "tag naming another commit refused" 1 "names $MAIN, not $SIDE" run_check v1.2.3 "$SIDE"
g update-ref refs/tags/v1.2.3-renamed "$(g rev-parse refs/tags/v1.2.3)"
expect "signed tag object under another name refused" 1 "was signed as v1.2.3" run_check v1.2.3-renamed "$MAIN"
tag v1.2.3-rc.1 "$MAIN" allowed
g update-ref refs/tags/v1.2.3 "$(g rev-parse refs/tags/v1.2.3-rc.1)"
expect "signed pre-release object pushed as the release refused" 1 "was signed as v1.2.3-rc.1" run_check v1.2.3 "$MAIN"
tag v1.2.3 "$MAIN" allowed
expect "missing tag refused" 1 "is not an annotated tag" run_check v1.2.3-rc.2 "$MAIN"
expect "missing allowed-signers refused" 1 "no allowed-signers file" \
    bash -c "cd '$G' && '$HERE/check-release-tag.sh' v1.2.3 '$MAIN' '$T/absent' main"
expect "usage error" 2 "usage:" "$HERE/check-release-tag.sh" v1.2.3 "$MAIN"
g update-ref refs/remotes/origin/main "$MAIN"
expect "default main ref is origin/main" 0 "accepted: v1.2.3" \
    bash -c "cd '$G' && '$HERE/check-release-tag.sh' v1.2.3 '$MAIN' '$T/allowed-signers'"
g update-ref refs/remotes/origin/main "$(g commit-tree "$(g rev-parse "$MAIN^{tree}")" -m unrelated)"
expect "default main ref refuses a commit not on origin/main" 1 "is not on origin/main" \
    bash -c "cd '$G' && '$HERE/check-release-tag.sh' v1.2.3 '$MAIN' '$T/allowed-signers'"

repo "$T/pre" 1.3.0-rc.1
PRE="$(g rev-parse main)"
tag v1.3.0-rc.1 "$PRE" allowed
expect "pre-release workspace: its own tag accepted" 0 "accepted: v1.3.0-rc.1" run_check v1.3.0-rc.1 "$PRE"
tag v1.3.0 "$PRE" allowed
expect "pre-release workspace: release tag refused" 1 "does not name the workspace version 1.3.0-rc.1" run_check v1.3.0 "$PRE"
tag v1.3.0-rc.2 "$PRE" allowed
expect "pre-release workspace: another pre-release refused" 1 "does not name the workspace version 1.3.0-rc.1" run_check v1.3.0-rc.2 "$PRE"

repo "$T/beta" 1.4.0-beta.1
BETA="$(g rev-parse main)"
tag v1.4.0 "$BETA" allowed
expect "beta workspace: release tag refused" 1 "does not name the workspace version 1.4.0-beta.1" run_check v1.4.0 "$BETA"
tag v1.4.0-beta.1 "$BETA" allowed
expect "beta workspace: its own tag accepted" 0 "accepted: v1.4.0-beta.1" run_check v1.4.0-beta.1 "$BETA"

# --- release-guard.sh -----------------------------------------------------

# A checker that records each call and answers as check-release-tag.sh would
# for the case at hand: STUB_CHECK=accept or refuse.
cat > "$T/checker" <<'CHK'
#!/usr/bin/env bash
echo "$*" >> "$STUB_CHECK_LOG"
[ "$STUB_CHECK" = accept ] && { echo "accepted: $1"; exit 0; }
echo "refused: stub" >&2; exit 1
CHK
guard() { (cd "$G" && STUB_CHECK_LOG="$T/checker.log" "$HERE/release-guard.sh" "$@" "$T/checker" "$T/allowed-signers"); }
G="$T/repo"
tag v1.2.3 "$MAIN" allowed
: > "$T/checker.log"
export STUB_CHECK=accept
expect "dispatch: never stages" 0 "publish=false" guard workflow_dispatch branch side "$SIDE" ""
expect "dispatch with a valid signed tag: still never stages" 0 "publish=false" guard workflow_dispatch branch main "$MAIN" v1.2.3
expect "dispatch with a tag: builds the commit the tag names" 0 "sha=$MAIN" guard workflow_dispatch branch side "$SIDE" v1.2.3
expect "dispatch without a tag: a dry-run label" 0 "label=dryrun-${SIDE:0:12}" guard workflow_dispatch branch side "$SIDE" ""
check "dispatch: the checker is never run" [ ! -s "$T/checker.log" ]
expect "dispatch: runs the legs" 0 "run=true" guard workflow_dispatch branch side "$SIDE" ""
# pr <action> <labels-json> [<added-label>] <guard args...>: a pull_request
# event in that state.
pr() {
    local action="$1" labels="$2" added="$3"
    shift 3
    PR_ACTION="$action" PR_LABELS_JSON="$labels" PR_ADDED_LABEL="$added" guard pull_request branch 7/merge "$@"
}
LABELLED='["documentation", "release-dry-run"]'
expect "labelled pull request: never stages" 0 "publish=false" pr opened "$LABELLED" "" "$SIDE" ""
expect "labelled pull request: runs the legs" 0 "run=true" pr synchronize "$LABELLED" "" "$SIDE" ""
expect "labelled pull request with a valid signed tag: still never stages" 0 "publish=false" pr opened "$LABELLED" "" "$MAIN" v1.2.3
expect "labelled pull request: a dry-run label" 0 "label=dryrun-${SIDE:0:12}" pr opened "$LABELLED" "" "$SIDE" ""
expect "the dry-run label just added: runs the legs" 0 "run=true" pr labeled "$LABELLED" release-dry-run "$SIDE" ""
expect "the dry-run label in another case: runs the legs" 0 "run=true" pr synchronize '["Release-Dry-Run"]' "" "$SIDE" ""
expect "the dry-run label just added in another case: runs the legs" 0 "run=true" pr labeled '["Release-Dry-Run"]' Release-Dry-Run "$SIDE" ""
check "pull request: the checker is never run" [ ! -s "$T/checker.log" ]
expect "unlabelled pull request: runs no leg" 0 "run=false" pr opened '["documentation"]' "" "$SIDE" ""
expect "a label that ends in the dry-run label: runs no leg" 0 "run=false" pr synchronize '["no-release-dry-run"]' "" "$SIDE" ""
expect "a label that starts with the dry-run label: runs no leg" 0 "run=false" pr synchronize '["release-dry-run-later"]' "" "$SIDE" ""
expect "pull request with no labels: runs no leg" 0 "run=false" pr reopened '[]' "" "$SIDE" ""
expect "another label added to a labelled pull request: runs no leg" 0 "run=false" pr labeled "$LABELLED" documentation "$SIDE" ""
expect "pull request labels that are not a JSON array: refused" 1 "is not a JSON array" pr opened 'release-dry-run' "" "$SIDE" ""
expect "dispatch naming a missing tag: refused" 1 "does not exist" guard workflow_dispatch branch main "$MAIN" v9.9.9
expect "dispatch naming a malformed tag: refused" 1 "is not of the form" guard workflow_dispatch branch main "$MAIN" "v1;x"
expect "tag push the checker accepts: stages" 0 "publish=true" guard push tag v1.2.3 "$MAIN" ""
check "tag push: the checker ran on the tag, the commit and origin/main" \
    grep -qxF "v1.2.3 $MAIN $T/allowed-signers origin/main" "$T/checker.log"
export STUB_CHECK=refuse
expect "tag push the checker refuses: refused" 1 "is not a tag this repository releases" guard push tag v1.2.3 "$MAIN" ""
expect "branch push: refused" 1 "must be a tag push" guard push branch main "$MAIN" ""
expect "other event: refused" 1 "unexpected event" guard schedule branch main "$MAIN" ""
expect "pull_request_target: refused" 1 "unexpected event" guard pull_request_target branch main "$MAIN" ""
expect "guard usage error" 2 "usage:" "$HERE/release-guard.sh" push tag
unset STUB_CHECK

# --- attach-draft.sh ------------------------------------------------------

mkdir -p "$T/bin" "$T/files"
cat > "$T/bin/gh" <<'STUB'
#!/usr/bin/env bash
# Stub gh: releases live in $STUB/releases.json; calls are logged to $STUB/calls,
# uploads to $STUB/uploaded as "<name> <sha256> <content-type> <path>".
# $STUB_FAIL names one call kind to fail: create, list, assets, delete,
# list:<n> for the n-th releases list, or upload:<n> for the n-th upload.
# $STUB_LIST_LAG leaves a created draft out of that many lists after creation.
set -euo pipefail
S="$STUB/releases.json"
echo "$*" >> "$STUB/calls"
save() { local tmp; tmp="$(mktemp)"; jq "$@" "$S" > "$tmp"; mv "$tmp" "$S"; }
failing() { [ "${STUB_FAIL:-}" = "$1" ] && { echo "HTTP 502: stub failure ($1)" >&2; exit 1; }; return 0; }
if [ "$1" = release ] && [ "$2" = create ]; then
    failing create
    save --arg t "$3" '. + [{id: 101, tag_name: $t, draft: true, assets: []}]'
    echo "${STUB_LIST_LAG:-0}" > "$STUB/lag"
    exit 0
fi
[ "$1" = api ] || { echo "stub: unhandled $*" >&2; exit 3; }
shift
method=GET filter=. ctype="" input="" path=""
while [ $# -gt 0 ]; do
    case "$1" in
        -X) method="$2"; shift 2 ;;
        -H) ctype="${2#Content-Type: }"; shift 2 ;;
        --jq) filter="$2"; shift 2 ;;
        --input) input="$2"; shift 2 ;;
        --paginate) shift ;;
        *) path="$1"; shift ;;
    esac
done
case "$method $path" in
    "GET repos/"*"/releases?per_page=100")
        failing list
        l=$(( $(cat "$STUB/lists" 2>/dev/null || echo 0) + 1 ))
        echo "$l" > "$STUB/lists"
        failing "list:$l"
        lag="$(cat "$STUB/lag" 2>/dev/null || echo 0)"
        if [ "$lag" -gt 0 ]; then
            echo $((lag - 1)) > "$STUB/lag"
            jq -r "map(select(.id != 101)) | $filter" "$S"
        else
            jq -r "$filter" "$S"
        fi ;;
    "GET repos/"*"/releases/"*"/assets?per_page=100")
        failing assets
        id="${path#*/releases/}"; id="${id%%/*}"
        jq -r --argjson i "$id" '.[] | select(.id == $i) | .assets' "$S" | jq -r "$filter" ;;
    "DELETE repos/"*"/releases/assets/"*)
        failing delete
        save --argjson a "${path##*/}" 'map(.assets |= map(select(.id != $a)))' ;;
    "POST https://uploads.github.com/repos/"*)
        n=$(( $(cat "$STUB/uploads" 2>/dev/null || echo 0) + 1 ))
        echo "$n" > "$STUB/uploads"
        failing "upload:$n"
        id="${path#*/releases/}"; id="${id%%/*}"
        name="${path#*name=}"
        if [ -n "$(jq -r --argjson i "$id" --arg n "$name" '.[] | select(.id == $i) | .assets[] | select(.name == $n) | .id' "$S")" ]; then
            echo "HTTP 422: already_exists" >&2; exit 1
        fi
        size="$(wc -c < "$input" | tr -d ' ')"
        echo "$name $(sha256sum < "$input" | cut -d' ' -f1) $ctype ${path%%/releases/*}" >> "$STUB/uploaded"
        save --argjson i "$id" --arg n "$name" --argjson a "$((5000 + n))" --argjson z "$size" \
            'map(if .id == $i then .assets += [{id: $a, name: $n, size: $z}] else . end)'
        if [ -n "${STUB_PUBLISH_AFTER:-}" ] && [ "$n" -ge "$STUB_PUBLISH_AFTER" ]; then
            save --argjson i "$id" 'map(if .id == $i then .draft = false else . end)'
        fi
        echo "$name" ;;
    *) echo "stub: unhandled $method $path" >&2; exit 3 ;;
esac
STUB
chmod +x "$T/bin/gh"
printf 'library tarball\n' > "$T/files/a.tar.gz"
printf 'checksum line\n' > "$T/files/a.tar.gz.sha256"

# scenario <name> <releases.json>: a fresh stub state
scenario() {
    export STUB="$T/stub-$1"
    mkdir -p "$STUB"
    printf '%s\n' "$2" > "$STUB/releases.json"
    : > "$STUB/calls"
    unset STUB_FAIL STUB_PUBLISH_AFTER STUB_LIST_LAG
}
attach() { PATH="$T/bin:$PATH" "$HERE/attach-draft.sh" v1.2.3 owner/repo "$T/files/a.tar.gz" "$T/files/a.tar.gz.sha256"; }
assets() { jq -r '.[] | select(.tag_name == "v1.2.3") | [.assets[].name] | join(",")' "$STUB/releases.json"; }
uploads() { cat "$STUB/uploads" 2>/dev/null || echo 0; }
sha() { sha256sum < "$1" | cut -d' ' -f1; }
others='{"id": 7, "tag_name": "v1.2.30", "draft": false, "assets": []}, {"id": 8, "tag_name": "v1.2.3-rc.1", "draft": false, "assets": []}'

scenario none "[$others]"
expect "no release: draft created and filled" 0 "holds exactly the 2 files given" attach
check "no release: created with --verify-tag" grep -q -- "release create v1.2.3 --repo owner/repo --draft --verify-tag" "$STUB/calls"
check "no release: both files attached" [ "$(assets)" = "a.tar.gz,a.tar.gz.sha256" ]
check "no release: the bytes uploaded are the files given" \
    grep -qxF "a.tar.gz $(sha "$T/files/a.tar.gz") application/octet-stream https://uploads.github.com/repos/owner/repo" "$STUB/uploaded"
check "no release: the checksum file's bytes uploaded" \
    grep -qxF "a.tar.gz.sha256 $(sha "$T/files/a.tar.gz.sha256") application/octet-stream https://uploads.github.com/repos/owner/repo" "$STUB/uploaded"
check "no release: releases of other tags untouched" \
    [ "$(jq -r '[.[] | select(.tag_name != "v1.2.3") | .assets | length] | add' "$STUB/releases.json")" = 0 ]

scenario lag "[$others]"
export STUB_LIST_LAG=2 ATTACH_LIST_DELAY=0
expect "a draft the list shows late: found and filled" 0 "holds exactly the 2 files given" attach
check "a draft the list shows late: created once" [ "$(grep -c 'release create' "$STUB/calls")" = 1 ]

scenario lagout "[$others]"
export STUB_LIST_LAG=9 ATTACH_LIST_ATTEMPTS=3 ATTACH_LIST_DELAY=0
expect "a draft the list never shows: refused" 1 "is not listed after it was created" attach
check "a draft the list never shows: nothing uploaded" [ "$(uploads)" = 0 ]
unset ATTACH_LIST_ATTEMPTS

scenario draft "[{\"id\": 9, \"tag_name\": \"v1.2.3\", \"draft\": true, \"assets\": [{\"id\": 1, \"name\": \"a.tar.gz\", \"size\": 3}]}, $others]"
expect "draft: files attached" 0 "holds exactly the 2 files given" attach
check "draft: no release created" bash -c "! grep -q 'release create' '$STUB/calls'"
check "draft: the old asset replaced, not duplicated" [ "$(assets)" = "a.tar.gz,a.tar.gz.sha256" ]
check "draft: the old asset deleted" grep -q "DELETE repos/owner/repo/releases/assets/1" "$STUB/calls"

scenario stale '[{"id": 9, "tag_name": "v1.2.3", "draft": true, "assets": [{"id": 1, "name": "old.tar.gz", "size": 3}]}]'
expect "draft holding a file not in the set: refused" 1 "not exactly the files given" attach

scenario published "[{\"id\": 9, \"tag_name\": \"v1.2.3\", \"draft\": false, \"assets\": []}, $others]"
expect "published: refused" 1 "already has a published release v1.2.3" attach
check "published: nothing uploaded" [ "$(uploads)" = 0 ]

scenario listfail "[$others]"
export STUB_FAIL=list
expect "list failure: refused" 1 "could not list the releases" attach
check "list failure: nothing created" bash -c "! grep -q 'release create' '$STUB/calls'"

scenario createfail "[$others]"
export STUB_FAIL=create
expect "create failure: refused" 1 "could not create a draft release" attach
check "create failure: nothing uploaded" [ "$(uploads)" = 0 ]

scenario uploadfail "[$others]"
export STUB_FAIL=upload:2
expect "upload failure: fails" 1 "could not upload a.tar.gz.sha256" attach

scenario deletefail '[{"id": 9, "tag_name": "v1.2.3", "draft": true, "assets": [{"id": 1, "name": "a.tar.gz", "size": 3}]}]'
export STUB_FAIL=delete
expect "delete failure: fails" 1 "could not replace a.tar.gz" attach
check "delete failure: nothing uploaded" [ "$(uploads)" = 0 ]

scenario assetsfail '[{"id": 9, "tag_name": "v1.2.3", "draft": true, "assets": []}]'
export STUB_FAIL=assets
expect "asset list failure: fails" 1 "could not list the assets" attach
check "asset list failure: nothing uploaded" [ "$(uploads)" = 0 ]

scenario flip '[{"id": 9, "tag_name": "v1.2.3", "draft": true, "assets": []}]'
export STUB_PUBLISH_AFTER=1
expect "published mid-run: stops" 1 "is no longer one draft release; not uploading a.tar.gz.sha256" attach
check "published mid-run: one file uploaded" [ "$(uploads)" = 1 ]

scenario lastflip '[{"id": 9, "tag_name": "v1.2.3", "draft": true, "assets": []}]'
export STUB_PUBLISH_AFTER=2
expect "published during the last upload: fails" 1 "no longer one draft release after the uploads" attach

scenario listgap '[{"id": 9, "tag_name": "v1.2.3", "draft": true, "assets": []}]'
export STUB_FAIL=list:3
expect "list failure between uploads: stops" 1 "could not list the releases" attach
check "list failure between uploads: one file uploaded" [ "$(uploads)" = 1 ]

scenario twice '[{"id": 9, "tag_name": "v1.2.3", "draft": true, "assets": []}, {"id": 10, "tag_name": "v1.2.3", "draft": true, "assets": []}]'
expect "two releases for the tag: refused" 1 "more than one release for v1.2.3" attach
check "two releases for the tag: nothing uploaded" [ "$(uploads)" = 0 ]

expect "missing file: usage error" 2 "not a file" \
    env PATH="$T/bin:$PATH" "$HERE/attach-draft.sh" v1.2.3 owner/repo "$T/files/absent"

# --- oxicrypt-fingerprint.sh -----------------------------------------------

FP="sha256:$(printf 'a%.0s' $(seq 64))"
FP2="sha256:$(printf 'b%.0s' $(seq 64))"
mkdir -p "$T/cfg"
printf '[env]\nOXICRYPT_LIB_DIR = "x"\nOXICRYPT_LIB_FINGERPRINT = "%s"\n' "$FP" > "$T/cfg/one.toml"
printf 'OXICRYPT_LIB_FINGERPRINT = "%s"\nOXICRYPT_LIB_FINGERPRINT = "%s"\n' "$FP" "$FP2" > "$T/cfg/two.toml"
printf '[env]\n' > "$T/cfg/none.toml"
printf 'OXICRYPT_LIB_FINGERPRINT = "sha256:short"\n' > "$T/cfg/bad.toml"
fingerprint() { env -u OXICRYPT_LIB_FINGERPRINT "$HERE/oxicrypt-fingerprint.sh" "$@"; }
expect "fingerprint: read from the cargo config" 0 "$FP" fingerprint "$T/cfg/one.toml"
expect "fingerprint: the environment overrides the config" 0 "$FP2" \
    env OXICRYPT_LIB_FINGERPRINT="$FP2" "$HERE/oxicrypt-fingerprint.sh" "$T/cfg/one.toml"
expect "fingerprint: two definitions refused" 1 "exactly once" fingerprint "$T/cfg/two.toml"
expect "fingerprint: no definition refused" 1 "exactly once" fingerprint "$T/cfg/none.toml"
expect "fingerprint: a malformed value refused" 1 "is not sha256" fingerprint "$T/cfg/bad.toml"
expect "fingerprint: the repository's own config holds one pin" 0 "sha256:" fingerprint

# --- stage-release-artifact.sh and check-release-artifact.py ---------------

# A fetched oxicrypt release directory: a library and oxicrypt's provenance.
L="$T/ffi"
mkdir -p "$L" "$T/bin-src"
printf '#include <stdio.h>\nint f(void) { return puts("lib"); }\n' > "$T/lib.c"
cc -shared -fPIC -o "$L/liboxicrypt_ffi.so.1" "$T/lib.c"
printf 'oxicrypt\n\n  verify key: %s\n' "$FP" > "$L/BUILD-PROVENANCE.txt"
printf '#include <stdio.h>\nint main(void) { return puts("bin") < 0; }\n' > "$T/main.c"
cc -o "$T/bin-src/daemonseed-tui" "$T/main.c"
printf 'licence text\n' > "$T/bin-src/LICENSE-MIT"
printf 'elf system libc.so.6\nelf system ld-linux-*.so.*\nelf bundled liboxicrypt_ffi.so.1\n' > "$T/allow.txt"
TRIPLE=x86_64-unknown-linux-gnu
stage() { stage_as "$TRIPLE" "$@"; }
stage_as() {
    local triple="$1"
    shift
    (cd "$HERE" && OXICRYPT_LIB_DIR="$L" OXICRYPT_LIB_FILE=liboxicrypt_ffi.so.1 OXICRYPT_LIB_FINGERPRINT="$FP" \
        "$HERE/stage-release-artifact.sh" t leg "$triple" "load check line" "$@")
}
check_artifact() { PYTHONDONTWRITEBYTECODE=1 python3 "$HERE/check-release-artifact.py" --triple "$1" --allow-list "$T/allow.txt" "$2"; }
# repack <out> <edit command...>: unpack the good tarball, run the edit in its
# directory, and pack it again as <out>.
repack() {
    local out="$1" w
    shift
    w="$(mktemp -d "$T/repack.XXXX")"
    tar -C "$w" -xzf "$T/stage-good/daemonseed-t-leg.tar.gz"
    (cd "$w/daemonseed-t-leg" && "$@")
    tar -C "$w" -czf "$out" daemonseed-t-leg
}

expect "stage: a good stage" 0 "daemonseed-t-leg.tar.gz" stage "$T/stage-good" "$T/bin-src/daemonseed-tui" "$L/liboxicrypt_ffi.so.1" "$T/bin-src/LICENSE-MIT"
check "stage: the provenance names the pinned key" \
    bash -c "tar -xOzf '$T/stage-good/daemonseed-t-leg.tar.gz' daemonseed-t-leg/BUILD-PROVENANCE.txt | grep -qxF 'oxicrypt release key : $FP'"
check "stage: the checksum names its tarball" \
    bash -c "cd '$T/stage-good' && sha256sum -c daemonseed-t-leg.tar.gz.sha256 >/dev/null"
expect "stage: a missing fingerprint refused" 2 "OXICRYPT_LIB_FINGERPRINT is not set" \
    env -u OXICRYPT_LIB_FINGERPRINT OXICRYPT_LIB_DIR="$L" OXICRYPT_LIB_FILE=liboxicrypt_ffi.so.1 \
    "$HERE/stage-release-artifact.sh" t leg "$TRIPLE" x "$T/stage-x" "$T/bin-src/daemonseed-tui"
expect "stage: a missing library directory refused" 2 "OXICRYPT_LIB_DIR is not set" \
    env -u OXICRYPT_LIB_DIR OXICRYPT_LIB_FILE=liboxicrypt_ffi.so.1 OXICRYPT_LIB_FINGERPRINT="$FP" \
    "$HERE/stage-release-artifact.sh" t leg "$TRIPLE" x "$T/stage-x" "$T/bin-src/daemonseed-tui"
expect "stage: a fingerprint oxicrypt's provenance does not name refused" 1 "not the pinned" \
    env OXICRYPT_LIB_DIR="$L" OXICRYPT_LIB_FILE=liboxicrypt_ffi.so.1 OXICRYPT_LIB_FINGERPRINT="$FP2" \
    "$HERE/stage-release-artifact.sh" t leg "$TRIPLE" x "$T/stage-x" "$T/bin-src/daemonseed-tui"

G_ART="$T/stage-good/daemonseed-t-leg.tar.gz"
expect "artifact: a good tarball passes" 0 "ok (2 binaries" check_artifact "$TRIPLE" "$G_ART"
expect "artifact: another row's triple refused" 1 "is not the matrix row's" check_artifact aarch64-unknown-linux-gnu "$G_ART"
repack "$T/empty-commit.tar.gz" sed -i 's/^commit  *: .*/commit               : /' BUILD-PROVENANCE.txt
expect "artifact: an empty commit refused" 1 "no single 'commit' line" check_artifact "$TRIPLE" "$T/empty-commit.tar.gz"
repack "$T/no-rustc.tar.gz" sed -i '/^rustc /d' BUILD-PROVENANCE.txt
expect "artifact: a missing rustc line refused" 1 "no single 'rustc' line" check_artifact "$TRIPLE" "$T/no-rustc.tar.gz"
repack "$T/stray.tar.gz" bash -c "head -c 64 /dev/urandom > notes.bin"
expect "artifact: an unrecognised file refused" 1 "neither a binary of a known kind" check_artifact "$TRIPLE" "$T/stray.tar.gz"
repack "$T/malformed.tar.gz" bash -c "printf 'MZ%062d' 0 > helper.dll"
expect "artifact: a file that does not parse as PE refused" 1 "does not parse as one" check_artifact "$TRIPLE" "$T/malformed.tar.gz"
printf 'int f(void) { return 0; }\n' > "$T/f.c"
cc -shared -nostdlib -fPIC -o "$T/libnone.so" "$T/f.c"
repack "$T/noimports.tar.gz" cp "$T/libnone.so" libnone.so
expect "artifact: a dynamic binary with no imports refused" 1 "has no imports" check_artifact "$TRIPLE" "$T/noimports.tar.gz"
repack "$T/tampered.tar.gz" bash -c "printf x >> liboxicrypt_ffi.so.1"
expect "artifact: a library that is not the release file refused" 1 "is not the oxicrypt library" check_artifact "$TRIPLE" "$T/tampered.tar.gz"
grep -v '^elf system libc' "$T/allow.txt" > "$T/allow-narrow.txt"
expect "artifact: an import the allow-list does not name refused" 1 "which the allow-list does not name" \
    env PYTHONDONTWRITEBYTECODE=1 python3 "$HERE/check-release-artifact.py" --triple "$TRIPLE" --allow-list "$T/allow-narrow.txt" "$G_ART"

# --- archive formats and verify-release-rows.sh ---------------------------

WIN=x86_64-pc-windows-msvc
expect "stage: a Windows triple stages a zip, named last" 0 "daemonseed-t-leg.zip" \
    stage_as "$WIN" "$T/stage-zip" "$T/bin-src/daemonseed-tui" "$L/liboxicrypt_ffi.so.1" "$T/bin-src/LICENSE-MIT"
check "stage: the zip's checksum names it" bash -c "cd '$T/stage-zip' && sha256sum -c daemonseed-t-leg.zip.sha256 >/dev/null"
expect "artifact: a Windows zip is read and passes" 0 "ok (2 binaries, target $WIN" \
    check_artifact "$WIN" "$T/stage-zip/daemonseed-t-leg.zip"
expect "artifact: a .tar.gz for a Windows triple refused" 1 "must be a .zip" check_artifact "$WIN" "$G_ART"
expect "artifact: a .zip for a Linux triple refused" 1 "must be a .tar.gz" \
    check_artifact "$TRIPLE" "$T/stage-zip/daemonseed-t-leg.zip"
mkdir -p "$T/zip-escape/x"
python3 -c 'import zipfile,sys; z=zipfile.ZipFile(sys.argv[1],"w"); z.writestr("../evil.txt","x"); z.close()' "$T/zip-escape/x.zip"
expect "artifact: a zip member that escapes the archive refused" 1 "escapes the archive" \
    check_artifact "$WIN" "$T/zip-escape/x.zip"

# leg <records> <name> <triple> [RELEASE_ARCHIVE]: one leg's records, staged
# and described the way the workflow's stage step does it.
leg() {
    local records="$1" name="$2" triple="$3" archive
    mkdir -p "$records/$name"
    archive="$(cd "$HERE" && RELEASE_ARCHIVE="${4:-}" OXICRYPT_LIB_DIR="$L" OXICRYPT_LIB_FILE=liboxicrypt_ffi.so.1 \
        OXICRYPT_LIB_FINGERPRINT="$FP" "$HERE/stage-release-artifact.sh" t "$name" "$triple" "load check line" \
        "$records/$name/dist" "$T/bin-src/daemonseed-tui" "$L/liboxicrypt_ffi.so.1" | tail -n 1)"
    echo "$archive $triple" > "$records/$name/row.txt"
}
verify_rows() { PYTHONDONTWRITEBYTECODE=1 "$HERE/verify-release-rows.sh" "$1" "$T/allow.txt" "$2"; }
leg "$T/rows-good" linux-tui "$TRIPLE"
leg "$T/rows-good" windows-gui "$WIN"
expect "verify: a Linux tar.gz and a Windows zip pass" 0 "2 legs checked" verify_rows "$T/rows-good" 2
expect "verify: a leg count that is not the matrix's refused" 1 "expected 3 legs, found 2" verify_rows "$T/rows-good" 3
leg "$T/rows-wintar" linux-tui "$TRIPLE"
leg "$T/rows-wintar" windows-gui "$WIN" tar.gz
check "verify: the misconfigured Windows leg did write a .tar.gz" \
    test -f "$T/rows-wintar/windows-gui/dist/daemonseed-t-windows-gui.tar.gz"
expect "verify: a Windows row that produced a .tar.gz refused" 1 "must be a .zip" verify_rows "$T/rows-wintar" 2
leg "$T/rows-extra" linux-tui "$TRIPLE"
printf 'stray\n' > "$T/rows-extra/linux-tui/dist/notes.txt"
expect "verify: a stray file beside the archive refused" 1 "not daemonseed-t-linux-tui.tar.gz and its checksum" verify_rows "$T/rows-extra" 1

# --- the workflow's structure ----------------------------------------------

# Reads a release workflow and prints one line per broken rule: what keeps a
# pull request or a dispatch away from the release environment and from write
# access. Needs python3 with PyYAML.
cat > "$T/workflow-check.py" <<'PY'
import sys, yaml

PUSH = "github.event_name == 'push'"


def conjuncts(expr):
    """The top-level `&&` operands of an expression, or None if it has a
    top-level `||`, which would let a non-push event through."""
    expr = " ".join(expr.split())
    if expr.startswith("${{") and expr.endswith("}}"):
        expr = expr[3:-2].strip()
    parts, depth, quote, start, i = [], 0, None, 0, 0
    while i < len(expr):
        c = expr[i]
        if quote:
            if c == quote:
                quote = None
        elif c == "'":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif depth == 0 and expr.startswith("||", i):
            return None
        elif depth == 0 and expr.startswith("&&", i):
            parts.append(expr[start:i].strip())
            start = i + 2
            i += 1
        i += 1
    parts.append(expr[start:].strip())
    return parts


wf = yaml.safe_load(open(sys.argv[1]))
jobs = wf["jobs"]
problems = []
for name in ("build-release", "attach"):
    parts = conjuncts(str(jobs[name].get("if", "")))
    if parts is None:
        problems.append(f"{name}'s condition has a top-level ||")
    elif PUSH not in parts:
        problems.append(f"{name} does not require a push event")
if jobs["build-release"].get("environment") != "release":
    problems.append("build-release does not use the release environment")
for name, job in jobs.items():
    if name != "build-release" and "environment" in job:
        problems.append(f"{name} names an environment")
if wf.get("permissions") != {"contents": "read"}:
    problems.append(f"workflow permissions are {wf.get('permissions')!r}, not contents: read")
for name, job in jobs.items():
    perms = job.get("permissions") or {}
    writes = perms == "write-all" or (isinstance(perms, dict) and "write" in perms.values())
    if writes and name != "attach":
        problems.append(f"{name} requests write permission")
for p in problems:
    print(p)
sys.exit(1 if problems else 0)
PY
workflow_check() { python3 "$T/workflow-check.py" "$1"; }
WF="$HERE/../.github/workflows/release.yml"
expect "workflow: the repository's release workflow keeps its protections" 0 "" workflow_check "$WF"
# planted <name> <python edit of the parsed workflow>: a copy with one rule broken.
planted() {
    python3 - "$WF" "$T/$1.yml" "$2" <<'PY'
import sys, yaml
src, out, edit = sys.argv[1:]
wf = yaml.safe_load(open(src))
exec(edit)
yaml.safe_dump(wf, open(out, "w"))
PY
    echo "$T/$1.yml"
}
expect "workflow: build-release without the push condition refused" 1 "build-release does not require a push event" \
    workflow_check "$(planted no-push-build "wf['jobs']['build-release']['if'] = \"needs.guard.outputs.publish == 'true'\"")"
expect "workflow: a push condition joined by || refused" 1 "build-release's condition has a top-level ||" \
    workflow_check "$(planted or-push "wf['jobs']['build-release']['if'] = \"github.event_name == 'push' || needs.guard.outputs.publish == 'true'\"")"
expect "workflow: a parenthesised push condition that admits anything refused" 1 "attach does not require a push event" \
    workflow_check "$(planted paren-push "wf['jobs']['attach']['if'] = \"needs.guard.outputs.publish == 'true' && (github.event_name == 'push' || true)\"")"
expect "workflow: attach without the push condition refused" 1 "attach does not require a push event" \
    workflow_check "$(planted no-push-attach "wf['jobs']['attach']['if'] = \"needs.guard.outputs.publish == 'true'\"")"
expect "workflow: build-release outside the release environment refused" 1 "does not use the release environment" \
    workflow_check "$(planted no-env "del wf['jobs']['build-release']['environment']")"
expect "workflow: an environment on another job refused" 1 "build names an environment" \
    workflow_check "$(planted env-on-build "wf['jobs']['build']['environment'] = 'release'")"
expect "workflow: write permission at the workflow level refused" 1 "workflow permissions are" \
    workflow_check "$(planted wf-write "wf['permissions'] = {'contents': 'write'}")"
expect "workflow: write permission on another job refused" 1 "build requests write permission" \
    workflow_check "$(planted job-write "wf['jobs']['build']['permissions'] = {'contents': 'read', 'pull-requests': 'write'}")"

echo "release scripts: $pass passed, $failed failed"
[ "$failed" -eq 0 ] && [ "$pass" -gt 0 ]
