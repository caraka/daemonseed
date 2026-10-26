#!/usr/bin/env bash
# Decides what a run of the release workflow builds and whether it stages a
# release.
#
#   release-guard.sh <event> <ref-type> <ref-name> <sha> <input-tag> <checker> <allowed-signers>
#
#   <event>            the workflow's event: push, workflow_dispatch or
#                      pull_request
#   <ref-type>         github.ref_type of the run
#   <ref-name>         github.ref_name of the run
#   <sha>              the commit the run was started for
#   <input-tag>        the dispatch input naming an existing tag, or empty
#   <checker>          the check-release-tag.sh to run (the workflow passes the
#                      copy from main)
#   <allowed-signers>  the allowed-signers file to check the tag against (the
#                      workflow passes the copy from main)
#
# A tag push stages a release (publish=true), and only for a tag <checker>
# accepts. A dispatch or a pull request never stages one (publish=false) and
# never runs <checker>: it builds the dispatched or pull-request commit, or the
# commit an existing tag names, as a dry run. Any other event is refused.
#
# A pull request's dry run is opt-in. The legs run (run=true) only when the
# pull request carries the `release-dry-run` label, and, for a `labeled`
# event, only when the label just added is that one, so adding another label
# does not start the legs again. The workflow passes the pull request's state
# in the environment: PR_LABELS_JSON (a JSON array of its label names),
# PR_ACTION (the event's activity type) and PR_ADDED_LABEL (the label a
# `labeled` event added). Label names compare without regard to case, as
# GitHub's do. Every other event that is not refused runs the legs.
#
# Prints sha=, label=, tag=, publish= and run= lines on stdout. Exits 0 with a
# decision, 1 when the run is refused (naming why), 2 on a usage error.
set -euo pipefail

if [ $# -ne 7 ]; then
    echo "usage: $0 <event> <ref-type> <ref-name> <sha> <input-tag> <checker> <allowed-signers>" >&2
    exit 2
fi
EVENT="$1" REF_TYPE="$2" REF_NAME="$3" SHA="$4" INPUT_TAG="$5" CHECKER="$6" SIGNERS="$7"
refuse() { echo "refused: $*" >&2; exit 1; }
DRY_RUN_LABEL=release-dry-run

case "${EVENT}" in
    push)
        publish=true
        run=true
        tag="${REF_NAME}"
        [ "${REF_TYPE}" = tag ] || refuse "a run that stages a release must be a tag push"
        [[ "${tag}" =~ ^v[0-9A-Za-z.-]+$ ]] || refuse "the tag is not of the form vX.Y.Z or vX.Y.Z-suffix"
        bash "${CHECKER}" "${tag}" "${SHA}" "${SIGNERS}" origin/main >&2 \
            || refuse "${tag} is not a tag this repository releases"
        ;;
    workflow_dispatch | pull_request)
        publish=false
        run=true
        if [ "${EVENT}" = pull_request ]; then
            added="${PR_ADDED_LABEL:-}"
            labels="$(printf '%s' "${PR_LABELS_JSON:-[]}" | jq -r '.[]')" \
                || refuse "PR_LABELS_JSON is not a JSON array of label names"
            if ! grep -qixF "${DRY_RUN_LABEL}" <<<"${labels}"; then
                run=false
            elif [ "${PR_ACTION:-}" = labeled ] && [ "${added,,}" != "${DRY_RUN_LABEL}" ]; then
                run=false
            fi
        fi
        tag="${INPUT_TAG}"
        if [ -n "${tag}" ]; then
            [[ "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] \
                || refuse "the tag is not of the form vX.Y.Z or vX.Y.Z-suffix"
            SHA="$(git rev-parse --verify --quiet "refs/tags/${tag}^{commit}")" \
                || refuse "refs/tags/${tag} does not exist"
        fi
        ;;
    *) refuse "unexpected event ${EVENT}" ;;
esac

if [ -n "${tag}" ]; then label="${tag}"; else label="dryrun-${SHA:0:12}"; fi
echo "sha=${SHA}"
echo "label=${label}"
echo "tag=${tag}"
echo "publish=${publish}"
echo "run=${run}"
