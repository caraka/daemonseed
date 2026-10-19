#!/usr/bin/env bash
# Report whether the tree of a pushed commit already passed a CI job in a
# pull-request run.
#
# Usage: scripts/ci/already-passed.sh <job-name>
#
# Reads GITHUB_REPOSITORY, GITHUB_SHA and GITHUB_WORKFLOW_REF, runs in a checkout
# that contains GITHUB_SHA, and authenticates `gh` with GH_TOKEN. Prints
# `already-passed: …` or `run: …`, and when GITHUB_OUTPUT is set appends
# `passed=true` or `passed=false` to it. It always exits 0 with an answer.
#
# The answer is `passed=true` only when all of these hold:
#
# - Among the `pull_request` runs of this workflow whose head is GITHUB_SHA, take
#   the newest, by `run_started_at` (`created_at` if that is absent), that ran a
#   job named <job-name>. A re-run moves `run_started_at`, so the latest attempt
#   of any run counts as its newest evidence. A newer run may be passed over only
#   when it is `completed` and lists the job as `skipped` or not at all. A newer
#   run that has not reported this job's result answers `false`; one still
#   running whose job has already concluded is judged on that job. Runs that
#   share a start time cannot be ordered, so reaching one answers `false`, and so
#   does any run whose start time is missing or not of the fixed-width form
#   YYYY-MM-DDTHH:MM:SSZ that GitHub returns.
#   The chosen run's latest attempt of the job concluded `success`.
# - That run holds an unexpired artifact named `tested-<job-name>-<tree>`, where
#   <tree> is the tree of GITHUB_SHA. A pull-request job uploads that artifact,
#   named for the tree of the merge commit it checked out, after its gate passes.
#
# A pull-request run tests the merge of its head into the base it had at the time,
# so its result says nothing about the pushed commit unless the merged tree is the
# pushed commit's tree. The artifact is the record of which tree was tested, and
# the tree comparison decides, for any merge that lands the pull request's head
# with its commit ID unchanged. A squash or rebase merge lands a new commit ID,
# which no pull-request run has as its head, so the gate always runs for it. An
# older pass behind a newer failure does not count. Anything else, including an
# API error, an unparseable input or no matching run, answers `passed=false`, so
# the gate runs whenever the answer is in doubt.

set -euo pipefail

answer() {
    local passed="$1" reason="$2"
    if [[ "$passed" == true ]]; then
        echo "already-passed: $reason"
    else
        echo "run: $reason"
    fi
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        echo "passed=$passed" >> "$GITHUB_OUTPUT"
    fi
    exit 0
}

job="${1:-}"
repo="${GITHUB_REPOSITORY:-}"
sha="${GITHUB_SHA:-}"
workflow_ref="${GITHUB_WORKFLOW_REF:-}"

[[ "$job" =~ ^[A-Za-z0-9_-]+$ ]] || answer false "job name '${job}' is missing or malformed"
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || answer false "GITHUB_REPOSITORY '${repo}' is missing or malformed"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || answer false "GITHUB_SHA '${sha}' is not a full commit id"
# `<owner>/<repo>/.github/workflows/<file>@<ref>`
[[ "$workflow_ref" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/([A-Za-z0-9_.-]+\.ya?ml)@.+$ ]] \
    || answer false "GITHUB_WORKFLOW_REF '${workflow_ref}' does not name a workflow file"
workflow="${BASH_REMATCH[1]}"

if ! tree="$(git rev-parse --verify --quiet "${sha}^{tree}")"; then
    answer false "the checkout does not contain ${sha}"
fi
[[ "$tree" =~ ^[0-9a-f]{40}$ ]] || answer false "unexpected tree id '${tree}'"
artifact="tested-${job}-${tree}"

if ! runs="$(gh api --paginate \
    "repos/${repo}/actions/workflows/${workflow}/runs?head_sha=${sha}&event=pull_request&per_page=100" \
    --jq ".workflow_runs[] | select(.head_sha == \"${sha}\" and .event == \"pull_request\") | \"\\(.run_started_at // .created_at) \\(.id) \\(.status // \"unknown\")\"")"; then
    answer false "could not list pull-request runs of ${sha}"
fi
[[ -n "$runs" ]] || answer false "no pull-request run has ${sha} as its head"

while read -r started _; do
    [[ "$started" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] \
        || answer false "a pull-request run of ${sha} has start time '${started}', which is not of the form YYYY-MM-DDTHH:MM:SSZ"
done <<< "$runs"

# Fixed-width UTC timestamps sort as bytes in time order, so this puts the newest
# run first.
newest_first="$(LC_ALL=C sort -r <<< "$runs")"

while read -r started run_id status; do
    [[ "$run_id" =~ ^[0-9]+$ ]] || answer false "unexpected run id '${run_id}'"
    ties="$(awk -v at="$started" '$1 == at { n++ } END { print n + 0 }' <<< "$newest_first")"
    [[ "$ties" == 1 ]] || answer false "${ties} pull-request runs started at ${started}, so none of them is the newest"
    if ! conclusions="$(gh api --paginate \
        "repos/${repo}/actions/runs/${run_id}/jobs?filter=latest&per_page=100" \
        --jq ".jobs[] | select(.name == \"${job}\") | (.conclusion // \"pending\")")"; then
        answer false "could not list the jobs of run ${run_id}"
    fi
    ran="$(grep -v -x -e skipped -e '' <<< "$conclusions" || true)"
    if [[ -z "$ran" ]]; then
        [[ "$status" == completed ]] \
            || answer false "run ${run_id} is ${status} and has not reported job ${job}"
        continue
    fi
    if [[ "$ran" != success ]]; then
        answer false "job ${job} in the newest pull-request run that ran it (${run_id}, ${started}) concluded $(tr '\n' ' ' <<< "$ran")"
    fi
    if ! recorded="$(gh api --paginate \
        "repos/${repo}/actions/runs/${run_id}/artifacts?name=${artifact}&per_page=100" \
        --jq ".artifacts[] | select(.name == \"${artifact}\" and .expired == false) | .name")"; then
        answer false "could not list the artifacts of run ${run_id}"
    fi
    [[ -n "$recorded" ]] || answer false "run ${run_id} passed job ${job} but recorded no test of tree ${tree}"
    answer true "job ${job} passed on tree ${tree} in pull-request run ${run_id}"
done <<< "$newest_first"

answer false "no pull-request run of ${sha} ran job ${job}"
