#!/usr/bin/env bash
# ============================================================================
# Cleanton dev-gate helpers — drive GitHub Actions as the build "second PC".
#
# The authoring sandbox has no Rust toolchain, so this script is the bridge to
# the CI runner: trigger the Dev gate workflow, watch it, and read its results.
#
#   scripts/dev-ci.sh trigger              # dispatch Dev gate on this branch
#   scripts/dev-ci.sh watch [run-id]       # block until a run finishes
#   scripts/dev-ci.sh report [run-id]      # per-job status table
#   scripts/dev-ci.sh logs  <run-id> [job] # dump a job's log
#   scripts/dev-ci.sh latest               # print the newest Dev gate run id
#   scripts/dev-ci.sh all                  # trigger + watch
#
# Requires: `gh` authenticated (GitHub CLI). Nothing else.
# ============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WORKFLOW_FILE="dev.yml"

die() {
    echo "error: $*" >&2
    exit 1
}

require_gh() {
    command -v gh >/dev/null 2>&1 || die "gh (GitHub CLI) is required"
    gh auth status >/dev/null 2>&1 || die "gh is not authenticated; run 'gh auth login'"
}

current_branch() {
    git rev-parse --abbrev-ref HEAD 2>/dev/null || echo main
}

cmd_trigger() {
    require_gh
    local ref
    ref="${1:-$(current_branch)}"
    echo "Dispatching '$WORKFLOW_FILE' on ref '$ref'..."
    gh workflow run "$WORKFLOW_FILE" --ref "$ref"
    echo
    echo "List the newest run with: scripts/dev-ci.sh latest"
}

cmd_latest() {
    require_gh
    gh run list --workflow "$WORKFLOW_FILE" --limit 1 \
        --json databaseId,status,conclusion,headBranch,event,url \
        --jq '.[0] | {id: .databaseId, status, conclusion, branch: .headBranch, event, url}'
}

resolve_run() {
    # Echo a run id from $1, or the latest run id when $1 is empty.
    if [[ -n "${1:-}" ]]; then
        echo "$1"
    else
        gh run list --workflow "$WORKFLOW_FILE" --limit 1 --json databaseId --jq '.[0].databaseId'
    fi
}

cmd_watch() {
    require_gh
    local run_id
    run_id="$(resolve_run "${1:-}")"
    [[ -n "$run_id" ]] || die "no Dev gate run found; run 'scripts/dev-ci.sh trigger' first"
    echo "Watching run $run_id (Ctrl-C to stop watching; the run continues)..."
    gh run watch "$run_id"
}

cmd_report() {
    require_gh
    local run_id
    run_id="$(resolve_run "${1:-}")"
    [[ -n "$run_id" ]] || die "no Dev gate run found"
    gh run view "$run_id" --json status,conclusion,jobs \
        --jq '{status, conclusion, jobs: [.jobs[] | {name, status, conclusion}]}' \
        | python3 -c '
import json, sys
data = json.load(sys.stdin)
print("run %s / conclusion: %s" % (data.get("status"), data.get("conclusion")))
for job in data.get("jobs", []):
    print("  %-10s %-10s %s" % (job["status"], job.get("conclusion") or "-", job["name"]))
'
}

cmd_logs() {
    require_gh
    local run_id
    run_id="${1:-}"
    [[ -n "$run_id" ]] || die "usage: scripts/dev-ci.sh logs <run-id>"
    # `gh run log` is unavailable on older gh; `--log-failed` fetches the
    # failed steps' log tails, which is what the driver needs after a red run.
    gh run view "$run_id" --log-failed
}

cmd_all() {
    cmd_trigger "$@"
    local run_id
    run_id="$(cmd_latest | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
    cmd_watch "$run_id"
}

usage() {
    sed -n '2,20p' "${BASH_SOURCE[0]}"
    exit 2
}

case "${1:-}" in
    trigger) shift; cmd_trigger "$@" ;;
    watch) shift; cmd_watch "$@" ;;
    report) shift; cmd_report "$@" ;;
    logs) shift; cmd_logs "$@" ;;
    latest) cmd_latest ;;
    all) shift; cmd_all "$@" ;;
    "" | -h | --help | help) usage ;;
    *) die "unknown command '$1' (see usage)" ;;
esac
