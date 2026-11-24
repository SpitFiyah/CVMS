#!/usr/bin/env bash
# Reconcile CVMS milestones and their verification issues in GitHub.
set -euo pipefail

repo=SpitFiyah/CVMS
oracle=https://github.com/$repo/actions/runs/45478293801
python=https://github.com/$repo/actions/runs/45478293887
mermaid=https://github.com/$repo/actions/runs/45478293669

sync_item() {
    local milestone=$1 title=$2 body=$3 state=$4 number issue desired
    number=$(gh api --paginate "repos/$repo/milestones?state=all&per_page=100" \
        --jq ".[] | select(.title == \"$milestone\") | .number")
    if [[ -z "$number" ]]; then
        number=$(gh api "repos/$repo/milestones" -f title="$milestone" --jq .number)
    fi
    issue=$(gh api --paginate "repos/$repo/issues?state=all&milestone=$number&per_page=100" \
        --jq ".[] | select(.pull_request == null and .title == \"$title\") | .number")
    if [[ -z "$issue" ]]; then
        issue=$(gh api "repos/$repo/issues" -f title="$title" -f body="$body" \
            -F milestone="$number" --jq .number)
    fi
    if [[ "$state" == closed ]]; then
        gh issue close "$issue" --repo "$repo" --reason completed
    fi
    desired=open
    if [[ "$state" == closed ]]; then
        local pending
        pending=$(gh api "repos/$repo/milestones/$number" --jq .open_issues)
        if [[ "$pending" == 0 ]]; then
            desired=closed
        fi
    fi
    gh api --method PATCH "repos/$repo/milestones/$number" -f state="$desired" --jq .html_url
}

sync_item 'M1 — Project Foundation' 'Verify repository foundation and Mermaid diagrams' \
    "The authenticated repository default contains the implementation. Requirements, architecture, and ER model are in the repository. Mermaid CI: $mermaid" closed
sync_item 'M2 — Oracle Schema Implementation' 'Verify a clean Oracle 11g schema installation' \
    "The Compose-backed runner installed the schema and passed SQL assertions covering integrity and workflow behavior. Oracle CI: $oracle" closed
sync_item 'M3 — NVD Data Collection Pipeline' 'Verify live NVD collection and CPE Dictionary reconciliation' \
    "Offline replay of five authentic records and Python unit tests passed. Run live collection and a scoped CPE Dictionary query, then record archived request provenance and observed counts. Python CI: $python" open
sync_item 'M4 — Data Population and Asset Mapping' 'Verify demo import, replay and evidence counts' \
    "The five-record import applied five changes and its replay applied none. The fictional inventory and evidence counts passed. Oracle CI: $oracle" closed
sync_item 'M5 — SQL and PL/SQL Implementation' 'Execute the full SQL reporting set in Oracle' \
    "The SQL and PL/SQL assertions ran in Oracle CI. Execute all twenty reports with demo input and record outputs for the reports that existing assertions do not cover. Oracle CI: $oracle" open
sync_item 'M6 — Testing and Final Documentation' 'Verify end-to-end Oracle demo and document CI evidence' \
    "Three workflows passed at e5c049d. The repository test report records schema, Python, Mermaid, import and replay evidence. Oracle CI: $oracle. Python CI: $python. Mermaid CI: $mermaid." closed
