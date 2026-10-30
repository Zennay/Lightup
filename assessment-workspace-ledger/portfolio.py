#!/usr/bin/env python3
"""Owner-private cross-case HUMAN follow-up portfolio; never target execution.

Explicitly chosen original case contexts and their corresponding original
finalized HUMAN action JSON/CSV remain independent. Native admission checks
the original historical source chain. No scanning, claims of permission,
notifications, scheduling, dispatch, or remote disclosure.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import html
import io
import os
from pathlib import Path
import shutil
import sys

from history_owner_brief import admitted_original
from history_team import private_parent_for_originals
from ledger import (
    FLAGS, Hold, MAX_MANIFEST, canonical, digest, html_page, new_private,
    private_parent, reject, safe_human, write_private,
)

MIN_CASES = 2
MAX_CASES = 8
MAX_ROWS = 2048
HEADERS = (
    "case_ordinal", "case_context_sha256", "original_action_packet_sha256",
    "transition", "kit_ordinal", "human_status", "human_priority",
    "proposed_day", "proposed_owner", "next_human_step",
)


def canonical_path(value):
    return (
        type(value) is str and os.path.isabs(value) and
        os.path.normpath(value) == value and len(value) <= 4096 and
        "\x00" not in value
    )


def collect(args):
    size = len(args.context)
    if not (MIN_CASES <= size <= MAX_CASES and
            len(args.actions) == size and len(args.plan) == size):
        reject("PRIVATE HOLD: choose 2–8 full ORIGINAL context/actions/plan triples")
    chosen = list(args.context) + list(args.actions) + list(args.plan)
    if any(not canonical_path(p) for p in chosen) or len(set(chosen)) != len(chosen):
        reject("PRIVATE HOLD: original files must be unique canonical absolute paths")
    if not canonical_path(args.private_parent):
        reject("PRIVATE HOLD: output parent must be canonical absolute")
    private_parent(args.private_parent)

    cases = []
    context_ids = set()
    total_rows = 0
    for ordinal, (context, actions, plan) in enumerate(
        zip(args.context, args.actions, args.plan), 1
    ):
        source = admitted_original(argparse.Namespace(
            action_context=context, actions=actions, plan=plan
        ))
        private_parent_for_originals(args.private_parent, source["sources"])
        # The original native helper checks only the FIRST source ledger's
        # first kit. This multi-case adapter must forbid outputs beneath ANY
        # original source kit, from ANY admitted case and ledger snapshot.
        for original in source["sources"]:
            for kit in original["doc"]["kits"]:
                root = kit["path"]
                if os.path.commonpath((root, args.private_parent)) == root:
                    reject("PRIVATE HOLD: output overlaps an ORIGINAL source kit")
        context_sha = digest(source["source_context"])
        if context_sha in context_ids:
            reject("PRIVATE HOLD: duplicate ORIGINAL case context; use history for revisions")
        context_ids.add(context_sha)
        total_rows += len(source["rows"])
        if total_rows > MAX_ROWS:
            reject("PRIVATE HOLD: combined HUMAN rows exceed private portfolio bound")
        cases.append({
            "ordinal": ordinal,
            "context_sha256": context_sha,
            "actions_sha256": digest(source["action_packet"]),
            "plan_sha256": digest(source["action_plan"]),
            "rows": source["rows"],
        })
    return cases


def snapshot_id(cases):
    return [
        (case["context_sha256"], case["actions_sha256"],
         case["plan_sha256"], len(case["rows"]))
        for case in cases
    ]


def active_items(cases):
    entries = []
    stats = []
    for case in cases:
        counts = Counter(row["action_status"] for row in case["rows"])
        pending = 0
        for row in case["rows"]:
            if row["action_status"] == "unassigned":
                continue
            pending += 1
            entries.append({
                "case_ordinal": case["ordinal"],
                "case_context_sha256": case["context_sha256"],
                "original_action_packet_sha256": case["actions_sha256"],
                "transition": row["transition"],
                "kit_ordinal": row["kit_ordinal"],
                "human_status": row["action_status"],
                "human_priority": row["human_priority"],
                "proposed_day": row["proposed_day"],
                "proposed_owner": row["accountable_human"],
                "next_human_step": row["next_human_step"],
            })
        stats.append({
            "case_ordinal": case["ordinal"],
            "original_human_rows": len(case["rows"]),
            "human_proposals": pending,
            "human_status_counts": dict(sorted(counts.items())),
        })
    priority = {"human_urgent": 0, "near_term": 1, "routine": 2, "unset": 3}
    entries.sort(key=lambda row: (
        not bool(row["proposed_day"]), row["proposed_day"] or "9999-12-31",
        priority.get(row["human_priority"], 4), row["case_ordinal"],
        row["transition"], row["kit_ordinal"],
    ))
    return stats, entries


def csv_report(entries):
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(HEADERS)
    for item in entries:
        writer.writerow([item[column] for column in HEADERS])
    return out.getvalue()


def summary_html(cases, stats, entries, owner=None):
    body = [
        "<p><strong>HUMAN-only multi-case PRIVATE desk.</strong> All original "
        "context/actions/plan bytes were locally re-admitted; archived ORIGINAL "
        "customer kit files were NOT reopened. Cases remain separate, unsigned, "
        "and unverified. No real action, recipient, permission or deadline exists.</p>",
        "<p>" + str(len(stats)) + " " +
        ("selected local HUMAN case slots" if owner is not None else
         "distinct ORIGINAL historical case contexts") + " · " +
        str(sum(row["original_human_rows"] for row in stats)) +
        " original HUMAN rows · " + str(len(entries)) +
        " HUMAN suggestions (not actual work).</p>",
        "<table><thead><tr><th>Local case</th><th>HUMAN rows</th>"
        "<th>HUMAN proposals</th><th>PRIVATE HUMAN statuses</th></tr></thead><tbody>",
    ]
    if owner is not None:
        body.insert(2,
            "<p><strong>EXACT proposed HUMAN owner selection:</strong> " +
            html.escape(owner, quote=True) +
            ". This label does NOT authenticate the person, recipient or "
            "disclosure permission. Unselected owners and proposals are not "
            "included in this workroom.</p>"
        )
    for row in stats:
        statuses = "; ".join(html.escape(key) + ": " + str(value)
                             for key, value in row["human_status_counts"].items())
        body.append(
            "<tr><td>" + str(row["case_ordinal"]) + "</td><td>" +
            str(row["original_human_rows"]) + "</td><td>" +
            str(row["human_proposals"]) + "</td><td>" + statuses + "</td></tr>"
        )
    body.append(
        "</tbody></table><p>Human names, private original hashes and suggested "
        "steps are deliberately omitted from this overview. "
        "<a href='PRIVATE-HUMAN-portfolio.html'>Open sensitive HUMAN proposal desk</a>. "
        "The separate PRIVATE CSV/JSON contain case-bound human proposals and "
        "must not be emailed or uploaded without separate verified authority.</p>"
    )
    return html_page("LightUp PRIVATE cross-case HUMAN portfolio", "".join(body))


def detailed_html(entries, owner=None):
    body = [
        "<p><strong>SENSITIVE PRIVATE HUMAN PROPOSALS.</strong> The local case "
        "numbers prevent coalescing independent source contexts. Proposed days "
        "are not appointments, statuses are not completed scans, owner strings "
        "are not authenticated identities. All entries remain DRAFT/HOLD.</p>",
        "<table><thead><tr><th>Case</th><th>Kit / transition</th>"
        "<th>Human state</th><th>Human priority</th><th>Proposed day</th>"
        "<th>Proposed owner</th><th>Next HUMAN step</th></tr></thead><tbody>",
    ]
    if owner is not None:
        body.insert(1,
            "<p>Only explicit exact-label proposals for <strong>" +
            html.escape(owner, quote=True) +
            "</strong> were selected. This does not verify recipient identity.</p>"
        )
    for item in entries:
        def e(key):
            return html.escape(str(item[key]), quote=True)
        body.append(
            "<tr><td>" + e("case_ordinal") + "</td><td>" +
            e("kit_ordinal") + " / " + e("transition") + "</td><td>" +
            e("human_status") + "</td><td>" + e("human_priority") +
            "</td><td>" + e("proposed_day") + "</td><td>" +
            e("proposed_owner") + "</td><td>" + e("next_human_step") +
            "</td></tr>"
        )
    body.append(
        "</tbody></table><p>No source kit file has been copied, transmitted, "
        "re-scanned, remediated or re-authorized. "
        "<a href='OPEN-PRIVATE.html'>Back to counts</a>.</p>"
    )
    return html_page("LightUp PRIVATE HUMAN portfolio worklist", "".join(body))


def run(args):
    cases = collect(args)
    stats, entries = active_items(cases)
    owner = args.owner
    if owner is not None:
        owner = safe_human(owner, 80)
        if not owner or owner != owner.strip():
            reject("PRIVATE HOLD: choose an exact nonempty proposed HUMAN owner label")
        entries = [item for item in entries if item["proposed_owner"] == owner]
        if not entries:
            reject("PRIVATE HOLD: no explicit HUMAN proposals for that exact owner")
        # A recipient-limited view must not reveal counts or statuses
        # belonging to other proposed owners, even on the summary page.
        selected = {case["ordinal"]: [] for case in cases}
        for item in entries:
            selected[item["case_ordinal"]].append(item)
        stats = [{
            "case_ordinal": n,
            "original_human_rows": len(rows),
            "human_proposals": len(rows),
            "human_status_counts": dict(sorted(Counter(
                row["human_status"] for row in rows
            ).items())),
        } for n, rows in selected.items() if rows]
    # Re-admit every ORIGINAL chain after combining to prevent stale or
    # substituted source inputs from entering the private output.
    refreshed = collect(args)
    if snapshot_id(cases) != snapshot_id(refreshed) or (
        [case["rows"] for case in cases] != [case["rows"] for case in refreshed]
    ):
        reject("PRIVATE HOLD: ORIGINAL case source/HUMAN content changed during portfolio")
    record = {
        "schema": "lightup.private.workspace-ledger-human-portfolio.v1",
        "authority": FLAGS,
        "historical_only": True,
        "sources_reopened": False,
        "recipient_authenticated": False,
        "consent_assumed": False,
        "actions_dispatched": False,
        "owner_filter_is_unauthenticated_human_label": owner is not None,
        "proposed_owner_filter": owner,
        "cases": [{
            "case_ordinal": case["ordinal"],
            "context_sha256": case["context_sha256"],
            "original_human_actions_sha256": case["actions_sha256"],
            "original_human_plan_sha256": case["plan_sha256"],
        } for case in cases if owner is None or
           any(item["case_ordinal"] == case["ordinal"] for item in entries)],
        "human_case_counts": stats,
        "human_proposals": entries,
    }
    encoded = canonical(record)
    if len(encoded) > MAX_MANIFEST:
        reject("PRIVATE HOLD: cross-case HUMAN record exceeds re-openable private manifest limit")
    private_csv = csv_report(entries)
    if len(private_csv.encode("utf-8")) > MAX_MANIFEST:
        reject("PRIVATE HOLD: private HUMAN portfolio CSV exceeds storage bound")
    folder = new_private(args.private_parent)
    try:
        write_private(folder, "OPEN-PRIVATE.html", summary_html(cases, stats, entries, owner))
        write_private(folder, "PRIVATE-HUMAN-portfolio.html", detailed_html(entries, owner))
        write_private(folder, "PRIVATE-HUMAN-portfolio.csv", private_csv)
        write_private(folder, "PRIVATE-HUMAN-portfolio.json", encoded)
    except BaseException:
        shutil.rmtree(folder)
        raise
    print("PRIVATE HOLD: independent historical HUMAN case suggestions combined locally only")
    print(str(Path(folder) / "OPEN-PRIVATE.html"))
    return 3


def main():
    p = argparse.ArgumentParser(
        description="PRIVATE 2–8 independent ORIGINAL case HUMAN proposal workroom"
    )
    p.add_argument("--context", action="append", required=True,
                   help="Original 0600 PRIVATE-action-context.json; repeat per distinct case")
    p.add_argument("--actions", action="append", required=True,
                   help="Matching original 0600 PRIVATE-HUMAN-actions.json")
    p.add_argument("--plan", action="append", required=True,
                   help="Matching original 0600 HUMAN-action-plan.csv")
    p.add_argument("--owner", help="Optional exact proposed HUMAN owner; never authenticated")
    p.add_argument("--private-parent", required=True,
                   help="Existing 0700 output directory outside source checkout and original kits")
    args = p.parse_args()
    try:
        return run(args)
    except (Hold, OSError, ValueError, TypeError, UnicodeError, csv.Error):
        print("PRIVATE HOLD: cannot admit independent exact ORIGINAL HUMAN case portfolio",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
