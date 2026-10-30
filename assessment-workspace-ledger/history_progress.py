#!/usr/bin/env python3
"""PRIVATE longitudinal HUMAN action-plan comparison with explicit source custody.

2-8 originally finalized owner-private HUMAN action records, in selected order.
All original source/reviewer/action CSVs are admitted by the unchanged native
chain checks. Purely historical proposals; no scheduling, scanning or grant.
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
from ledger import FLAGS, Hold, canonical, digest, html_page, new_private, reject, write_private

MAX_REVISIONS = 8
FIELDS = ("action_status", "human_priority", "accountable_human",
          "proposed_day", "next_human_step")
COLUMNS = ("human_step", "original_transition", "original_kit",
           "changed_fields", "old_human_status", "new_human_status",
           "old_proposed_owner", "new_proposed_owner", "old_proposed_day",
           "new_proposed_day", "old_human_priority", "new_human_priority")


def capture(args):
    n = len(args.actions)
    if not (2 <= n <= MAX_REVISIONS and n == len(args.plan)):
        reject("PRIVATE HOLD: choose 2-8 corresponding original action JSON/CSV pairs")
    all_paths = [args.action_context] + args.actions + args.plan
    if any(not isinstance(p, str) or not os.path.isabs(p) or
           os.path.normpath(p) != p or len(p) > 4096 for p in all_paths):
        reject("PRIVATE HOLD: action history requires canonical absolute original references")
    if len(set(args.actions)) != n or len(set(args.plan)) != n:
        reject("PRIVATE HOLD: action revisions must refer to distinct original files")
    results = []
    identities = set()
    for action_path, plan_path in zip(args.actions, args.plan):
        input_args = argparse.Namespace(
            action_context=args.action_context, actions=action_path, plan=plan_path
        )
        case = admitted_original(input_args)
        fingerprint = case["action_packet"]
        if fingerprint in identities:
            reject("PRIVATE HOLD: exact duplicated human action snapshot in selected timeline")
        identities.add(fingerprint)
        results.append({
            "actions_path": action_path, "plan_path": plan_path,
            "action_packet_sha256": digest(fingerprint),
            "original_action_plan_sha256": digest(case["action_plan"]),
            "original_source_context_sha256": digest(case["source_context"]),
            "rows": case["rows"], "sources": case["sources"],
        })
    root = results[0]
    for revision in results[1:]:
        if (
            revision["original_source_context_sha256"] != root["original_source_context_sha256"]
            or len(revision["rows"]) != len(root["rows"])
        ):
            reject("PRIVATE HOLD: original source context or row count changed between HUMAN drafts")
        for a, b in zip(root["rows"], revision["rows"]):
            if any(a[field] != b[field] for field in (
                "transition", "kit_ordinal", "original_ledger_sha256",
                "original_kit_digest", "original_team_choice_sha256",
                "original_reviewer_sha256", "original_human_stage"
            )):
                reject("PRIVATE HOLD: no revisions across changed original source identities")
    return results


def analyze(records):
    changes = []
    by_pair = []
    total_changes = 0
    for ordinal in range(1, len(records)):
        before = records[ordinal - 1]["rows"]
        after = records[ordinal]["rows"]
        step_counts = Counter()
        for old, new in zip(before, after):
            fields = [field for field in FIELDS if old[field] != new[field]]
            if not fields:
                continue
            step_counts.update(fields)
            changes.append({
                "human_step": ordinal,
                "original_transition": new["transition"],
                "original_kit": new["kit_ordinal"],
                "original_ledger_sha256": new["original_ledger_sha256"],
                "original_kit_digest": new["original_kit_digest"],
                "changed_fields": fields,
                "previous": {f: old[f] for f in FIELDS},
                "proposed": {f: new[f] for f in FIELDS},
            })
        by_pair.append({
            "human_step": ordinal,
            "from_actions_sha256": records[ordinal - 1]["action_packet_sha256"],
            "to_actions_sha256": records[ordinal]["action_packet_sha256"],
            "changed_human_cases": len({(row["original_transition"],row["original_kit"])
                                        for row in changes if row["human_step"] == ordinal}),
            "changed_field_counts": dict(step_counts),
        })
        total_changes += by_pair[-1]["changed_human_cases"]
    latest = records[-1]["rows"]
    status_counts = dict(Counter(row["action_status"] for row in latest))
    active = [dict(row) for row in latest if row["action_status"] != "unassigned"]
    ordering = {"human_urgent": 0, "near_term": 1, "routine": 2, "unset": 3}
    active.sort(key=lambda r: (
        r["proposed_day"] == "", r["proposed_day"] or "9999-12-31",
        ordering.get(r["human_priority"], 4), r["accountable_human"],
        r["transition"], r["kit_ordinal"]
    ))
    return changes, by_pair, status_counts, active, total_changes


def minimal(records, changes, steps, statuses, active, count):
    contents = [
        "<p><strong>HUMAN-selected order, NOT independently signed chronology.</strong> "
        "These are local historic HUMAN proposal drafts bound to original archived "
        "ledgers and original reviewer choices. No authenticated reviewer, real "
        "client consent, security finding, verified remediation or released action. "
        "Original customer kit files have NOT been reopened.</p>",
        "<p>" + str(len(records)) + " original HUMAN snapshots · " +
        str(len(steps)) + " adjacent comparisons · " +
        str(count) + " changed HUMAN cases across comparisons. Latest selected "
        "private statuses: " + ", ".join(
            html.escape(k) + " " + str(v) for k,v in sorted(statuses.items())
        ) + ".</p>",
        "<table><thead><tr><th>Selected HUMAN transition</th><th>Changed HUMAN cases</th>"
        "<th>Changed fields</th></tr></thead><tbody>",
    ]
    for row in steps:
        field_counts = ", ".join(
            html.escape(key) + ": " + str(value)
            for key, value in sorted(row["changed_field_counts"].items())
        ) or "None"
        contents.append(
            "<tr><td>" + str(row["human_step"]) + "</td><td>" +
            str(row["changed_human_cases"]) + "</td><td>" + field_counts + "</td></tr>"
        )
    contents.append("</tbody></table><p>PRIVATE source-relative identifiers, personal "
                    "names, sensitive next-step questions and unsigned ledger hashes "
                    "are deliberately absent here.</p>"
                    "<p><a href='PRIVATE-HUMAN-changes.html'>Open PRIVATE HUMAN changes</a> · "
                    "<a href='PRIVATE-HUMAN-worklist.html'>Open PRIVATE suggested worklist</a>.</p>"
                    "<p>Proposed days are NOT real deadlines or booked events; "
                    "the worklist is a review aid, not a queue or status of actual work.</p>")
    return html_page("LightUp PRIVATE historical HUMAN action dashboard", "".join(contents))


def changes_html(changes):
    body = [
        "<p>PRIVATE original-source-bound HUMAN-only proposal revisions. "
        "No authentic review identity, performed security work, real scheduling "
        "or authorized remediation. The comparison order is chosen by a HUMAN "
        "and is not independently dated.</p>",
        "<table><thead><tr><th>Step</th><th>Original kit</th>"
        "<th>Changed fields</th><th>Previous HUMAN proposal</th>"
        "<th>New HUMAN proposal</th></tr></thead><tbody>"
    ]
    for change in changes:
        for field in change["changed_fields"]:
            body.append(
                "<tr><td>" + str(change["human_step"]) + "</td><td>" +
                str(change["original_kit"]) + " / transition " +
                str(change["original_transition"]) + "</td><td>" +
                html.escape(field) + "</td><td>" +
                html.escape(change["previous"][field]) + "</td><td>" +
                html.escape(change["proposed"][field]) + "</td></tr>"
            )
    body.append("</tbody></table><p>NONE of these changes verifies any fix or "
                "creates a legal obligation. All fields remain PRIVATE.</p>"
                "<p><a href='OPEN-PRIVATE.html'>Return to summary</a></p>")
    return html_page("LightUp PRIVATE HUMAN proposal change history", "".join(body))


def worklist_html(active):
    body = [
        "<p>PRIVATE manually PROPOSED worklist, sorted by proposed HUMAN day "
        "then proposed priority, with missing days last. Date is not a booked "
        "deadline. No event, permission, scan, task assignment or notification "
        "has been created. Do not treat pending work as a verified vulnerability.</p>",
        "<table><thead><tr><th>Proposed day</th><th>Human priority</th>"
        "<th>Original kit</th><th>Proposed owner</th><th>HUMAN state</th>"
        "<th>Next HUMAN action</th></tr></thead><tbody>"
    ]
    for row in active:
        body.append(
            "<tr><td>" + html.escape(row["proposed_day"] or "(not proposed)") +
            "</td><td>" + html.escape(row["human_priority"]) + "</td><td>" +
            str(row["kit_ordinal"]) + " / transition " +
            str(row["transition"]) + "</td><td>" +
            html.escape(row["accountable_human"]) + "</td><td>" +
            html.escape(row["action_status"]) + "</td><td>" +
            html.escape(row["next_human_step"]) + "</td></tr>"
        )
    body.append("</tbody></table><p>Original kit files NOT reopened; every "
                "activity remains human-only DRAFT/HOLD. "
                "<a href='OPEN-PRIVATE.html'>Return to summary</a>.</p>")
    return html_page("LightUp PRIVATE proposed HUMAN worklist", "".join(body))


def export_change_csv(changes):
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(COLUMNS)
    for row in changes:
        old,new=row["previous"],row["proposed"]
        writer.writerow([
            row["human_step"],row["original_transition"],row["original_kit"],
            ";".join(row["changed_fields"]),old["action_status"],new["action_status"],
            old["accountable_human"],new["accountable_human"],
            old["proposed_day"],new["proposed_day"],
            old["human_priority"],new["human_priority"]
        ])
    return out.getvalue()


def run(args):
    records = capture(args)
    changes, steps, statuses, active, count = analyze(records)
    private_parent = private_parent_for_originals(args.private_parent, records[0]["sources"])
    # Original archived ledger/reviewer/choice/action bytes must still match
    # before writing any output, not only at the initial comparison.
    reread = capture(args)
    if [
        (r["action_packet_sha256"],r["original_action_plan_sha256"],
         r["original_source_context_sha256"]) for r in records
    ] != [
        (r["action_packet_sha256"],r["original_action_plan_sha256"],
         r["original_source_context_sha256"]) for r in reread
    ]:
        reject("PRIVATE HOLD: ORIGINAL HUMAN history changed during review")
    handoff = {
        "schema":"lightup.private.workspace-ledger-action-progress.v1",
        "authority":FLAGS,
        "sources_reopened":False,
        "historical_only":True,
        "human_order_is_not_proven_chronology":True,
        "actions_dispatched":False,
        "source_context_sha256":records[0]["original_source_context_sha256"],
        "human_snapshots":[{
            "slot":i+1,"actions_sha256":row["action_packet_sha256"],
            "action_plan_sha256":row["original_action_plan_sha256"]
        } for i,row in enumerate(records)],
        "human_transitions":steps,
        "changed_human_proposals":changes,
        "latest_selected_human_statuses":statuses,
        "latest_selected_human_worklist":active,
    }
    folder = new_private(private_parent)
    try:
        write_private(folder,"PRIVATE-HUMAN-progress.json",canonical(handoff))
        write_private(folder,"OPEN-PRIVATE.html",minimal(records,changes,steps,statuses,active,count))
        write_private(folder,"PRIVATE-HUMAN-changes.html",changes_html(changes))
        write_private(folder,"PRIVATE-HUMAN-worklist.html",worklist_html(active))
        write_private(folder,"PRIVATE-HUMAN-changes.csv",export_change_csv(changes))
    except BaseException:
        shutil.rmtree(folder)
        raise
    print("PRIVATE HOLD: compared ONLY historical HUMAN action proposals, never actual security work")
    print(str(Path(folder)/"OPEN-PRIVATE.html"))
    return 3


def main():
    p = argparse.ArgumentParser(
        description="Owner-private 2-8 exact original HUMAN action snapshots, no action dispatch"
    )
    p.add_argument("--action-context", required=True,
                   help="Original owner-private 0600 PRIVATE-action-context.json")
    p.add_argument("--actions", action="append", required=True,
                   help="Original finalized PRIVATE-HUMAN-actions.json (repeat 2-8)")
    p.add_argument("--plan", action="append", required=True,
                   help="Corresponding original finalized HUMAN-action-plan.csv (repeat 2-8)")
    p.add_argument("--private-parent", required=True)
    args=p.parse_args()
    try:
        return run(args)
    except (Hold,OSError,ValueError,UnicodeError,TypeError,csv.Error):
        print("PRIVATE HOLD: cannot admit source-exact HUMAN longitudinal proposal history",file=sys.stderr)
        return 3


if __name__=="__main__":
    sys.exit(main())
