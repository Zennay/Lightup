#!/usr/bin/env python3
"""Source-bound owner-private HUMAN planning dayboard from an existing portfolio.

Explicit HUMAN reference day; never actual scheduling, grant, notification,
verification of remediation, current target state or recipient identity.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
from datetime import date
import html
import io
import os
from pathlib import Path
import shutil
import sys

from ledger import (
    FLAGS, Hold, MAX_MANIFEST, canonical, digest, html_page, new_private,
    private_parent, reject, safe_human, write_private,
)
from portfolio_delta import read_portfolio, valid_day

MAX_ROWS = 2048
HEADERS = (
    "local_case", "historical_transition", "original_kit",
    "human_priority", "human_status", "proposed_day", "date_bucket",
    "proposed_owner", "next_human_step",
)
PRIORITY = {"human_urgent": 0, "near_term": 1, "routine": 2, "unset": 3}
BUCKETS = ("past_proposed_day", "selected_reference_day",
           "later_proposed_day", "no_proposed_day")


def reference_day(text):
    if not valid_day(text) or not text:
        reject("PRIVATE HOLD: explicitly supply a real ISO calendar reference day")
    return date.fromisoformat(text)


def local_path(value):
    return (type(value) is str and os.path.isabs(value)
            and os.path.normpath(value) == value
            and len(value) <= 4096 and "\x00" not in value)


def select(args, admitted):
    document = admitted[1]
    # A previously owner-scoped original cannot silently become an
    # "all owners" report if the caller omits --owner.
    owner = args.owner
    if owner is None and document["owner_filter_is_unauthenticated_human_label"]:
        owner = document["proposed_owner_filter"]
    if owner is not None:
        if type(owner) is not str or not owner or owner != owner.strip():
            reject("PRIVATE HOLD: select exact nonempty locally PROPOSED HUMAN owner")
        safe_human(owner, 80)
        if document["owner_filter_is_unauthenticated_human_label"] and (
            owner != document["proposed_owner_filter"]
        ):
            reject("PRIVATE HOLD: cannot widen previously owner-filtered source")
    cutoff = reference_day(args.reference_day)
    entries = []
    for original in document["human_proposals"]:
        if owner is not None and original["proposed_owner"] != owner:
            continue
        proposed = original["proposed_day"]
        bucket = ("no_proposed_day" if not proposed else
                  "past_proposed_day" if proposed < cutoff.isoformat() else
                  "selected_reference_day" if proposed == cutoff.isoformat() else
                  "later_proposed_day")
        entries.append({
            "local_case": original["case_ordinal"],
            "historical_transition": original["transition"],
            "original_kit": original["kit_ordinal"],
            "human_priority": original["human_priority"],
            "human_status": original["human_status"],
            "proposed_day": proposed,
            "date_bucket": bucket,
            "proposed_owner": original["proposed_owner"],
            "next_human_step": original["next_human_step"],
        })
    if not entries:
        reject("PRIVATE HOLD: no original HUMAN proposals for selected workroom")
    if len(entries) > MAX_ROWS:
        reject("PRIVATE HOLD: HUMAN dayboard action limit")
    entries.sort(key=lambda row: (
        BUCKETS.index(row["date_bucket"]),
        row["proposed_day"] or "9999-12-31",
        PRIORITY.get(row["human_priority"], 4),
        row["local_case"], row["historical_transition"], row["original_kit"],
    ))
    return entries, owner


def anonymous_dashboard(entries, when, owner):
    counter = Counter(row["date_bucket"] for row in entries)
    priority = Counter(row["human_priority"] for row in entries)
    body = [
        "<p><strong>PRIVATE HUMAN-ONLY historical proposal planning.</strong> "
        "Operator explicitly selected a reference date. Past suggestions are "
        "NOT overdue real obligations; present/future suggestions are NOT "
        "scheduled calendar events. The original assessment source files "
        "were not reopened, and no client consent, access, finding, fix or "
        "real task is verified.</p>",
        "<p><strong>HUMAN reference day: " + html.escape(when) +
        "</strong> · Selected HUMAN proposals: " + str(len(entries)) +
        " · Scope: " + ("exact single proposed owner" if owner is not None
                       else "all original HUMAN proposals") + ".</p>",
        "<table><thead><tr><th>Historical HUMAN proposal bucket</th>"
        "<th>Count</th></tr></thead><tbody>",
    ]
    for b in BUCKETS:
        body.append("<tr><td>" + html.escape(b.replace("_", " ")) +
                    "</td><td>" + str(counter[b]) + "</td></tr>")
    body.append("</tbody></table><p>Proposed HUMAN priority: " +
                " · ".join(html.escape(k.replace("_", " ")) + ": " + str(priority[k])
                           for k in PRIORITY) + ".</p>"
                "<p>No owner names, source SHA, private action text or target "
                "details appear in this source-minimal summary. "
                "<a href='PRIVATE-HUMAN-dayboard.html'>Open PRIVATE detailed "
                "HUMAN workboard</a>. Nobody was contacted.</p>")
    return html_page("LightUp PRIVATE historical HUMAN planning dayboard", "".join(body))


def private_worklist(entries, when, owner, capacity):
    body = [
        "<p><strong>OWNER-PRIVATE HUMAN proposal details.</strong> All dates and "
        "priorities below were HISTORIC HUMAN suggestions; no actual task, "
        "appointment, authenticated recipient, target scan, permission, "
        "consent or remediation was created or verified.</p>",
        "<p>Manually selected historical reference day: " + html.escape(when) +
        ". " + ("Explicit proposed HUMAN owner: <strong>" +
                html.escape(owner, quote=True) +
                "</strong>. This label does not authenticate identity." if owner
                else "All original PROPOSED HUMAN owners; keep this report PRIVATE.")
        + "</p>",
        "<table><thead><tr><th>Historical proposal bucket</th><th>Day</th>"
        "<th>Priority</th><th>Case / transition / kit</th>"
        "<th>HUMAN stage</th><th>Locally proposed owner</th>"
        "<th>PRIVATE HUMAN next-step text</th></tr></thead><tbody>",
    ]
    # Proposed owner-level workload comparison is entirely PRIVATE. It is
    # intentionally absent from the anonymous high-level HTML summary.
    body.insert(2,
        "<p><strong>Proposed HUMAN workload by locally selected owner:</strong> " +
        " · ".join(
            html.escape(row["proposed_human_owner"], quote=True) +
            ": " + str(row["historical_human_proposals"]) +
            " proposals / " + str(row["past_proposed_day"]) +
            " with suggested day earlier than reference"
            for row in capacity
        ) +
        ". None of these counts implies a real assigned task or workload.</p>"
    )
    for r in entries:
        def e(key):
            return html.escape(str(r[key]), quote=True)
        body.append(
            "<tr><td>" + e("date_bucket") + "</td><td>" + e("proposed_day") +
            "</td><td>" + e("human_priority") + "</td><td>" +
            e("local_case") + " / " + e("historical_transition") + " / " +
            e("original_kit") + "</td><td>" + e("human_status") +
            "</td><td>" + e("proposed_owner") + "</td><td>" +
            e("next_human_step") + "</td></tr>"
        )
    body.append("</tbody></table><p>HUMAN proposals only. "
                "<a href='OPEN-PRIVATE.html'>Private overview</a>.</p>")
    return html_page("LightUp PRIVATE original HUMAN dayboard details", "".join(body))


def per_owner_capacity(entries):
    """PRIVATE suggested workload, not authenticated assignments or actual work."""
    grouped = defaultdict(list)
    for row in entries:
        grouped[row["proposed_owner"]].append(row)
    result = []
    for owner, original in sorted(grouped.items()):
        counts = Counter(row["date_bucket"] for row in original)
        priorities = Counter(row["human_priority"] for row in original)
        result.append({
            "proposed_human_owner": owner,
            "historical_human_proposals": len(original),
            "past_proposed_day": counts["past_proposed_day"],
            "selected_reference_day": counts["selected_reference_day"],
            "later_proposed_day": counts["later_proposed_day"],
            "no_proposed_day": counts["no_proposed_day"],
            "human_urgent": priorities["human_urgent"],
            "near_term": priorities["near_term"],
            "routine": priorities["routine"],
            "unset": priorities["unset"],
        })
    return result


def capacity_csv(capacity):
    columns = ("proposed_human_owner", "historical_human_proposals",
               *BUCKETS, "human_urgent", "near_term", "routine", "unset")
    file = io.StringIO(newline="")
    writer = csv.writer(file, lineterminator="\n")
    writer.writerow(columns)
    for row in capacity:
        writer.writerow([row[column] for column in columns])
    return file.getvalue()


def as_csv(entries):
    file = io.StringIO(newline="")
    writer = csv.writer(file, lineterminator="\n")
    writer.writerow(HEADERS)
    for row in entries:
        writer.writerow([row[column] for column in HEADERS])
    return file.getvalue()


def run(args):
    if not local_path(args.portfolio) or not local_path(args.private_parent):
        reject("PRIVATE HOLD: canonical absolute paths required")
    private_parent(args.private_parent)
    original = read_portfolio(args.portfolio)
    entries, owner = select(args, original)
    source_sha = digest(original[0])
    # The native original byte-conformant source reader is authoritative.
    # Re-admit before writing, never trust a browser-only source preview.
    reread = read_portfolio(args.portfolio)
    if (digest(reread[0]) != source_sha or reread[1] != original[1]):
        reject("PRIVATE HOLD: original HUMAN source changed during dayboard")
    capacity = per_owner_capacity(entries)
    cases = sorted({
        (r["local_case"], r["historical_transition"], r["original_kit"])
        for r in entries
    })
    context = {case["case_ordinal"]: case for case in original[1]["cases"]}
    visible = {r["local_case"] for r in entries}
    output = {
        "schema": "lightup.private.workspace-ledger-human-dayboard.v1",
        "authority": FLAGS,
        "historical_only": True,
        "sources_reopened": False,
        "recipient_authenticated": False,
        "consent_assumed": False,
        "actions_dispatched": False,
        "appointments_booked": False,
        "verified_remediation": False,
        "original_portfolio_sha256": source_sha,
        "original_case_contexts": [{
            "case_ordinal": n,
            "original_context_sha256": context[n]["context_sha256"],
            "original_human_actions_sha256": context[n]["original_human_actions_sha256"],
        } for n in sorted(visible)],
        "manually_selected_reference_day": args.reference_day,
        "proposed_human_owner_filter": owner,
        "bucket_counts": dict(sorted(Counter(r["date_bucket"] for r in entries).items())),
        "proposed_human_owner_capacity": capacity,
        "historical_proposal_rows": entries,
        "distinct_original_human_item_slots": len(cases),
    }
    encoded = canonical(output)
    csv_text = as_csv(entries)
    capacity_text = capacity_csv(capacity)
    if (len(encoded) > MAX_MANIFEST or len(csv_text.encode("utf-8")) > MAX_MANIFEST
        or len(capacity_text.encode("utf-8")) > MAX_MANIFEST):
        reject("PRIVATE HOLD: report cannot fit original native 1 MiB source limit")
    folder = new_private(args.private_parent)
    try:
        write_private(folder, "OPEN-PRIVATE.html",
                      anonymous_dashboard(entries, args.reference_day, owner))
        write_private(folder, "PRIVATE-HUMAN-dayboard.html",
                      private_worklist(entries, args.reference_day, owner, capacity))
        write_private(folder, "PRIVATE-HUMAN-owner-capacity.csv", capacity_text)
        write_private(folder, "PRIVATE-HUMAN-dayboard.json", encoded)
        write_private(folder, "PRIVATE-HUMAN-dayboard.csv", csv_text)
    except BaseException:
        shutil.rmtree(folder)
        raise
    print("PRIVATE HOLD: historical HUMAN plan-only report, no real task created")
    print(str(Path(folder) / "OPEN-PRIVATE.html"))
    return 3


def main():
    parser = argparse.ArgumentParser(
        description="Owner-private original-case HUMAN proposal date/priority workboard"
    )
    parser.add_argument("--portfolio", required=True,
                        help="Original owner-private 0600 PRIVATE-HUMAN-portfolio.json")
    parser.add_argument("--reference-day", required=True,
                        help="Explicit HUMAN-selected ISO yyyy-mm-dd, never current implicit deadline")
    parser.add_argument("--owner",
                        help="Optional exact original proposed HUMAN owner label")
    parser.add_argument("--private-parent", required=True,
                        help="Existing owner-private 0700 folder outside checkout")
    args = parser.parse_args()
    try:
        return run(args)
    except (Hold, OSError, ValueError, TypeError, UnicodeError, csv.Error):
        print("PRIVATE HOLD: no admissible local HUMAN planning dayboard", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
