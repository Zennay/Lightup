#!/usr/bin/env python3
"""Private, minimum-necessary HUMAN follow-up packet from original portfolio.

No task dispatch, deadline scheduling, remediation verification, grant or consent.
Original private kit bytes are not reopened. An owner label is not identity.
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

from ledger import (
    FLAGS, Hold, MAX_MANIFEST, canonical, digest, html_page, new_private,
    private_parent, reject, write_private,
)
from portfolio_delta import read_portfolio
from portfolio_dayboard import BUCKETS, HEADERS, PRIORITY, local_path, select

SCHEMA = "lightup.private.workspace-ledger-human-focus.v1"
MAX_ROWS = 2048
MAX_TITLE = 100
REVIEW_HEADERS = (
    "local_case", "historical_transition", "original_kit", "meeting_sha256",
    "human_meeting_stage", "human_decision_note",
)


def options(args):
    if not local_path(args.portfolio) or not local_path(args.private_parent):
        reject("PRIVATE HOLD: source/output paths must be canonical absolute paths")
    private_parent(args.private_parent)
    if type(args.title) is not str or not 1 <= len(args.title) <= MAX_TITLE:
        reject("PRIVATE HOLD: explicit bounded HUMAN meeting title required")
    if args.title != args.title.strip() or any(ord(c) < 32 or ord(c) == 127 for c in args.title):
        reject("PRIVATE HOLD: invalid HUMAN title")
    allowed = {
        "bucket": set(BUCKETS),
        "priority": set(PRIORITY),
    }
    selected = {}
    for field, valid in allowed.items():
        values = getattr(args, field)
        if type(values) is not list or not values or len(values) > len(valid):
            reject("PRIVATE HOLD: select one or more explicit HUMAN focus filters")
        if any(type(item) is not str or item not in valid for item in values):
            reject("PRIVATE HOLD: unexpected HUMAN focus filter")
        if len(set(values)) != len(values):
            reject("PRIVATE HOLD: duplicate HUMAN focus filter")
        selected[field] = set(values)
    return selected


def csv_rows(entries):
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(HEADERS)
    for row in entries:
        writer.writerow([row[column] for column in HEADERS])
    return buffer.getvalue()


def review_template(entries, meeting_sha):
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(REVIEW_HEADERS)
    for row in entries:
        writer.writerow([
            row["local_case"], row["historical_transition"], row["original_kit"],
            meeting_sha, "needs_discussion", "",
        ])
    return buffer.getvalue()


def private_markdown(entries, args, source_sha, owner):
    # This is explicitly PRIVATE. JSON-quoted values avoid accidental Markdown
    # heading/list/injected links when the operator supplies freeform text.
    import json
    quoted = lambda value: json.dumps(value, ensure_ascii=True)
    lines = [
        "# LightUp · PRIVATE HUMAN follow-up meeting",
        "",
        "**DRAFT/HOLD · ORIGINAL historical HUMAN proposals only.**",
        "No actual due dates, authenticated recipient, approval, grant,",
        "client consent, scan, task dispatch, verified fix or security finding.",
        "",
        "Meeting label: " + quoted(args.title),
        "Reference day (manually selected): " + args.reference_day,
        "Original private portfolio SHA-256 (UNSIGNED): " + source_sha,
        "Proposed owner filter: " + (quoted(owner) if owner is not None else "ALL proposed owners — PRIVATE"),
        "Priority selection: " + ", ".join(sorted(args.priority)),
        "Historical date buckets: " + ", ".join(sorted(args.bucket)),
        "",
        "These original historical dates are merely HUMAN proposals; none is a scheduled event.",
        "The original assessment kits have NOT been reopened.",
        "",
    ]
    for i, item in enumerate(entries, 1):
        lines += [
            "## " + str(i) + " · Local case " + str(item["local_case"]),
            "",
            "Historical transition/kit: " + str(item["historical_transition"]) +
            " / " + str(item["original_kit"]),
            "HUMAN priority / status: " + item["human_priority"] + " / " + item["human_status"],
            "Suggested date / bucket: " + (item["proposed_day"] or "none") +
            " / " + item["date_bucket"],
            "Proposed HUMAN owner: " + quoted(item["proposed_owner"]),
            "Private HUMAN next-step note: " + quoted(item["next_human_step"]),
            "",
        ]
    lines += ["All proposed assignments remain unverified human drafts; independently check recipients before sharing.", ""]
    return "\n".join(lines)


def detail_html(entries, args, owner):
    body = [
        "<p><strong>PRIVATE DRAFT/HOLD — offline human-only meeting packet.</strong> "
        "No client data or recipient identity has been authenticated. All proposed "
        "days, people, priorities and actions are HISTORICAL HUMAN suggestions. "
        "No permission, grant, consent, scan, active work, task, calendar booking "
        "or verified remediation was created.</p>",
        "<p><strong>Meeting:</strong> " + html.escape(args.title, quote=True) +
        "<br>Explicit HUMAN reference day: " + html.escape(args.reference_day) +
        "<br>Proposed HUMAN owner selection: " +
        (html.escape(owner, quote=True) if owner else "ALL — PRIVATE") +
        "</p>",
        "<p>Only entries matching explicitly selected priority and historical "
        "date-bucket filters appear below. Source identities are unsigned and "
        "original assessment kits were not reopened.</p>",
        "<table><thead><tr><th>Case / transition / kit</th><th>HUMAN priority</th>"
        "<th>Original proposed day</th><th>Proposed owner</th>"
        "<th>PRIVATE next HUMAN step</th></tr></thead><tbody>",
    ]
    for item in entries:
        esc = lambda key: html.escape(str(item[key]), quote=True)
        body.append(
            "<tr><td>" + esc("local_case") + "/" + esc("historical_transition") +
            "/" + esc("original_kit") + "</td><td>" + esc("human_priority") +
            " · " + esc("human_status") + "</td><td>" + esc("proposed_day") +
            " (" + esc("date_bucket") + ")</td><td>" + esc("proposed_owner") +
            "</td><td>" + esc("next_human_step") + "</td></tr>"
        )
    body.append("</tbody></table><p>Private human discussions only. "
                "Verify actual recipient identity and disclosure permissions outside this offline draft.</p>")
    return html_page("LightUp · PRIVATE HUMAN focus meeting", "".join(body))


def summary_html(entries, args):
    dates = Counter(item["date_bucket"] for item in entries)
    priorities = Counter(item["human_priority"] for item in entries)
    body = [
        "<h2>Source-minimal HUMAN meeting overview</h2>",
        "<p><strong>PRIVATE/HUMAN DRAFT/HOLD.</strong> Counts describe selected "
        "historical HUMAN proposals only, not actual tasks or verified findings. "
        "No authorization, consent, source reopening or security approval.</p>",
        "<p>Selected proposals: " + str(len(entries)) +
        ". No owner labels, case IDs, original hashes, paths or proposed action "
        "text are included here. This is still a PRIVATE handoff.</p>",
        "<h3>Historical proposed-day groups</h3><table><thead><tr>"
        "<th>Group</th><th>Count</th></tr></thead><tbody>",
    ]
    for field in BUCKETS:
        body.append("<tr><td>" + html.escape(field) + "</td><td>" +
                    str(dates[field]) + "</td></tr>")
    body.append("</tbody></table><h3>Proposed HUMAN priorities</h3><table><thead>"
                "<tr><th>Priority</th><th>Count</th></tr></thead><tbody>")
    for field in PRIORITY:
        body.append("<tr><td>" + html.escape(field) + "</td><td>" +
                    str(priorities[field]) + "</td></tr>")
    body.append("</tbody></table><p>No file was shared, sent, scheduled or scanned.</p>")
    return html_page("LightUp · source-minimal HUMAN focus", "".join(body))


def run(args):
    selected = options(args)
    original = read_portfolio(args.portfolio)
    # select() carries the original portfolio's owner restriction forward.
    entries, owner = select(args, original)
    focus = [row for row in entries if (
        row["date_bucket"] in selected["bucket"] and
        row["human_priority"] in selected["priority"]
    )]
    if not focus or len(focus) > MAX_ROWS:
        reject("PRIVATE HOLD: explicit HUMAN focus selected no admissible proposals")
    raw, document = original[0], original[1]
    sha = digest(raw)
    current = read_portfolio(args.portfolio)
    if current[0] != raw or current[1] != document:
        reject("PRIVATE HOLD: original HUMAN portfolio bytes changed before publishing")
    original_cases = {row["case_ordinal"]: row for row in document["cases"]}
    context = [{
        "case_ordinal": n,
        "original_context_sha256": original_cases[n]["context_sha256"],
        "original_human_actions_sha256": original_cases[n]["original_human_actions_sha256"],
    } for n in sorted({row["local_case"] for row in focus})]
    payload = {
        "schema": SCHEMA, "authority": FLAGS, "historical_only": True,
        "sources_reopened": False, "recipient_authenticated": False,
        "consent_assumed": False, "actions_dispatched": False,
        "appointments_booked": False, "verified_remediation": False,
        "original_portfolio_sha256": sha,
        "original_case_contexts": context,
        "meeting_title": args.title,
        "manually_selected_reference_day": args.reference_day,
        "proposed_human_owner_filter": owner,
        "selected_date_buckets": [b for b in BUCKETS if b in selected["bucket"]],
        "selected_human_priorities": [p for p in PRIORITY if p in selected["priority"]],
        "historical_human_proposals": focus,
    }
    manifest = canonical(payload)
    table = csv_rows(focus)
    review = review_template(focus, digest(manifest))
    markdown = private_markdown(focus, args, sha, owner)
    if any(len(value if isinstance(value, bytes) else value.encode("utf-8")) > MAX_MANIFEST for value in (
        manifest, table, markdown, review
    )):
        reject("PRIVATE HOLD: HUMAN meeting packet is too large")
    folder = new_private(args.private_parent)
    try:
        write_private(folder, "OPEN-PRIVATE.html", summary_html(focus, args))
        write_private(folder, "PRIVATE-HUMAN-meeting.html", detail_html(focus, args, owner))
        write_private(folder, "PRIVATE-HUMAN-meeting.md", markdown)
        write_private(folder, "PRIVATE-HUMAN-meeting.csv", table)
        write_private(folder, "HUMAN-meeting-review-template.csv", review)
        write_private(folder, "PRIVATE-HUMAN-meeting.json", manifest)
    except BaseException:
        shutil.rmtree(folder)
        raise
    print("PRIVATE HOLD: source-bound historical HUMAN meeting prepared; no real actions")
    print(str(Path(folder) / "OPEN-PRIVATE.html"))
    return 3


def main():
    parser = argparse.ArgumentParser(
        description="Create an owner-private filtered HUMAN meeting packet from an original portfolio"
    )
    parser.add_argument("--portfolio", required=True, help="Original owner-private portfolio JSON")
    parser.add_argument("--reference-day", required=True, help="Explicit yyyy-mm-dd HUMAN reference")
    parser.add_argument("--owner", help="Optional exact proposed HUMAN owner; cannot widen prior scope")
    parser.add_argument("--title", required=True, help="Private human meeting label; not identity")
    parser.add_argument("--bucket", action="append", required=True, choices=BUCKETS,
                        help="Repeat for each selected historical day group")
    parser.add_argument("--priority", action="append", required=True, choices=tuple(PRIORITY),
                        help="Repeat for each selected HUMAN priority")
    parser.add_argument("--private-parent", required=True, help="Existing 0700 private parent")
    args = parser.parse_args()
    try:
        return run(args)
    except (Hold, OSError, ValueError, TypeError, UnicodeError, csv.Error):
        print("PRIVATE HOLD: cannot prepare original HUMAN focus packet", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
