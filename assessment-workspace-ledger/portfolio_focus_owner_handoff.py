#!/usr/bin/env python3
"""Minimum-necessary PRIVATE original HUMAN meeting handoff per proposed owner.

Requires one original exact-source HUMAN meeting and original FINALIZED review
return. Owner labels are NOT authenticated humans or disclosure permission.
No sending, scheduling, grants, scans, remediation claims or target access.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import html
import io
import json
import os
from pathlib import Path
import shutil
import sys

from ledger import (
    FLAGS, Hold, MAX_MANIFEST, canonical, digest, html_page, new_private,
    private_parent, read_owner_file, reject, safe_human, write_private,
)
from portfolio_delta import read_portfolio
from portfolio_focus import local_path
from portfolio_focus_review import read_focus, STAGES
from portfolio_focus_history import read_return

SCHEMA = "lightup.private.workspace-ledger-human-owner-handoff.v1"
MAX_OWNERS = 8
COLUMNS = (
    "local_case", "historical_transition", "original_kit",
    "original_human_priority", "original_proposed_day",
    "human_review_stage", "original_private_human_next_step",
    "private_human_meeting_note",
)


def exact_owners(items):
    if type(items) is not list or not 1 <= len(items) <= MAX_OWNERS:
        reject("PRIVATE HOLD: choose 1–8 exact original proposed HUMAN owner labels")
    if any(type(v) is not str or not v or v != v.strip() for v in items):
        reject("PRIVATE HOLD: original proposed HUMAN owner label required")
    for name in items:
        safe_human(name, 80)
    if len(set(items)) != len(items):
        reject("PRIVATE HOLD: duplicate proposed HUMAN owner selection")
    return items


def match_owners(owners, proposals, reviews):
    result = []
    for owner in owners:
        selected = []
        for original, human in zip(proposals, reviews):
            if original["proposed_owner"] != owner:
                continue
            selected.append({
                "local_case": original["local_case"],
                "historical_transition": original["historical_transition"],
                "original_kit": original["original_kit"],
                "original_human_priority": original["human_priority"],
                "original_proposed_day": original["proposed_day"],
                "human_review_stage": human["human_meeting_stage"],
                "original_private_human_next_step": original["next_human_step"],
                "private_human_meeting_note": human["human_decision_note"],
            })
        if not selected:
            reject("PRIVATE HOLD: selected HUMAN owner has no original matching source proposals")
        result.append(selected)
    return result


def as_csv(rows):
    file = io.StringIO(newline="")
    writer = csv.writer(file, lineterminator="\n")
    writer.writerow(COLUMNS)
    for row in rows:
        writer.writerow([row[key] for key in COLUMNS])
    return file.getvalue()


REPLY_HEADERS = (
    "local_case", "historical_transition", "original_kit",
    "original_owner_packet_sha256", "human_reply_stage", "private_reply_note",
)
REPLY_STAGES = ("needs_discussion", "proposed_followup", "hold")


def owner_reply_template(rows, packet_sha):
    """PRIVATE review invitation, never authority or authenticated identity."""
    result = io.StringIO(newline="")
    writer = csv.writer(result, lineterminator="\n")
    writer.writerow(REPLY_HEADERS)
    for row in rows:
        writer.writerow((row["local_case"], row["historical_transition"],
                         row["original_kit"], packet_sha,
                         "needs_discussion", ""))
    return result.getvalue()


def one_html(owner, rows):
    stages = Counter(r["human_review_stage"] for r in rows)
    body = [
        "<p><strong>OWNER-PRIVATE HUMAN-only proposed follow-up, DRAFT/HOLD.</strong> "
        "This label is NEVER authenticated receiver identity or distribution "
        "permission. Verify human recipients independently before any sharing. "
        "Historical HUMAN entries are NOT verified security, actual work, "
        "consent, task assignment, appointment, grant or completed remediation.</p>",
        "<p>Exact locally proposed HUMAN owner label: <strong>" +
        html.escape(owner, quote=True) + "</strong>. "
        "Selected original historical HUMAN proposals: " + str(len(rows)) +
        ". Source kits were NOT physically reopened.</p>",
        "<p>HUMAN stage counts: " + " · ".join(
            html.escape(stage.replace("_", " ")) + ": " + str(stages[stage])
            for stage in STAGES
        ) + ".</p>",
        "<table><thead><tr><th>Original slot</th><th>HUMAN priority</th>"
        "<th>Historical proposal date</th><th>HUMAN review stage</th>"
        "<th>Original private HUMAN note</th><th>Latest private HUMAN"
        " discussion note</th></tr></thead><tbody>",
    ]
    for row in rows:
        def esc(key):
            return html.escape(str(row[key]), quote=True)
        body.append(
            "<tr><td>" + esc("local_case") + " / " + esc("historical_transition") +
            " / " + esc("original_kit") + "</td><td>" +
            esc("original_human_priority") + "</td><td>" +
            esc("original_proposed_day") + "</td><td>" +
            esc("human_review_stage") + "</td><td>" +
            esc("original_private_human_next_step") + "</td><td>" +
            esc("private_human_meeting_note") + "</td></tr>"
        )
    body.append("</tbody></table><p>This file includes only the selected "
                "ORIGINAL proposed owner's rows. It does not authenticate "
                "the original publisher or verify that any finding is real.</p>")
    return html_page("LightUp · PRIVATE proposed HUMAN owner workroom", "".join(body))


def root_overview(groups):
    summary = Counter()
    for rows in groups:
        summary[len(rows)] += 1
    body = [
        "<p><strong>PRIVATE HUMAN owner workrooms staged only on this "
        "device — no sending or authenticated recipient access.</strong> "
        "Original source bytes and original review return were re-admitted, "
        "but original client source kits were not reopened. These are "
        "HUMAN proposal drafts only; no verified findings or remediation.</p>",
        "<p>Selected opaque owner workrooms: " + str(len(groups)) +
        ". Total selected original HUMAN slots: " +
        str(sum(len(r) for r in groups)) + ".</p>",
        "<p>Each numbered output directory contains only that exact "
        "proposed HUMAN owner label and corresponding subset of original "
        "HUMAN proposal rows. No other owner label or free text is included "
        "in that owner's folder. Verify actual recipient before transfer.</p>",
    ]
    return html_page("LightUp · owner-private HUMAN proposal packets", "".join(body))


def run(args):
    owners = exact_owners(args.owner)
    paths = [args.portfolio, args.meeting, args.review_return, args.private_parent]
    if any(not local_path(p) for p in paths) or len(set(paths)) != len(paths):
        reject("PRIVATE HOLD: unique exact absolute original source paths required")
    private_parent(args.private_parent)
    source = read_portfolio(args.portfolio)
    meeting, doc, proposals = read_focus(args.meeting, source)
    original = read_return(
        args.review_return, digest(source[0]), digest(meeting),
        doc["original_case_contexts"], proposals,
    )
    selections = match_owners(owners, proposals, original[1])
    # No source-owner widening: already filtered original meetings can only
    # produce that SAME exact original proposed owner label.
    selected_owner = doc["proposed_human_owner_filter"]
    if selected_owner is not None and (
        len(owners) != 1 or owners[0] != selected_owner
    ):
        reject("PRIVATE HOLD: cannot broaden previously scoped HUMAN owner meeting")
    if (read_portfolio(args.portfolio)[0] != source[0] or
        read_focus(args.meeting, source)[0] != meeting or
        read_return(args.review_return, digest(source[0]), digest(meeting),
                    doc["original_case_contexts"], proposals)[0] != original[0]):
        reject("PRIVATE HOLD: original HUMAN source or return changed before handoff")
    packets = []
    for owner, rows in zip(owners, selections):
        result = {
            "schema": SCHEMA,
            "authority": FLAGS,
            "historical_only": True,
            "sources_reopened": False,
            "recipient_authenticated": False,
            "consent_assumed": False,
            "actions_dispatched": False,
            "appointments_booked": False,
            "verified_remediation": False,
            "proposed_human_owner_label": owner,
            "original_source_portfolio_sha256": digest(source[0]),
            "original_source_meeting_sha256": digest(meeting),
            "original_review_return_sha256": digest(original[0]),
            "human_rows_only_for_selected_owner": rows,
        }
        contents = {
            "OPEN-PRIVATE.html": one_html(owner, rows),
            "PRIVATE-HUMAN-owner.csv": as_csv(rows),
            "PRIVATE-HUMAN-owner.json": canonical(result),
            "HUMAN-owner-reply-template.csv": owner_reply_template(
                rows, digest(canonical(result))
            ),
        }
        if any(len(value if isinstance(value, bytes) else value.encode("utf-8")) > MAX_MANIFEST
               for value in contents.values()):
            reject("PRIVATE HOLD: selected human owner packet exceeds private bound")
        packets.append(contents)
    overview = root_overview(selections)
    if len(overview.encode("utf-8")) > MAX_MANIFEST:
        reject("PRIVATE HOLD: HUMAN overview exceeds private source bound")
    folder = new_private(args.private_parent)
    try:
        write_private(folder, "OPEN-PRIVATE.html", overview)
        for number, files in enumerate(packets, 1):
            location = Path(folder) / ("OWNER-%02d" % number)
            os.mkdir(location, mode=0o700)
            for name, value in files.items():
                write_private(str(location), name, value)
    except BaseException:
        shutil.rmtree(folder)
        raise
    print("PRIVATE HOLD: owner-labelled HUMAN workrooms created; nobody authenticated/contacted")
    print(str(Path(folder) / "OPEN-PRIVATE.html"))
    return 3


def main():
    ap = argparse.ArgumentParser(
        description="Prepare minimum-necessary PRIVATE HUMAN owner packets from original review"
    )
    ap.add_argument("--portfolio", required=True)
    ap.add_argument("--meeting", required=True)
    ap.add_argument("--review-return", required=True)
    ap.add_argument("--owner", action="append", required=True,
                    help="Exact original proposed HUMAN label; repeat for 1–8")
    ap.add_argument("--private-parent", required=True)
    a = ap.parse_args()
    try:
        return run(a)
    except (Hold, OSError, ValueError, TypeError, UnicodeError, csv.Error):
        print("PRIVATE HOLD: original HUMAN owner handoff refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
