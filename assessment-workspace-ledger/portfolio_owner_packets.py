#!/usr/bin/env python3
"""PRIVATE offline HUMAN owner workrooms from one native cross-case portfolio.

No grants, task dispatch, email, network I/O, real recipient authentication,
or original customer-kit reopening. An explicitly selected HUMAN label is
not proof that the named human exists, owns a case, or may receive its data.
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

from ledger import FLAGS, Hold, MAX_MANIFEST, canonical, digest, html_page, new_private, private_parent, reject, safe_human, write_private
from portfolio_delta import read_portfolio

MAX_OWNERS = 8
MAX_ROWS = 2048
COLUMNS = (
    "human_case", "human_transition", "original_kit", "human_status",
    "human_priority", "proposed_day", "proposed_owner", "next_human_step",
)
PRIORITY_ORDER = {"human_urgent": 0, "near_term": 1, "routine": 2, "unset": 3}


def owners_from_original(args, original):
    doc = original[1]
    names = args.owner
    if not 1 <= len(names) <= MAX_OWNERS or len(set(names)) != len(names):
        reject("PRIVATE HOLD: explicitly select 1–8 DISTINCT proposed HUMAN owners")
    for name in names:
        if type(name) is not str or not name or name != name.strip():
            reject("PRIVATE HOLD: exact nonempty HUMAN owner labels only")
        safe_human(name, 80)
        if doc["owner_filter_is_unauthenticated_human_label"] and (
            name != doc["proposed_owner_filter"]
        ):
            reject("PRIVATE HOLD: cannot broaden a previously filtered HUMAN source")
    groups = []
    for ordinal, name in enumerate(names, 1):
        matches = [row for row in doc["human_proposals"]
                   if row["proposed_owner"] == name]
        if not matches:
            reject("PRIVATE HOLD: selected HUMAN owner has no explicit original proposals")
        if len(matches) > MAX_ROWS:
            reject("PRIVATE HOLD: bounded HUMAN owner rows exceeded")
        matches.sort(key=lambda row: (
            not bool(row["proposed_day"]), row["proposed_day"] or "9999-12-31",
            PRIORITY_ORDER.get(row["human_priority"], 4),
            row["case_ordinal"], row["transition"], row["kit_ordinal"],
        ))
        case_ids = {row["case_ordinal"] for row in matches}
        cases = [{
            "case_ordinal": case["case_ordinal"],
            "original_case_context_sha256": case["context_sha256"],
            "original_human_actions_sha256": case["original_human_actions_sha256"],
            "original_human_plan_sha256": case["original_human_plan_sha256"],
        } for case in doc["cases"] if case["case_ordinal"] in case_ids]
        groups.append({
            "label_ordinal": ordinal, "label": name, "cases": cases,
            "entries": matches,
        })
    return groups


def export_csv(group):
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(COLUMNS)
    for row in group["entries"]:
        writer.writerow([
            row["case_ordinal"], row["transition"], row["kit_ordinal"],
            row["human_status"], row["human_priority"], row["proposed_day"],
            row["proposed_owner"], row["next_human_step"],
        ])
    return output.getvalue()


def detail_html(group):
    body = [
        "<p><strong>PRIVATE HUMAN-ONLY proposal handoff — not sent.</strong> "
        "The exact selected owner label is NOT an authenticated identity. "
        "These historic suggested steps are NOT verified findings, booked "
        "deadlines, assigned work or release authority. Independently verify "
        "the actual recipient and explicit disclosure permission before "
        "considering any separate manual share.</p>",
        "<p>Proposed HUMAN label: <strong>" +
        html.escape(group["label"], quote=True) +
        "</strong>. Other selected owners and their case metadata are NOT "
        "included in this workroom.</p>",
        "<table><thead><tr><th>Local case / kit / transition</th>"
        "<th>HUMAN status</th><th>Human priority</th><th>Proposed day</th>"
        "<th>Next PRIVATE HUMAN step</th></tr></thead><tbody>",
    ]
    for row in group["entries"]:
        body.append(
            "<tr><td>" + str(row["case_ordinal"]) + " / " +
            str(row["kit_ordinal"]) + " / " + str(row["transition"]) +
            "</td><td>" + html.escape(row["human_status"]) +
            "</td><td>" + html.escape(row["human_priority"]) +
            "</td><td>" + html.escape(row["proposed_day"]) +
            "</td><td>" + html.escape(row["next_human_step"]) +
            "</td></tr>"
        )
    body.append(
        "</tbody></table><p>Source SHA references are only in the PRIVATE "
        "local JSON. Original source kits were NOT reopened; no action "
        "was dispatched and no permissions were changed.</p>"
    )
    return html_page("LightUp PRIVATE HUMAN owner proposals", "".join(body))


def overview_html(groups):
    body = [
        "<p><strong>PRIVATE workroom index, not a mailing list.</strong> "
        "Only explicitly selected HUMAN owner labels and aggregate counts "
        "are included. No original action text, original source SHA or "
        "customer target identifier appears on this index. None of these "
        "labels authenticates a real recipient, consent, approved scope, "
        "actual work or successful remediation.</p>",
        "<table><thead><tr><th>Local owner slot</th><th>HUMAN proposals</th>"
        "<th>Local case slots</th><th>PRIVATE local link</th></tr></thead><tbody>"
    ]
    for group in groups:
        label = group["label_ordinal"]
        body.append(
            "<tr><td>" + str(label) + "</td><td>" +
            str(len(group["entries"])) + "</td><td>" +
            str(len(group["cases"])) + "</td><td><a href='owner-" +
            ("%02d" % label) + "/OPEN-PRIVATE.html'>Open PRIVATE HUMAN "
            "workroom</a></td></tr>"
        )
    body.append(
        "</tbody></table><p>All output folders are local owner-private; "
        "NOT encrypted transfers. Nothing was sent, approved, scheduled, "
        "booked, scanned, verified or authorized.</p>"
    )
    return html_page("LightUp PRIVATE offline HUMAN owner workroom index", "".join(body))


def run(args):
    if (not isinstance(args.portfolio, str) or not os.path.isabs(args.portfolio) or
        os.path.normpath(args.portfolio) != args.portfolio or
        not isinstance(args.private_parent, str) or
        not os.path.isabs(args.private_parent) or
        os.path.normpath(args.private_parent) != args.private_parent):
        reject("PRIVATE HOLD: canonical absolute original paths required")
    if os.path.commonpath((args.portfolio, args.private_parent)) == args.portfolio:
        reject("PRIVATE HOLD: output cannot be nested beneath source file")
    private_parent(args.private_parent)
    source = read_portfolio(args.portfolio)
    groups = owners_from_original(args, source)
    source_sha = digest(source[0])
    # Check all ORIGINAL PRIVATE stored bytes again before creating any
    # selected-owner folder. No stale or substituted source admission.
    updated = read_portfolio(args.portfolio)
    if digest(updated[0]) != source_sha or updated[1] != source[1]:
        reject("PRIVATE HOLD: original cross-case HUMAN portfolio changed")
    packets = []
    for group in groups:
        entries = group["entries"]
        packet = {
            "schema": "lightup.private.workspace-ledger-human-owner-workroom.v1",
            "authority": FLAGS,
            "historical_only": True,
            "sources_reopened": False,
            "recipient_authenticated": False,
            "disclosure_approved": False,
            "actions_dispatched": False,
            "original_portfolio_sha256": source_sha,
            "proposed_human_owner": group["label"],
            "owner_label_is_not_authenticated_identity": True,
            "source_cases": group["cases"],
            "human_proposals": entries,
            "human_status_counts": dict(sorted(Counter(
                row["human_status"] for row in entries
            ).items())),
        }
        json_bytes = canonical(packet)
        csv_text = export_csv(group)
        if len(json_bytes) > MAX_MANIFEST or len(csv_text.encode("utf-8")) > MAX_MANIFEST:
            reject("PRIVATE HOLD: selected owner package cannot fit bounded native source format")
        packets.append((group, json_bytes, csv_text))
    folder = new_private(args.private_parent)
    try:
        write_private(folder, "OPEN-PRIVATE.html", overview_html(groups))
        for group, json_bytes, csv_text in packets:
            dest = Path(folder) / ("owner-%02d" % group["label_ordinal"])
            os.mkdir(dest, 0o700)
            write_private(dest, "OPEN-PRIVATE.html", detail_html(group))
            write_private(dest, "PRIVATE-HUMAN-owner.json", json_bytes)
            write_private(dest, "PRIVATE-HUMAN-owner.csv", csv_text)
    except BaseException:
        shutil.rmtree(folder)
        raise
    print("PRIVATE HOLD: created separately scoped local HUMAN workrooms; NOTHING sent")
    print(str(Path(folder) / "OPEN-PRIVATE.html"))
    return 3


def main():
    parser = argparse.ArgumentParser(
        description="PRIVATE local per-HUMAN owner handoff from original cross-case portfolio"
    )
    parser.add_argument("--portfolio", required=True,
                        help="Original 0600 PRIVATE-HUMAN-portfolio.json")
    parser.add_argument("--owner", required=True, action="append",
                        help="One exact locally proposed HUMAN owner label; repeat 1–8")
    parser.add_argument("--private-parent", required=True,
                        help="Existing 0700 PRIVATE destination outside checkout")
    args = parser.parse_args()
    try:
        return run(args)
    except (Hold, OSError, ValueError, TypeError, UnicodeError, csv.Error):
        print("PRIVATE HOLD: explicit ORIGINAL HUMAN owner workroom refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
