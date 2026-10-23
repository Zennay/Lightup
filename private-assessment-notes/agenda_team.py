#!/usr/bin/env python3
"""Minimal original-bound PRIVATE HUMAN team conversation extract, offline only."""
from __future__ import annotations

import argparse
import csv
from hashlib import sha256
import html
import io
import os
from pathlib import Path
import shutil
import sys
import tempfile

from notes import FALSE_FLAGS, Hold, file_new, private_directory, private_input, save_json
from history_agenda import (HOLD_FLAGS, SCHEMA as AGENDA_SCHEMA, TEAMS,
                            canonical_history, admit_completed_csv,
                            read_original_json, STYLE)

SCHEMA = "lightup.private_assessment_human_team_discussion.v1"
FIELDS = ("original_source_ordinal", "original_human_stage", "human_proposal",
          "proposed_team", "proposed_day", "private_human_question")


def team_packet(review_kit: str, history_kit: str, latest_packet: str,
                team: str, parent_string: str) -> int:
    if team not in TEAMS or team == "UNASSIGNED":
        raise Hold("HOLD: select exactly one explicit original HUMAN discussion team")
    parent = private_directory(parent_string)
    review = private_directory(review_kit)
    _, history_sha, positions, manifest_sha, decision_sha = canonical_history(
        history_kit, latest_packet)
    raw_manifest, doc = read_original_json(
        review / "PRIVATE-HUMAN-agenda-review.json", 64 * 1024)
    if (set(doc) != {
            "schema", "claimed_status", "history_sha256_unsigned",
            "latest_original_manifest_sha256_unsigned",
            "latest_original_decisions_sha256_unsigned",
            "completed_human_csv_sha256_unsigned", "original_source_count",
            "proposed_discussion_count", "not_an_actual_assignment",
            "private_human_proposals", *HOLD_FLAGS}
            or doc["schema"] != "lightup.private_assessment_human_agenda_review.v1"
            or doc["claimed_status"] != "HOLD"
            or doc["history_sha256_unsigned"] != history_sha
            or doc["latest_original_manifest_sha256_unsigned"] != manifest_sha
            or doc["latest_original_decisions_sha256_unsigned"] != decision_sha
            or type(doc["original_source_count"]) is not int
            or doc["original_source_count"] != len(positions)
            or doc["not_an_actual_assignment"] is not True
            or any(doc[flag] is not False for flag in HOLD_FLAGS)):
        raise Hold("HOLD: PRIVATE HUMAN review and actual original source differ")
    native_csv = private_input(str(review / "PRIVATE-HUMAN-agenda-reviewed.csv"), 64 * 1024)
    # The native retained reviewed CSV is the full ordered source roster, not
    # a selected-only export; independent original identity admission follows.
    original_rows = admit_completed_csv(native_csv, positions, history_sha)
    proposed = [row for row in original_rows if row["human_proposal"] != "NO_PROPOSAL"]
    if (type(doc["proposed_discussion_count"]) is not int
            or doc["proposed_discussion_count"] != len(proposed)
            or doc["private_human_proposals"] != proposed
            or type(doc["completed_human_csv_sha256_unsigned"]) is not str
            or len(doc["completed_human_csv_sha256_unsigned"]) != 64
            or any(ch not in "0123456789abcdef"
                   for ch in doc["completed_human_csv_sha256_unsigned"])):
        raise Hold("HOLD: original completed HUMAN discussion packet is inconsistent")
    selected = [row for row in proposed if row["proposed_team"] == team]
    if not selected:
        raise Hold("HOLD: no original explicitly proposed HUMAN topic for this team")

    # A team label isn't an authenticated member or a verified recipient.
    # The source-minimal output includes ONLY explicitly tagged team entries.
    output = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-human-team-", dir=parent))
    os.chmod(output, 0o700)
    finished = False
    try:
        source_receipt = {
            "schema": SCHEMA,
            "claimed_status": "HOLD",
            "intended_human_team_label": team,
            "team_discussion_count": len(selected),
            "recipient_authenticated": False,
            "team_membership_verified": False,
            "human_schedule_created": False,
            "dispatch_allowed": False,
            "release_allowed": False,
            "review_receipt_sha256_unsigned": sha256(raw_manifest).hexdigest(),
            "source_history_sha256_unsigned": history_sha,
            "private_human_team_proposals": selected,
        }
        save_json(output / "PRIVATE-HUMAN-team-brief.json", source_receipt)
        buf = io.StringIO(newline="")
        writer = csv.DictWriter(buf, fieldnames=FIELDS, lineterminator="\r\n")
        writer.writeheader()
        for row in selected:
            writer.writerow({key: row[key] for key in FIELDS})
        file_new(output / "PRIVATE-HUMAN-team-brief.csv",
                 buf.getvalue().encode("utf-8"))
        table = "".join(
            "<tr><td>#" + str(row["original_source_ordinal"]) + "</td><td>" +
            html.escape(row["original_human_stage"]) + "</td><td>" +
            html.escape(row["human_proposal"]) + "</td><td>" +
            html.escape(row["proposed_day"] or "Not proposed") + "</td><td>" +
            html.escape(row["private_human_question"]) + "</td></tr>" for row in selected
        )
        index = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp PRIVATE HUMAN team-only discussion</title><style>""" +
                 STYLE + """</style><header><aside><b>HOLD · PRIVATE HUMAN ONLY</b>
<p>This is a *proposed* discussion category, not a verified recipient
identity, team membership, actual assignment, customer action,
appointment, scan or permission to share.</p></aside>
<h1>PRIVATE HUMAN team discussion: """ + html.escape(team) + """</h1>
<p>Only explicitly selected original cases for this HUMAN team are
included. No other team's original HUMAN questions are present.</p>
</header><article><table><thead><tr><th>Original source</th>
<th>Latest HUMAN stage</th><th>HUMAN proposal</th>
<th>Manually proposed day</th><th>PRIVATE question</th></tr></thead><tbody>""" +
                 table + """</tbody></table></article>
<article><a href="PRIVATE-HUMAN-team-brief.json">PRIVATE source-bound team JSON</a>
 · <a href="PRIVATE-HUMAN-team-brief.csv">PRIVATE team-only CSV</a>
<p>Never transfer this file without separate actual recipient verification,
privacy authorization and current real consent. No communication occurred.</p>
</article></html>""")
        file_new(output / "OPEN-PRIVATE.html", index.encode("utf-8"))
        finished = True
        print("HOLD: PRIVATE local HUMAN team discussion excerpt prepared, not delivered.")
        print("OPEN LOCALLY: " + str(output / "OPEN-PRIVATE.html"))
        return 3
    finally:
        if not finished:
            shutil.rmtree(output)


def main() -> int:
    cli = argparse.ArgumentParser(
        description="PRIVATE source-bound HUMAN team subset; no verified recipient or distribution")
    cli.add_argument("--review-kit", required=True)
    cli.add_argument("--history-kit", required=True)
    cli.add_argument("--latest-packet", required=True)
    cli.add_argument("--team", required=True,
                     choices=[name for name in TEAMS if name != "UNASSIGNED"])
    cli.add_argument("--private-parent", required=True)
    args = cli.parse_args()
    try:
        return team_packet(args.review_kit, args.history_kit, args.latest_packet,
                           args.team, args.private_parent)
    except (Hold, OSError, TypeError, ValueError, KeyError) as exc:
        print(str(exc) if isinstance(exc, Hold) else
              "HOLD: original PRIVATE HUMAN team extract refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.modules.setdefault("notes", __import__("notes"))
    raise SystemExit(main())
