#!/usr/bin/env python3
"""Minimal recipient-team PRIVATE HUMAN task deck; no unselected team data."""
from __future__ import annotations

import csv
import html
import io
import json
import os
from pathlib import Path
import shutil

import private_session as custody
import route_queue

SCHEMA = "lightup.private.assessment-human-team-deck.v1"


def render(rows: list[dict], team: str) -> bytes:
    cards = []
    for item in rows:
        cards.append(
            "<li><h3>" + html.escape(item["title"]) + "</h3>" +
            "<p>HUMAN proposed stage: <b>" + html.escape(item["human_stage"]) +
            "</b> · follow-up: " + html.escape(item["followup_date"] or "Not declared") +
            "</p><p>Original local output availability (not review readiness): " +
            html.escape(item["local_state"]) + "</p><p>HUMAN question: " +
            html.escape(item["human_question"] or "No question entered") +
            "</p><p>Suggested manual next step: " + html.escape(item["human_next"]) +
            "</p></li>"
        )
    listed = "".join(cards) if cards else (
        "<li>No exact-session HUMAN tasks assigned to this team. "
        "This does not imply the team has reviewed, cleared or approved anything.</li>"
    )
    document = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>LightUp PRIVATE HUMAN Team Task Deck</title>
<style>:root{color-scheme:dark;font:16px/1.6 system-ui,sans-serif;background:#112137;color:#eef6fc}
body{max-width:900px;margin:2rem auto;padding:1rem}
header,main,footer{padding:22px;background:#203951;border:1px solid #466782;border-radius:16px;margin:15px 0}
h1{font-size:2rem;line-height:1.15}.warn{color:#ffdeab;font-weight:bold}li{padding:13px 0;border-top:1px solid #4b708d}
h3{margin:0}p{margin:.4rem 0}footer{border-left:5px solid #ffdeab}</style>
<header><p class="warn">LIGHTUP · PRIVATE HUMAN ONLY · NO AUTHORITY</p>
<h1>Team Task Deck: """ + html.escape(team) + """</h1>
<p>Exactly """ + str(len(rows)) + """ locally assigned HUMAN task(s). Assignment
is based only on manually edited CSV, not authenticated identity, consent
or approved release. Other teams and private original file locations are
intentionally excluded from this minimum-necessary deck.</p></header>
<main><ol>""" + listed + """</ol></main>
<footer class="warn">Never share without independently verifying the actual
recipient and channel. Contains confidential HUMAN questions. Not a validated
finding, privacy clearance, approved scope, release decision or task dispatch.
No files were sent, no original source opened, no scan, retest, grant, model,
deletion or calendar event scheduled. INCUBATE M3/M7 · DRAFT/HOLD.</footer></html>"""
    return document.encode("utf-8")


def build(session, original_csv: str, team: str,
          parent_name: str, name: str) -> Path:
    if team not in route_queue.TEAMS[1:]:
        raise custody.Hold("only exact, known HUMAN teams can receive a deck")
    if not custody.NAME.fullmatch(name):
        raise custody.Hold("invalid unused private HUMAN team folder")
    parent = Path(parent_name).resolve(strict=True)
    if (parent == custody.ROOT or custody.ROOT in parent.parents
            or not custody.private(parent, True)):
        raise custody.Hold("owner-only 0700 parent outside checkout required")
    room = parent / name
    if os.path.lexists(room):
        raise custody.Hold("existing PRIVATE HUMAN deck cannot be overwritten")
    rows, _ = route_queue.rows_for(session)
    admitted = route_queue.admit_human_edits(rows, original_csv)
    filtered = [item for item in admitted if item["review_team"] == team]
    # Important: no local_href, PATH digest, other team's question, client
    # evidence, full assessment corpus or arbitrary original source content.
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(("workflow_key", "human_stage", "review_team",
                     "followup_date", "human_question"))
    for item in filtered:
        writer.writerow([item[field] for field in
                         ("workflow_key", "human_stage", "review_team",
                          "followup_date", "human_question")])
    csv_document = stream.getvalue().encode("utf-8")
    manifest = {
        "schema": SCHEMA, "status": "REVIEW_ONLY", "authority": custody.AUTHORITY,
        "declared_team": team, "selected_count": len(filtered),
        "owner_path_references_included": False, "other_team_items_included": False,
        "client_evidence_included": False, "recipient_authenticated": False,
        "human_team_proposals": [
            {"workflow_key": row["workflow_key"], "human_stage": row["human_stage"],
             "followup_date": row["followup_date"]}
            for row in filtered
        ]
    }
    json_document = (json.dumps(manifest, ensure_ascii=True, sort_keys=True,
                                 separators=(",", ":")) + "\n").encode("ascii")
    page = render(filtered, team)
    room.mkdir(mode=0o700)
    try:
        if not custody.private(room, True):
            raise custody.Hold("new HUMAN team deck not private")
        custody.private_write(room, "OPEN-PRIVATE.html", page)
        custody.private_write(room, "PRIVATE-TEAM-TASKS.csv", csv_document)
        custody.private_write(room, "PRIVATE-TEAM-RECEIPT.json", json_document)
        fd = os.open(room, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except (OSError, ValueError):
        shutil.rmtree(room)
        raise custody.Hold("could not publish PRIVATE HUMAN team deck") from None
    return room / "OPEN-PRIVATE.html"
