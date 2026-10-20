#!/usr/bin/env python3
"""Offline PRIVATE HUMAN workload priority board from original queue CSV.

Strict, source-PATH-bound local admission only. All priority interpretations
are HUMAN-declared suggestions, never security authority or actual schedules.
"""
from __future__ import annotations
import csv
from datetime import date, timedelta
import html
import io
import json
import os
from pathlib import Path
import shutil

import private_session as privacy
import route_queue

SCHEMA = "lightup.private.assessment-human-priorities.v1"
BUCKETS = (
    ("HOLD", "HUMAN-declared HOLD / needs independent investigation"),
    ("MISSING_ORIGINAL", "Referenced original local workroom unavailable"),
    ("PAST_DECLARED_DATE", "HUMAN-declared follow-up date is before review date"),
    ("DUE_DECLARED_TODAY", "HUMAN-declared follow-up equals review date"),
    ("NEXT_DECLARED_WEEK", "HUMAN-declared follow-up in next 7 days"),
    ("UNASSIGNED", "HUMAN item lacks a team assignment"),
    ("OTHER", "Later, undefined or unassessed HUMAN proposals"),
)


def as_of(value: str) -> date:
    if len(value) != 10 or value[4] != "-" or value[7] != "-":
        raise privacy.Hold("human review date must be YYYY-MM-DD")
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        raise privacy.Hold("invalid HUMAN reference date") from None
    if parsed.isoformat() != value:
        raise privacy.Hold("non-canonical HUMAN reference date")
    return parsed


def categorize(item: dict, today: date) -> str:
    stage = item["human_stage"]
    if stage in ("HOLD", "NEEDS_INPUT"):
        return "HOLD"
    if (item["local_state"] == "HOLD_PAGE_UNAVAILABLE"
            or (stage != "UNASSESSED" and
                item["local_state"] != "LOCAL_PAGE_PRESENT_REVIEW_ONLY")):
        # A previously referenced but now unavailable original workroom
        # deserves attention EVEN when no HUMAN status was assigned yet.
        return "MISSING_ORIGINAL"
    due = date.fromisoformat(item["followup_date"]) if item["followup_date"] else None
    if due is not None and due < today:
        return "PAST_DECLARED_DATE"
    if due is not None and due == today:
        return "DUE_DECLARED_TODAY"
    if due is not None and due <= today + timedelta(days=7):
        return "NEXT_DECLARED_WEEK"
    if stage != "UNASSESSED" and not item["review_team"]:
        return "UNASSIGNED"
    return "OTHER"


def build(session, source_csv: str, parent_name: str, name: str,
          today_str: str) -> Path:
    today = as_of(today_str)
    if not privacy.NAME.fullmatch(name):
        raise privacy.Hold("invalid original HUMAN priority folder name")
    parent = Path(parent_name).resolve(strict=True)
    if (parent == privacy.ROOT or privacy.ROOT in parent.parents
            or not privacy.private(parent, True)):
        raise privacy.Hold("existing owner-only 0700 parent outside source checkout required")
    room = parent / name
    if os.path.lexists(room):
        raise privacy.Hold("existing PRIVATE priority folder cannot be overwritten")
    # Call the original strict source-PATH/session + HUMAN CSV admission first.
    baseline, _ = route_queue.rows_for(session)
    rows = route_queue.admit_human_edits(baseline, source_csv)
    categorized = [{**row, "priority_bucket": categorize(row, today)} for row in rows]
    team_names = ("Unassigned", "Security", "Privacy", "Client operations", "Platform")
    team_load = {
        team: sum((row["review_team"] or "Unassigned") == team and
                  row["human_stage"] != "UNASSESSED" for row in rows)
        for team in team_names
    }
    sections = []
    for code, label in BUCKETS:
        members = [row for row in categorized if row["priority_bucket"] == code]
        cards = []
        for row in members:
            cells = [
                html.escape(row["title"]),
                html.escape(row["human_stage"]),
                html.escape(row["review_team"] or "Unassigned"),
                html.escape(row["followup_date"] or "No HUMAN date"),
                html.escape(row["local_state"]),
                html.escape(row["human_next"]),
            ]
            cards.append(
                "<li><strong>" + cells[0] + "</strong><p>HUMAN: " + cells[1] +
                " · Team: " + cells[2] + " · Declared follow-up: " + cells[3] +
                "</p><p>Original local availability: " + cells[4] +
                "</p><p>Suggested HUMAN next step: " + cells[5] +
                "</p><p>PRIVATE HUMAN question deliberately excluded.</p></li>"
            )
        sections.append("<section><h2>" + html.escape(label) + " · " +
                        str(len(members)) + "</h2><ul>" +
                        ("".join(cards) if cards else
                         "<li>No items in this HUMAN priority group.</li>") +
                        "</ul></section>")
    workload = "".join("<li>" + html.escape(team) + ": " + str(count) +
                       " HUMAN assigned tasks</li>" for team, count in team_load.items())
    page = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp PRIVATE HUMAN Assessment Priorities</title>
<style>:root{color-scheme:dark;font:16px/1.55 system-ui;background:#0d1728;color:#ecf6ff}
*{box-sizing:border-box}body{max-width:1260px;margin:auto;padding:24px}
header,footer{background:#1d344a;border:1px solid #496b84;border-radius:15px;padding:25px}
h1{font-size:clamp(1.8rem,4vw,3rem)}p{color:#d3e4ef}
main{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,510px),1fr));gap:16px;margin:18px 0}
section{background:#1b2e44;border:1px solid #466683;border-radius:15px;padding:20px}
h2{font-size:1.12rem;color:#b7ead7}ul{padding-left:25px}li{margin:13px 0}
strong,.warn{color:#ffe0ab}footer{border-left:5px solid #ffe0ab}</style>
<header><p class="warn">LIGHTUP / OWNER-PRIVATE / HUMAN-ONLY / PLAN-LAB</p>
<h1>Local HUMAN priority and capacity desk</h1>
<p>The review date is <strong>""" + html.escape(today_str) + """</strong>, supplied
by the operator. Priority is a convenience sorting of unverified HUMAN
declarations and current local page availability. It is NOT real
scheduled work, due-date enforcement, vulnerability severity, client
identity, source authentication, permission, or evidence of a fix.</p>
<h2>Declared local HUMAN team workload</h2><ul>""" + workload + """</ul></header>
<main>""" + "".join(sections) + """</main>
<footer>Every original is separate and remains PRIVATE. Source-path digest,
actual original file paths, HUMAN question text, client artifacts, passwords
and reviewer identities are absent from this report. The operator-chosen
review date and stored follow-up dates are not verified chronology. There
is no network, scan, model, grant, client/operator consent, calendar action,
retest, recipient contact, or data deletion. Exact original source ownership,
independent reviews, current authenticated separate client/operator
consent and action-time revocation, and explicit HUMAN GO are required
for any authorized external action. REVIEW_ONLY / DRAFT-HOLD.</footer></html>""".encode("utf-8")
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(("workflow_key", "priority_bucket", "human_stage",
                     "review_team", "followup_date", "local_availability"))
    for code, _ in BUCKETS:
        for row in categorized:
            if row["priority_bucket"] == code:
                writer.writerow((row["workflow_key"], code, row["human_stage"],
                                 row["review_team"], row["followup_date"],
                                 row["local_state"]))
    summary = {
        "schema": SCHEMA, "status": "REVIEW_ONLY", "authority": privacy.AUTHORITY,
        "declared_review_date": today_str, "human_source_verified": False,
        "paths_included": False, "questions_included": False,
        "scheduled_actions": False,
        "buckets": {code: sum(row["priority_bucket"] == code for row in categorized)
                    for code, _ in BUCKETS},
        "team_workload": team_load,
    }
    json_bytes = (json.dumps(summary, ensure_ascii=True, sort_keys=True,
                             separators=(",", ":")) + "\n").encode("ascii")
    room.mkdir(mode=0o700)
    try:
        if not privacy.private(room, True):
            raise privacy.Hold("PRIVATE priority desk owner-only mode refused")
        privacy.private_write(room, "OPEN-PRIVATE.html", page)
        privacy.private_write(room, "PRIVATE-PRIORITIES.csv",
                              stream.getvalue().encode("utf-8"))
        privacy.private_write(room, "PRIVATE-PRIORITIES.json", json_bytes)
        fd = os.open(room, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except (OSError, ValueError):
        shutil.rmtree(room)
        raise privacy.Hold("HOLD: could not publish PRIVATE HUMAN priority desk") from None
    return room / "OPEN-PRIVATE.html"
