#!/usr/bin/env python3
"""PRIVATE HUMAN work-queue revision history, no source/notes/paths in result."""
from __future__ import annotations
import csv
import html
import io
import json
import os
from pathlib import Path
import shutil

import private_session as privacy
import route_queue

SCHEMA = "lightup.private.assessment-human-queue-history.v1"


def build(session, inputs: list[str], parent_name: str, name: str) -> Path:
    if (not 2 <= len(inputs) <= 8 or len(set(inputs)) != len(inputs)):
        raise privacy.Hold("two to eight distinct owner-private HUMAN CSV revisions required")
    if not privacy.NAME.fullmatch(name):
        raise privacy.Hold("invalid UNIQUE HUMAN queue history name")
    parent = Path(parent_name).resolve(strict=True)
    if (parent == privacy.ROOT or privacy.ROOT in parent.parents or
            not privacy.private(parent, True)):
        raise privacy.Hold("owner-only 0700 history parent outside checkout required")
    room = parent / name
    if os.path.lexists(room):
        raise privacy.Hold("PRIVATE queue history already exists; no overwrite")
    base, _ = route_queue.rows_for(session)
    versions = [route_queue.admit_human_edits(base, source) for source in inputs]
    changes = []
    for idx in range(1, len(versions)):
        previous, current = versions[idx - 1], versions[idx]
        for old, new in zip(previous, current):
            fields = []
            if old["human_stage"] != new["human_stage"]:
                fields.append("stage")
            if old["review_team"] != new["review_team"]:
                fields.append("team")
            if old["followup_date"] != new["followup_date"]:
                fields.append("followup_date")
            if old["human_question"] != new["human_question"]:
                fields.append("question_presence_or_text")
            if fields:
                changes.append({
                    "declared_from": idx, "declared_to": idx + 1,
                    "workflow_key": old["workflow_key"], "workflow_title": old["title"],
                    "changed_fields": fields,
                    "previous_stage": old["human_stage"], "current_stage": new["human_stage"],
                    "previous_team": old["review_team"], "current_team": new["review_team"],
                    "previous_due": old["followup_date"],
                    "current_due": new["followup_date"],
                    # Only whether confidential HUMAN question content exists.
                    "previous_question_present": bool(old["human_question"]),
                    "current_question_present": bool(new["human_question"]),
                })
    entries = []
    for item in changes:
        entry = ("<li><b>" + html.escape(item["workflow_title"]) + "</b> · declared " +
                 str(item["declared_from"]) + " → " + str(item["declared_to"]) +
                 "<br>Fields: " + html.escape(", ".join(item["changed_fields"])) +
                 "<br>HUMAN stage " + html.escape(item["previous_stage"]) + " → " +
                 html.escape(item["current_stage"]) +
                 "<br>Team " + html.escape(item["previous_team"] or "unassigned") +
                 " → " + html.escape(item["current_team"] or "unassigned") +
                 "<br>Due " + html.escape(item["previous_due"] or "unspecified") + " → " +
                 html.escape(item["current_due"] or "unspecified") +
                 "<br>Question text deliberately excluded</li>")
        entries.append(entry)
    page = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp PRIVATE HUMAN Assessment Queue History</title>
<style>:root{color-scheme:dark;font:16px/1.6 system-ui;background:#132438;color:#eaf4fa}
body{max-width:950px;padding:20px;margin:25px auto}header,main,footer{background:#1c344b;border:1px solid #4c6e89;border-radius:16px;padding:24px;margin:12px 0}
h1{font-size:clamp(1.7rem,4vw,2.5rem)}.warn{color:#ffdfa9;font-weight:700}
li{border-top:1px solid #46667f;padding:14px 0}</style>
<header><p class="warn">PRIVATE HUMAN / HISTORICAL / NON-AUTHORIZING</p>
<h1>Assessment HUMAN queue changes</h1><p>""" + str(len(inputs)) + """ operator-ordered original CSV revisions · """ + str(len(changes)) + """ workflow transitions. These are compared HUMAN metadata only, NOT source evidence or chronology proof.</p></header>
<main><ol>""" + ("".join(entries) or "<li>No changes in manually declared HUMAN task fields.</li>") + """</ol></main>
<footer>No original file locations, client source, private question text,
session paths, model outputs or credentials were placed in this history.
Identical paths do not prove identical source bytes. HUMAN stages are
unverified declarations, not approval. No scans, network, grant, re-test,
contact, calendar event, file deletion, deployment or automatic acceptance.
Original authenticated client/operator consent, revocation-at-use,
independent review and HUMAN GO remain required. INCUBATE M3/M7 · DRAFT/HOLD.</footer></html>""".encode("utf-8")
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(("declared_from", "declared_to", "workflow_key", "changed_fields",
                     "previous_stage", "current_stage", "previous_team",
                     "current_team", "previous_due", "current_due",
                     "previous_question_present", "current_question_present"))
    for row in changes:
        writer.writerow((row["declared_from"], row["declared_to"],
                         row["workflow_key"], "+".join(row["changed_fields"]),
                         row["previous_stage"], row["current_stage"],
                         row["previous_team"], row["current_team"],
                         row["previous_due"], row["current_due"],
                         str(row["previous_question_present"]).lower(),
                         str(row["current_question_present"]).lower()))
    doc = {
        "schema": SCHEMA, "status": "REVIEW_ONLY", "authority": privacy.AUTHORITY,
        "operator_declared_order": True, "source_authenticated": False,
        "original_paths_included": False, "human_question_text_included": False,
        "versions": len(inputs), "changed_workflow_transitions": len(changes),
        "changes": [{k: v for k, v in row.items() if k != "workflow_title"}
                    for row in changes],
    }
    data = (json.dumps(doc, ensure_ascii=True, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("ascii")
    room.mkdir(mode=0o700)
    try:
        if not privacy.private(room, True):
            raise privacy.Hold("new PRIVATE human-history room mode refused")
        privacy.private_write(room, "OPEN-PRIVATE.html", page)
        privacy.private_write(room, "PRIVATE-HUMAN-CHANGES.csv", stream.getvalue().encode("utf-8"))
        privacy.private_write(room, "PRIVATE-HUMAN-CHANGES.json", data)
        fd = os.open(room, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except (OSError, ValueError):
        shutil.rmtree(room)
        raise privacy.Hold("could not prepare original PRIVATE HUMAN queue history") from None
    return room / "OPEN-PRIVATE.html"
