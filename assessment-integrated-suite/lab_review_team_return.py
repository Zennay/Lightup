#!/usr/bin/env python3
"""Admit PRIVATE HUMAN Lab team feedback without granting or auto-finalizing.

Each exact original original-owner Lab Launchpad packet and published HUMAN
final row set is re-admitted, then only one declared team's selected packet
rows may be changed. An operator must STILL reopen the full candidate in
the original HUMAN Studio and manually finalize separately.
"""
from __future__ import annotations

import argparse
import csv
from hashlib import sha256
import html
import io
import json
import os
from pathlib import Path
import shutil
import sys

import lab_plans
import lab_plan_review
import lab_review_history
import lab_review_team_handoff as handoff
import private_session as privacy
import route_queue
import workpack_progress

SCHEMA = "lightup.private.original-lab-human-team-return.v1"


def _read_team(name: str, originals: list[dict], team: str) -> list[dict]:
    raw = route_queue.read_owner_csv(name)
    try:
        rows = list(csv.reader(io.StringIO(raw.decode("utf-8", "strict"), newline=""),
                               strict=True))
    except (UnicodeError, csv.Error):
        raise privacy.Hold("HOLD: completed private HUMAN team CSV malformed") from None
    if not rows or tuple(rows[0]) != lab_plan_review.COLUMNS:
        raise privacy.Hold("HOLD: original HUMAN team CSV header differs")
    if len(rows)-1 != len(originals):
        raise privacy.Hold("HOLD: original HUMAN team CSV row count changed")
    result = []
    for before, fields in zip(originals, rows[1:]):
        if len(fields) != len(lab_plan_review.COLUMNS):
            raise privacy.Hold("HOLD: complete original HUMAN team row required")
        new = dict(zip(lab_plan_review.COLUMNS, fields))
        if (new["source_snapshot_sha256"] != before["source_snapshot_sha256"]
                or new["proposal_slot"] != before["proposal_slot"]
                or new["human_team"] != team):
            raise privacy.Hold("HOLD: HUMAN return escaped assigned team or original scope")
        stage, question = new["human_stage"], new["human_question"]
        if stage not in route_queue.STAGES or stage == "UNASSESSED":
            raise privacy.Hold("HOLD: unsupported HUMAN team stage")
        if (len(question) > lab_plan_review.NOTE_MAX
                or any(ord(ch) < 32 or ord(ch) == 127 for ch in question)
                or question.lstrip().startswith(("=", "+", "-", "@"))):
            raise privacy.Hold("HOLD: unsafe PRIVATE HUMAN team question")
        result.append(new)
    return result


def _receipt(handoff_room: Path, original_rows: list[dict],
             fingerprint: str) -> dict:
    receipt = workpack_progress._private_receipt(
        handoff_room / "PRIVATE-HUMAN-TEAM-MANIFEST.json")
    expected = {
        "schema", "status", "authority", "verified_source", "verified_consent",
        "recipients_authenticated", "automated_dispatch",
        "assessment_authorized", "original_lab_urls_included",
        "private_question_text_included", "team_workrooms", "unassessed",
        "unassigned_human", "original_source_fingerprint_sha256_unsigned",
        "original_final_human_csv_sha256_unsigned",
    }
    if (set(receipt) != expected
            or receipt.get("schema") != handoff.SCHEMA
            or receipt.get("status") != "REVIEW_ONLY"
            or any(receipt[k] is not False for k in (
                "verified_source", "verified_consent", "recipients_authenticated",
                "automated_dispatch", "assessment_authorized",
                "original_lab_urls_included", "private_question_text_included"))
            or type(receipt["authority"]) is not dict
            or set(receipt["authority"]) != set(privacy.AUTHORITY)
            or any(type(receipt["authority"][k]) is not bool or
                   receipt["authority"][k] is not False for k in privacy.AUTHORITY)
            or receipt["original_source_fingerprint_sha256_unsigned"] != fingerprint
            or receipt["original_final_human_csv_sha256_unsigned"] != sha256(
                lab_plan_review._csv(original_rows)).hexdigest()):
        raise privacy.Hold("HOLD: original HUMAN team handoff source changed")
    return receipt


def build(packets: list[str], final_room: str, handoff_room: str,
          team: str, response_csv: str, parent: str, folder: str) -> Path:
    if team not in handoff.SLUGS:
        raise privacy.Hold("HOLD: select one original HUMAN assigned team")
    output = lab_plans._new_path(parent, folder)
    original, fingerprint = lab_plan_review._source_rows(packets)
    source = lab_plans._packet(final_room)
    handoff_source = lab_plans._packet(handoff_room)
    if (source == output or source in output.parents
            or handoff_source == output or handoff_source in output.parents):
        raise privacy.Hold("HOLD: cannot overwrite original HUMAN source")
    base = lab_review_history._admit_final(str(source), original, fingerprint)
    manifest = _receipt(handoff_source, base, fingerprint)
    selected = [row for row in base if row["human_team"] == team]
    if not selected:
        raise privacy.Hold("HOLD: original final HUMAN review has no assigned team tasks")
    team_filename = "TEAM-" + handoff.SLUGS[team] + "-DRAFT.csv"
    pinned = route_queue.read_owner_csv(str(handoff_source / team_filename))
    if pinned != handoff._team_csv(selected):
        raise privacy.Hold("HOLD: original assigned team subset modified after creation")
    candidates = {
        item["label"]: item for item in manifest["team_workrooms"]
        if type(item) is dict and set(item) == {"label", "filename", "human_tasks"}
    } if type(manifest["team_workrooms"]) is list else {}
    if (team not in candidates or
            candidates[team]["filename"] != "TEAM-" + handoff.SLUGS[team] + ".html"
            or type(candidates[team]["human_tasks"]) is not int
            or candidates[team]["human_tasks"] != len(selected)):
        raise privacy.Hold("HOLD: selected original HUMAN team manifest changed")
    returned = _read_team(response_csv, selected, team)
    replacements = {row["proposal_slot"]: row for row in returned}
    all_rows = [replacements.get(row["proposal_slot"], row) for row in base]
    changes = [{
        "proposal_slot": int(old["proposal_slot"]),
        "previous_stage": old["human_stage"],
        "new_human_stage": new["human_stage"],
        "private_question_changed": old["human_question"] != new["human_question"],
    } for old,new in zip(selected, returned)
        if old["human_stage"] != new["human_stage"]
        or old["human_question"] != new["human_question"]]
    receipt = {
        "schema":SCHEMA,"status":"REVIEW_ONLY",
        "authority":privacy.AUTHORITY,
        "source_authenticity_verified":False,"consent_verified":False,
        "reviewer_authenticated":False,"external_delivery":False,
        "approval_or_scan_allowed":False,"automated_actions":False,
        "original_lab_urls_included":False,"private_question_text_included":False,
        "declared_team":team,"assigned_original_tasks":len(selected),
        "human_changed_tasks":len(changes),"declared_changes":changes,
        "original_source_snapshot_sha256_unsigned":fingerprint,
    }
    entries = "".join(
        "<li>Original packet #" + str(c["proposal_slot"]) +
        " · HUMAN stage: " + html.escape(c["previous_stage"]) +
        " → " + html.escape(c["new_human_stage"]) +
        " · private question edited: " +
        ("YES" if c["private_question_changed"] else "NO")+"</li>"
        for c in changes
    )
    page = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>LightUp PRIVATE HUMAN Lab team return</title>
<style>:root{color-scheme:dark;background:#0f1e30;color:#ecf7ff;font:16px/1.6 system-ui}
body{max-width:920px;margin:3rem auto;padding:0 1rem}
header,main,footer{background:#1c364d;border:1px solid #59768c;border-radius:17px;padding:25px;margin:16px 0}
li{padding:12px 0;border-bottom:1px solid #4d6579}b{color:#b8e9d4}
.warn{font-weight:750;color:#ffdfa5}</style>
<header><p class="warn">ORIGINAL LAB SOURCE · PRIVATE HUMAN / REVIEW_ONLY</p>
<h1>HUMAN team return · """ + html.escape(team) + """</h1>
<p>Original assigned HUMAN tasks: """ + str(len(selected)) +
        """. Proposed HUMAN edits: """ + str(len(changes)) +
        """. This is NOT reviewer identity verification or authorization.</p></header>
<main><h2>Manually proposed edits, not applied to original</h2><ol>""" +
        (entries or "<li>No HUMAN edits declared.</li>") + """</ol>
<p>To manually review this candidate, use original console option 58 with
the original PRIVATE HUMAN Studio receipt and newly generated owner-only
PRIVATE-HUMAN-CANDIDATE.csv. A later original FINALIZE is a separate
explicit HUMAN action; this return NEVER auto-finalizes anything.</p></main>
<footer><p class="warn">DRAFT/HOLD · NO SCAN, GRANT, CONTACT OR RELEASE</p>
<p>All original source-owning Lab Launchpad packets and FINAL HUMAN rows
were re-admitted. No addresses, paths, customer identities or private
questions are on this HTML page. Unsigned source SHA cannot authenticate
a reviewer. Original CI, independent security/privacy/browser reviews,
verified separate client+operator consent and revocation-at-use, HUMAN GO
remain mandatory.</p></footer></html>""").encode("utf-8")
    docs = (
        ("OPEN-PRIVATE.html", page),
        ("PRIVATE-HUMAN-CANDIDATE.csv", lab_plan_review._csv(all_rows)),
        ("PRIVATE-TEAM-RETURN-RECEIPT.json",
            (json.dumps(receipt,sort_keys=True,separators=(",",":"))+"\n").encode("ascii")),
    )
    output.mkdir(mode=0o700)
    try:
        if not privacy.private(output,True):
            raise privacy.Hold("HOLD: new PRIVATE HUMAN team return room invalid")
        for filename,content in docs:
            privacy.private_write(output,filename,content)
        fd=os.open(output,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
    except (OSError,ValueError):
        shutil.rmtree(output)
        raise privacy.Hold("HOLD: original HUMAN Lab team return not published") from None
    return output/"OPEN-PRIVATE.html"


def main(argv: list[str]|None=None) -> int:
    cli=argparse.ArgumentParser(description="PRIVATE original HUMAN lab team return to FULL draft CSV")
    cli.add_argument("--packet",action="append",required=True)
    cli.add_argument("--final-room",required=True)
    cli.add_argument("--handoff-room",required=True)
    cli.add_argument("--team",required=True,choices=tuple(handoff.SLUGS))
    cli.add_argument("--response-csv",required=True)
    cli.add_argument("--private-parent",required=True)
    cli.add_argument("--folder",required=True)
    cli.add_argument("--human-confirm",required=True)
    opts=cli.parse_args(argv)
    try:
        if opts.human_confirm!="ADMIT PRIVATE LAB TEAM RETURN":
            raise privacy.Hold("HOLD: manual source-bound team return confirmation required")
        page=build(opts.packet,opts.final_room,opts.handoff_room,
                   opts.team,opts.response_csv,opts.private_parent,opts.folder)
        print("PRIVATE REVIEW_ONLY: HUMAN team candidate created; original unchanged")
        print("OPEN LOCALLY: "+str(page))
        return 2
    except Exception as exc:
        print(str(exc) if isinstance(exc,privacy.Hold) else
              "HOLD: original HUMAN Lab team return refused",file=sys.stderr)
        return 3

if __name__=="__main__":
    raise SystemExit(main())
