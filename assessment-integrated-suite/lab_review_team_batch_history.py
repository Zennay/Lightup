#!/usr/bin/env python3
"""PRIVATE HUMAN Lab multi-team batch history, based on re-admitted original sources.

Compares only already-produced unfinalized HUMAN proposals. It never infers
scans, actual elapsed time, source verification, incident resolution or consent.
"""
from __future__ import annotations

import argparse
import csv
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
import lab_review_team_batch_reopen as reopening
import private_session as privacy
import route_queue
import workpack_progress

SCHEMA = "lightup.private.original-lab-human-multiteam-history.v1"
MAX_ROUNDS = 8


def _stage_view(rooms: list[list[dict]], teams: list[list[dict]]) -> bytes:
    esc = lambda value: html.escape(str(value), quote=True)
    sections = []
    for i, (stage_rows, roster) in enumerate(zip(rooms, teams), 1):
        distribution = [
            f"<li>{esc(stage)}: {sum(x['human_stage'] == stage for x in stage_rows)}</li>"
            for stage in route_queue.STAGES
        ]
        team_entries = [
            f"<li>{esc(item['team'])} · {esc(item['disposition'])} · " +
            f"{item['assigned']} original assigned slots</li>"
            for item in roster
        ]
        sections.append(
            f"<section><h2>Operator supplied position #{i}</h2>"
            "<p>Not a verified date or actual recipient activity.</p>"
            "<h3>Original source-bound HUMAN stages</h3><ul>" +
            "".join(distribution) +
            "</ul><h3>Declared team processing</h3><ul>" +
            ("".join(team_entries) or "<li>No declared team replies.</li>") +
            "</ul></section>"
        )
    return "".join(sections).encode("utf-8")


def _page(rooms: list[list[dict]], teams: list[list[dict]],
          changes: list[dict], team_transitions: list[dict]) -> bytes:
    esc = lambda value: html.escape(str(value), quote=True)
    stage_markup = _stage_view(rooms, teams).decode("utf-8")
    changed = "".join(
        "<li>Original proposal #" + str(x["proposal_slot"]) +
        " · operator positions " + str(x["previous_position"]) + " → " +
        str(x["current_position"]) + " · declared team " + esc(x["team"]) +
        " · HUMAN stage " + esc(x["before_stage"]) + " → " +
        esc(x["after_stage"]) + " · PRIVATE HUMAN question changed: " +
        ("YES" if x["private_question_changed"] else "NO") + "</li>"
        for x in changes
    )
    transitions = "".join(
        "<li>" + esc(x["team"]) + " · operator positions " +
        str(x["previous_position"]) + " → " + str(x["current_position"]) +
        " · " + esc(x["previous_disposition"]) + " → " +
        esc(x["current_disposition"]) + "</li>" for x in team_transitions
    )
    return ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>LightUp PRIVATE HUMAN team batch history</title>
<style>:root{color-scheme:dark;background:#0f1f32;color:#ecf7ff;font:16px/1.6 system-ui}
body{max-width:1000px;margin:2rem auto;padding:0 1.2rem}
header,section,footer{padding:24px;margin:15px 0;border-radius:16px;
background:#20384d;border:1px solid #5b7e95}
h1{font-size:2rem}li{margin:12px 0;border-bottom:1px solid #4b667b}
strong{color:#ffdfa9}</style></head><body>
<header><strong>ORIGINAL LAB · PRIVATE HUMAN · REVIEW_ONLY</strong>
<h1>Multi-team unfinalized Lab review history</h1>
<p>""" + str(len(rooms)) + """ ORIGINAL source-rechecked, operator-ordered
batch proposal positions. These are NOT verified dates, authenticated people,
agreed incidents or any assertion a security issue was resolved.</p></header>""" +
        stage_markup +
        """<section><h2>Changed original HUMAN proposal ordinals</h2><ol>""" +
        (changed or "<li>No changes between these unfinalized proposals.</li>") +
        """</ol></section><section><h2>Manual team inclusion/withholding transitions</h2><ol>""" +
        (transitions or "<li>No changed HUMAN team disposition recorded.</li>") +
        """</ol></section><footer><strong>INCUBATE M3/M7 · DRAFT/HOLD</strong>
<p>Original owner-only packets, final HUMAN Lab source, team handoff and every
saved batch were strictly re-admitted before generating this new PRIVATE room.
No original source URLs, client paths, credentials, private questions, SHA,
automated delivery, timestamps, scan or external contact are included in
this offline overview. No stage or team transition proves consent, closure,
source authenticity or actual elapsed time. Original exact-head named VPS/
hosted CI, source-owner, independent security/privacy/browser review,
separate authenticated current client/operator consent with revocation-at-use
and explicit HUMAN GO remain mandatory. DO NOT DEPLOY OR SEND.</p>
</footer></body></html>""").encode("utf-8")


def build(packets: list[str], final_room: str, handoff_room: str,
          batch_rooms: list[str], parent: str, folder: str) -> Path:
    if (type(batch_rooms) is not list or not 2 <= len(batch_rooms) <= MAX_ROUNDS
            or any(type(name) is not str for name in batch_rooms)):
        raise privacy.Hold("HOLD: provide 2–8 distinct original HUMAN Lab batch rooms")
    target = lab_plans._new_path(parent, folder)
    sources = [lab_plans._packet(room) for room in batch_rooms]
    original = [lab_plans._packet(final_room), lab_plans._packet(handoff_room)]
    if (len(set(sources)) != len(sources) or
            any(path == target or path in target.parents for path in sources + original)):
        raise privacy.Hold("HOLD: repeated or nested original PRIVATE HUMAN batch source")
    originals, fingerprint = lab_plan_review._source_rows(packets)
    final = lab_review_history._admit_final(final_room, originals, fingerprint)
    rooms = []
    teams = []
    for path in sources:
        # Deliberately re-admit original owner/packet, original FINAL + handoff,
        # complete 0600 batch receipts, all byte inventory and full HUMAN CSV.
        reopening.inspect(packets, final_room, handoff_room, str(path))
        saved = lab_plan_review._rows_admit(
            originals, str(path / "PRIVATE-HUMAN-CANDIDATE.csv"))
        receipt = workpack_progress._private_receipt(
            path / "PRIVATE-HUMAN-MULTITEAM-RECEIPT.json")
        if receipt["original_source_snapshot_sha256_unsigned"] != fingerprint:
            raise privacy.Hold("HOLD: original HUMAN Lab batch history source changed")
        # Omitted replies are explicitly visible in EACH saved round;
        # absence must never be misread as agreement or completion.
        roster = list(receipt["teams"]) + [
            {"team": item["team"], "assigned": item["assigned"],
             "disposition": "NOT_RETURNED"}
            for item in receipt["unreturned_original_teams"]
        ]
        for row, old in zip(saved, final):
            if row["human_team"] != old["human_team"]:
                raise privacy.Hold("HOLD: original HUMAN Lab team identity changed")
        rooms.append(saved)
        teams.append(roster)

    movements = []
    transitions = []
    for round_index in range(1, len(rooms)):
        first, second = rooms[round_index - 1], rooms[round_index]
        for a, b in zip(first, second):
            if (a["human_stage"] != b["human_stage"]
                    or a["human_question"] != b["human_question"]):
                movements.append({
                    "previous_position": round_index,
                    "current_position": round_index + 1,
                    "proposal_slot": int(b["proposal_slot"]),
                    "team": b["human_team"] or "Unassigned",
                    "before_stage": a["human_stage"],
                    "after_stage": b["human_stage"],
                    "private_question_changed": a["human_question"] != b["human_question"],
                })
        prior = {item["team"]: item["disposition"] for item in teams[round_index - 1]}
        now = {item["team"]: item["disposition"] for item in teams[round_index]}
        for name in sorted(set(prior) | set(now)):
            before = prior.get(name, "NOT_RETURNED")
            after = now.get(name, "NOT_RETURNED")
            if before != after:
                transitions.append({
                    "previous_position": round_index, "current_position": round_index + 1,
                    "team": name, "previous_disposition": before,
                    "current_disposition": after,
                })

    summary = {
        "schema": SCHEMA, "status": "REVIEW_ONLY", "authority": privacy.AUTHORITY,
        "source_authenticity_verified": False,
        "authenticated_actor_verified": False, "client_consent_verified": False,
        "operator_consent_verified": False, "human_go_recorded": False,
        "scan_or_release_allowed": False, "verified_real_chronology": False,
        "original_urls_or_paths_included": False, "private_question_text_included": False,
        "rounds": len(rooms), "changed_proposal_ordinals": movements,
        "human_team_disposition_transitions": transitions,
        "human_stages_by_position": [
            {"position": i, "stages": {
                stage: sum(row["human_stage"] == stage for row in rs)
                for stage in route_queue.STAGES
            }} for i, rs in enumerate(rooms, 1)
        ],
    }
    out_csv = io.StringIO(newline="")
    fields = ("previous_position", "current_position", "proposal_slot", "team",
              "before_stage", "after_stage", "private_question_changed")
    writer = csv.writer(out_csv, lineterminator="\r\n")
    writer.writerow(fields)
    for item in movements:
        writer.writerow([item[x] for x in fields])
    participation_csv = io.StringIO(newline="")
    participation_fields = ("previous_position", "current_position", "team",
                            "previous_disposition", "current_disposition")
    participation_writer = csv.writer(participation_csv, lineterminator="\r\n")
    participation_writer.writerow(participation_fields)
    for item in transitions:
        participation_writer.writerow([item[x] for x in participation_fields])
    output = (
        ("OPEN-PRIVATE.html", _page(rooms, teams, movements, transitions)),
        ("PRIVATE-HUMAN-BATCH-HISTORY.json",
         (json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")),
        ("PRIVATE-HUMAN-BATCH-CHANGES.csv", out_csv.getvalue().encode("utf-8")),
        ("PRIVATE-HUMAN-TEAM-TRANSITIONS.csv", participation_csv.getvalue().encode("utf-8")),
    )
    target.mkdir(mode=0o700)
    try:
        if not privacy.private(target, True):
            raise privacy.Hold("HOLD: new PRIVATE HUMAN batch history custody invalid")
        for name, data in output:
            privacy.private_write(target, name, data)
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except Exception:
        shutil.rmtree(target)
        raise privacy.Hold("HOLD: original PRIVATE HUMAN batch history not published") from None
    return target / "OPEN-PRIVATE.html"


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(
        description="Compare 2–8 original source-bound PRIVATE unfinalized team batches")
    cli.add_argument("--packet", action="append", required=True)
    cli.add_argument("--final-room", required=True)
    cli.add_argument("--handoff-room", required=True)
    cli.add_argument("--batch-room", action="append", required=True)
    cli.add_argument("--private-parent", required=True)
    cli.add_argument("--folder", required=True)
    cli.add_argument("--human-confirm", required=True)
    opts = cli.parse_args(argv)
    try:
        if opts.human_confirm != "BUILD PRIVATE LAB TEAM BATCH HISTORY":
            raise privacy.Hold("HOLD: explicit original HUMAN history confirmation missing")
        page = build(opts.packet, opts.final_room, opts.handoff_room,
                     opts.batch_room, opts.private_parent, opts.folder)
        print("PRIVATE REVIEW_ONLY: original HUMAN Lab proposal history, no finalization")
        print("OPEN LOCALLY: " + str(page))
        return 2
    except Exception as exc:
        print(str(exc) if isinstance(exc, privacy.Hold) else
              "HOLD: original PRIVATE HUMAN Lab history refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
