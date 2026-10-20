#!/usr/bin/env python3
"""Source-bound multi-team PRIVATE HUMAN lab return, never automatic finalization.

Composes *existing* original Launchpad, final HUMAN and team handoff readers.
All selected team returns are admitted before the first output is created.
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
import lab_review_team_handoff as handoff
import lab_review_team_return as one_team
import private_session as privacy
import route_queue

SCHEMA = "lightup.private.original-lab-human-multiteam-return.v1"
MAX_TEAMS = len(handoff.SLUGS)


def _selected_manifest(room: Path, base: list[dict], fingerprint: str) -> dict:
    manifest = one_team._receipt(room, base, fingerprint)
    entries = manifest["team_workrooms"]
    if not isinstance(entries, list) or len(entries) > MAX_TEAMS + 1:
        raise privacy.Hold("HOLD: original HUMAN team directory malformed")
    by_team = {}
    unassigned_seen = False
    for entry in entries:
        if type(entry) is not dict or set(entry) != {"label", "filename", "human_tasks"}:
            raise privacy.Hold("HOLD: original HUMAN team directory malformed")
        label = entry["label"]
        if label not in handoff.SLUGS:
            if (label != "Unassigned HUMAN follow-up" or unassigned_seen
                    or entry["filename"] != "TEAM-unassigned-operator-only.html"
                    or type(entry["human_tasks"]) is not int
                    or entry["human_tasks"] < 1):
                raise privacy.Hold("HOLD: unknown original HUMAN team directory entry")
            unassigned_seen = True
            continue
        count = sum(row["human_team"] == label for row in base)
        if (label in by_team or count == 0
                or type(entry["human_tasks"]) is not int
                or entry["human_tasks"] != count
                or entry["filename"] != f"TEAM-{handoff.SLUGS[label]}.html"):
            raise privacy.Hold("HOLD: original HUMAN team directory changed")
        by_team[label] = count
    if set(by_team) != {row["human_team"] for row in base if row["human_team"] in handoff.SLUGS}:
        raise privacy.Hold("HOLD: original HUMAN team directory incomplete")
    expected_unassigned = sum(row["human_team"] == "" and row["human_stage"] != "UNASSESSED" for row in base)
    if unassigned_seen != (expected_unassigned > 0):
        raise privacy.Hold("HOLD: original unassigned HUMAN team handoff differs")
    return by_team


def _private_html(changes: list[dict], team_counts: list[dict], missing: list[dict]) -> bytes:
    esc = lambda x: html.escape(str(x), quote=True)
    rows = "".join("<tr><th scope='row'>" + esc(x["team"]) + "</th><td>" +
                   str(x["assigned"]) + "</td><td>" + str(x["changed"]) + "</td></tr>"
                   for x in team_counts)
    bullets = "".join("<li>Original proposal #" + str(x["proposal_slot"]) +
                      " · " + esc(x["team"]) + " · HUMAN " +
                      esc(x["previous_stage"]) + " → " + esc(x["current_stage"]) +
                      " · private question changed: " +
                      ("YES" if x["private_question_changed"] else "NO") + "</li>"
                      for x in changes)
    pending = "".join("<li>" + esc(x["team"]) + " · " + str(x["assigned"]) +
                      " original HUMAN assignments · no returned CSV; unchanged</li>"
                      for x in missing)
    return ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>LightUp PRIVATE HUMAN Lab Team Batch</title>
<style>:root{color-scheme:dark;background:#101e30;color:#f0f8ff;font:16px/1.6 system-ui}
body{max-width:950px;margin:2rem auto;padding:0 1rem}header,section,footer{padding:24px;margin:15px 0;
border-radius:16px;background:#1e374e;border:1px solid #587990}th,td{text-align:left;
padding:12px;border-bottom:1px solid #526f82}table{width:100%}li{margin:12px 0}
strong{color:#ffdea0}</style></head><body>
<header><strong>PRIVATE · ORIGINAL LAB · HUMAN REVIEW_ONLY</strong>
<h1>Multiple independent HUMAN team returns</h1>
<p>Original assignments and separately returned HUMAN edits are displayed by
original ordinal only. No actor has been authenticated. This is NOT an authorized
scan, security finding, approval or completed assessment.</p></header>
<section><h2>Assigned teams without a response</h2><ul>""" +
            (pending or "<li>All originally assigned teams supplied a response.</li>") +
            """</ul><p>A missing response never means agreement, consent or closure.</p></section>
<section><h2>Manual team participation</h2><table><thead><tr><th>HUMAN team</th>
<th>Original assignments</th><th>Proposed changed entries</th></tr></thead><tbody>""" +
            rows + """</tbody></table></section>
<section><h2>Selected proposed changes</h2><ol>""" +
            (bullets or "<li>No differences were declared.</li>") +
            """</ol><p>Open the owner-private complete candidate CSV in the
original HUMAN Lab Review Studio (console option 58). Re-admit and
manually finalize separately. This batch does not change the original FINAL,
contact recipients, or grant authority. Do not assume unanswered teams approved.</p></section>
<footer><strong>DRAFT/HOLD · NO DEPLOY / DISPATCH / SCAN / GRANT / GO</strong>
<p>Each original owner-only Launchpad packet, FINAL receipt, team handoff,
original assigned-team CSV and returned HUMAN CSV was re-admitted. This
HTML excludes original targets, paths, source hashes and private questions.
Source hashes are unsigned and do not authenticate any actor. Exact-head
CI, source-owner, independent security/privacy/browser review, separately
authenticated current client and operator consent, action-time revocation and
explicit HUMAN GO remain mandatory.</p></footer></body></html>""").encode("utf-8")


def build(packets: list[str], final_room: str, handoff_room: str,
          returns: list[tuple[str, str]], parent: str, folder: str) -> Path:
    if (not 1 <= len(returns) <= MAX_TEAMS or
            len({team for team, _ in returns}) != len(returns) or
            any(team not in handoff.SLUGS or not path for team, path in returns)):
        raise privacy.Hold("HOLD: choose 1–4 different original assigned HUMAN teams")
    target = lab_plans._new_path(parent, folder)
    originals, fingerprint = lab_plan_review._source_rows(packets)
    final = lab_plans._packet(final_room)
    handoff_room_path = lab_plans._packet(handoff_room)
    input_rooms = [final, handoff_room_path] + [lab_plans._packet(p) for p in packets]
    if any(p == target or p in target.parents for p in input_rooms):
        raise privacy.Hold("HOLD: new room cannot live inside an original source room")
    base = lab_review_history._admit_final(str(final), originals, fingerprint)
    counts = _selected_manifest(handoff_room_path, base, fingerprint)
    next_rows = [dict(row) for row in base]
    slot_index = {row["proposal_slot"]: i for i, row in enumerate(base)}
    changes = []
    overview = []
    for team, response_path in returns:
        if team not in counts:
            raise privacy.Hold("HOLD: returned HUMAN team has no assigned original tasks")
        selected = [row for row in base if row["human_team"] == team]
        pinned = route_queue.read_owner_csv(str(
            handoff_room_path / ("TEAM-" + handoff.SLUGS[team] + "-DRAFT.csv")))
        if pinned != handoff._team_csv(selected):
            raise privacy.Hold("HOLD: original assigned team handoff draft has changed")
        returned = one_team._read_team(response_path, selected, team)
        changed_count = 0
        for old, new in zip(selected, returned):
            if (old["human_stage"] != new["human_stage"] or
                    old["human_question"] != new["human_question"]):
                changed_count += 1
                changes.append({
                    "team": team,
                    "proposal_slot": int(old["proposal_slot"]),
                    "previous_stage": old["human_stage"],
                    "current_stage": new["human_stage"],
                    "private_question_changed": old["human_question"] != new["human_question"]
                })
            next_rows[slot_index[old["proposal_slot"]]] = new
        overview.append({"team": team, "assigned": len(selected), "changed": changed_count})

    missing = [{"team": team, "assigned": count} for team, count in counts.items()
               if team not in {name for name, _ in returns}]
    # The original complete ordering is preserved and unselected teams retain
    # their existing decisions. No stage is interpreted as permission or PASS.
    receipt = {
        "schema": SCHEMA, "status": "REVIEW_ONLY", "authority": privacy.AUTHORITY,
        "source_authenticity_verified": False, "client_consent_verified": False,
        "operator_consent_verified": False, "recipients_authenticated": False,
        "human_go_recorded": False, "automated_actions": False,
        "scan_or_release_allowed": False, "original_urls_included": False,
        "private_question_text_included": False,
        "original_source_snapshot_sha256_unsigned": fingerprint,
        "teams": overview, "changed_ordinals": len(changes),
        "unreturned_original_team_count": len(missing),
        "unreturned_original_teams": missing,
    }
    diff_stream = io.StringIO(newline="")
    fields = ("team", "proposal_slot", "previous_stage", "current_stage",
              "private_question_changed")
    writer = csv.writer(diff_stream, lineterminator="\r\n")
    writer.writerow(fields)
    for change in changes:
        writer.writerow([change[k] for k in fields])
    docs = (
        ("OPEN-PRIVATE.html", _private_html(changes, overview, missing)),
        ("PRIVATE-HUMAN-CANDIDATE.csv", lab_plan_review._csv(next_rows)),
        ("PRIVATE-HUMAN-MULTITEAM-DIFF.csv", diff_stream.getvalue().encode("utf-8")),
        ("PRIVATE-HUMAN-MULTITEAM-RECEIPT.json",
         (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")),
    )
    target.mkdir(mode=0o700)
    try:
        if not privacy.private(target, True):
            raise privacy.Hold("HOLD: newly created HUMAN room is not owner-private")
        for name, data in docs:
            privacy.private_write(target, name, data)
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except Exception:
        shutil.rmtree(target)
        raise privacy.Hold("HOLD: original PRIVATE multi-team receipt not published") from None
    return target / "OPEN-PRIVATE.html"


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(description="PRIVATE original HUMAN Lab multiple team return; no finalize")
    cli.add_argument("--packet", action="append", required=True)
    cli.add_argument("--final-room", required=True)
    cli.add_argument("--handoff-room", required=True)
    cli.add_argument("--team-return", action="append", required=True,
                     metavar="TEAM=PRIVATE_CSV")
    cli.add_argument("--private-parent", required=True)
    cli.add_argument("--folder", required=True)
    cli.add_argument("--human-confirm", required=True)
    opts = cli.parse_args(argv)
    try:
        if opts.human_confirm != "ADMIT MULTIPLE PRIVATE LAB TEAM RETURNS":
            raise privacy.Hold("HOLD: manual multiple-team HUMAN admission confirmation missing")
        teams = []
        for item in opts.team_return:
            if "=" not in item:
                raise privacy.Hold("HOLD: --team-return requires exact TEAM=PRIVATE_CSV")
            team, path = item.split("=", 1)
            teams.append((team, path))
        page = build(opts.packet, opts.final_room, opts.handoff_room, teams,
                     opts.private_parent, opts.folder)
        print("PRIVATE REVIEW_ONLY: multiple HUMAN team candidate prepared, not finalized")
        print("OPEN LOCALLY: " + str(page))
        return 2
    except Exception as exc:
        print(str(exc) if isinstance(exc, privacy.Hold) else
              "HOLD: original PRIVATE HUMAN multi-team return refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
