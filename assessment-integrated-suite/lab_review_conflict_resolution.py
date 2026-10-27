#!/usr/bin/env python3
"""Private, source-bound manual HUMAN team-conflict resolution over saved batches.

Never scans or infers a decision. The only way to incorporate an overlapping
new HUMAN answer is a separate deliberate per-original-ordinal selection in an
owner-private CSV prepared from the exact existing original HUMAN inputs.
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
import lab_conflict_choice_editor
import lab_plan_review
import lab_review_history
import lab_review_team_batch as batch
import lab_review_team_batch_reopen as batch_reopen
import lab_review_team_continue_reopen as continued_reopen
import lab_review_team_handoff as handoff
import lab_review_team_return as returned_team
import private_session as privacy
import route_queue

SCHEMA = "lightup.private.original-lab-human-conflict-resolution.v1"
COLUMNS = ("source_snapshot_sha256", "prior_candidate_sha256", "proposal_slot",
           "human_team", "prior_stage", "proposed_stage", "human_question_changed",
           "human_choice")
CHOICES = ("KEEP_PREVIOUS", "APPLY_RETURN")
MAX_REPLIES = 4


def _csv(rows: list[dict]) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(COLUMNS)
    for row in rows:
        writer.writerow([row[key] for key in COLUMNS])
    return buffer.getvalue().encode("utf-8")


def _page(rows: list[dict], *, published: bool) -> bytes:
    esc = lambda s: html.escape(str(s), quote=True)
    items = "".join("<tr><td>" + esc(row["proposal_slot"]) +
                    "</td><td>" + esc(row["human_team"]) +
                    "</td><td>" + esc(row["prior_stage"]) +
                    "</td><td>" + esc(row["proposed_stage"]) +
                    "</td><td>" + esc(row["human_question_changed"]) +
                    "</td><td>" + esc(row["human_choice"]) + "</td></tr>"
                    for row in rows)
    return ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; connect-src 'none'; form-action 'none'">
<title>LightUp PRIVATE HUMAN conflict resolution</title>
<style>:root{color-scheme:dark;background:#101e31;color:#e9f8ff;font:16px/1.6 system-ui}
body{max-width:1100px;margin:2rem auto;padding:0 1rem}
header,section,footer{padding:24px;margin:15px 0;background:#213b51;
border:1px solid #648296;border-radius:15px}
table{width:100%;border-collapse:collapse}td,th{padding:12px;text-align:left;
border-bottom:1px solid #536e80}th{color:#c1ebdd}
strong{color:#ffe1af}div{overflow-x:auto}</style></head><body>
<header><strong>PRIVATE · ORIGINAL LAB · HUMAN REVIEW_ONLY</strong>
<h1>Original-source HUMAN conflict decisions</h1>
<p>""" + ("New PRIVATE candidate assembled from explicit HUMAN selections."
             if published else
             "Edit the PRIVATE draft CSV deliberately. KEEP_PREVIOUS is the default.") +
            """ Every source row is a HUMAN proposal, never permission, authenticity
or a proven security issue. Missing decisions are not silently applied.</p></header>
<section><h2>Original private HUMAN editing</h2>""" +
            ("""<p><a href="EDIT-PRIVATE.html">Open the LOCAL offline HUMAN choice editor</a>.
It exports all original source-bound rows as a completed PRIVATE CSV for
separate native admission. This workroom is owner-only 0600.</p>""" if not published else
             """<p>The complete chosen source-bound CSV and resulting new PRIVATE
candidate remain separate files for manual original HUMAN Studio review.</p>""") +
            """</section>
<section><h2>Original HUMAN ordinal choices</h2><div><table>
<thead><tr><th>Ordinal</th><th>Assigned team</th><th>Earlier stage</th>
<th>Returned stage</th><th>PRIVATE question changed?</th>
<th>Operator choice</th></tr></thead><tbody>""" + items +
            """</tbody></table></div></section>
<footer><strong>INCUBATE M3/M7 · DRAFT/HOLD · NO SCAN / GO / GRANT</strong>
<p>Confidential HUMAN question text is absent from this HTML. Complete
PRIVATE candidate CSVs remain exclusively owner-0600. All original packets,
previous complete HUMAN rounds and exact team replies must be re-admitted.
Human selections are NOT authenticated reviewer consent, real client/operator
approval or a security assessment. Exact-head CI, original source owners,
independent security/privacy/browser review, #177/#182/#829, separately
authenticated current client and operator consent, revocation-at-use and
explicit HUMAN GO remain mandatory. No external network or auto-finalize.</p>
</footer></body></html>""").encode("utf-8")


def _source(packets: list[str], final_room: str, handoff_room: str,
            root_batch: str, prior_continuations: tuple[str, ...],
            team_returns: list[tuple[str, str]]) -> tuple[list[dict], list[dict], str]:
    if (not 1 <= len(team_returns) <= MAX_REPLIES
            or len({team for team, _ in team_returns}) != len(team_returns)
            or any(team not in handoff.SLUGS or not path
                   for team, path in team_returns)
            or type(prior_continuations) is not tuple
            or len(prior_continuations) > 6):
        raise privacy.Hold("HOLD: select 1–4 distinct original assigned teams")
    if prior_continuations:
        continued_reopen.inspect(packets, final_room, handoff_room,
                                 root_batch, prior_continuations[-1],
                                 prior_continuations=prior_continuations[:-1])
    else:
        batch_reopen.inspect(packets, final_room, handoff_room, root_batch)
    origin, fingerprint = lab_plan_review._source_rows(packets)
    finalized = lab_review_history._admit_final(final_room, origin, fingerprint)
    prior_room = lab_plans._packet(prior_continuations[-1] if prior_continuations
                                   else root_batch)
    prior_name = ("PRIVATE-HUMAN-CONTINUED-CANDIDATE.csv" if prior_continuations
                  else "PRIVATE-HUMAN-CANDIDATE.csv")
    raw = route_queue.read_owner_csv(str(prior_room / prior_name))
    prior = lab_plan_review._rows_admit(origin, str(prior_room / prior_name))
    digest = sha256(raw).hexdigest()
    lookup = {row["proposal_slot"]: row for row in prior}
    source_handoff = lab_plans._packet(handoff_room)
    teams = batch._selected_manifest(source_handoff, finalized, fingerprint)
    changes = []
    for team, filename in team_returns:
        if team not in teams:
            raise privacy.Hold("HOLD: returned HUMAN team absent from original assignment")
        selected = [row for row in finalized if row["human_team"] == team]
        pinned = route_queue.read_owner_csv(str(
            source_handoff / ("TEAM-" + handoff.SLUGS[team] + "-DRAFT.csv")))
        if pinned != handoff._team_csv(selected):
            raise privacy.Hold("HOLD: original assigned HUMAN team draft changed")
        returned = returned_team._read_team(filename, selected, team)
        for baseline, proposed in zip(selected, returned):
            old = lookup[baseline["proposal_slot"]]
            if all(old[key] == proposed[key] for key in
                   ("human_stage", "human_question")):
                continue
            # Only actual source-bound differences are offered to the HUMAN.
            changes.append({
                "source_snapshot_sha256": fingerprint,
                "prior_candidate_sha256": digest,
                "proposal_slot": old["proposal_slot"],
                "human_team": team,
                "prior_stage": old["human_stage"],
                "proposed_stage": proposed["human_stage"],
                "human_question_changed": "YES" if
                    old["human_question"] != proposed["human_question"] else "NO",
                "human_choice": "KEEP_PREVIOUS",
                "_candidate": proposed,
            })
    if not changes:
        raise privacy.Hold("HOLD: no new original HUMAN decision differences to curate")
    # Original source order independent from team-return order.
    order = {row["proposal_slot"]: i for i, row in enumerate(prior)}
    changes.sort(key=lambda row: order[row["proposal_slot"]])
    return prior, changes, digest


def _publish(parent: str, folder: str, artifacts: list[tuple[str, bytes]]) -> Path:
    dest = lab_plans._new_path(parent, folder)
    dest.mkdir(mode=0o700)
    try:
        if not privacy.private(dest, True):
            raise privacy.Hold("HOLD: original PRIVATE HUMAN room not owner-only")
        for name, payload in artifacts:
            privacy.private_write(dest, name, payload)
        fd = os.open(dest, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except Exception:
        shutil.rmtree(dest)
        raise privacy.Hold("HOLD: source-bound HUMAN room incomplete") from None
    return dest / "OPEN-PRIVATE.html"


def _receipt(files: list[tuple[str, bytes]], *, original: str,
             source_digest: str, applied: int) -> bytes:
    result = {
        "schema": SCHEMA, "status": "REVIEW_ONLY",
        "authority": privacy.AUTHORITY,
        "verified_client_consent": False, "verified_operator_consent": False,
        "verified_reviewer_identity": False, "verified_source_identity": False,
        "human_go_recorded": False, "scan_or_release_allowed": False,
        "automatic_finalization": False, "external_contact": False,
        "private_question_text_included_in_overview": False,
        "original_source_sha256_unsigned": original,
        "previous_candidate_sha256_unsigned": source_digest,
        "human_decisions_to_apply": applied,
        "private_artifact_sha256_unsigned": {
            name: sha256(payload).hexdigest() for name, payload in files
        },
    }
    return (json.dumps(result, sort_keys=True, separators=(",", ":")) +
            "\n").encode("utf-8")


def build(packets: list[str], final_room: str, handoff_room: str,
          root_batch: str, prior_continuations: tuple[str, ...],
          team_returns: list[tuple[str, str]], parent: str, folder: str,
          *, completed: str = "", expected_room: str = "") -> Path:
    prior, changes, digest = _source(
        packets, final_room, handoff_room, root_batch, prior_continuations,
        team_returns)
    original = changes[0]["source_snapshot_sha256"]
    public_rows = [{key: val for key, val in item.items() if not key.startswith("_")}
                   for item in changes]
    if not completed:
        files = [
            ("OPEN-PRIVATE.html", _page(public_rows, published=False)),
            ("EDIT-PRIVATE.html", lab_conflict_choice_editor.render(public_rows)),
            ("PRIVATE-HUMAN-CHOICES.csv", _csv(public_rows)),
        ]
        files.append(("PRIVATE-HUMAN-DECISIONS-RECEIPT.json",
                      _receipt(files, original=original, source_digest=digest,
                               applied=0)))
        return _publish(parent, folder, files)

    room = lab_plans._packet(expected_room)
    initial = route_queue.read_owner_csv(str(room / "PRIVATE-HUMAN-CHOICES.csv"))
    if initial != _csv(public_rows):
        raise privacy.Hold("HOLD: original HUMAN choice template/source changed")
    from workpack_progress import _private_receipt
    stored = _private_receipt(room / "PRIVATE-HUMAN-DECISIONS-RECEIPT.json")
    expected = {
        "schema", "status", "authority", "verified_client_consent",
        "verified_operator_consent", "verified_reviewer_identity",
        "verified_source_identity", "human_go_recorded", "scan_or_release_allowed",
        "automatic_finalization", "external_contact",
        "private_question_text_included_in_overview",
        "original_source_sha256_unsigned", "previous_candidate_sha256_unsigned",
        "human_decisions_to_apply", "private_artifact_sha256_unsigned",
    }
    if (set(stored) != expected or stored["schema"] != SCHEMA
            or stored["status"] != "REVIEW_ONLY"
            or stored["original_source_sha256_unsigned"] != original
            or stored["previous_candidate_sha256_unsigned"] != digest
            or type(stored["human_decisions_to_apply"]) is not int
            or stored["human_decisions_to_apply"] != 0
            or type(stored["authority"]) is not dict
            or set(stored["authority"]) != set(privacy.AUTHORITY)
            or any(type(stored["authority"][key]) is not bool or
                   stored["authority"][key] is not False
                   for key in privacy.AUTHORITY)
            or any(stored[key] is not False for key in (
                "verified_client_consent", "verified_operator_consent",
                "verified_reviewer_identity", "verified_source_identity",
                "human_go_recorded", "scan_or_release_allowed",
                "automatic_finalization", "external_contact",
                "private_question_text_included_in_overview"))):
        raise privacy.Hold("HOLD: original HUMAN choice room receipt invalid")
    expected_files = ("OPEN-PRIVATE.html", "EDIT-PRIVATE.html",
                      "PRIVATE-HUMAN-CHOICES.csv")
    inventory = stored["private_artifact_sha256_unsigned"]
    if (type(inventory) is not dict or set(inventory) != set(expected_files)
            or any(type(inventory[name]) is not str or
                   inventory[name] != sha256(
                       route_queue.read_owner_csv(str(room / name))).hexdigest()
                   for name in expected_files)):
        raise privacy.Hold("HOLD: original HUMAN choice workspace bytes changed")
    completed_raw = route_queue.read_owner_csv(completed)
    try:
        lines = list(csv.reader(io.StringIO(completed_raw.decode("utf-8", "strict"),
                                            newline=""), strict=True))
    except (UnicodeError, csv.Error):
        raise privacy.Hold("HOLD: PRIVATE HUMAN completed choices malformed") from None
    if len(lines) != len(public_rows) + 1 or tuple(lines[0]) != COLUMNS:
        raise privacy.Hold("HOLD: complete source-bound HUMAN choice set required")
    proposals = []
    for source, fields in zip(public_rows, lines[1:]):
        if len(fields) != len(COLUMNS):
            raise privacy.Hold("HOLD: original HUMAN choice row malformed")
        item = dict(zip(COLUMNS, fields))
        if (any(item[key] != source[key] for key in COLUMNS if key != "human_choice")
                or item["human_choice"] not in CHOICES):
            raise privacy.Hold("HOLD: altered HUMAN ordinal, source or unsupported choice")
        proposals.append(item)
    previous = [dict(row) for row in prior]
    slots = {row["proposal_slot"]: i for i, row in enumerate(previous)}
    accepted = []
    for original_change, chosen in zip(changes, proposals):
        if chosen["human_choice"] != "APPLY_RETURN":
            continue
        row = original_change["_candidate"]
        previous[slots[row["proposal_slot"]]] = row
        accepted.append(chosen)
    if not accepted:
        raise privacy.Hold("HOLD: no deliberately selected HUMAN changes to publish")
    files = [
        ("OPEN-PRIVATE.html", _page(proposals, published=True)),
        ("PRIVATE-HUMAN-RESOLVED-CANDIDATE.csv", lab_plan_review._csv(previous)),
        ("PRIVATE-HUMAN-FINAL-CHOICES.csv", _csv(proposals)),
    ]
    files.append(("PRIVATE-HUMAN-RESOLUTION-RECEIPT.json",
                  _receipt(files, original=original, source_digest=digest,
                           applied=len(accepted))))
    return _publish(parent, folder, files)


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(
        description="PRIVATE source-bound per-ordinal HUMAN Lab conflict choices")
    cli.add_argument("mode", choices=("prepare", "publish"))
    cli.add_argument("--packet", action="append", required=True)
    cli.add_argument("--final-room", required=True)
    cli.add_argument("--handoff-room", required=True)
    cli.add_argument("--root-batch", required=True)
    cli.add_argument("--prior-continuation", action="append", default=[])
    cli.add_argument("--team-return", action="append", required=True)
    cli.add_argument("--choice-room", default="")
    cli.add_argument("--completed-csv", default="")
    cli.add_argument("--private-parent", required=True)
    cli.add_argument("--folder", required=True)
    cli.add_argument("--human-confirm", required=True)
    opt = cli.parse_args(argv)
    try:
        expected_confirm = ("PREPARE PRIVATE HUMAN CONFLICT CHOICES" if
                            opt.mode == "prepare" else
                            "PUBLISH PRIVATE HUMAN CONFLICT CANDIDATE")
        if opt.human_confirm != expected_confirm:
            raise privacy.Hold("HOLD: explicit original HUMAN action confirmation missing")
        teams = []
        for value in opt.team_return:
            if "=" not in value:
                raise privacy.Hold("HOLD: TEAM=OWNER_PRIVATE_CSV is required")
            teams.append(tuple(value.split("=", 1)))
        if opt.mode == "publish" and not opt.choice_room:
            raise privacy.Hold("HOLD: original PRIVATE choices room required")
        if opt.mode == "publish" and not opt.completed_csv:
            raise privacy.Hold("HOLD: completed PRIVATE HUMAN choices CSV required")
        result = build(
            opt.packet, opt.final_room, opt.handoff_room, opt.root_batch,
            tuple(opt.prior_continuation), teams, opt.private_parent, opt.folder,
            completed=opt.completed_csv if opt.mode == "publish" else "",
            expected_room=opt.choice_room if opt.mode == "publish" else "")
        print("PRIVATE REVIEW_ONLY: HUMAN source-bound conflict room created, not finalized")
        print("OPEN LOCALLY: " + str(result))
        return 2
    except Exception as exc:
        print(str(exc) if isinstance(exc, privacy.Hold) else
              "HOLD: original PRIVATE HUMAN conflict source refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
