#!/usr/bin/env python3
"""Offline owner-private HUMAN workpack progression, never an assessment result.

Read 2–8 explicit original workpack snapshots in HUMAN-declared order.
All inputs must match ONE original saved PATH-only session, and output is
source-minimal HUMAN metadata, never original private question text.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import html
import io
import json
import os
from pathlib import Path
import shutil
import stat

import human_priorities
import human_workpack
import private_session as privacy
import route_queue
import workpack_progress_browser

SCHEMA = "lightup.private.assessment-workpack-progress.v1"
MAX_PACKS = 8


def _private_receipt(path: Path) -> dict:
    """Descriptor-pinned, duplicate-key-rejecting original private receipt."""
    if not privacy.private(path.parent, True) or not privacy.private(path, False):
        raise privacy.Hold("HOLD: original receipt parent/file is not owner-private")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) & 0o077
                or not 0 < before.st_size <= privacy.MAX_JSON):
            raise privacy.Hold("HOLD: original private receipt is not a regular owned file")
        raw = os.read(fd, privacy.MAX_JSON + 1)
        after = os.fstat(fd)
        attrs = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns,
                            st.st_mode, st.st_uid, st.st_nlink)
        if attrs(before) != attrs(after) or len(raw) != before.st_size:
            raise privacy.Hold("HOLD: original private receipt changed during reading")
    finally:
        os.close(fd)
    try:
        doc = json.loads(raw.decode("utf-8", "strict"),
                         object_pairs_hook=privacy.unique_pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(
                             privacy.Hold("HOLD: invalid original receipt JSON constant")))
    except (UnicodeError, ValueError):
        raise privacy.Hold("HOLD: original private receipt malformed") from None
    if type(doc) is not dict:
        raise privacy.Hold("HOLD: original private receipt must be an object")
    return doc


def original_workpack(folder: str, base: list[dict]) -> tuple[str, list[dict], bytes]:
    """Read original workpack and its pinned CSV *once*, preserving exact bytes."""
    path = Path(folder)
    if not path.is_absolute() or path.is_symlink() or not privacy.private(path, True):
        raise privacy.Hold("HOLD: original HUMAN workpack must be an owner-only directory, not a link")
    # Local unsigned HUMAN declaration; cannot authenticate the source.
    receipt = _private_receipt(path / "PRIVATE-WORKPACK-RECEIPT.json")
    expected_fields = {
        "schema", "status", "authority", "declared_review_date",
        "original_client_source_included", "pinned_private_human_csv_included",
        "created_from_unassessed_session", "original_session_paths_included",
        "external_recipient_authenticated", "review_verified",
        "automated_actions", "workflows", "human_staged", "team_decks",
        "generated_views",
    }
    is_legacy = receipt.get("schema") == human_workpack.LEGACY_SCHEMA
    if is_legacy:
        pass  # Backward-compatible acceptance for existing original v1 workpacks.
    elif receipt.get("schema") == human_workpack.SCHEMA:
        expected_fields.update({
            "pinned_private_human_csv_sha256_unsigned",
            "pinned_private_human_csv_bytes",
        })
    else:
        raise privacy.Hold("HOLD: unsupported original HUMAN workpack receipt schema")
    flags = ("original_client_source_included",
             "original_session_paths_included", "external_recipient_authenticated",
             "review_verified", "automated_actions")
    authority = receipt.get("authority")
    if (set(receipt) != expected_fields
            or type(authority) is not dict
            or set(authority) != set(privacy.AUTHORITY)
            or any(type(authority[key]) is not bool or authority[key] is not False
                   for key in privacy.AUTHORITY)
            or any(type(receipt.get(key)) is not bool or receipt[key] is not False
                   for key in flags)
            or receipt.get("pinned_private_human_csv_included") is not True):
        raise privacy.Hold("HOLD: original workpack receipt authority or schema invalid")
    if (type(receipt) is not dict
            or receipt.get("status") != "REVIEW_ONLY"
            or receipt.get("authority") != privacy.AUTHORITY
            or receipt.get("original_client_source_included") is not False
            or receipt.get("original_session_paths_included") is not False
            or receipt.get("automated_actions") is not False
            or type(receipt.get("workflows")) is not int
            or receipt["workflows"] != len(base)):
        raise privacy.Hold("HOLD: original HUMAN workpack receipt not canonical")
    date = receipt.get("declared_review_date")
    if type(date) is not str:
        raise privacy.Hold("HOLD: missing operator-declared workpack date")
    human_priorities.as_of(date)
    source = path / "PINNED-HUMAN-QUEUE.csv"
    if source.is_symlink():
        raise privacy.Hold("HOLD: pinned original HUMAN workpack CSV cannot be linked")
    raw = route_queue.read_owner_csv(str(source))
    if not is_legacy:
        digest = receipt["pinned_private_human_csv_sha256_unsigned"]
        if (type(digest) is not str or len(digest) != 64
                or not all(c in "0123456789abcdef" for c in digest)
                or type(receipt["pinned_private_human_csv_bytes"]) is not int
                or receipt["pinned_private_human_csv_bytes"] != len(raw)
                or not hmac.compare_digest(digest, hashlib.sha256(raw).hexdigest())):
            raise privacy.Hold("HOLD: original pinned HUMAN CSV digest/size differs")
    rows = route_queue.admit_human_edits_bytes(base, raw)
    teams = [(team, sum(row["review_team"] == team and
                        row["human_stage"] != "UNASSESSED" for row in rows))
             for team in human_workpack.TEAM_FOLDERS]
    teams = [(team, count) for team, count in teams if count]
    expected_decks = [{"team": team, "human_workflows": count}
                      for team, count in teams]
    expected_views = ["queue", "priorities"] + [
        human_workpack.TEAM_FOLDERS[team] for team, _ in teams]
    if (receipt.get("human_staged") != sum(x["human_stage"] != "UNASSESSED" for x in rows)
            or type(receipt.get("created_from_unassessed_session")) is not bool
            or receipt.get("team_decks") != expected_decks
            or receipt.get("generated_views") != expected_views):
        raise privacy.Hold("HOLD: original HUMAN workpack receipt disagrees with pinned rows")
    return date, rows, raw


def _read_workpack(folder: str, base: list[dict]) -> tuple[str, list[dict]]:
    date, rows, _ = original_workpack(folder, base)
    return date, rows


def _counts(rows: list[dict]) -> dict:
    return {
        "unassessed": sum(x["human_stage"] == "UNASSESSED" for x in rows),
        "attention": sum(x["human_stage"] in ("HOLD", "NEEDS_INPUT") for x in rows),
        "human_review": sum(x["human_stage"] == "HUMAN_REVIEW" for x in rows),
        "human_followup": sum(x["human_stage"] == "HUMAN_FOLLOWUP" for x in rows),
        "teams": {
            team: sum(x["review_team"] == team and x["human_stage"] != "UNASSESSED"
                      for x in rows)
            for team in human_workpack.TEAM_FOLDERS
        }
    }


def _changes(snapshots: list[tuple[str, list[dict]]]) -> list[dict]:
    changes = []
    for index in range(1, len(snapshots)):
        before, after = snapshots[index - 1][1], snapshots[index][1]
        for previous, current in zip(before, after):
            fields = [
                label for key, label in (
                    ("human_stage", "stage"), ("review_team", "team"),
                    ("followup_date", "review_date"),
                    ("human_question", "private_question_changed"))
                if previous[key] != current[key]
            ]
            if fields:
                changes.append({
                    "from_snapshot": index, "to_snapshot": index + 1,
                    "workflow_key": current["workflow_key"],
                    "workflow_title": current["title"],
                    "fields": fields,
                    "previous_stage": previous["human_stage"],
                    "current_stage": current["human_stage"],
                    "previous_team": previous["review_team"],
                    "current_team": current["review_team"],
                    "previous_review_date": previous["followup_date"],
                    "current_review_date": current["followup_date"],
                    "private_question_text_included": False,
                })
    return changes



def _declared_movement(snapshots: list[tuple[str, list[dict]]]) -> list[dict]:
    """HUMAN stage movements across operator-ordered snapshots, not outcomes."""
    result = []
    for index in range(1, len(snapshots)):
        before, after = snapshots[index - 1][1], snapshots[index][1]
        old_attention = [r["human_stage"] in ("HOLD", "NEEDS_INPUT") for r in before]
        new_attention = [r["human_stage"] in ("HOLD", "NEEDS_INPUT") for r in after]
        result.append({
            "from_snapshot": index, "to_snapshot": index + 1,
            "human_stage_changes": sum(a["human_stage"] != b["human_stage"]
                                       for a, b in zip(before, after)),
            "human_team_changes": sum(a["review_team"] != b["review_team"]
                                      for a, b in zip(before, after)),
            "newly_declared_attention": sum(not a and b for a, b in zip(
                old_attention, new_attention)),
            "no_longer_declared_attention": sum(a and not b for a, b in zip(
                old_attention, new_attention)),
            "continuously_declared_attention": sum(a and b for a, b in zip(
                old_attention, new_attention)),
            "human_question_edits": sum(a["human_question"] != b["human_question"]
                                        for a, b in zip(before, after)),
        })
    return result


def _latest_attention(snapshots: list[tuple[str, list[dict]]]) -> list[dict]:
    """Last HUMAN HOLD/NEEDS_INPUT, never an inferred security severity."""
    result = []
    for index, row in enumerate(snapshots[-1][1]):
        if row["human_stage"] not in ("HOLD", "NEEDS_INPUT"):
            continue
        streak = 0
        for _, earlier in reversed(snapshots):
            if earlier[index]["human_stage"] not in ("HOLD", "NEEDS_INPUT"):
                break
            streak += 1
        result.append({
            "workflow_key": row["workflow_key"],
            "workflow_title": row["title"],
            "declared_stage": row["human_stage"],
            "declared_team": row["review_team"],
            "declared_followup": row["followup_date"],
            "consecutive_attention_snapshots": streak,
            "first_continuous_declared_position": len(snapshots) - streak + 1,
        })
    return result


def _html(snapshots: list[tuple[str, list[dict]]], metrics: list[dict],
          changes: list[dict], attention: list[dict]) -> bytes:
    esc = lambda value: html.escape(str(value), quote=True)
    snap_rows = []
    for number, ((date, _), counts) in enumerate(zip(snapshots, metrics), 1):
        team_counts = " · ".join(
            esc(team) + ": " + str(count)
            for team, count in counts["teams"].items() if count
        ) or "No HUMAN team assigned"
        snap_rows.append(
            "<tr><th scope='row'>" + str(number) + "</th><td>" + esc(date) +
            "</td><td>" + str(counts["unassessed"]) + "</td><td>" +
            str(counts["attention"]) + "</td><td>" +
            str(counts["human_review"]) + "</td><td>" +
            str(counts["human_followup"]) + "</td><td>" + team_counts +
            "</td></tr>"
        )
    timeline = []
    for change in changes:
        timeline.append(
            "<li><strong>" + esc(change["workflow_title"]) + "</strong> · #" +
            str(change["from_snapshot"]) + " → #" + str(change["to_snapshot"]) +
            "<br>Changed: " + esc(", ".join(change["fields"])) +
            "<br>HUMAN stage: " + esc(change["previous_stage"]) + " → " +
            esc(change["current_stage"]) +
            "<br>Team: " + esc(change["previous_team"] or "none") + " → " +
            esc(change["current_team"] or "none") +
            "<br>Proposed follow-up: " + esc(change["previous_review_date"] or "none") +
            " → " + esc(change["current_review_date"] or "none") + "</li>"
        )
    attention_rows = [
        "<li><strong>" + esc(row["workflow_title"]) + "</strong> · " +
        esc(row["declared_stage"]) + " · " +
        esc(row["declared_team"] or "Team not assigned") +
        "<br>Proposed follow-up: " + esc(row["declared_followup"] or "none") +
        "<br>Consecutive declared snapshots needing attention: " +
        str(row["consecutive_attention_snapshots"]) + " (since position #" +
        str(row["first_continuous_declared_position"]) + ")</li>"
        for row in attention
    ]
    document = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp PRIVATE HUMAN Workpack Progress</title>
<style>:root{color-scheme:dark;background:#101c2f;color:#e8f3fc;font:16px/1.5 system-ui}
body{max-width:1140px;margin:auto;padding:22px}header,section,footer{padding:24px;margin:16px 0;border:1px solid #426482;border-radius:16px;background:#1c3349}
h1{font-size:clamp(1.7rem,3vw,2.7rem)}.warn{font-weight:bold;color:#ffe0a7}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:11px;border-bottom:1px solid #4e6982}
.scroller{overflow-x:auto}li{padding:12px 0;border-bottom:1px solid #426482}
li strong{color:#b8f1da}</style>
<header><p class="warn">PRIVATE HUMAN / ORIGINAL-SESSION BOUND / REVIEW_ONLY</p>
<h1>Assessment Workpack Progress</h1><p>""" + str(len(snapshots)) + """ distinct original local HUMAN workpacks in operator-declared order;
""" + str(len(changes)) + """ changed workflow transitions. Dates are manually declared,
not verified chronology, actual deadlines or appointments.</p></header>
<section><h2>HUMAN review snapshots</h2><div class="scroller"><table>
<thead><tr><th>Snapshot</th><th>Declared date</th><th>UNASSESSED</th><th>HOLD / NEEDS INPUT</th>
<th>HUMAN REVIEW</th><th>HUMAN FOLLOWUP</th><th>Declared team workload</th></tr></thead>
<tbody>""" + "".join(snap_rows) + """</tbody></table></div></section>
<section><h2>Still-declared HUMAN attention in the latest snapshot</h2>
<p>""" + str(len(attention)) + """ HUMAN tasks marked HOLD or NEEDS_INPUT.
Streaks count *consecutive declared snapshots*, not actual days,
incident duration, risk severity or priority.</p><ol>""" + (
        "".join(attention_rows) or "<li>No latest HUMAN HOLD / NEEDS_INPUT.</li>"
    ) + """</ol></section>
<section><h2>Manually recorded differences</h2><ol>""" + (
        "".join(timeline) or "<li>No changes in HUMAN metadata.</li>"
    ) + """</ol></section><footer><p class="warn">DRAFT/HOLD · NO AUTHORIZATION OR SCAN</p>
<p>Strictly local declared coordination metadata. No original filenames, original
source bytes, source paths, free HUMAN question text, credentials, real
recipient identity, authenticated consent, verified source, genuine findings,
real scheduling or release. An unchanged PATH fingerprint does not prove
unchanged original data. Inputs are original local owner-private HUMAN snapshots,
not proof of completed security assessments. Separate client and operator
consent, action-time revocation, source-owner and independent reviews,
existing CI and explicit HUMAN GO remain required.</p></footer></html>"""
    return document.encode("utf-8")


def build(session, workpacks: list[str], parent_name: str, name: str) -> Path:
    if (not 2 <= len(workpacks) <= MAX_PACKS
            or type(workpacks) is not list
            or any(type(x) is not str for x in workpacks)):
        raise privacy.Hold("HOLD: choose two to eight original HUMAN workpacks")
    if not privacy.NAME.fullmatch(name):
        raise privacy.Hold("HOLD: unused PRIVATE progress folder name required")
    parent = Path(parent_name).resolve(strict=True)
    if (parent == privacy.ROOT or privacy.ROOT in parent.parents
            or not privacy.private(parent, True)):
        raise privacy.Hold("HOLD: owner-only 0700 progress parent outside checkout required")
    destination = parent / name
    original_paths = [Path(x) for x in workpacks]
    if (len({str(x.resolve(strict=True)) for x in original_paths}) != len(workpacks)
            or any(x.resolve(strict=True) == destination or
                   destination in x.resolve(strict=True).parents for x in original_paths)
            or os.path.lexists(destination)):
        raise privacy.Hold("HOLD: repeated or overwritten original HUMAN workpack refused")
    base, _ = route_queue.rows_for(session)
    admitted = [original_workpack(folder, base) for folder in workpacks]
    # Copies of the exact same HUMAN date+CSV are not separate observations.
    identities = {(date, hashlib.sha256(raw).digest())
                  for date, _, raw in admitted}
    if len(identities) != len(admitted):
        raise privacy.Hold("HOLD: repeated exact HUMAN snapshot is not a new review")
    snapshots = [(date, rows) for date, rows, _ in admitted]
    metrics = [_counts(rows) for _, rows in snapshots]
    movement = _declared_movement(snapshots)
    changes = _changes(snapshots)
    attention = _latest_attention(snapshots)
    # Optional local-only CSP-pinned interactive cockpit; preserve the
    # independent scriptless reading option for restricted browsers.
    page = workpack_progress_browser.render(snapshots, metrics, changes, attention, movement)
    scriptless = _html(snapshots, metrics, changes, attention)
    metadata = {
        "schema": SCHEMA, "status": "REVIEW_ONLY", "authority": privacy.AUTHORITY,
        "human_order_declared_not_authenticated": True,
        "owner_private_original_paths_included": False,
        "original_source_data_included": False,
        "private_question_text_included": False,
        "automated_actions": False, "verified_source": False,
        "snapshots": [
            {"position": i, "declared_review_date": date, **metric}
            for i, ((date, _), metric) in enumerate(zip(snapshots, metrics), 1)
        ],
        "transitions": [
            {key: value for key, value in change.items() if key != "workflow_title"}
            for change in changes
        ],
        "human_transition_summary": movement,
        "latest_declared_attention": [
            {key: value for key, value in item.items() if key != "workflow_title"}
            for item in attention
        ],
    }
    data = (json.dumps(metadata, sort_keys=True, ensure_ascii=True,
                       separators=(",", ":")) + "\n").encode("ascii")
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(("from_snapshot", "to_snapshot", "workflow_key", "fields",
                     "previous_stage", "current_stage", "previous_team",
                     "current_team", "previous_review_date", "current_review_date"))
    for entry in changes:
        writer.writerow([
            entry["from_snapshot"], entry["to_snapshot"], entry["workflow_key"],
            "+".join(entry["fields"]), entry["previous_stage"],
            entry["current_stage"], entry["previous_team"], entry["current_team"],
            entry["previous_review_date"], entry["current_review_date"]
        ])
    destination.mkdir(mode=0o700)
    try:
        if not privacy.private(destination, True):
            raise privacy.Hold("HOLD: new progress folder not owner-private")
        privacy.private_write(destination, "OPEN-PRIVATE.html", page)
        privacy.private_write(destination, "PRIVATE-SCRIPTLESS.html", scriptless)
        attention_csv = io.StringIO(newline="")
        attention_writer = csv.writer(attention_csv, lineterminator="\r\n")
        attention_writer.writerow((
            "workflow_key", "human_stage", "human_team", "proposed_followup",
            "consecutive_declared_attention_snapshots", "first_continuous_snapshot"))
        for item in attention:
            attention_writer.writerow((
                item["workflow_key"], item["declared_stage"],
                item["declared_team"], item["declared_followup"],
                item["consecutive_attention_snapshots"],
                item["first_continuous_declared_position"]))
        privacy.private_write(
            destination, "PRIVATE-HUMAN-ATTENTION.csv",
            attention_csv.getvalue().encode("utf-8"))
        movement_csv = io.StringIO(newline="")
        movement_writer = csv.writer(movement_csv, lineterminator="\r\n")
        columns = (
            "from_snapshot", "to_snapshot", "human_stage_changes",
            "human_team_changes", "newly_declared_attention",
            "no_longer_declared_attention", "continuously_declared_attention",
            "human_question_edits")
        movement_writer.writerow(columns)
        for item in movement:
            movement_writer.writerow([item[key] for key in columns])
        privacy.private_write(
            destination, "PRIVATE-HUMAN-STAGE-MOVEMENT.csv",
            movement_csv.getvalue().encode("utf-8"))
        privacy.private_write(destination, "PRIVATE-HUMAN-PROGRESS.json", data)
        privacy.private_write(
            destination, "PRIVATE-HUMAN-TRANSITIONS.csv", stream.getvalue().encode("utf-8"))
        fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except (OSError, ValueError):
        shutil.rmtree(destination)
        raise privacy.Hold("HOLD: PRIVATE HUMAN progress room not published") from None
    return destination / "OPEN-PRIVATE.html"
