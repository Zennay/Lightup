#!/usr/bin/env python3
"""Original-history-bound PRIVATE HUMAN discussion planning; no work dispatch.

The plan is a deliberately non-authorizing, local follow-up proposal only.
A verified source roster is required for every conversion to a new packet.
"""
from __future__ import annotations

from private_csv_formula import unsafe_private_csv_note

import argparse
import csv
from datetime import date
from hashlib import sha256
import html
import io
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

from notes import (ALLOWED, FALSE_FLAGS, Hold, file_new, private_directory,
                   private_input, save_json)
from revision_changes import admit_completed
from agenda_board import render as render_agenda_board

SCHEMA = "lightup.private_assessment_human_agenda.v1"
HISTORY_SCHEMA = "lightup.private_assessment_human_history.v1"
ACTIONS = ("NO_PROPOSAL", "DISCUSS_PRIVATELY", "ASK_SOURCE_OWNER", "WITHHOLD")
TEAMS = ("UNASSIGNED", "SECURITY", "PRIVACY", "CLIENT_OPERATIONS", "PLATFORM")
FIELDS = ("original_source_ordinal", "original_human_stage", "history_sha256_unsigned",
          "human_proposal", "proposed_team", "proposed_day", "private_human_question")
HOLD_FLAGS = ("source_authenticated", "recipient_authenticated",
              "actual_findings_verified", *FALSE_FLAGS)
DIGEST = re.compile(r"^[0-9a-f]{64}$")
STYLE = """body{max-width:1050px;margin:2rem auto;padding:18px;
font:16px/1.6 system-ui;color:#1c3046}h1{font-size:2rem}
article,header{border:1px solid #c9d8e5;border-radius:12px;padding:18px;margin:15px 0}
aside{border-left:5px solid #b45330;background:#fff1e8;padding:15px}
a{color:#135775}a:focus-visible{outline:3px solid #bf8122}
table{width:100%;border-collapse:collapse;table-layout:fixed}
th,td{border:1px solid #9db5c7;padding:9px;word-break:break-word;text-align:left}
@media print{body{max-width:none;margin:0}article{break-inside:avoid}}"""


def read_original_json(path: Path, max_bytes: int) -> tuple[bytes, dict]:
    """Strictly parse the ONE already-owner-private original-byte snapshot."""
    raw = private_input(str(path), max_bytes)
    try:
        def no_duplicate(pairs):
            output = {}
            for key, value in pairs:
                if key in output:
                    raise ValueError("duplicate original JSON object key")
                output[key] = value
            return output

        doc = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=no_duplicate,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        if type(doc) is not dict:
            raise ValueError("original object required")
    except (UnicodeError, ValueError, TypeError):
        raise Hold("HOLD: original PRIVATE HUMAN JSON is malformed or ambiguous") from None
    return raw, doc


def canonical_history(history_kit: str, latest_packet: str) -> tuple[dict, str, list[dict], str, str]:
    # An unsigned history is a local derivative, never a trusted source of
    # authorization. Independently re-admit its latest ORIGINAL packet.
    history_dir = private_directory(history_kit)
    raw, doc = read_original_json(
        history_dir / "PRIVATE-HUMAN-history.json", 256 * 1024)
    latest, latest_manifest, latest_csv, sources, _, decisions = admit_completed(latest_packet)
    doc_hash = sha256(raw).hexdigest()
    manifest_hash = sha256(latest_manifest).hexdigest()
    decisions_hash = sha256(latest_csv).hexdigest()
    if set(doc) != {
            "schema", "claimed_status", "source_authenticated",
            "recipient_authenticated", "actual_findings_verified",
            "original_source_count", "revision_packet_count",
            "first_revision_level", "last_revision_level", "human_event_count",
            "human_discussion_needed_count", "last_review_stage_counts",
            "packets", "events", "current_source_positions", *FALSE_FLAGS}:
        raise Hold("HOLD: PRIVATE HUMAN history has an unknown or missing original field")
    for flag in HOLD_FLAGS:
        if doc.get(flag) is not False:
            raise Hold("HOLD: PRIVATE HUMAN history contains non-false authority flags")
    packets = doc.get("packets")
    rows = doc.get("current_source_positions")
    stages = doc.get("last_review_stage_counts")
    if (doc.get("schema") != HISTORY_SCHEMA or doc.get("claimed_status") != "HOLD"
            or type(doc.get("original_source_count")) is not int
            or doc["original_source_count"] != len(sources)
            or type(packets) is not list or not 2 <= len(packets) <= 16
            or doc.get("revision_packet_count") != len(packets)
            or type(rows) is not list or len(rows) != len(sources)
            or type(stages) is not dict or set(stages) != set(ALLOWED)
            or any(type(stages[name]) is not int or stages[name] < 0 for name in ALLOWED)
            or sum(stages.values()) != len(sources)
            or doc.get("last_revision_level") != latest.get("revision_level", 0)):
        raise Hold("HOLD: PRIVATE original history roster or authority is invalid")
    # Every original packet entry has a finite sequential unsigned identity.
    # This validates structure, not independent producer authentication.
    first_level = doc.get("first_revision_level")
    if (type(first_level) is not int or not 0 <= first_level <= 32
            or first_level + len(packets) - 1 != doc["last_revision_level"]
            or doc["last_revision_level"] > 32):
        raise Hold("HOLD: PRIVATE HUMAN revision level sequence is invalid")
    for offset, item in enumerate(packets):
        if (type(item) is not dict
                or set(item) != {"revision_level", "manifest_sha256_unsigned",
                                "human_decisions_sha256_unsigned"}
                or type(item["revision_level"]) is not int
                or item["revision_level"] != first_level + offset
                or any(type(item[key]) is not str or not DIGEST.fullmatch(item[key])
                       for key in ("manifest_sha256_unsigned",
                                   "human_decisions_sha256_unsigned"))):
            raise Hold("HOLD: PRIVATE HUMAN packet chain contains invalid identities")
    last = packets[-1]
    if (type(last) is not dict
            or set(last) != {"revision_level", "manifest_sha256_unsigned",
                              "human_decisions_sha256_unsigned"}
            or last["revision_level"] != latest.get("revision_level", 0)
            or last["manifest_sha256_unsigned"] != manifest_hash
            or last["human_decisions_sha256_unsigned"] != decisions_hash):
        raise Hold("HOLD: original completed last HUMAN packet differs from history")
    if (type(doc.get("human_event_count")) is not int
            or type(doc.get("human_discussion_needed_count")) is not int
            or not 0 <= doc["human_discussion_needed_count"] <= len(sources)
            or type(doc.get("events")) is not list
            or len(doc["events"]) != doc["human_event_count"]
            or len(doc["events"]) > 16 * 12):
        raise Hold("HOLD: original private history event roster is invalid")
    for event in doc["events"]:
        if (type(event) is not dict or set(event) != {
                "revision_level", "original_source_ordinal",
                "previous_human_stage", "current_human_stage",
                "stage_changed", "private_note_changed"}
                or type(event["revision_level"]) is not int
                or not first_level < event["revision_level"] <= doc["last_revision_level"]
                or type(event["original_source_ordinal"]) is not int
                or not 1 <= event["original_source_ordinal"] <= len(sources)
                or event["previous_human_stage"] not in ALLOWED
                or event["current_human_stage"] not in ALLOWED
                or type(event["stage_changed"]) is not bool
                or type(event["private_note_changed"]) is not bool
                or not (event["stage_changed"] or event["private_note_changed"])):
            raise Hold("HOLD: PRIVATE original HUMAN event data is structurally invalid")
    counts = {stage: sum(d["human_stage"] == stage for d in decisions) for stage in ALLOWED}
    if stages != counts:
        raise Hold("HOLD: latest original HUMAN stages differ from history")
    admitted = []
    for i, (row, decision) in enumerate(zip(rows, decisions), start=1):
        if (type(row) is not dict or set(row) != {
                "original_source_ordinal", "current_human_stage",
                "stage_changes_total", "private_note_changes_total",
                "last_changed_revision", "human_action_needed"}
                or type(row["original_source_ordinal"]) is not int
                or row["original_source_ordinal"] != i
                or row["current_human_stage"] != decision["human_stage"]
                or type(row["human_action_needed"]) is not bool
                or row["human_action_needed"] != (decision["human_stage"] != "INTERNAL_REVIEW_ONLY")
                or any(type(row[name]) is not int or not 0 <= row[name] <= 16
                       for name in ("stage_changes_total", "private_note_changes_total"))
                or row["last_changed_revision"] != ""
                and (type(row["last_changed_revision"]) is not int
                     or not 0 <= row["last_changed_revision"] <= 32)):
            raise Hold("HOLD: original HUMAN stage/ordinal differs from source history")
        admitted.append({"original_source_ordinal": i,
                         "original_human_stage": decision["human_stage"]})
    return doc, doc_hash, admitted, manifest_hash, decisions_hash


def csv_bytes(rows: list[dict]) -> bytes:
    out = io.StringIO(newline="")
    writer = csv.DictWriter(out, fieldnames=FIELDS, lineterminator="\r\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: row[key] for key in FIELDS})
    return out.getvalue().encode("utf-8")


def rows_default(rows: list[dict], digest: str) -> list[dict]:
    return [{**row, "history_sha256_unsigned": digest, "human_proposal": "NO_PROPOSAL",
             "proposed_team": "UNASSIGNED", "proposed_day": "",
             "private_human_question": ""} for row in rows]


def prepare(history_kit: str, latest_packet: str, parent_path: str) -> int:
    parent = private_directory(parent_path)
    _, digest, positions, last_manifest, last_decisions = canonical_history(
        history_kit, latest_packet)
    output = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-human-agenda-", dir=parent))
    os.chmod(output, 0o700)
    complete = False
    try:
        bindings = {
            "schema": SCHEMA, "claimed_status": "HOLD",
            "history_sha256_unsigned": digest,
            "last_original_manifest_sha256_unsigned": last_manifest,
            "last_original_human_csv_sha256_unsigned": last_decisions,
            "original_source_count": len(positions),
            "source_positions": positions,
            **{flag: False for flag in HOLD_FLAGS},
        }
        save_json(output / "PRIVATE-agenda-bindings.json", bindings)
        file_new(output / "PRIVATE-HUMAN-agenda-template.csv",
                 csv_bytes(rows_default(positions, digest)))
        file_new(output / "PRIVATE-HUMAN-agenda-editor.html",
                 render_agenda_board(positions, digest))
        index = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; connect-src 'none'">
<title>LightUp PRIVATE HUMAN next discussion agenda</title><style>""" +
                 STYLE + """</style><header><aside><b>PRIVATE HUMAN-ONLY / HOLD</b>
<p>No actual task, assignment, authenticated owner, deadline,
consent, grant, client security finding or release.</p></aside>
<h1>Offline HUMAN follow-up proposal workspace</h1>
<p>""" + str(len(positions)) + """ original source positions, independently
re-admitted against their latest completed original HUMAN packet.</p>
<ul><li><a href="PRIVATE-HUMAN-agenda-editor.html">Open offline PRIVATE HUMAN agenda editor</a></li>
<li><a href="PRIVATE-HUMAN-agenda-template.csv">Original-complete PRIVATE CSV template</a></li>
<li><a href="PRIVATE-agenda-bindings.json">Original unsigned source-bound PRIVATE bindings</a></li></ul>
<p>Native `notes.py agenda-finalize` must separately re-admit all original bytes
and an explicitly completed PRIVATE CSV. Nothing is scheduled or sent.</p>
</header></html>""")
        file_new(output / "OPEN-PRIVATE.html", index.encode("utf-8"))
        complete = True
        print("REVIEW_ONLY: local PRIVATE original HUMAN follow-up agenda prepared.")
        print("OPEN LOCALLY: " + str(output / "OPEN-PRIVATE.html"))
        return 2
    finally:
        if not complete:
            shutil.rmtree(output)


def admit_completed_csv(raw: bytes, positions: list[dict], digest: str) -> list[dict]:
    try:
        content = raw.decode("utf-8", errors="strict")
        if not content or "\x00" in content:
            raise ValueError()
        reader = csv.DictReader(io.StringIO(content, newline=""), strict=True)
        if reader.fieldnames != list(FIELDS):
            raise ValueError()
        proposed = list(reader)
    except (UnicodeError, csv.Error, ValueError):
        raise Hold("HOLD: PRIVATE HUMAN agenda CSV is invalid") from None
    if len(proposed) != len(positions):
        raise Hold("HOLD: incomplete or extra original HUMAN agenda rows")
    admitted = []
    for slot, (item, original) in enumerate(zip(proposed, positions), 1):
        if (type(item) is not dict or None in item
                or set(item) != set(FIELDS)
                or item["original_source_ordinal"] != str(slot)
                or item["original_human_stage"] != original["original_human_stage"]
                or item["history_sha256_unsigned"] != digest
                or item["human_proposal"] not in ACTIONS
                or item["proposed_team"] not in TEAMS):
            raise Hold("HOLD: source-bound HUMAN agenda identity or choice changed")
        day = item["proposed_day"]
        if day:
            try:
                if len(day) != 10 or date.fromisoformat(day).isoformat() != day:
                    raise ValueError()
            except ValueError:
                raise Hold("HOLD: HUMAN proposed calendar date is not exact ISO day") from None
        question = item["private_human_question"]
        if (type(question) is not str or len(question) > 300
                or question.lstrip().startswith(("=", "+", "-", "@"))
                or unsafe_private_csv_note(question, 300)
                or any(ord(ch) < 32 and ch not in "\t" for ch in question)):
            raise Hold("HOLD: PRIVATE HUMAN discussion question must be short literal text")
        if item["human_proposal"] == "NO_PROPOSAL" and (
                item["proposed_team"] != "UNASSIGNED" or day or question):
            raise Hold("HOLD: unscheduled HUMAN row has hidden action details")
        admitted.append({
            "original_source_ordinal": slot,
            "original_human_stage": original["original_human_stage"],
            "human_proposal": item["human_proposal"],
            "proposed_team": item["proposed_team"],
            "proposed_day": day,
            "private_human_question": question,
        })
    return admitted


def finalize(agenda_kit: str, history_kit: str, latest_packet: str,
             completed_csv: str, parent_path: str) -> int:
    parent = private_directory(parent_path)
    kit = private_directory(agenda_kit)
    _, digest, positions, manifest_hash, last_csv_hash = canonical_history(
        history_kit, latest_packet)
    _, bindings = read_original_json(kit / "PRIVATE-agenda-bindings.json", 64 * 1024)
    if (type(bindings) is not dict
            or set(bindings) != {"schema", "claimed_status", "history_sha256_unsigned",
                                 "last_original_manifest_sha256_unsigned",
                                 "last_original_human_csv_sha256_unsigned",
                                 "original_source_count", "source_positions", *HOLD_FLAGS}
            or bindings["schema"] != SCHEMA or bindings["claimed_status"] != "HOLD"
            or bindings["history_sha256_unsigned"] != digest
            or bindings["last_original_manifest_sha256_unsigned"] != manifest_hash
            or bindings["last_original_human_csv_sha256_unsigned"] != last_csv_hash
            or type(bindings["original_source_count"]) is not int
            or bindings["original_source_count"] != len(positions)
            or bindings["source_positions"] != positions
            or any(bindings[flag] is not False for flag in HOLD_FLAGS)):
        raise Hold("HOLD: PRIVATE HUMAN agenda source-bound roster changed")
    original_csv = private_input(str(kit / "PRIVATE-HUMAN-agenda-template.csv"), 64 * 1024)
    if original_csv != csv_bytes(rows_default(positions, digest)):
        raise Hold("HOLD: original PRIVATE HUMAN agenda template changed")
    raw = private_input(completed_csv, 64 * 1024)
    reviewed = admit_completed_csv(raw, positions, digest)
    selected = [row for row in reviewed if row["human_proposal"] != "NO_PROPOSAL"]
    output = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-human-agenda-review-", dir=parent))
    os.chmod(output, 0o700)
    complete = False
    try:
        document = {
            "schema": "lightup.private_assessment_human_agenda_review.v1",
            "claimed_status": "HOLD",
            "history_sha256_unsigned": digest,
            "latest_original_manifest_sha256_unsigned": manifest_hash,
            "latest_original_decisions_sha256_unsigned": last_csv_hash,
            "completed_human_csv_sha256_unsigned": sha256(raw).hexdigest(),
            "original_source_count": len(positions),
            "proposed_discussion_count": len(selected),
            "not_an_actual_assignment": True,
            **{flag: False for flag in HOLD_FLAGS},
            "private_human_proposals": selected,
        }
        save_json(output / "PRIVATE-HUMAN-agenda-review.json", document)
        file_new(output / "PRIVATE-HUMAN-agenda-reviewed.csv",
                 csv_bytes([{**r, "history_sha256_unsigned": digest} for r in reviewed]))
        table = "".join(
            "<tr><td>#" + str(row["original_source_ordinal"]) + "</td><td>" +
            html.escape(row["original_human_stage"]) + "</td><td>" +
            html.escape(row["human_proposal"]) + "</td><td>" +
            html.escape(row["proposed_team"]) + "</td><td>" +
            html.escape(row["proposed_day"] or "Not proposed") + "</td><td>" +
            html.escape(row["private_human_question"]) + "</td></tr>" for row in selected
        )
        page = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; connect-src 'none'; form-action 'none'">
<title>LightUp PRIVATE HUMAN discussion proposals</title><style>""" + STYLE +
                """</style><header><aside><b>HOLD · PRIVATE HUMAN DISCUSSION ONLY</b>
<p>Manual, unsigned HUMAN concepts. No identity, communication, task,
calendar entry, client permission, verified risk, or scan.</p></aside>
<h1>Original source-bound HUMAN follow-up proposals</h1><p>""" +
                str(len(selected)) + " of " + str(len(positions)) +
                """ original cases have an explicit local discussion proposal.
All other original cases remain NO_PROPOSAL.</p></header>
<article><table><thead><tr><th>Original slot</th><th>Last HUMAN stage</th>
<th>Proposal</th><th>Human team suggestion</th><th>Proposed day</th>
<th>PRIVATE question</th></tr></thead><tbody>""" +
                (table or "<tr><td colspan='6'>No HUMAN proposals recorded</td></tr>") +
                """</tbody></table></article><article>
<a href="PRIVATE-HUMAN-agenda-review.json">PRIVATE original-bound JSON</a> ·
<a href="PRIVATE-HUMAN-agenda-reviewed.csv">Complete PRIVATE HUMAN CSV</a>
<p>No external recipient, review, owner, deadline or real action exists
as a result of this local file. Re-check authentic source owner,
privacy/security and current separate consent before actual use.</p>
</article></html>""")
        file_new(output / "OPEN-PRIVATE.html", page.encode("utf-8"))
        complete = True
        print("HOLD: source-bound PRIVATE HUMAN agenda review saved locally, NOT scheduled.")
        print("OPEN LOCALLY: " + str(output / "OPEN-PRIVATE.html"))
        return 3
    finally:
        if not complete:
            shutil.rmtree(output)


def main() -> int:
    cli = argparse.ArgumentParser(description="Offline PRIVATE HUMAN agenda; no execution or permission")
    sub = cli.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--history-kit", required=True)
    prep.add_argument("--latest-packet", required=True)
    prep.add_argument("--private-parent", required=True)
    end = sub.add_parser("finalize")
    end.add_argument("--agenda-kit", required=True)
    end.add_argument("--history-kit", required=True)
    end.add_argument("--latest-packet", required=True)
    end.add_argument("--completed-csv", required=True)
    end.add_argument("--private-parent", required=True)
    args = cli.parse_args()
    try:
        if args.command == "prepare":
            return prepare(args.history_kit, args.latest_packet, args.private_parent)
        return finalize(args.agenda_kit, args.history_kit, args.latest_packet,
                        args.completed_csv, args.private_parent)
    except (Hold, OSError, KeyError, ValueError, TypeError) as exc:
        print(str(exc) if isinstance(exc, Hold) else
              "HOLD: original PRIVATE HUMAN agenda refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.modules.setdefault("notes", __import__("notes"))
    raise SystemExit(main())
