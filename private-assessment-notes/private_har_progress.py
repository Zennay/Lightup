"""Offline source-bound HAR HUMAN progress import; never clearance or consent."""
from __future__ import annotations
import csv
from hashlib import sha256
from html import escape
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
from notes import Hold, FALSE_FLAGS, file_new, load_workroom, private_directory, private_input, save_json
from private_har_worklist import FIELDS, entries, worksheet_csv
from private_masking_cues import reopen as reopen_cues

STATES = frozenset(("PENDING_HUMAN", "IN_PROGRESS", "HUMAN_REVIEWED",
                    "SOURCE_OWNER_NEEDED", "WITHHOLD"))
REPORT_FIELDS = ("original_ordinal", "review_area", "human_status")
SCHEMA = "lightup.private_har_manual_progress.v2"


def _edited(raw: bytes, expected: list[dict]) -> list[dict]:
    try:
        source = raw.decode("utf-8", errors="strict")
        parsed = csv.DictReader(io.StringIO(source, newline=""), strict=True)
        if parsed.fieldnames != list(FIELDS):
            raise ValueError("unexpected or reordered original action columns")
        result = list(parsed)
        if len(result) != len(expected):
            raise ValueError("missing or extra original action")
        for proposed, original in zip(result, expected):
            if None in proposed or set(proposed) != set(FIELDS):
                raise ValueError("malformed action row")
            for field in FIELDS[:4]:
                if proposed[field] != str(original[field]):
                    raise ValueError("original action identity changed")
            if proposed["human_status"] not in STATES:
                raise ValueError("unknown HUMAN status")
            # Never transfer arbitrary HUMAN free text to derived pages.
            # Retain the editable CSV privately with the original owner.
            if proposed["human_notes"]:
                raise ValueError("clear free-text notes before source-free import")
        return result
    except (UnicodeError, csv.Error, ValueError, TypeError) as exc:
        raise Hold("HOLD: original-bound PRIVATE HAR actions invalid: " + str(exc)) from None


def _dashboard(rows: list[dict]) -> bytes:
    from collections import Counter
    totals = Counter(item["human_status"] for item in rows)
    lines = []
    for row in rows:
        lines.append("<tr><td>Original #" +
                     escape(row["original_ordinal"]) + "</td><td>" +
                     escape(row["review_area"].replace("_", " ")) +
                     "</td><td>" + escape(row["human_status"]) + "</td></tr>")
    summary = " · ".join(escape(k) + ": " + str(totals[k])
                         for k in sorted(STATES))
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';form-action 'none';base-uri 'none';object-src 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LightUp PRIVATE HAR manual work status</title>
<style>body{font:16px/1.5 system-ui;max-width:970px;margin:2rem auto;padding:1rem}
aside{background:#fff1e5;border-left:5px solid #aa5e32;padding:1rem}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #bbc4cd;padding:.5rem}
@media print{tr{break-inside:avoid}}</style>
<h1>PRIVATE HUMAN HAR action status</h1>
<aside><b>UNVERIFIED HUMAN SELF-REPORT · REVIEW_ONLY / HOLD.</b>
Statuses are typed by a local human, not checked against actual original
sources. Even HUMAN_REVIEWED is NOT privacy proof, clearance, consent,
a verified finding, grant, assessment authority or release.
Source holder must independently examine unchanged original material.
No original source bytes, names, URLs, hashes or free-text HUMAN notes
are present here.</aside><p>""" + summary + """</p>
<table><thead><tr><th>Original</th><th>Action</th><th>Manual status</th>
</tr></thead><tbody>""" + "".join(lines) + """</tbody></table>
<p>No storage, scripts, network, recipients or automatic action.
This report never modifies the original decision/receipt packet.</p></html>"""
            ).encode("utf-8")


def _status_csv(rows: list[dict]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=REPORT_FIELDS, lineterminator="\r\n")
    writer.writeheader()
    writer.writerows({field: row[field] for field in REPORT_FIELDS} for row in rows)
    return stream.getvalue().encode("utf-8")


def import_progress(original_kit: str, cue_room: str, edited_actions: str,
                    private_parent: str,
                    created_room: list[Path] | None = None) -> int:
    original = private_directory(original_kit)
    room = private_directory(cue_room)
    parent = private_directory(private_parent)
    _bindings, _sources, sources = load_workroom(original)
    # Recompute all original source-bound receipts and exact immutable pages.
    if reopen_cues(str(original), str(room)) != 3:
        raise Hold("HOLD: original masking cues failed read-only admission")
    baseline = worksheet_csv(sources)
    if private_input(str(room / "PRIVATE-HAR-ACTIONS.csv"), 65536) != baseline:
        raise Hold("HOLD: original-bound PRIVATE action template changed")
    edited = private_input(edited_actions, 65536)
    parsed = _edited(edited, entries(sources))
    output = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-har-human-status-",
                                   dir=parent))
    os.chmod(output, 0o700)
    complete = False
    try:
        save_json(output / "PRIVATE-HAR-status-receipt.json", {
            "schema": SCHEMA,
            "claimed_status": "HOLD", "status_is_unverified_human_report": True,
            "original_worksheet_sha256_unsigned": sha256(baseline).hexdigest(),
            "edited_input_sha256_unsigned": sha256(edited).hexdigest(),
            "action_count": len(parsed),
            **{key: False for key in FALSE_FLAGS},
        })
        # Retain *only validated* human status fields, never arbitrary notes,
        # as source-bound bytes for a later entirely offline read-only reopen.
        file_new(output / "PRIVATE-HAR-HUMAN-edited-actions.csv", edited)
        file_new(output / "PRIVATE-HAR-HUMAN-status.html", _dashboard(parsed))
        file_new(output / "PRIVATE-HAR-HUMAN-status.csv", _status_csv(parsed))
        complete = True
        if created_room is not None:
            created_room.append(output)
        print("HOLD: local PRIVATE HUMAN status imported; NOT verified or authorised")
        print("OPEN LOCALLY: " + str(output / "PRIVATE-HAR-HUMAN-status.html"))
        return 3
    finally:
        if not complete:
            shutil.rmtree(output)


def reopen_progress(original_kit: str, cue_room: str,
                    progress_room: str) -> int:
    """Reconstruct every immutable report byte; do not trust typed statuses."""
    original = private_directory(original_kit)
    cues = private_directory(cue_room)
    report = private_directory(progress_room)
    _bindings, _sources, originals = load_workroom(original)
    if reopen_cues(str(original), str(cues)) != 3:
        raise Hold("HOLD: original cue admission failed")
    baseline = worksheet_csv(originals)
    # Only the original v18 generated worksheet is an admitted template.
    if private_input(str(cues / "PRIVATE-HAR-ACTIONS.csv"), 65536) != baseline:
        raise Hold("HOLD: original HAR actions template changed")
    edited = private_input(str(report / "PRIVATE-HAR-HUMAN-edited-actions.csv"),
                           65536)
    parsed = _edited(edited, entries(originals))
    expected_receipt = {
        "schema": SCHEMA, "claimed_status": "HOLD",
        "status_is_unverified_human_report": True,
        "original_worksheet_sha256_unsigned": sha256(baseline).hexdigest(),
        "edited_input_sha256_unsigned": sha256(edited).hexdigest(),
        "action_count": len(parsed),
        **{key: False for key in FALSE_FLAGS},
    }
    expected_receipt_bytes = (json.dumps(expected_receipt, indent=2,
                                         sort_keys=True, ensure_ascii=False)
                              + "\n").encode("utf-8")
    expected_files = (
        ("PRIVATE-HAR-status-receipt.json", expected_receipt_bytes),
        ("PRIVATE-HAR-HUMAN-status.html", _dashboard(parsed)),
        ("PRIVATE-HAR-HUMAN-status.csv", _status_csv(parsed)),
    )
    for name, expected in expected_files:
        if private_input(str(report / name), 65536) != expected:
            raise Hold("HOLD: immutable PRIVATE HAR manual progress packet changed")
    print("HOLD: original-bound PRIVATE HAR HUMAN status reopened read-only")
    print("OPEN LOCALLY: " + str(report / "PRIVATE-HAR-HUMAN-status.html"))
    return 3
