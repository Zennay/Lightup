"""PRIVATE source-bound HUMAN HAR review-round history, never approval."""
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

from notes import (FALSE_FLAGS, Hold, file_new, load_workroom,
                   private_directory, private_input, save_json)
from private_har_worklist import entries, worksheet_csv
from private_har_progress import _edited, reopen_progress

SCHEMA = "lightup.private_har_manual_history.v1"
MAX_ROUNDS = 8
MAX_OUTPUT_BYTES = 256 * 1024
BASE_FIELDS = ("original_ordinal", "review_area", "literal_cue_count",
               "next_human_action")
CLOSED = "HUMAN_REVIEWED"  # a typed label only; it is NEVER approval.


def _admit(original: str, cue: str, rounds: list[str]):
    if not 2 <= len(rounds) <= MAX_ROUNDS:
        raise Hold("HOLD: choose 2–8 separate original PRIVATE human-status rounds")
    absolute = [str(Path(p).absolute()) for p in rounds]
    if len(set(absolute)) != len(absolute):
        raise Hold("HOLD: repeated PRIVATE human-status round")
    kit = private_directory(original)
    cue_room = private_directory(cue)
    _binding, _sources, originals = load_workroom(kit)
    original_rows = entries(originals)
    template = worksheet_csv(originals)
    histories = []
    receipt_hashes = []
    for name in absolute:
        folder = private_directory(name)
        # Native original+cue+human progress byte-for-byte admission. No
        # source inference, tampering acceptance or implicit owner authority.
        if reopen_progress(str(kit), str(cue_room), str(folder)) != 3:
            raise Hold("HOLD: an original source-bound HUMAN round is invalid")
        edited = private_input(str(folder / "PRIVATE-HAR-HUMAN-edited-actions.csv"),
                               65536)
        parsed = _edited(edited, original_rows)
        histories.append([item["human_status"] for item in parsed])
        receipt_hashes.append(sha256(private_input(
            str(folder / "PRIVATE-HAR-status-receipt.json"), 65536
        )).hexdigest())
    return original_rows, template, histories, receipt_hashes


def _longitudinal(original_rows: list[dict], rounds: list[list[str]]):
    summary = []
    for index, source in enumerate(original_rows):
        states = [round_status[index] for round_status in rounds]
        changed = sum(before != after for before, after
                      in zip(states, states[1:]))
        reopened = any(before == CLOSED and after != CLOSED
                       for before, after in zip(states, states[1:]))
        summary.append({
            **{key: source[key] for key in BASE_FIELDS},
            "manually_changed_rounds": changed,
            "reopened_after_human_marked_review": int(reopened),
            "last_human_status": states[-1],
            "status_by_round": states,
        })
    return summary


def _csv(rows: list[dict], n: int) -> bytes:
    names = (*BASE_FIELDS, *(f"manual_round_{i+1}" for i in range(n)),
             "manually_changed_rounds", "reopened_after_human_marked_review",
             "last_human_status")
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=names, lineterminator="\r\n")
    writer.writeheader()
    for item in rows:
        values = {field: item[field] for field in BASE_FIELDS}
        values.update({f"manual_round_{i+1}": stage
                       for i, stage in enumerate(item["status_by_round"])})
        values.update({field: item[field] for field in names[-3:]})
        writer.writerow(values)
    return output.getvalue().encode("utf-8")


def _html(rows: list[dict], n: int) -> bytes:
    labels = "".join("<th scope='col'>Manually ordered R" +
                     str(i+1) + "</th>" for i in range(n))
    details = []
    for item in rows:
        vals = item["status_by_round"]
        stages = "".join("<td>" + escape(value) + "</td>" for value in vals)
        marker = ("HUMAN status reopened" if
                  item["reopened_after_human_marked_review"] else
                  "No review reopening indicated")
        details.append(
            "<tr><th scope='row'>Original #" +
            str(item["original_ordinal"]) + "</th><td>" +
            escape(item["review_area"].replace("_", " ")) +
            "</td><td>" + str(item["literal_cue_count"]) +
            " literal cues</td>" + stages + "<td>" +
            str(item["manually_changed_rounds"]) + "</td><td>" +
            escape(marker) + "</td></tr>"
        )
    unreviewed = sum(item["last_human_status"] != CLOSED for item in rows)
    changed = sum(item["manually_changed_rounds"] > 0 for item in rows)
    reopened = sum(item["reopened_after_human_marked_review"] for item in rows)
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';form-action 'none';base-uri 'none';object-src 'none'">
<title>LightUp PRIVATE HUMAN HAR work history</title>
<style>body{font:16px/1.5 system-ui;max-width:1200px;margin:2rem auto;
padding:1rem;color:#173346}aside{background:#fff0e5;border-left:5px solid #a85b33;
padding:1rem}table{border-collapse:collapse;width:100%}
th,td{border:1px solid #c2cdd7;padding:.5rem;text-align:left}
thead{background:#f0f4f8}.scroll{overflow-x:auto}
@media print{tr{break-inside:avoid}body{max-width:none;margin:0}}
</style><h1>PRIVATE original HAR HUMAN status history</h1>
<aside><b>INCUBATE / REVIEW_ONLY / HOLD.</b> Rounds are placed in the
operator's manual supplied order — not independently authenticated times.
All states are unverified self-reports. HUMAN_REVIEWED is NOT a completed
privacy/security assessment, release, client consent, authorized scan or
safe-sharing verdict. Even zero changes does not mean safe or complete.
No raw sources, names, URLs, hashes, paths or HUMAN free-text notes appear.</aside>
<p>Manual rounds: """ + str(n) + """. Original actions: """ + str(len(rows)) +
""". Latest human status is not HUMAN_REVIEWED on """ + str(unreviewed) +
""" actions; changed at least once: """ + str(changed) +
"""; manually re-opened after a prior HUMAN_REVIEWED label: """ +
str(reopened) + """. Treat these as coordination hints, NOT findings.</p>
<div class="scroll"><table><thead><tr><th>Original</th><th>Task area</th>
<th>Literal cue count</th>""" + labels + """
<th>Changed rounds</th><th>Review-reopened cue</th></tr></thead><tbody>""" +
"".join(details) + """</tbody></table></div>
<p>Consult original PRIVATE packets and source owners separately. Report
bytes are source-bound by unsigned local digests, not trusted signatures.
No browser scripts, network, scanner, external handoff, grant or deployment.</p>
</html>""").encode("utf-8")


def _package(rows: list[dict], template: bytes,
             histories: list[list[str]], receipts: list[str]):
    summary = _longitudinal(rows, histories)
    page = _html(summary, len(histories))
    csv_bytes = _csv(summary, len(histories))
    if max(len(page), len(csv_bytes)) > MAX_OUTPUT_BYTES:
        raise Hold("HOLD: PRIVATE HUMAN history output exceeds bounded size")
    receipt = {
        "schema": SCHEMA, "claimed_status": "HOLD",
        "status_is_unverified_human_report": True,
        "round_order_is_human_supplied_not_attested": True,
        "source_action_template_sha256_unsigned": sha256(template).hexdigest(),
        "round_receipt_sha256_unsigned_in_operator_order": receipts,
        "round_count": len(histories), "original_action_count": len(rows),
        "history_html_sha256_unsigned": sha256(page).hexdigest(),
        "history_csv_sha256_unsigned": sha256(csv_bytes).hexdigest(),
        **{key: False for key in FALSE_FLAGS},
    }
    receipt_bytes = (json.dumps(receipt, indent=2, sort_keys=True,
                                ensure_ascii=False) + "\n").encode("utf-8")
    return page, csv_bytes, receipt_bytes


def create(original: str, cue: str, rounds: list[str], parent: str) -> int:
    _parent = private_directory(parent)
    rows, template, history, hashes = _admit(original, cue, rounds)
    page, csv_bytes, receipt = _package(rows, template, history, hashes)
    output = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-har-review-history-",
                                   dir=_parent))
    os.chmod(output, 0o700)
    ready = False
    try:
        file_new(output / "PRIVATE-HAR-HISTORY.html", page)
        file_new(output / "PRIVATE-HAR-HISTORY.csv", csv_bytes)
        file_new(output / "PRIVATE-HAR-HISTORY-receipt.json", receipt)
        ready = True
        print("HOLD: PRIVATE HUMAN HAR review rounds prepared, not authorised")
        print("OPEN LOCALLY: " + str(output / "PRIVATE-HAR-HISTORY.html"))
        return 3
    finally:
        if not ready:
            shutil.rmtree(output)


def reopen(original: str, cue: str, rounds: list[str], prior: str) -> int:
    room = private_directory(prior)
    rows, template, history, hashes = _admit(original, cue, rounds)
    page, csv_bytes, receipt = _package(rows, template, history, hashes)
    for filename, expected in (
        ("PRIVATE-HAR-HISTORY.html", page),
        ("PRIVATE-HAR-HISTORY.csv", csv_bytes),
        ("PRIVATE-HAR-HISTORY-receipt.json", receipt),
    ):
        if private_input(str(room / filename), MAX_OUTPUT_BYTES) != expected:
            raise Hold("HOLD: original-bound PRIVATE HAR history bytes changed")
    print("HOLD: PRIVATE HUMAN HAR history reopened read-only; no authorisation")
    print("OPEN LOCALLY: " + str(room / "PRIVATE-HAR-HISTORY.html"))
    return 3
