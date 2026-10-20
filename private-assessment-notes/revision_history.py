#!/usr/bin/env python3
"""Source-bound original PRIVATE HUMAN review history and next-discussion desk.

Reconciles completed direct native revisions only; never a security verdict,
permission grant, scan, transmission, or proof of reviewer authentication.
"""
from __future__ import annotations

import argparse
import csv
from hashlib import sha256
import html
import io
import os
from pathlib import Path
import shutil
import sys
import tempfile

from notes import ALLOWED, FALSE_FLAGS, Hold, file_new, private_directory, save_json
from revision_changes import admit_completed
from history_board import render as render_history_browser

SCHEMA = "lightup.private_assessment_human_history.v1"
MAX_PACKETS = 16
EVENT_FIELDS = (
    "revision_level", "original_source_ordinal", "previous_human_stage",
    "current_human_stage", "stage_changed", "private_note_changed",
)
LATEST_FIELDS = (
    "original_source_ordinal", "current_human_stage", "stage_changes_total",
    "private_note_changes_total", "last_changed_revision", "human_action_needed",
)
HUMAN_ACTION = {"NEEDS_HUMAN_REVIEW", "SOURCE_OWNER_REQUIRED", "WITHHOLD"}
STYLE = """body{font:16px/1.6 system-ui;max-width:1120px;margin:auto;padding:24px;color:#172c41}
h1{font-size:clamp(1.65rem,4vw,2.5rem)}section,header{background:#f9fbfe;
border:1px solid #d4e0e8;border-radius:12px;padding:18px;margin:18px 0}
.warn{border-left:5px solid #ad4b28;background:#fff0e8;padding:14px}
table{width:100%;border-collapse:collapse}th,td{border:1px solid #b4c5d3;
padding:9px;text-align:left;vertical-align:top}th{background:#e5edf4}
a{color:#135577}a:focus-visible{outline:3px solid #a76b22}
small{color:#405367}details{margin:10px 0}
@media print{body{max-width:none;padding:0}section{break-inside:avoid}}"""


def csv_bytes(fields: tuple[str, ...], rows: list[dict]) -> bytes:
    out = io.StringIO(newline="")
    writer = csv.DictWriter(out, fieldnames=fields, lineterminator="\r\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({field: row[field] for field in fields})
    return out.getvalue().encode("utf-8")


def build_history(packet_dirs: list[str], parent_path: str) -> int:
    if not 2 <= len(packet_dirs) <= MAX_PACKETS:
        raise Hold("HOLD: select 2-16 sequential original completed HUMAN packets")
    parent = private_directory(parent_path)
    normalized = [private_directory(path) for path in packet_dirs]
    if len(set(normalized)) != len(normalized):
        raise Hold("HOLD: repeated original HUMAN packet is not a revision")

    snapshots = [admit_completed(str(path)) for path in normalized]
    reference = snapshots[0][3]  # original source roster, not an approval
    source_count = len(reference)
    level0 = snapshots[0][0].get("revision_level", 0)
    if type(level0) is not int or not 0 <= level0 <= 32:
        raise Hold("HOLD: original HUMAN revision level is malformed")
    previous = snapshots[0]
    for current in snapshots[1:]:
        prev_manifest, prev_raw, prev_csv, prev_sources, prev_rows, _ = previous
        manifest, _, _, sources, rows, _ = current
        level = manifest.get("revision_level")
        prior_level = prev_manifest.get("revision_level", 0)
        if (type(prior_level) is not int or type(level) is not int
                or level != prior_level + 1 or level > 32
                or manifest.get("prior_packet_manifest_sha256_unsigned") != sha256(prev_raw).hexdigest()
                or manifest.get("prior_human_decisions_sha256_unsigned") != sha256(prev_csv).hexdigest()
                or sources != reference or prev_sources != reference
                or [item["redacted_text"] for item in rows] !=
                   [item["redacted_text"] for item in prev_rows]):
            raise Hold("HOLD: HUMAN packet chain does not preserve exact direct-original lineage")
        previous = current

    events = []
    changes_per_source = [
        {"stage": 0, "note": 0, "last": level0} for _ in reference
    ]
    for earlier, later in zip(snapshots, snapshots[1:]):
        earlier_decisions = earlier[5]
        latest_decisions = later[5]
        level = later[0]["revision_level"]
        for i, (old, new) in enumerate(zip(earlier_decisions, latest_decisions), start=1):
            stage_change = old["human_stage"] != new["human_stage"]
            note_change = old["human_note"] != new["human_note"]
            if not (stage_change or note_change):
                continue
            events.append({
                "revision_level": level,
                "original_source_ordinal": i,
                "previous_human_stage": old["human_stage"],
                "current_human_stage": new["human_stage"],
                "stage_changed": stage_change,
                "private_note_changed": note_change,
            })
            if stage_change:
                changes_per_source[i-1]["stage"] += 1
            if note_change:
                changes_per_source[i-1]["note"] += 1
            changes_per_source[i-1]["last"] = level

    final = snapshots[-1]
    final_decisions = final[5]
    rows = []
    for i, (decision, counts) in enumerate(zip(final_decisions, changes_per_source), start=1):
        current = decision["human_stage"]
        rows.append({
            "original_source_ordinal": i,
            "current_human_stage": current,
            "stage_changes_total": counts["stage"],
            "private_note_changes_total": counts["note"],
            "last_changed_revision": counts["last"] if (
                counts["stage"] or counts["note"]) else "",
            "human_action_needed": current in HUMAN_ACTION,
        })
    current_totals = {stage: sum(d["human_stage"] == stage for d in final_decisions)
                      for stage in ALLOWED}
    manifest = {
        "schema": SCHEMA,
        "claimed_status": "HOLD",
        "source_authenticated": False,
        "recipient_authenticated": False,
        "actual_findings_verified": False,
        "original_source_count": source_count,
        "revision_packet_count": len(snapshots),
        "first_revision_level": level0,
        "last_revision_level": final[0]["revision_level"],
        "human_event_count": len(events),
        "human_discussion_needed_count": sum(row["human_action_needed"] for row in rows),
        "last_review_stage_counts": current_totals,
        "packets": [
            {
                "revision_level": item[0].get("revision_level", 0),
                "manifest_sha256_unsigned": sha256(item[1]).hexdigest(),
                "human_decisions_sha256_unsigned": sha256(item[2]).hexdigest(),
            } for item in snapshots
        ],
        **{flag: False for flag in FALSE_FLAGS},
        "events": events,
        "current_source_positions": rows,
    }

    # Completed original private sources must remain private. The derived
    # history purposely has no names, masked text, source hashes or HUMAN notes
    # in its HTML/CSV; the owner-private manifest only binds packet bytes.
    events_html = "".join(
        "<tr><td>" + str(event["revision_level"]) + "</td><td>#" +
        str(event["original_source_ordinal"]) + "</td><td>" +
        html.escape(event["previous_human_stage"]) + "</td><td>" +
        html.escape(event["current_human_stage"]) + "</td><td>" +
        ("Changed" if event["stage_changed"] else "Unchanged") + "</td><td>" +
        ("Changed, text withheld" if event["private_note_changed"] else "Unchanged") +
        "</td></tr>" for event in events
    )
    latest_html = "".join(
        "<tr><td>#" + str(row["original_source_ordinal"]) + "</td><td>" +
        html.escape(row["current_human_stage"]) + "</td><td>" +
        str(row["stage_changes_total"]) + "</td><td>" +
        str(row["private_note_changes_total"]) + "</td><td>" +
        (str(row["last_changed_revision"]) if row["last_changed_revision"] != "" else "—") +
        "</td><td>" + ("HUMAN follow-up" if row["human_action_needed"] else
                        "Internal PRIVATE discussion only") + "</td></tr>" for row in rows
    )
    timeline = "".join(
        "<li>Original completed PRIVATE revision " + str(item[0].get("revision_level", 0)) +
        ": " + str(len(item[5])) + " original source positions, unsigned byte-bound packet</li>"
        for item in snapshots
    )
    page = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp PRIVATE HUMAN original review history</title>
<style>""" + STYLE + """</style><header>
<p class="warn"><b>HOLD · PRIVATE HUMAN REVIEW ONLY</b><br>
Not security clearance, customer authorization, authenticated reviewer history,
remediation evidence or permission to share. Nothing was sent.</p>
<h1>Original source-bound HUMAN review history</h1><p>""" +
    str(source_count) + " original positions · " + str(len(snapshots)) +
    " completed consecutive PRIVATE HUMAN revisions · " + str(len(events)) +
    " declared HUMAN change events · " +
    str(manifest["human_discussion_needed_count"]) +
    """ latest positions for HUMAN follow-up.</p><p>Only ordinals and declared review stages
    appear here. PRIVATE free-text notes, masked source content and all original
    source names are excluded from this report.</p></header>
<section><h2>Recorded original revision sequence</h2><ol>""" + timeline +
    """</ol></section><section><h2>Current PRIVATE HUMAN discussion desk</h2>
<table><thead><tr><th>Original slot</th><th>Latest declared HUMAN stage</th>
<th>Stage changes</th><th>PRIVATE note changed</th>
<th>Last changed revision</th><th>Local follow-up</th></tr></thead>
<tbody>""" + latest_html + """</tbody></table></section>
<section><h2>Declared HUMAN event history</h2><table><thead>
<tr><th>Revision</th><th>Original slot</th><th>Previous stage</th>
<th>Current stage</th><th>Stage</th><th>Free-text note</th></tr></thead>
<tbody>""" + (events_html or "<tr><td colspan='6'>No declared HUMAN changes</td></tr>") +
    """</tbody></table></section><section><h2>PRIVATE local exports</h2>
<ul><li><a href="PRIVATE-HUMAN-board.html">Interactive offline source-minimal HUMAN timeline explorer</a></li>
<li><a href="PRIVATE-HUMAN-history.json">Original-byte-bound unsigned PRIVATE history JSON</a></li>
<li><a href="PRIVATE-HUMAN-events.csv">Source-minimal declared change events CSV</a></li>
<li><a href="PRIVATE-HUMAN-current-review.csv">Current HUMAN discussion desk CSV</a></li>
</ul><small>Unsigned local hashes only bind bytes: they do not authenticate
a person, grant or recipient. This local page is not a completed review or
security PASS; decisions still require the native original HUMAN process.</small>
</section><footer>Incubate M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.
No active assessment, network, model, scan, grant or deployment.</footer></html>""")
    destination = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-human-history-", dir=parent))
    os.chmod(destination, 0o700)
    finished = False
    try:
        save_json(destination / "PRIVATE-HUMAN-history.json", manifest)
        file_new(destination / "PRIVATE-HUMAN-events.csv", csv_bytes(EVENT_FIELDS, events))
        file_new(destination / "PRIVATE-HUMAN-current-review.csv",
                 csv_bytes(LATEST_FIELDS, rows))
        file_new(destination / "PRIVATE-HUMAN-board.html",
                 render_history_browser(rows, events, len(snapshots)))
        file_new(destination / "OPEN-PRIVATE.html", page.encode("utf-8"))
        finished = True
        print("HOLD: PRIVATE original-bound multi-revision HUMAN history created locally.")
        print("OPEN LOCALLY: " + str(destination / "OPEN-PRIVATE.html"))
        return 3
    finally:
        if not finished:
            shutil.rmtree(destination)


def main() -> int:
    cli = argparse.ArgumentParser(
        description="PRIVATE offline original-source HUMAN revision history; no execution or grant")
    cli.add_argument("--packet", action="append", required=True,
                     help="completed owner-private HUMAN packet, ordered earliest to latest (2-16)")
    cli.add_argument("--private-parent", required=True, help="owner-private directory 0700")
    args = cli.parse_args()
    try:
        return build_history(args.packet, args.private_parent)
    except (Hold, OSError, KeyError, ValueError) as exc:
        print(str(exc) if isinstance(exc, Hold) else
              "HOLD: original PRIVATE HUMAN history refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
