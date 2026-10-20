#!/usr/bin/env python3
"""Offline ORIGINAL source-exact HUMAN review revision delta; no security conclusion."""
from __future__ import annotations

import argparse
import csv
from hashlib import sha256
import html
import io
from pathlib import Path
import os
import shutil
import sys
import tempfile

from notes import (
    ALLOWED, FALSE_FLAGS, Hold, file_new, load_decisions,
    load_workroom, private_directory, private_input, save_json,
)

SCHEMA = "lightup.private_assessment_human_revision_changes.v1"
COLUMNS = (
    "original_source_ordinal", "previous_human_stage", "current_human_stage",
    "stage_changed", "private_note_changed",
)


def admit_completed(directory: str) -> tuple[dict, bytes, bytes, list[dict], list[dict], list[dict]]:
    original = private_directory(directory)
    manifest, sources, rows = load_workroom(original)
    if manifest.get("human_proposals_recorded") is not True:
        raise Hold("HOLD: HUMAN revision difference needs two completed PRIVATE packets")
    raw_manifest = private_input(str(original / "PRIVATE-source-bindings.json"), 128 * 1024)
    raw_csv = private_input(str(original / "PRIVATE-HUMAN-decisions.csv"), 64 * 1024)
    if (manifest.get("human_decisions_sha256_unsigned") != sha256(raw_csv).hexdigest()):
        raise Hold("HOLD: original completed HUMAN decision bytes changed")
    decisions = load_decisions(raw_csv, sources)
    expected = {stage: sum(row["human_stage"] == stage for row in decisions) for stage in ALLOWED}
    if manifest.get("human_stages") != expected:
        raise Hold("HOLD: original HUMAN stage roster differs from completed manifest")
    return manifest, raw_manifest, raw_csv, sources, rows, decisions


def compare(earlier_dir: str, later_dir: str, parent_dir: str) -> int:
    parent = private_directory(parent_dir)
    earlier = private_directory(earlier_dir)
    later = private_directory(later_dir)
    if earlier == later:
        raise Hold("HOLD: a HUMAN revision must be distinct from its original packet")
    a, a_raw, a_csv, sources_a, rows_a, decisions_a = admit_completed(str(earlier))
    b, b_raw, b_csv, sources_b, rows_b, decisions_b = admit_completed(str(later))
    prior_level = a.get("revision_level", 0)
    later_level = b.get("revision_level")
    if (type(prior_level) is not int or type(later_level) is not int
            or not 0 <= prior_level < 32 or later_level != prior_level + 1
            or b.get("prior_packet_manifest_sha256_unsigned") != sha256(a_raw).hexdigest()
            or b.get("prior_human_decisions_sha256_unsigned") != sha256(a_csv).hexdigest()):
        raise Hold("HOLD: second HUMAN packet is not an original-bound direct revision")
    if sources_a != sources_b:
        raise Hold("HOLD: original unmasked source identities differ between revisions")
    if ([row["redacted_text"] for row in rows_a] !=
            [row["redacted_text"] for row in rows_b]):
        raise Hold("HOLD: original masked source bytes changed during HUMAN revision")

    changes = []
    for slot, (previous, current) in enumerate(zip(decisions_a, decisions_b), start=1):
        stage_changed = previous["human_stage"] != current["human_stage"]
        note_changed = previous["human_note"] != current["human_note"]
        if stage_changed or note_changed:
            changes.append({
                "original_source_ordinal": slot,
                "previous_human_stage": previous["human_stage"],
                "current_human_stage": current["human_stage"],
                "stage_changed": stage_changed,
                "private_note_changed": note_changed,
            })

    destination = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-human-revision-changes-", dir=parent))
    os.chmod(destination, 0o700)
    complete = False
    try:
        data = {
            "schema": SCHEMA, "claimed_status": "HOLD",
            "original_source_count": len(sources_a),
            "changed_source_count": len(changes),
            "prior_revision_level": prior_level,
            "new_revision_level": later_level,
            "prior_manifest_sha256_unsigned": sha256(a_raw).hexdigest(),
            "current_manifest_sha256_unsigned": sha256(b_raw).hexdigest(),
            "prior_decisions_sha256_unsigned": sha256(a_csv).hexdigest(),
            "current_decisions_sha256_unsigned": sha256(b_csv).hexdigest(),
            "source_authenticated": False,
            "recipient_authenticated": False,
            "actual_findings_verified": False,
            **{flag: False for flag in FALSE_FLAGS},
            "changes": changes,
        }
        save_json(destination / "PRIVATE-HUMAN-changes.json", data)
        out = io.StringIO(newline="")
        writer = csv.DictWriter(out, fieldnames=COLUMNS, lineterminator="\r\n")
        writer.writeheader()
        for change in changes:
            writer.writerow(change)
        file_new(destination / "PRIVATE-HUMAN-changes.csv", out.getvalue().encode("utf-8"))
        rows = "".join(
            "<tr><td>#" + str(item["original_source_ordinal"]) + "</td><td>" +
            html.escape(item["previous_human_stage"]) + "</td><td>" +
            html.escape(item["current_human_stage"]) + "</td><td>" +
            ("Changed" if item["stage_changed"] else "Unchanged") + "</td><td>" +
            ("Changed, text withheld" if item["private_note_changed"] else "Unchanged") +
            "</td></tr>" for item in changes
        )
        page = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; connect-src 'none'; form-action 'none'">
<title>LightUp PRIVATE original HUMAN revision changes</title>
<style>body{font:16px/1.55 system-ui;max-width:1000px;margin:2rem auto;padding:1rem;color:#203047}
table{width:100%;border-collapse:collapse}td,th{border:1px solid #9bacba;padding:10px;text-align:left}
aside{background:#fff1e7;border-left:5px solid #a94626;padding:15px}
a{color:#13547a}a:focus-visible{outline:3px solid #bf7629}
@media print{body{max-width:100%;margin:0}}</style>
<h1>PRIVATE HUMAN review revision changes</h1>
<aside><b>HOLD · HUMAN-DECLARED CHANGES ONLY · NOT A SECURITY VERDICT</b>
<p>Original masked content and original note text were deliberately withheld
from this report. Even a direct original-byte-bound revision does not prove
authorship, client consent, security risk removal, source authenticity or
permission to share. This packet was prepared locally, not sent.</p></aside>
<p>Total unchanged original source roster: """ + str(len(sources_a)) +
""" · changed HUMAN decision positions: """ + str(len(changes)) +
""" · direct HUMAN revisions: """ + str(prior_level) + " → " + str(later_level) +
"""</p><table><thead><tr><th>Original source</th><th>Earlier HUMAN stage</th>
<th>Later HUMAN stage</th><th>Stage</th><th>PRIVATE HUMAN note</th></tr></thead>
<tbody>""" + (rows or "<tr><td colspan='5'>No HUMAN stage/note changes</td></tr>") +
"""</tbody></table>
<p><a href="PRIVATE-HUMAN-changes.json">Unsigned PRIVATE source-bound receipt</a>
· <a href="PRIVATE-HUMAN-changes.csv">PRIVATE changes CSV</a></p>
<footer>Incubate M3/M7 PLAN/LAB ONLY DRAFT/HOLD. No execution, scan, model,
network, authorization, external delivery, remediation assertion or release.</footer></html>""")
        file_new(destination / "OPEN-PRIVATE.html", page.encode("utf-8"))
        complete = True
        print("HOLD: original source-bound PRIVATE HUMAN revision changes prepared locally.")
        print("OPEN LOCALLY: " + str(destination / "OPEN-PRIVATE.html"))
        return 3
    finally:
        if not complete:
            shutil.rmtree(destination)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PRIVATE HUMAN direct revision change report; no client authority, network or scan")
    parser.add_argument("--earlier", required=True, help="completed original owner-private HUMAN packet")
    parser.add_argument("--later", required=True, help="completed direct HUMAN revision packet")
    parser.add_argument("--private-parent", required=True, help="existing owner-only 0700 directory")
    args = parser.parse_args()
    try:
        return compare(args.earlier, args.later, args.private_parent)
    except (Hold, OSError, ValueError, KeyError) as exc:
        print(str(exc) if isinstance(exc, Hold) else "HOLD: original HUMAN revision change review refused",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
