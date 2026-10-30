#!/usr/bin/env python3
"""PRIVATE HUMAN-only reassessment attention handoff from two original reviews.

No source/recipient authentication, security risk scoring, remediation assertion,
automatic outreach or permission to share. Explicit original-source re-admission.
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

from notes import Hold, file_new, private_directory, save_json
from privacy_triage import TOPICS, FALSE_FLAGS, completed_packet
from privacy_triage_history import load_round

SCHEMA = "lightup.private_notes_human_sensitivity_attention.v1"
FIELDS = ("original_ordinal", "earlier_human_status", "later_human_status",
          "earlier_human_topics", "later_human_topics",
          "human_labels_changed", "human_free_note_changed",
          "human_free_note_present")
KINDS = ("ALL_ATTENTION", "CHANGES_ONLY", "CURRENT_WITHHOLD")


def candidates(previous: list[dict], latest: list[dict], kind: str,
               topic: str | None) -> list[dict]:
    result = []
    for earlier, later in zip(previous, latest):
        label_changed = (
            earlier["review_status"] != later["review_status"]
            or earlier["privacy_topics"] != later["privacy_topics"]
        )
        note_changed = earlier["human_followup"] != later["human_followup"]
        changed = label_changed or note_changed
        current_attention = later["review_status"] in ("WITHHOLD", "REVIEW_REQUIRED")
        if kind == "ALL_ATTENTION":
            include = changed or current_attention
        elif kind == "CHANGES_ONLY":
            include = changed
        else:
            include = later["review_status"] == "WITHHOLD"
        if topic and topic not in later["privacy_topics"].split("|"):
            include = False
        if not include:
            continue
        result.append({
            "original_ordinal": int(later["source_ordinal"]),
            "earlier_human_status": earlier["review_status"],
            "later_human_status": later["review_status"],
            "earlier_human_topics": earlier["privacy_topics"],
            "later_human_topics": later["privacy_topics"],
            "human_labels_changed": label_changed,
            "human_free_note_changed": note_changed,
            "human_free_note_present": bool(later["human_followup"]),
        })
    return result


def csv_out(rows: list[dict]) -> bytes:
    out = io.StringIO(newline="")
    writer = csv.DictWriter(out, fieldnames=FIELDS, lineterminator="\r\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({
            column: ("TRUE" if row[column] else "FALSE")
            if column.startswith("human_") and type(row[column]) is bool
            else row[column]
            for column in FIELDS
        })
    return out.getvalue().encode("utf-8")


def page(rows: list[dict], kind: str, topic: str | None,
         identical_decisions: bool = False) -> bytes:
    tr = []
    for row in rows:
        tr.append(
            "<tr><th scope='row'>#" + str(row["original_ordinal"]) + "</th>" +
            "<td>" + html.escape(row["earlier_human_status"]) + " → " +
            html.escape(row["later_human_status"]) + "</td>" +
            "<td>" + html.escape(row["earlier_human_topics"]) + " → " +
            html.escape(row["later_human_topics"]) + "</td>" +
            "<td>" + ("Yes" if row["human_labels_changed"] else "No") +
            "</td><td>" + ("Yes" if row["human_free_note_changed"] else "No") +
            "</td><td>" + ("Yes" if row["human_free_note_present"] else "No") +
            "</td></tr>"
        )
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';base-uri 'none';connect-src 'none';form-action 'none';object-src 'none'">
<title>LightUp PRIVATE HUMAN attention board</title>
<style>body{max-width:1050px;margin:2rem auto;padding:1rem;font:16px/1.6 system-ui;color:#1c314c}
.warning{border-left:5px solid #ad4c2c;padding:1rem;background:#fff0e8}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #c9d8e3;text-align:left;padding:9px}
th{background:#f0f5fa}@media(max-width:700px){.scroll{overflow-x:auto}}
</style><h1>PRIVATE HUMAN sensitivity follow-up board</h1>
<aside class="warning"><strong>HOLD · NOT CLIENT CLEARED · HUMAN CONVERSATION ONLY</strong>
<p>This is a local category/status discussion proposal, never a finding, risk
score, verified fix, evidence sanitization, recipient clearance, actual consent,
authentication or security PASS. A category disappearing between HUMAN rounds
does not prove the sensitive material was removed. No original/masked content,
source filename/digest or free-human-note text is embedded in this page.</p></aside>
<p>Explicit selection: """ + html.escape(kind) + """;
latest HUMAN category: """ + html.escape(topic if topic else "ANY") +
           """ · selected original positions: """ + str(len(rows)) + """.</p>
<p>These two separate review packets have """ + ("byte-identical HUMAN decisions; identical content is NOT evidence of independent authors or clearance." if identical_decisions else "different HUMAN decision bytes; this is NOT proof of distinct authenticated authors.") + """</p>
<div class="scroll"><table><thead><tr><th>Original #</th>
<th>Earlier → later HUMAN label</th><th>Earlier → later declared categories</th>
<th>Labels changed?</th><th>PRIVATE note changed?</th>
<th>PRIVATE note present?</th></tr></thead><tbody>""" + "".join(tr) + """</tbody>
</table></div><p>No automatic action, data transfer, network, email, scan, grant,
deletion or review signoff. The PRIVATE manifest and selected-only CSV are for
an independent, authenticated HUMAN conversation only after original
consent/privacy/ownership gates. Incubate M3/M7 PLAN/LAB ONLY DRAFT/HOLD.</p>
</html>""").encode("utf-8")


def create(original: str, earlier: str, later: str, kind: str,
           topic: str | None, parent_string: str) -> int:
    if str(Path(earlier).absolute()) == str(Path(later).absolute()):
        raise Hold("HOLD: distinct completed original HUMAN reviews are required")
    parent = private_directory(parent_string)
    sources, manifest_sha, decisions_sha = completed_packet(original)
    left = load_round(earlier, sources, manifest_sha, decisions_sha)
    right = load_round(later, sources, manifest_sha, decisions_sha)
    identical_decisions = (
        left["csv_sha256_unsigned"] == right["csv_sha256_unsigned"]
    )
    # Genuine distinct completed packets may repeat unchanged HUMAN labels.
    # CHANGES_ONLY naturally finds no work and HOLDs, but CURRENT_WITHHOLD
    # still has legitimate, explicitly chosen PRIVATE HUMAN discussion work.
    positions = candidates(left["rows"], right["rows"], kind, topic)
    if not positions:
        raise Hold("HOLD: this explicit HUMAN conversation has no selected originals")
    kit = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-sensitivity-attention-", dir=parent))
    os.chmod(kit, 0o700)
    done = False
    try:
        packet = {
            "schema": SCHEMA,
            "claimed_status": "HOLD",
            "manual_order_not_verified_timestamp": True,
            "human_only_not_privacy_clearance": True,
            "original_manifest_sha256_unsigned": manifest_sha,
            "original_human_csv_sha256_unsigned": decisions_sha,
            "earlier_review_receipt_sha256_unsigned": left["receipt_sha256_unsigned"],
            "earlier_review_csv_sha256_unsigned": left["csv_sha256_unsigned"],
            "later_review_receipt_sha256_unsigned": right["receipt_sha256_unsigned"],
            "later_review_csv_sha256_unsigned": right["csv_sha256_unsigned"],
            "original_count": len(sources),
            "selected_original_positions": [r["original_ordinal"] for r in positions],
            "selected_count": len(positions),
            "identical_human_csv_not_independent_confirmation": identical_decisions,
            "explicit_kind": kind,
            "explicit_latest_topic": topic,
            "recipient_authenticated": False,
            **{flag: False for flag in FALSE_FLAGS},
        }
        save_json(kit / "PRIVATE-HUMAN-attention-bindings.json", packet)
        file_new(kit / "PRIVATE-HUMAN-attention-only.csv", csv_out(positions))
        file_new(kit / "OPEN-PRIVATE.html", page(positions, kind, topic, identical_decisions))
        done = True
        print("HOLD: source-bound PRIVATE HUMAN attention-only handoff prepared; never a release")
        print("OPEN LOCALLY: " + str(kit / "OPEN-PRIVATE.html"))
        return 3
    finally:
        if not done:
            shutil.rmtree(kit)


def main() -> int:
    p = argparse.ArgumentParser(description="PRIVATE source-bound HUMAN concern follow-up only")
    p.add_argument("--completed-packet", required=True)
    p.add_argument("--earlier-review", required=True)
    p.add_argument("--later-review", required=True)
    p.add_argument("--kind", choices=KINDS, required=True)
    p.add_argument("--topic", choices=TOPICS, help="optional exact latest HUMAN category")
    p.add_argument("--private-parent", required=True)
    args = p.parse_args()
    try:
        return create(args.completed_packet, args.earlier_review, args.later_review,
                      args.kind, args.topic, args.private_parent)
    except (Hold, OSError, ValueError, KeyError, TypeError):
        print("HOLD: PRIVATE HUMAN attention proposal refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
