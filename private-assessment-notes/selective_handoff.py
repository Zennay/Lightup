#!/usr/bin/env python3
"""Prepare an EXPLICIT selected-only local PRIVATE masked-note discussion handoff.

No recipient authentication, validation of privacy, permission to share, scan or release.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import html
import os
from pathlib import Path
import shutil
import sys
import tempfile

from notes import (
    ALLOWED, FALSE_FLAGS, Hold, csv_document, file_new, load_decisions,
    load_workroom, private_directory, private_input, save_json, summary,
)

SCHEMA = "lightup.private_assessment_selected_human_discussion.v1"


def prepare_selected(completed_packet: str, slots: list[int], private_parent: str) -> int:
    original = private_directory(completed_packet)
    parent = private_directory(private_parent)
    bindings, sources, rows = load_workroom(original)

    # Only the completed original native HUMAN packet can be narrowed. An
    # unreviewed packet, a mismatched CSV, or a synthetic stage is not admitted.
    if bindings.get("human_proposals_recorded") is not True:
        raise Hold("HOLD: select from an already completed PRIVATE HUMAN packet")
    raw_manifest = private_input(str(original / "PRIVATE-source-bindings.json"), 128 * 1024)
    raw_csv = private_input(str(original / "PRIVATE-HUMAN-decisions.csv"), 64 * 1024)
    digest = bindings.get("human_decisions_sha256_unsigned")
    if (type(digest) is not str or len(digest) != 64
            or sha256(raw_csv).hexdigest() != digest):
        raise Hold("HOLD: original complete HUMAN decisions are not byte-bound")
    decisions = load_decisions(raw_csv, sources)
    totals = {stage: sum(d["human_stage"] == stage for d in decisions) for stage in ALLOWED}
    if bindings.get("human_stages") != totals:
        raise Hold("HOLD: original completed HUMAN stage counts disagree")

    if (not slots or len(slots) > len(rows) or len(set(slots)) != len(slots)
            or any(type(slot) is not int or not 1 <= slot <= len(rows) for slot in slots)):
        raise Hold("HOLD: choose distinct original source positions within completed packet")

    # Only a *manually* marked internal-private discussion item is eligible;
    # this is NOT a release, a recipient grant, or consent. Never distribute
    # WITHHOLD/owner-required/unreviewed entries from this restricted operation.
    selected = []
    for slot in slots:
        row, decision = rows[slot - 1], decisions[slot - 1]
        if decision["human_stage"] != "INTERNAL_REVIEW_ONLY":
            raise Hold("HOLD: selected source was not explicitly marked INTERNAL_REVIEW_ONLY")
        selected.append((row, decision))

    destination = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-selected-discussion-", dir=parent))
    os.chmod(destination, 0o700)
    finished = False
    try:
        notes = destination / "notes"
        notes.mkdir(mode=0o700)
        packet_sources = []
        safe_rows = []
        safe_decisions = []
        for row, decision in selected:
            slot = row["ordinal"]
            text = row["redacted_text"]
            content = text.encode("utf-8")
            file_new(notes / f"PRIVATE-masked-original-{slot:03d}.txt", content)
            packet_sources.append({
                "original_ordinal": slot,
                "original_source_sha256_unsigned": row["source_sha256_unsigned"],
                "original_source_bytes": row["source_bytes"],
                "masked_sha256_unsigned": sha256(content).hexdigest(),
                "masked_bytes": len(content),
                "human_stage": "INTERNAL_REVIEW_ONLY",
                "human_note_withheld": True,
            })
            # Intentionally strip original free-text HUMAN notes from recipient
            # previews. Selected original masked text itself is still PRIVATE.
            safe_rows.append(row)
            safe_decisions.append({**decision, "human_note": ""})

        manifest = {
            "schema": SCHEMA,
            "claimed_status": "HOLD",
            "intended_audience": "ORIGINAL_OWNER_PRIVATE_INTERNAL_DISCUSSION_ONLY",
            "pattern_redaction_not_anonymization": True,
            "recipient_authenticated": False,
            "source_authenticated": False,
            "source_manifest_sha256_unsigned": sha256(raw_manifest).hexdigest(),
            "complete_original_human_csv_sha256_unsigned": sha256(raw_csv).hexdigest(),
            "selected_original_positions": slots,
            "sources": packet_sources,
            **{flag: False for flag in FALSE_FLAGS},
        }
        save_json(destination / "PRIVATE-selected-bindings.json", manifest)
        file_new(destination / "PRIVATE-selected-review.html",
                 summary(safe_rows, safe_decisions))
        # This is a deliberately INCOMPLETE selected-only CSV for discussion,
        # never an acceptable complete input to the original finalize command.
        selected_csv_rows = [{
            "source_ordinal": row["ordinal"],
            "source_sha256_unsigned": row["source_sha256_unsigned"],
            "human_stage": "INTERNAL_REVIEW_ONLY",
            "human_note": "",
        } for row, _ in selected]
        file_new(destination / "PRIVATE-selected-discussion-only.csv",
                 csv_document(selected_csv_rows))
        links = "".join(
            "<li><a href='notes/PRIVATE-masked-original-" +
            f"{slot:03d}" + ".txt'>Masked PRIVATE original position #" +
            str(slot) + "</a></li>" for slot in slots
        )
        index = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>LightUp · selected PRIVATE HUMAN discussion</title>
<style>body{max-width:780px;margin:2rem auto;padding:1rem;font:17px/1.55 system-ui;color:#18304a}
aside{border-left:5px solid #b34b27;background:#fff1eb;padding:1rem}
a{color:#105177}a:focus-visible{outline:3px solid #d99419}
li{margin:10px 0}</style><h1>Selected PRIVATE HUMAN discussion</h1>
<aside><strong>HOLD · INTERNAL ONLY · NOT CLEARED FOR SHARING</strong>
<p>Original local HUMAN INTERNAL_REVIEW_ONLY stages are recommendations, not
recipient authentication, consent, authority, masking completeness or release.
Masked content may still contain personal, sensitive or credential material.
This package was created locally; NOTHING was sent.</p></aside><p>Original
selected source positions: """ + str(len(slots)) + """. Only these manually
chosen originals are contained here. HUMAN free-text notes were withheld.
A human must inspect content and verify the actual recipient and channel
independently. Never use the selected CSV to finalize the original packet.</p>
<ul><li><a href="PRIVATE-selected-review.html">Read selected PRIVATE masked notes</a></li>
<li><a href="PRIVATE-selected-bindings.json">Original byte identities (unsigned, PRIVATE)</a></li>
<li><a href="PRIVATE-selected-discussion-only.csv">Selected-only discussion CSV (not finalize input)</a></li>""" +
                 links + """</ul><footer>Incubate M3/M7 PLAN/LAB ONLY DRAFT/HOLD.
No scan, network, model, authentication, grant or release.</footer></html>""")
        file_new(destination / "OPEN-PRIVATE.html", index.encode("utf-8"))
        finished = True
        print("HOLD: selected-only PRIVATE HUMAN discussion created. NOT authorized to share.")
        print("OPEN LOCALLY: " + str(destination / "OPEN-PRIVATE.html"))
        return 3
    finally:
        if not finished:
            shutil.rmtree(destination)


def main() -> int:
    cli = argparse.ArgumentParser(description="Selected-only masked PRIVATE internal HUMAN discussion; never a release")
    cli.add_argument("--completed-packet", required=True, help="unchanged completed owner-private HUMAN notes packet")
    cli.add_argument("--position", required=True, action="append", type=int,
                     help="one original ordinal per argument; only INTERNAL_REVIEW_ONLY")
    cli.add_argument("--private-parent", required=True, help="existing owner-only 0700 directory")
    args = cli.parse_args()
    try:
        return prepare_selected(args.completed_packet, args.position, args.private_parent)
    except (Hold, OSError, ValueError, KeyError) as exc:
        print(str(exc) if isinstance(exc, Hold) else "HOLD: selected PRIVATE discussion refused",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
