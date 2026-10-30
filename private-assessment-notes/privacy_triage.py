#!/usr/bin/env python3
"""PRIVATE, non-authorizing original-bound HUMAN sensitivity triage.

Operates only on existing completed LightUp masked-note packets. Does not scan,
infer secrecy, disclose note text, authenticate recipients or grant permission.
"""
from __future__ import annotations

import argparse
import csv
from hashlib import sha256
import html
import io
from pathlib import Path
import shutil
import sys
import tempfile
import os

from private_csv_formula import unsafe_private_csv_note
from notes import (ALLOWED, Hold, csv_document, file_new, load_decisions,
                   load_workroom, private_directory, private_input, read_json,
                   save_json)

SCHEMA = "lightup.private_notes_human_sensitivity_triage.v1"
CUE_DRAFT_SCHEMA = "lightup.private_notes_human_sensitivity_triage.v2"
FIELDS = ("source_ordinal", "source_sha256_unsigned", "review_status",
          "privacy_topics", "human_followup")
STATUSES = ("PENDING", "REVIEW_REQUIRED", "WITHHOLD")
TOPICS = ("CREDENTIALS", "PERSONAL_DATA", "CLIENT_DATA", "OTHER", "UNKNOWN")
FALSE_FLAGS = ("source_authenticated", "privacy_clearance_granted",
               "recipient_authenticated", "client_consent_verified",
               "operator_consent_verified", "approved_to_share",
               "release_allowed", "dispatch_allowed")


def completed_packet(path: str):
    original = private_directory(path)
    bindings, sources, rows = load_workroom(original)
    if bindings.get("human_proposals_recorded") is not True:
        raise Hold("HOLD: sensitivity triage requires completed original HUMAN notes")
    manifest = private_input(str(original / "PRIVATE-source-bindings.json"), 128 * 1024)
    decisions_raw = private_input(str(original / "PRIVATE-HUMAN-decisions.csv"), 64 * 1024)
    if bindings.get("human_decisions_sha256_unsigned") != sha256(decisions_raw).hexdigest():
        raise Hold("HOLD: original completed HUMAN CSV identity changed")
    decisions = load_decisions(decisions_raw, sources)
    counts = {stage: sum(d["human_stage"] == stage for d in decisions) for stage in ALLOWED}
    if bindings.get("human_stages") != counts:
        raise Hold("HOLD: original HUMAN stage totals do not agree")
    return sources, sha256(manifest).hexdigest(), sha256(decisions_raw).hexdigest()


def csv_bytes(rows: list[dict]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=FIELDS, lineterminator="\r\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({field: row[field] for field in FIELDS})
    return stream.getvalue().encode("utf-8")


def default_rows(sources: list[dict]) -> list[dict]:
    return [{"source_ordinal": str(row["ordinal"]),
             "source_sha256_unsigned": row["source_sha256_unsigned"],
             "review_status": "PENDING", "privacy_topics": "UNKNOWN",
             "human_followup": ""} for row in sources]


def read_completed_csv(raw: bytes, sources: list[dict]) -> list[dict]:
    try:
        content = raw.decode("utf-8", errors="strict")
        if "\x00" in content or "\r" in content.replace("\r\n", ""):
            raise ValueError("control")
        reader = csv.DictReader(io.StringIO(content, newline=""), strict=True)
        if reader.fieldnames != list(FIELDS):
            raise ValueError("header")
        rows = list(reader)
    except (UnicodeError, ValueError, csv.Error):
        raise Hold("HOLD: unsupported PRIVATE sensitivity CSV") from None
    if len(rows) != len(sources):
        raise Hold("HOLD: incomplete original sensitivity source roster")
    for index, (row, source) in enumerate(zip(rows, sources), start=1):
        if (type(row) is not dict or set(row) != set(FIELDS) or None in row
                or any(type(v) is not str for v in row.values())
                or row["source_ordinal"] != str(index)
                or row["source_sha256_unsigned"] != source["source_sha256_unsigned"]
                or row["review_status"] not in STATUSES):
            raise Hold("HOLD: HUMAN sensitivity row/order/source identity mismatch")
        topic = row["privacy_topics"].split("|")
        if (not topic or any(value not in TOPICS for value in topic)
                or topic != [value for value in TOPICS if value in topic]
                or ("UNKNOWN" in topic and len(topic) != 1)):
            raise Hold("HOLD: privacy topics must be canonical and bounded")
        note = row["human_followup"]
        if (len(note) > 300 or note.lstrip().startswith(("=", "+", "-", "@"))
                or unsafe_private_csv_note(note, 300)
                or any(ord(ch) < 32 and ch != "\t" for ch in note)):
            raise Hold("HOLD: unsafe PRIVATE HUMAN follow-up text")
    return rows


def admit_preflight(path: str, sources: list[dict], manifest_sha: str,
                    decision_sha: str, original: str) -> None:
    kit = private_directory(path)
    data = read_json(kit / "PRIVATE-triage-bindings.json", 64 * 1024)
    with_cues = data.get("schema") == CUE_DRAFT_SCHEMA
    allowed = {"schema", "claimed_status", "original_manifest_sha256_unsigned",
               "original_human_csv_sha256_unsigned", "sources", *FALSE_FLAGS}
    if with_cues:
        allowed.add("original_masking_cues_receipt_required")
    if (set(data) != allowed or data["schema"] not in (SCHEMA, CUE_DRAFT_SCHEMA)
            or (with_cues and data.get("original_masking_cues_receipt_required") is not True)
            or data["claimed_status"] != "HOLD"
            or data["original_manifest_sha256_unsigned"] != manifest_sha
            or data["original_human_csv_sha256_unsigned"] != decision_sha
            or any(data[field] is not False for field in FALSE_FLAGS)
            or data["sources"] != [
                {"ordinal": r["ordinal"],
                 "source_sha256_unsigned": r["source_sha256_unsigned"]}
                for r in sources]):
        raise Hold("HOLD: changed original PRIVATE sensitivity preflight or authority")
    # The template must still be the source-exact original draft. A browser or
    # spreadsheet may only write a DISTINCT completed file, not rewrite origin.
    template = private_input(str(kit / "PRIVATE-HUMAN-sensitivity-template.csv"), 64 * 1024)
    if template != csv_bytes(default_rows(sources)):
        raise Hold("HOLD: original sensitivity template was modified")
    if with_cues:
        # A v2 source-bound draft cannot drop its original masking cue
        # evidence or silently swap the navigator before HUMAN finalization.
        # The established independent original receipt checks exact v6
        # HTML, CSV, receipt and the original PRIVATE masked source bytes.
        from private_masking_cues import reopen as reopen_cues
        reopen_cues(original, str(kit))


def render(rows: list[dict], prepared: bool,
           include_masking_cues: bool = False) -> bytes:
    entries = "".join(
        "<tr><th scope='row'>" + html.escape(row["source_ordinal"]) +
        "</th><td>" + html.escape(row["review_status"]) +
        "</td><td>" + html.escape(row["privacy_topics"]) +
        "</td><td>" + html.escape(row["human_followup"]) + "</td></tr>"
        for row in rows
    )
    copy = ("Fill a COPY of the complete PRIVATE template CSV locally; never "
            "edit the source template. Alternatively open PRIVATE-HUMAN-sensitivity-editor.html " 
            "to save the complete local CSV. Then explicitly run finalize with that "
            "copy and the unchanged original packet."
            if prepared else
            "HUMAN observations only. Every label may be wrong; this output "
            "never clears, proves sanitization or authorizes sharing.")
    page = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>LightUp PRIVATE HUMAN sensitivity triage</title>
<style>body{max-width:1000px;margin:2rem auto;padding:1rem;font:16px/1.6 system-ui;color:#192d47}
aside{padding:1rem;background:#fff1ec;border-left:5px solid #a43c1d}
table{width:100%;border-collapse:collapse}th,td{border:1px solid #bdcdd9;padding:.6rem;text-align:left;overflow-wrap:anywhere}
@media print{body{margin:0}}</style>
<h1>PRIVATE original-bound HUMAN sensitivity triage</h1>
<aside><b>HOLD · NOT CLEARED · NOT ANONYMIZED</b><p>All source content, original
identities and human notes stay PRIVATE. Source hashes are UNSIGNED; matching is
not authentication. Review status is NEVER consent, privacy certification,
security assurance, grant or permission to disclose. No network/target action.</p></aside>
<p>""" + html.escape(copy) + """</p>""" + (
    """<p><a href="PRIVATE-masking-cues.html">Open PRIVATE original-source masking cues</a>
    (literal navigation only, never privacy clearance). Independently reopen the
    source-bound receipt using the existing masking-cues-reopen command.</p>"""
    if include_masking_cues else "") + """
<table><caption>Original positions · no content copied</caption>
<thead><tr><th>Original #</th><th>HUMAN status</th><th>Concern categories</th>
<th>PRIVATE HUMAN follow-up</th></tr></thead><tbody>""" + entries + """</tbody></table>
<p>Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. Separate verified
client/operator consent, revocation-at-use, owner/security/privacy approval and
explicit HUMAN GO remain required.</p></html>"""
    return page.encode("utf-8")


def prepare(original: str, parent_string: str,
            include_masking_cues: bool = False) -> int:
    parent = private_directory(parent_string)
    sources, manifest_sha, decision_sha = completed_packet(original)
    destination = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-sensitivity-draft-", dir=parent))
    os.chmod(destination, 0o700)
    complete = False
    try:
        bindings = {"schema": CUE_DRAFT_SCHEMA if include_masking_cues else SCHEMA,
                    "claimed_status": "HOLD",
                    "original_manifest_sha256_unsigned": manifest_sha,
                    "original_human_csv_sha256_unsigned": decision_sha,
                    "sources": [{"ordinal": r["ordinal"],
                                 "source_sha256_unsigned": r["source_sha256_unsigned"]}
                                for r in sources],
                    **{field: False for field in FALSE_FLAGS}}
        if include_masking_cues:
            bindings["original_masking_cues_receipt_required"] = True
        rows = default_rows(sources)
        save_json(destination / "PRIVATE-triage-bindings.json", bindings)
        file_new(destination / "PRIVATE-HUMAN-sensitivity-template.csv", csv_bytes(rows))
        from privacy_triage_studio import render as render_sensitivity_studio
        cue_records = None
        if include_masking_cues:
            # Optional ORIGINAL source-bound navigation, not another HUMAN
            # classification. No modified source or canonical sensitivity
            # manifest; the independent receipt can be read-only re-admitted
            # with the existing notes.py masking-cues-reopen command.
            from notes import load_workroom
            from private_masking_cues import cue_csv, cue_page, cue_receipt, cues
            origin = private_directory(original)
            _, original_sources, masked_rows = load_workroom(origin)
            manifest_bytes = private_input(str(origin / "PRIVATE-source-bindings.json"),
                                           128 * 1024)
            if (original_sources != sources
                    or sha256(manifest_bytes).hexdigest() != manifest_sha):
                raise Hold("HOLD: original sources changed during PRIVATE cue preparation")
            save_json(destination / "PRIVATE-masking-cues-receipt.json",
                      cue_receipt(manifest_bytes, original_sources))
            cue_records = cues(masked_rows)
            file_new(destination / "PRIVATE-masking-cues.csv", cue_csv(cue_records))
            file_new(destination / "PRIVATE-masking-cues.html", cue_page(cue_records))
        # Combined original privacy editor displays only literal cue COUNTS
        # and all original rows remain in the unfiltered complete CSV.
        file_new(destination / "PRIVATE-HUMAN-sensitivity-editor.html",
                 render_sensitivity_studio(rows, cue_records))
        file_new(destination / "OPEN-PRIVATE.html",
                 render(rows, prepared=True,
                        include_masking_cues=include_masking_cues))
        complete = True
        print("REVIEW_ONLY: complete original-bound HUMAN sensitivity template created")
        print("OPEN LOCALLY: " + str(destination / "OPEN-PRIVATE.html"))
        return 2
    finally:
        if not complete:
            shutil.rmtree(destination)


def finalize(original: str, kit: str, completed: str, parent_string: str) -> int:
    parent = private_directory(parent_string)
    sources, manifest_sha, decision_sha = completed_packet(original)
    admit_preflight(kit, sources, manifest_sha, decision_sha, original)
    raw = private_input(completed, 64 * 1024)
    rows = read_completed_csv(raw, sources)
    destination = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-sensitivity-review-", dir=parent))
    os.chmod(destination, 0o700)
    finished = False
    try:
        status_counts = {name: sum(row["review_status"] == name for row in rows)
                         for name in STATUSES}
        topic_counts = {name: sum(name in row["privacy_topics"].split("|")
                                  for row in rows) for name in TOPICS}
        # The locally completed browser/manual input can use different valid
        # CSV quoting from the canonical DictWriter serialization stored in
        # this PRIVATE packet. Bind the receipt to the EXACT SAVED bytes:
        # downstream original-round readers verify the stored 0600 CSV, not
        # the temporary pre-canonicalization upload. Never claim authorship.
        recorded_csv = csv_bytes(rows)
        manifest = {
            "schema": SCHEMA, "claimed_status": "HOLD", "human_review_only": True,
            "original_manifest_sha256_unsigned": manifest_sha,
            "original_human_csv_sha256_unsigned": decision_sha,
            "sensitivity_human_csv_sha256_unsigned": sha256(recorded_csv).hexdigest(),
            "original_count": len(sources), "status_counts": status_counts,
            "topic_counts": topic_counts,
            **{field: False for field in FALSE_FLAGS}
        }
        save_json(destination / "PRIVATE-HUMAN-sensitivity-receipt.json", manifest)
        file_new(destination / "PRIVATE-HUMAN-sensitivity.csv", recorded_csv)
        file_new(destination / "OPEN-PRIVATE.html", render(rows, prepared=False))
        finished = True
        print("HOLD: source-bound HUMAN sensitivity discussion produced; never a clearance")
        print("OPEN LOCALLY: " + str(destination / "OPEN-PRIVATE.html"))
        return 3
    finally:
        if not finished:
            shutil.rmtree(destination)


def main() -> int:
    p = argparse.ArgumentParser(description="Private offline HUMAN sensitivity triage; never a clearance")
    actions = p.add_subparsers(dest="action", required=True)
    draft = actions.add_parser("prepare", help="owner-private original-bound HUMAN template")
    draft.add_argument("--completed-packet", required=True)
    draft.add_argument("--private-parent", required=True)
    draft.add_argument("--with-mask-cues", action="store_true",
                       help="embed original private masking cue desk and receipt")
    end = actions.add_parser("finalize", help="independent complete HUMAN sensitivity receipt; HOLD")
    end.add_argument("--completed-packet", required=True)
    end.add_argument("--triage-kit", required=True)
    end.add_argument("--completed-csv", required=True)
    end.add_argument("--private-parent", required=True)
    a = p.parse_args()
    try:
        if a.action == "prepare":
            return prepare(a.completed_packet, a.private_parent,
                           include_masking_cues=a.with_mask_cues)
        return finalize(a.completed_packet, a.triage_kit, a.completed_csv, a.private_parent)
    except (Hold, OSError, ValueError, KeyError, TypeError):
        print("HOLD: PRIVATE sensitivity review refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
