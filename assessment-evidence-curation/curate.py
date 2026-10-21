#!/usr/bin/env python3
"""Offline source-bound PRIVATE selection of ORIGINAL LightUp lab declarations.

This companion DOES NOT execute tools, verify findings or confer authorization.
All original producer and HUMAN fields remain unverified; only selected records
are copied into the expressly PRIVATE output after human-local confirmation.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import html
import io
import json
from pathlib import Path
import re
import sys
import unicodedata

# Use the frozen, original-source admission contracts from the held owner.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "assessment-briefing"))
from briefing import (CSS, DENIAL_FLAGS, Hold, h, json_bytes, open_source,
                      publish_new, require, SEVERITIES, strict_pairs)
from human_return import (MAX_CSV_BYTES, MAX_MANIFEST_BYTES, read_human_csv,
                          read_limited_file, source_manifest)
from browser import source_free_studio

SCHEMA = "lightup.private_lab_curated_selection.v1"
HEADER = ("original_ordinal", "source_reported_severity", "evidence_reference_count",
          "select_for_private_dossier", "human_priority", "human_question")
PRIORITIES = ("routine", "soon", "urgent")
MAX_SELECTED = 64
MAX_QUESTION = 500
MAX_RECEIPT_BYTES = 64 * 1024
UNVERIFIED = {
    "source_authenticated": False, "ground_truth_verified": False,
    "human_identity_authenticated": False, "client_consent_verified": False,
    "operator_consent_verified": False, **DENIAL_FLAGS,
}
SAFE_TEXT = re.compile(r"[\x00-\x1f\x7f]")
FORMULA = set("=+-@")

def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def literal_sha(s: object) -> bool:
    return type(s) is str and len(s) == 64 and all(c in "0123456789abcdef" for c in s)

def human_text_ok(s: object) -> bool:
    if type(s) is not str or len(s) > MAX_QUESTION or SAFE_TEXT.search(s):
        return False
    if any(unicodedata.category(c) in ("Cf", "Cs", "Co", "Cn") for c in s):
        return False
    # Spreadsheet imports may interpret compatibility forms (FULLWIDTH +/-/=)
    # or leading combining marks before a dangerous formula prefix.
    first = unicodedata.normalize("NFKC", s).lstrip()
    while first and unicodedata.category(first[0]).startswith("M"):
        first = first[1:].lstrip()
    return not first or first[0] not in FORMULA

def read_original(source_path: str, manifest_path: str, worksheet_path: str):
    source, _, original_digest = open_source(source_path)
    source_manifest(read_limited_file(manifest_path, MAX_MANIFEST_BYTES),
                    original_digest, source)
    human_raw = read_limited_file(worksheet_path, MAX_CSV_BYTES)
    notes = read_human_csv(human_raw, source)
    return source, original_digest, human_raw, notes

def make_template(source: dict) -> bytes:
    file = io.StringIO(newline="")
    out = csv.writer(file, lineterminator="\r\n")
    out.writerow(HEADER)
    for ordinal, record in enumerate(source["findings"], 1):
        out.writerow((ordinal, record["severity"], len(record["evidence_ids"]),
                      "", "", ""))
    return file.getvalue().encode("utf-8")

def prepare(source_path: str, manifest_path: str, worksheet_path: str,
            destination: str) -> None:
    source, original_sha, worksheet_raw, _ = read_original(
        source_path, manifest_path, worksheet_path)
    template = make_template(source)
    receipt = {
        "schema": SCHEMA, "status": "REVIEW_ONLY",
        "original_source_sha256_unsigned": original_sha,
        "original_human_worksheet_sha256_unsigned": digest(worksheet_raw),
        "original_finding_count": len(source["findings"]),
        "original_template_sha256_unsigned": digest(template),
        **UNVERIFIED,
    }
    instructions = (
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "style-src 'none'; script-src 'none'; base-uri 'none'\">"
        "<title>PRIVATE curation preparation</title><body><h1>PRIVATE · Review only</h1>"
        "<p>Keep the original source, original HUMAN worksheet, this unsigned receipt "
        "and your edited selection together in the same approved PRIVATE environment.</p>"
        "<p>For selected rows enter <code>yes</code>, choose priority "
        "<code>routine</code>, <code>soon</code> or <code>urgent</code>, and write a "
        "human question. Leave all priority and question fields empty on nonselected rows."
        " At most 64 rows may be selected.</p>"
        "<p>Original data and HUMAN comments are NOT proof of a finding, permission, "
        "retest, fix, reviewer identity or source authenticity.</p>"
        "<p>Spreadsheet software may sync data externally. Export UTF-8 CSV privately."
        " Never publish the private generated dossier without a separate HUMAN review.</p>"
        "</body></html>\n"
    ).encode("utf-8")
    publish_new(destination, {
        "selection-template.csv": template, "selection-receipt.json": json_bytes(receipt),
        "PRIVATE-selection-instructions.html": instructions,
        "PRIVATE-source-free-selection-studio.html": source_free_studio(source),
    })

def read_selection(raw: bytes, source: dict) -> list[dict]:
    try:
        text = raw.decode("utf-8-sig")
        require("\x00" not in text and "\r" not in text.replace("\r\n", ""))
        reader = csv.reader(io.StringIO(text, newline=""), strict=True)
        require(tuple(next(reader)) == HEADER)
        records = list(reader)
        require(len(records) == len(source["findings"]))
        selection = []
        for ordinal, (row, f) in enumerate(zip(records, source["findings"]), 1):
            require(len(row) == len(HEADER) and row[0] == str(ordinal))
            require(row[1] == f["severity"] and
                    row[2] == str(len(f["evidence_ids"])))
            require(row[3] in ("", "no", "yes"))
            require(human_text_ok(row[5]))
            if row[3] == "yes":
                require(row[4] in PRIORITIES and bool(row[5].strip()))
                selection.append({"ordinal": ordinal, "priority": row[4],
                                  "question": row[5]})
                require(len(selection) <= MAX_SELECTED)
            else:
                require(row[4] == "" and row[5] == "")
        require(bool(selection))
        return selection
    except (csv.Error, StopIteration, ValueError, TypeError, UnicodeError,
            OverflowError, RecursionError, MemoryError):
        raise Hold("PRIVATE selection rejected (HOLD); nothing published") from None

def read_receipt(raw: bytes, original_digest: str, worksheet_digest: str,
                 source: dict) -> None:
    try:
        x = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_pairs,
                       parse_constant=lambda _: require(False))
        required = {"schema", "status", "original_source_sha256_unsigned",
                    "original_human_worksheet_sha256_unsigned",
                    "original_finding_count", "original_template_sha256_unsigned",
                    *UNVERIFIED}
        require(type(x) is dict and set(x) == required)
        require(x["schema"] == SCHEMA and x["status"] == "REVIEW_ONLY")
        require(all(x[k] is False for k in UNVERIFIED))
        require(literal_sha(x["original_source_sha256_unsigned"]) and
                x["original_source_sha256_unsigned"] == original_digest)
        require(literal_sha(x["original_human_worksheet_sha256_unsigned"]) and
                x["original_human_worksheet_sha256_unsigned"] == worksheet_digest)
        require(x["original_finding_count"] == len(source["findings"]) and
                type(x["original_finding_count"]) is int)
        require(x["original_template_sha256_unsigned"] == digest(make_template(source)))
    except (ValueError, TypeError, UnicodeError, KeyError,
            OverflowError, RecursionError, MemoryError):
        raise Hold("PRIVATE source/worksheet binding rejected (HOLD)") from None

def page(source: dict, original_digest: str, worksheet_digest: str,
         selected: list[dict], notes: list[dict]) -> bytes:
    pin = base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode("ascii")
    csp = ("default-src 'none'; style-src 'sha256-" + pin +
           "'; script-src 'none'; connect-src 'none'; img-src 'none'; "
           "object-src 'none'; form-action 'none'; base-uri 'none'")
    cards = []
    for item in selected:
        ordinal = item["ordinal"]
        f, n = source["findings"][ordinal-1], notes[ordinal-1]
        labels = (
            ("Original reported severity (UNVERIFIED)", f["severity"]),
            ("Original finding ID", f["finding_id"]),
            ("Original target", f["target"]),
            ("Original check/capability", f["check_id"] + " / " + f["capability_id"]),
            ("Original impact", f["impact"]),
            ("Original proposed mitigation", f["fix"]),
            ("Original proposed retest", f["retest"]),
            ("Original evidence summary", f["evidence_summary"]),
            ("Original evidence reference IDs", ", ".join(f["evidence_ids"])),
            ("Human-reported stage (UNVERIFIED)", n["stage"]),
            ("Human owner/group label (UNVERIFIED)", n["owner"]),
            ("Human action proposal", n["action"]),
            ("Human blocker", n["blocker"]),
        )
        details = "".join("<dt>" + h(k) + "</dt><dd><pre>" + h(v) +
                          "</pre></dd>" for k, v in labels)
        cards.append(
            "<article id='ordinal-" + str(ordinal) + "'><h2>Original source ordinal #" + str(ordinal) +
            " · human priority " + h(item["priority"]) + "</h2>"
            "<p class='notice'>Human question — PRIVATE, unverified</p><pre>" +
            h(item["question"]) + "</pre>"
            "<p><strong>Original source title:</strong> " + h(f["finding"]) + "</p>"
            "<details><summary>PRIVATE original evidence and HUMAN notes</summary>"
            "<dl>" + details + "</dl></details>"
            "<div class='worksheet'>Independent reviewer: __________ &nbsp; "
            "Original evidence checked: __________ &nbsp; Follow-up: __________</div>"
            "</article>"
        )
    start = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"" + h(csp) + "\">"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>PRIVATE curated LightUp lab evidence</title><style>" + CSS +
        "</style></head><body><header><h1>LightUp · curated PRIVATE HUMAN evidence dossier</h1>"
        "<p class='notice'>REVIEW ONLY · Original source, findings, HUMAN identity, "
        "evidence, consent, action-time revocation and remediation NOT independently "
        "verified. Selection or priority NEVER grants permission or proves a finding.</p>"
        "<p>PRIVATE: source target, impact, evidence and human comments may identify clients. "
        "Separate authorized human disclosure approval is required before sharing.</p>"
        "<p>Selected original ordinals: " + str(len(selected)) + " of " +
        str(len(source["findings"])) + "</p>"
        "<p>Original source SHA-256 (UNSIGNED): <code>" + h(original_digest) +
        "</code><br>HUMAN worksheet SHA-256 (UNSIGNED): <code>" + h(worksheet_digest) +
        "</code></p></header>"
    )
    return (start + "".join(cards) + "</body></html>\n").encode("utf-8")


def private_question_handoff(source: dict, selected: list[dict]) -> bytes:
    """Small source-minimized PRIVATE agenda; human questions can contain secrets.

    Unlike the full dossier, this does not copy original finding IDs, target
    strings, source hashes, evidence bodies, HUMAN owner labels or other notes.
    Still PRIVATE: original severity distributions + human questions can reveal
    source/customer identity. No claim of true anonymization is made.
    """
    pin = base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode("ascii")
    csp = ("default-src 'none'; style-src 'sha256-" + pin +
           "'; script-src 'none'; img-src 'none'; connect-src 'none'; "
           "form-action 'none'; base-uri 'none'; object-src 'none'")
    elements = []
    for item in selected:
        ordinal = item["ordinal"]
        finding = source["findings"][ordinal-1]
        elements.append(
            "<article id='ordinal-" + str(ordinal) + "'><h2>Original ordinal #" + str(ordinal) + "</h2>"
            "<p><strong>Source-reported severity (UNVERIFIED):</strong> " +
            h(finding["severity"]) + " · original evidence reference count: " +
            str(len(finding["evidence_ids"])) + "</p>"
            "<p><strong>HUMAN priority:</strong> " + h(item["priority"]) + "</p>"
            "<p><strong>PRIVATE HUMAN question:</strong></p><pre>" +
            h(item["question"]) + "</pre>"
            "<div class='worksheet'>Independent HUMAN reviewer: __________ &nbsp; "
            "Review date: __________ &nbsp; Source evidence checked: __________</div>"
            "</article>"
        )
    document = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"" + h(csp) + "\">"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>PRIVATE source-minimized HUMAN questions</title><style>" + CSS +
        "</style></head><body><header><h1>LightUp · PRIVATE HUMAN question handoff</h1>"
        "<p class='notice'>REVIEW ONLY — not source authenticated, not an "
        "independent finding, consent, grant, approved scope, retest or remediation. "
        "Human questions may embed confidential client names or targets. "
        "This is source-minimized, NOT certified anonymous or public-safe.</p>"
        "<p>Original lab finding IDs, targets, run/scenario IDs, original evidence "
        "summaries and source hashes are deliberately absent. Selected rows: " +
        str(len(selected)) + ".</p></header>" + "".join(elements) +
        "</body></html>\n"
    )
    return document.encode("utf-8")

def publish(source_path: str, manifest_path: str, worksheet_path: str,
            receipt_path: str, selection_path: str, destination: str) -> None:
    source, original_digest, human_raw, notes = read_original(
        source_path, manifest_path, worksheet_path)
    read_receipt(read_limited_file(receipt_path, MAX_RECEIPT_BYTES),
                 original_digest, digest(human_raw), source)
    selection_raw = read_limited_file(selection_path, MAX_CSV_BYTES)
    selected = read_selection(selection_raw, source)
    private_report = page(source, original_digest, digest(human_raw), selected, notes)
    from packet_directory import render as private_directory
    directory = private_directory(source, selected, PRIORITIES)
    limited_handoff = private_question_handoff(source, selected)
    # Optional independent human routing packets. A PRIVATE recipient receives
    # only the selected HUMAN questions in their proposed priority group.
    # No original producer, client or assigned reviewer identity is inferred.
    prioritized = {
        priority: private_question_handoff(
            source, [item for item in selected if item["priority"] == priority])
        for priority in PRIORITIES
        if any(item["priority"] == priority for item in selected)
    }
    # Build strictly source-minimized PRIVATE reply templates for the same
    # priority slices, preserving the canonical original recipient CSV contract.
    from response import csv_template as original_reply_template
    replies = {
        priority: original_reply_template(
            source, [item for item in selected if item["priority"] == priority])
        for priority in prioritized
    }
    counts = {s: sum(source["findings"][i["ordinal"]-1]["severity"] == s
                     for i in selected) for s in SEVERITIES}
    priorities = {p: sum(i["priority"] == p for i in selected) for p in PRIORITIES}
    aggregate = {
        "schema": "lightup.private_curated_lab_aggregate.v1", "status": "REVIEW_ONLY",
        "declared_total_source_findings": len(source["findings"]),
        "human_selected_count": len(selected),
        "human_selected_source_severity_counts": counts,
        "human_selected_priority_counts": priorities,
        "source_identifiers_included": False,
        "source_authenticated": False, "human_identity_authenticated": False,
        "ground_truth_verified": False, "client_consent_verified": False,
        "operator_consent_verified": False, **DENIAL_FLAGS,
    }
    private_receipt = {
        "schema": "lightup.private_curated_lab_receipt.v1", "status": "REVIEW_ONLY",
        "original_source_sha256_unsigned": original_digest,
        "human_worksheet_sha256_unsigned": digest(human_raw),
        "human_selection_sha256_unsigned": digest(selection_raw),
        "private_curated_dossier_sha256_unsigned": digest(private_report),
        "private_packet_directory_sha256_unsigned": digest(directory),
        "anonymous_counts_sha256_unsigned": digest(json_bytes(aggregate)),
        "source_minimized_human_handoff_sha256_unsigned": digest(limited_handoff),
        "private_priority_handoff_sha256_unsigned": {
            priority: digest(data) for priority, data in prioritized.items()
        },
        "private_priority_reply_template_sha256_unsigned": {
            priority: digest(data) for priority, data in replies.items()
        },
        "selected_original_ordinals": [i["ordinal"] for i in selected],
        **UNVERIFIED,
    }
    publish_new(destination, {
        "PRIVATE-curated-dossier.html": private_report,
        "PRIVATE-packet-directory.html": directory,
        "PRIVATE-source-minimized-HUMAN-handoff.html": limited_handoff,
        "PRIVATE-curation-receipt.json": json_bytes(private_receipt),
        "anonymous-counts-PRIVATE.json": json_bytes(aggregate),
        **{
            "PRIVATE-HUMAN-" + priority + "-reply-template.csv": data
            for priority, data in replies.items()
        },
        **{
            "PRIVATE-HUMAN-" + priority + "-priority.html": data
            for priority, data in prioritized.items()
        },
    })

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Source-bound PRIVATE human lab evidence curation; NEVER executes targets")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("prepare", "publish"):
        p = sub.add_parser(command)
        p.add_argument("--source", required=True, help="unchanged original lab JSON")
        p.add_argument("--manifest", required=True, help="original PRIVATE briefing manifest")
        p.add_argument("--worksheet", required=True, help="source-bound original HUMAN CSV")
        p.add_argument("--output-dir", required=True, help="NEW private output directory")
        if command == "publish":
            p.add_argument("--selection-receipt", required=True)
            p.add_argument("--selection", required=True, help="completed private CSV selection")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            prepare(args.source, args.manifest, args.worksheet, args.output_dir)
        else:
            publish(args.source, args.manifest, args.worksheet,
                    args.selection_receipt, args.selection, args.output_dir)
    except Hold as exc:
        print(str(exc), file=sys.stderr)
        return 3
    print("PRIVATE package created: human REVIEW ONLY; NO scan, approval or release")
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
