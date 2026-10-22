#!/usr/bin/env python3
"""PRIVATE local source-bound HUMAN follow-up action list.

Contains original finding references and therefore must never be placed in
the source-free receiving Cockpit or published outside original owner custody.
"""
from __future__ import annotations

import argparse
from collections import Counter
import html
from pathlib import Path
import sys

import board
import verify

review = verify.review
triage = verify.triage
workspace = verify.workspace

ROUTING = (
    ("needs_source_owner", "Return to original source owner",
     "A HUMAN review needs original source-owner clarification, not an automated scan."),
    ("open", "Unreviewed proposed HUMAN work",
     "Arrange manual review and inspect the original source record before any conclusion."),
    ("in_human_review", "HUMAN review in progress",
     "Continue the offline local human discussion. This is not a verified fix."),
    ("answered_human", "Locally answered — not a verified repair",
     "Local reply exists; never interpret it as an authenticated remediation, retest or approval."),
)
MAX_HTML = 4 * 1024 * 1024

def safe(value: object) -> str:
    return html.escape(str(value), quote=True)

def collect(originals: list[Path]) -> dict:
    review.require(1 <= len(originals) <= 12 and len(set(originals)) == len(originals),
                   "Require 1–12 separate PRIVATE original workspaces")
    rows = []
    snapshots = []
    for slot, folder in enumerate(originals, 1):
        _, raw = verify.inspect(folder)
        cbytes = raw["current.json"]
        pbytes = raw.get("previous.json")
        current = review.parse_packet_data(cbytes)
        previous = review.parse_packet_data(pbytes) if pbytes is not None else None
        session = triage.admit_session(raw["session.json"],
                                       triage.make_session(current, previous, cbytes, pbytes))
        for item in session["records"]:
            review.require(item["stage"] in triage.STAGES and
                           all(reason in board.ADVICE for reason in item["reasons"]),
                           "Unsupported original HUMAN reason or stage")
            rows.append({
                "slot": slot, "ordinal": item["ordinal"],
                "finding_id": item["finding_id"], "fingerprint": item["local_sha256"],
                "stage": item["stage"], "reasons": item["reasons"],
                "has_private_note": bool(item["human_note"]),
            })
        snapshots.append((folder, raw, review.private_read(folder / "manifest.json")))
    for folder, raw, manifest in snapshots:
        review.require(review.private_read(folder / "manifest.json") == manifest and
                       {x.name for x in folder.iterdir()} == set(raw) | {"manifest.json"},
                       "Original private source changed during HUMAN task queue composition")
        for filename, prior in raw.items():
            review.require(review.private_read(folder / filename) == prior,
                           "Original private review bytes changed during HUMAN task queue composition")
    return {"source_slots": len(originals), "local_questions": len(rows),
            "rows": rows}

def render(data: dict, original_links: bool = True) -> bytes:
    review.require(type(data) is dict and set(data) == {"source_slots", "local_questions", "rows"},
                   "Only original source-owned HUMAN action plans are accepted")
    group_counts = Counter(row["stage"] for row in data["rows"])
    groups = []
    for stage, label, help_text in ROUTING:
        matching = [r for r in data["rows"] if r["stage"] == stage]
        table = []
        for row in matching:
            review.require(type(row["slot"]) is int and 1 <= row["slot"] <= data["source_slots"],
                           "Invalid original private source slot")
            ref = "original-" + f"{row['slot']:02}" + "/inbox.html"
            link = ("<a href='" + ref + "'>Open ORIGINAL PRIVATE inbox</a>"
                    if original_links else "Open original source inbox locally (no link)")
            proposed = "<ul>" + "".join("<li>" + safe(board.ADVICE[k]) +
                                         "</li>" for k in row["reasons"]) + "</ul>"
            table.append("<tr><th scope='row'>" + str(row["slot"]) + " / " +
                         str(row["ordinal"]) + "</th><td>" + link +
                         "</td><td><code>" +
                         safe(row["finding_id"]) + "</code></td><td><code>" +
                         safe(row["fingerprint"]) + "</code></td><td>" + proposed +
                         "</td><td>" +
                         ("PRIVATE note present" if row["has_private_note"] else "No local note") +
                         "</td></tr>")
        contents = ("<div class='scroll'><table><thead><tr><th>Slot / row</th>"
                    "<th>Source record</th><th>Claimed original finding</th>"
                    "<th>Local SHA reference</th><th>Proposed HUMAN owner question</th>"
                    "<th>Current PRIVATE note</th></tr></thead><tbody>" +
                    "".join(table) + "</tbody></table></div>" if matching else
                    "<p>No local HUMAN records in this stage.</p>")
        groups.append("<details" + (" open" if stage != "answered_human" else "") +
                      "><summary>" + safe(label) + " · " +
                      str(group_counts.get(stage, 0)) + "</summary><p>" +
                      safe(help_text) + "</p>" + contents + "</details>")
    doc = (
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "style-src 'unsafe-inline'; script-src 'none'; connect-src 'none'; "
        "img-src 'none'; form-action 'none'; base-uri 'none'\">"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>LightUp PRIVATE original HUMAN action queue</title>"
        "<style>body{font:15px system-ui;background:#f4f7fc;color:#20324a;"
        "max-width:1280px;padding:1.5rem;margin:auto}aside{background:#fff7e0;"
        "padding:1rem;border-left:4px solid #a87516}details{background:white;"
        "margin:1rem 0;border-radius:10px;padding:1rem}summary{cursor:pointer;"
        "font-size:1.1rem;font-weight:650}table{border-collapse:collapse;width:100%}"
        "td,th{padding:.6rem;text-align:left;border-bottom:1px solid #e0e5ee}"
        "td{vertical-align:top}ul{margin:0;padding-left:1.2rem}code{overflow-wrap:anywhere}"
        ".scroll{overflow:auto}a{color:#115496}</style><main>"
        "<h1>Original source-bound PRIVATE HUMAN follow-up queue</h1>"
        "<aside><strong>SOURCE-OWNER MACHINE ONLY · INCUBATE · DRAFT/HOLD.</strong> "
        "This page deliberately contains self-declared original finding IDs, "
        "evidence SHA labels and private local HUMAN stage metadata. It is NOT "
        "anonymous, must never be copied to cockpit/ or a receiving party, "
        "and is not authenticated evidence, owner consent, granted execution, "
        "severity ranking, proven fix or a verified retest. "
        "Every proposed question requires original human source review.</aside>"
        "<p><strong>" + str(data["source_slots"]) + "</strong> original private source "
        "slot(s) · <strong>" + str(data["local_questions"]) +
        "</strong> proposed HUMAN questions · <strong>" +
        str(data["local_questions"] - group_counts.get("answered_human", 0)) +
        "</strong> locally outstanding. The stage order below is for HUMAN "
        "follow-up routing, not security risk severity.</p>"
        "<p>Open the linked original inbox to inspect context. To edit HUMAN "
        "notes use the original trusted CLI and source-owned private input "
        "session, then generate a NEW complete workroom. Browser is strictly "
        "read-only. A locally answered question is NOT a security approval.</p>"
        + "".join(groups) +
        "<p>Keep this full private workroom on the original trusted owner's machine. "
        "Only the separate source-free cockpit/ folder may be considered for a "
        "separately authorized private receiver.</p></main></html>\n"
    ).encode("utf-8")
    review.require(len(doc) <= MAX_HTML, "Private HUMAN action queue exceeds safe HTML size")
    return doc

def main() -> int:
    p = argparse.ArgumentParser(description="Generate PRIVATE source-record HUMAN follow-up list")
    p.add_argument("--bundle", type=Path, action="append", required=True,
                   help="Already-created full original PRIVATE Evidence Relationship Desk folder (1–12)")
    p.add_argument("--html", type=Path, required=True,
                   help="NEW PRIVATE HTML next to existing 0700 original owner workrooms")
    args = p.parse_args()
    try:
        review.require(args.bundle and
                       all(args.html.parent != bundle.parent and
                           bundle.parent not in args.html.parents and
                           bundle not in args.html.parents for bundle in args.bundle),
                       "Standalone HUMAN desk must not modify any original workroom")
        triage.private_parent(args.html)
        payload = render(collect(args.bundle), original_links=False)
        review.private_publish(args.html, payload)
        print("PRIVATE original-source HUMAN action list created (not source-free).")
        print("HUMAN ONLY: no fix, grant, consent, task execution or validated security verdict.")
        return 2
    except (review.Hold, OSError, ValueError):
        print("HOLD: PRIVATE source-bound action list could not be created.", file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
