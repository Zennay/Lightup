#!/usr/bin/env python3
"""Admit a locally edited PRIVATE HUMAN reason journal against exact original receipt.

Human notes are never authorization, retest, security evidence or writeback.
Valid output is one NEW owner-private 0700 directory with 0600 files.
"""
from __future__ import annotations

import argparse
import hashlib
import html
from pathlib import Path
import sys
import unicodedata

import recipient_studio

review = recipient_studio.review
workspace = recipient_studio.workspace
triage = recipient_studio.triage
board = recipient_studio.board
verify = recipient_studio.verify

STAGES = ("open", "in_review", "waiting_source_owner", "answered_human")
ROUTES = ("unassigned", "source_owner", "human_reviewer", "privacy_reviewer")
JOURNAL_KEYS = frozenset(("kind","schema_version","disposition","source_sha256",
                          "warning","entries"))
ENTRY_KEYS = frozenset(("reason", "count", "delta", "stage", "route", "note"))
FOLLOWUP_KIND = "lightup.private_recipient_human_reason_followup"
AGG_WARNING = (
    "Unverified aggregate HUMAN follow-up counts for internal PRIVATE discussion "
    "only. Counts may expose sensitive staffing for small groups. Nothing here "
    "authenticates original client/source identity, findings, consent, fixes, "
    "scans or retests."
)


def private_note(value: object) -> str:
    review.require(type(value) is str and
                   len(value.encode("utf-8")) <= 1200 and
                   sum(2 if ord(c) > 0xffff else 1 for c in value) <= 800 and
                   all(c == "\n" or (unicodedata.category(c)[0] != "C" and
                                     unicodedata.category(c) not in ("Zl","Zp"))
                       for c in value),
                   "Invalid or nonprintable PRIVATE HUMAN note")
    return value


def validate_journal(doc: object, seed: dict) -> dict:
    review.require(type(doc) is dict and set(doc) == JOURNAL_KEYS and
                   doc.get("kind") == recipient_studio.JOURNAL_KIND and
                   type(doc.get("schema_version")) is int and
                   doc["schema_version"] == 1 and
                   doc.get("disposition") == recipient_studio.DISPOSITION and
                   doc.get("warning") == recipient_studio.WARNING and
                   type(doc.get("source_sha256")) is str and
                   doc["source_sha256"] == seed["source_sha256"],
                   "The PRIVATE human draft is not bound to this exact source receipt")
    rows = doc.get("entries")
    expected = seed["reasons"]
    review.require(type(rows) is list and len(rows) == len(expected),
                   "Incomplete or reordered local HUMAN categories")
    for row, origin in zip(rows, expected):
        review.require(type(row) is dict and set(row) == ENTRY_KEYS and
                       type(row.get("reason")) is str and
                       row["reason"] == origin["reason"] and
                       type(row.get("count")) is int and
                       row["count"] == origin["count"] and
                       type(row.get("delta")) is int and
                       row["delta"] == origin["delta"] and
                       type(row.get("stage")) is str and row["stage"] in STAGES and
                       type(row.get("route")) is str and row["route"] in ROUTES,
                       "Unexpected HUMAN reason, original count or selection")
        private_note(row["note"])
    return doc


def anonymous(doc: dict) -> dict:
    tally_stage = {key: 0 for key in sorted(STAGES)}
    tally_route = {key: 0 for key in sorted(ROUTES)}
    for row in doc["entries"]:
        tally_stage[row["stage"]] += 1
        tally_route[row["route"]] += 1
    return {"kind": FOLLOWUP_KIND + ".aggregate",
            "schema_version": 1,
            "disposition": "UNVERIFIED_HUMAN_COUNTS_ONLY",
            **{flag: False for flag in review.FLAGS},
            "warning": AGG_WARNING,
            "human_reason_groups": len(doc["entries"]),
            "stages_not_original_finding_counts": tally_stage,
            "routes_not_native_assignments": tally_route}


def private_html(doc: dict) -> bytes:
    cards = []
    for row in doc["entries"]:
        brief = board.ADVICE[row["reason"]]
        note = row["note"]
        cards.append(
            "<section><h2>" + html.escape(row["reason"]) + "</h2>"
            "<p>" + str(row["count"]) + " local reason occurrence(s), "
            "selected arithmetic difference " + ("%+d" % row["delta"]) +
            ".</p><p>" + html.escape(brief) + "</p>"
            "<p><strong>HUMAN stage:</strong> " + html.escape(row["stage"]) +
            " · <strong>Proposed HUMAN route:</strong> " + html.escape(row["route"]) +
            "</p><p><strong>PRIVATE local HUMAN note:</strong></p>"
            "<pre style='white-space:pre-wrap;overflow-wrap:anywhere'>" +
            html.escape(note) + "</pre></section>"
        )
    body = ("<section><h2>Local PRIVATE reason-level follow-up</h2>"
            "<p>Only aggregates and operator-entered private text are shown. "
            "No automatic action, evidence read, verified security finding, "
            "client assignment or authorization is represented.</p></section>"
            + "".join(cards))
    return board.shell(body, "LightUp PRIVATE HUMAN Recipient Follow-up")


def artifacts(doc: dict) -> dict[str, bytes]:
    return {
        "journal.json": workspace.pretty(doc),
        "private-review.html": private_html(doc),
        "anonymous-counts.json": workspace.pretty(anonymous(doc)),
    }


def publish(receipt: Path, kind: str, journal: Path, output: Path) -> dict:
    review.require(output.is_absolute() and output != receipt and
                   output != journal and receipt not in output.parents and
                   output not in receipt.parents and
                   journal not in output.parents and
                   output.parent != receipt and
                   output.parent == output.parent.resolve(strict=True),
                   "Original PRIVATE journal/receipt must never be overwritten")
    triage.private_parent(output)
    # The native original receipt is ALWAYS admitted, not just a supplied hash.
    original, manifest, source = recipient_studio.admit_receipt(receipt, kind)
    seed = recipient_studio.studio_seed(original, manifest, source, kind)
    raw = review.private_read(journal)
    review.require(len(raw) <= 65536, "PRIVATE HUMAN journal is over 64 KiB")
    record = validate_journal(verify.json_obj(raw), seed)
    files = artifacts(record)
    local_manifest = {
        "kind": FOLLOWUP_KIND + ".local_receipt",
        "schema_version": 1,
        "disposition": recipient_studio.DISPOSITION,
        **{flag: False for flag in review.FLAGS},
        "warning": recipient_studio.WARNING,
        "files": {k: {"bytes": len(v),
                      "sha256": hashlib.sha256(v).hexdigest()}
                  for k, v in sorted(files.items())},
    }
    _, latest_manifest, latest_source = recipient_studio.admit_receipt(receipt, kind)
    review.require(manifest == latest_manifest and source == latest_source and
                   review.private_read(journal) == raw,
                   "Original private human source or draft changed during publication")
    workspace.publish_bundle(output, files, workspace.pretty(local_manifest))
    return {"reason_groups": len(record["entries"]),
            "local_human_open": sum(row["stage"] != "answered_human"
                                   for row in record["entries"]),
            "private_files": len(files) + 1}


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Admit an original-byte-bound PRIVATE HUMAN-only journal against a real "
        "canonical local source-free recipient receipt and publish local workroom"))
    parser.add_argument("--receipt", type=Path, required=True,
                        help="Original unchanged source-free PRIVATE comparison/series folder")
    parser.add_argument("--kind", choices=("compare","series"), required=True)
    parser.add_argument("--journal", type=Path, required=True,
                        help="Private 0600 downloaded HUMAN journal inside a 0700 owner folder")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="NEW owner-private 0700 reviewed HUMAN follow-up folder")
    args = parser.parse_args()
    try:
        summary = publish(args.receipt, args.kind, args.journal, args.output_dir)
        print("REVIEW_ONLY: local PRIVATE HUMAN reason handoff published, " +
              str(summary["reason_groups"]) + " reason groups; " +
              str(summary["local_human_open"]) +
              " locally not answered. No original source/evidence/permission changed.")
        return 2
    except (review.Hold, OSError, ValueError, UnicodeError):
        print("HOLD: PRIVATE HUMAN notes or exact source-free receipt cannot be admitted.",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
