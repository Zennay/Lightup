#!/usr/bin/env python3
"""Offline PRIVATE longitudinal HUMAN checkpoint change desk (never a security verdict)."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import html
import json
from pathlib import Path
import sys

from review import FLAGS, Hold, private_publish, private_read, require
from triage import admit_session, make_session, selected_sources, single_host_lock
from history import open_checkpoint

LIMIT = 12


def load_history(paths: list[Path], expected: dict) -> tuple[list[dict], list[bytes]]:
    require(2 <= len(paths) <= LIMIT,
            "Choose 2–12 distinct owner-private HUMAN checkpoints")
    states, sources = [], []
    seen = set()
    for path in paths:
        data = private_read(path)
        digest = hashlib.sha256(data).hexdigest()
        require(digest not in seen, "Duplicate byte-identical checkpoint cannot be a new source slot")
        seen.add(digest)
        session, _ = open_checkpoint(data, expected)
        states.append(session)
        sources.append(data)
    return states, sources


def trajectory(states: list[dict]) -> dict:
    require(len(states) >= 2, "Expected multiple original-source HUMAN snapshots")
    base = states[0]["records"]
    spans = []
    for index, anchor in enumerate(base):
        snapshots = [state["records"][index] for state in states]
        changes = []
        statuses = [record["stage"] for record in snapshots]
        for slot in range(1, len(snapshots)):
            before, after = snapshots[slot - 1], snapshots[slot]
            changes.append({
                "user_slot_after": slot + 1,
                "stage_changed": before["stage"] != after["stage"],
                "human_note_changed": before["human_note"] != after["human_note"],
                "stage_before": before["stage"],
                "stage_after": after["stage"],
            })
        if any(c["stage_changed"] or c["human_note_changed"] for c in changes):
            spans.append({
                "ordinal": anchor["ordinal"],
                "finding_id": anchor["finding_id"],
                "local_sha256": anchor["local_sha256"],
                "statuses": statuses,
                "changes": changes,
                "human_note_presence_only": [bool(record["human_note"]) for record in snapshots],
            })
    metric = []
    for slot, state in enumerate(states):
        by_status = Counter(item["stage"] for item in state["records"])
        metric.append({
            "user_selected_slot": slot + 1,
            "open": by_status["open"],
            "in_human_review": by_status["in_human_review"],
            "needs_source_owner": by_status["needs_source_owner"],
            "answered_human": by_status["answered_human"],
            "changed_human_questions_since_prior": (
                sum(1 for record in spans
                    if any(c["user_slot_after"] == slot + 1 and
                           (c["stage_changed"] or c["human_note_changed"])
                           for c in record["changes"])) if slot else 0),
        })
    return {"count": len(states), "total": len(base), "changed": spans, "slots": metric}


def counts(history: dict) -> dict:
    return {
        "kind": "lightup.anonymous_human_evidence_checkpoint_trajectory",
        "schema_version": 1, "disposition": "HUMAN_ONLY_NO_AUTHORITY",
        "user_selected_private_checkpoints": history["count"],
        "local_original_followup_questions": history["total"],
        "question_records_changed_at_least_once": len(history["changed"]),
        "per_user_selected_slot": history["slots"],
        "notice": "User-selected file order is NOT authenticated chronology. All stages are HUMAN local, not repairs, signed review or grants.",
    }


def private_handoff(source: dict, history: dict) -> dict:
    return {
        "kind": "lightup.private_human_checkpoint_trajectory_handoff",
        "schema_version": 1, "disposition": "PRIVATE_UNVERIFIED_HUMAN_ONLY",
        "source_contract": source["source_contract"],
        "source_sha256": source["source_sha256"],
        "source_count": source["source_count"],
        "client_reference": source["client_reference"],
        "engagement_reference": source["engagement_reference"],
        **{flag: False for flag in FLAGS},
        "private_user_ordered_question_transitions": history["changed"],
        "warning": "PRIVATE human change indications only; no original source authentication, legal history, fix, consent or native Apply.",
    }


def make_html(source: dict, history: dict) -> bytes:
    e = lambda v: html.escape(str(v), quote=True)
    rows = []
    for record in history["changed"]:
        stages = "".join("<td>" + e(status) + "</td>" for status in record["statuses"])
        changed_notes = sum(c["human_note_changed"] for c in record["changes"])
        rows.append("<tr><td>" + str(record["ordinal"]) + "</td><td><code>" +
                    e(record["finding_id"]) + "</code></td><td><code>" +
                    e(record["local_sha256"]) + "</code></td>" + stages +
                    "<td>" + str(changed_notes) + " local edits</td></tr>")
    metrics = "".join("<tr><td>" + str(slot["user_selected_slot"]) + "</td>" +
                     "<td>" + str(slot["open"]) + "</td><td>" +
                     str(slot["in_human_review"]) + "</td><td>" +
                     str(slot["needs_source_owner"]) + "</td><td>" +
                     str(slot["answered_human"]) + "</td><td>" +
                     str(slot["changed_human_questions_since_prior"]) + "</td></tr>"
                     for slot in history["slots"])
    heads = "".join("<th>Private slot " + str(i + 1) + "</th>"
                    for i in range(history["count"]))
    document = (
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "style-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; "
        "form-action 'none'; base-uri 'none'\"><title>PRIVATE HUMAN review journey</title>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<style>body{font:16px system-ui;max-width:1250px;margin:1.8rem auto;"
        "padding:0 1rem;background:#f6f8fb;color:#213047}table{border-collapse:collapse;"
        "width:100%;background:white;font-size:.88rem}th,td{border:1px solid #ddd;"
        "padding:.6rem;text-align:left;overflow-wrap:anywhere}section{overflow:auto;"
        "margin:1rem 0}aside{padding:1rem;background:#fff2d9;border-left:4px solid #ae6b00}"
        "code{overflow-wrap:anywhere}</style><main><h1>PRIVATE HUMAN checkpoint progression</h1>"
        "<aside>DRAFT/HOLD · operator-selected order is <b>NOT authenticated chronology</b>. "
        "None of these private statuses, checkpoint copies or digests proves a "
        "finding was repaired, review independently signed, legal custody, consent "
        "or authorization to scan or retest. No HUMAN notes are embedded in this HTML.</aside>"
        "<p>Self-declared private client " + e(source["client_reference"]) +
        " / engagement " + e(source["engagement_reference"]) + "</p>"
        "<p>Original source claim <code>" + e(source["source_sha256"]) + "</code></p>"
        "<section><h2>HUMAN status distribution by user slot</h2><table><thead><tr>"
        "<th>Slot</th><th>Open</th><th>Review</th><th>Needs original owner</th>"
        "<th>Answered human</th><th>Changed from supplied prior slot</th></tr></thead><tbody>" +
        metrics + "</tbody></table></section><section><h2>Changed HUMAN follow-up questions</h2>"
        "<table><thead><tr><th>#</th><th>Original finding</th><th>Local SHA</th>" +
        heads + "<th>Private note change count</th></tr></thead><tbody>" +
        "".join(rows) + "</tbody></table></section>"
        "<p>Use original authenticated source-owner review for any real security result. "
        "Keep this identifier-bearing HUMAN report PRIVATE.</p></main></html>\n"
    )
    return document.encode("utf-8")


def main() -> int:
    p = argparse.ArgumentParser(description="Read-only 2–12 PRIVATE HUMAN checkpoint progression (no network)")
    p.add_argument("--current", type=Path, required=True)
    p.add_argument("--previous", type=Path)
    p.add_argument("--session", type=Path, required=True,
                   help="Current original-bound HUMAN inbox for checking source, not modified")
    p.add_argument("--checkpoint", action="append", required=True, type=Path,
                   help="Private saved original HUMAN checkpoint, repeated in HUMAN-selected order")
    p.add_argument("--format", choices=("inspect", "html", "counts", "handoff"), default="inspect")
    p.add_argument("--output", type=Path, help="Unused owner-private output for html/counts/handoff")
    args = p.parse_args()
    try:
        require((args.format == "inspect") == (args.output is None),
                "Only exported PRIVATE report/counts/handoff accepts --output")
        if args.output is not None:
            require(args.output not in [args.current, args.previous, args.session, *args.checkpoint],
                    "Do not replace an original PRIVATE checkpoint/source/session")
        current, previous, cb, pb = selected_sources(args.current, args.previous)
        expected = make_session(current, previous, cb, pb)
        with single_host_lock(args.session):
            active_bytes = private_read(args.session)
            admit_session(active_bytes, expected)
            states, files = load_history(args.checkpoint, expected)
            result = trajectory(states)
            if args.format == "inspect":
                print(json.dumps(counts(result), indent=2, sort_keys=True))
                return 2
            if args.format == "html":
                data = make_html(current, result)
            else:
                obj = counts(result) if args.format == "counts" else private_handoff(current, result)
                data = (json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
            from argparse import Namespace
            from triage import fresh_original_bytes
            fresh_original_bytes(Namespace(current=args.current, previous=args.previous), cb, pb)
            require(private_read(args.session) == active_bytes,
                    "Active local HUMAN session changed during timeline export")
            require(all(private_read(path) == raw for path, raw in zip(args.checkpoint, files)),
                    "Original PRIVATE checkpoint content drifted during report preparation")
            private_publish(args.output, data)
            print("PRIVATE HUMAN-only checkpoint trajectory published; originals unchanged.")
        return 2
    except (Hold, OSError, ValueError) as exc:
        print("HOLD: " + str(exc), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
