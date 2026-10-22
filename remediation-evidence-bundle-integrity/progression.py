#!/usr/bin/env python3
"""Offline PRIVATE cross-bundle HUMAN checkpoint comparison; no chronology/authenticity."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import html
from pathlib import Path
import sys

import verify

review = verify.review
triage = verify.triage
workspace = verify.workspace

WARNING = "User-selected slot order is NOT independently authenticated chronology. Local HUMAN stages or checksums never prove source identity, consent, evidence, remediation or security clearance."

def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def assemble(paths: list[Path]) -> dict:
    review.require(2 <= len(paths) <= 12, "Require 2–12 original PRIVATE workspaces")
    review.require(len(set(paths)) == len(paths), "Repeated private workspace path")
    previous_source = None
    previous_snapshot = None
    packets = []
    for folder in paths:
        summary, raw = verify.inspect(folder)
        sources = (raw["current.json"], raw.get("previous.json"))
        if previous_source is None:
            previous_source = sources
        else:
            review.require(sources == previous_source,
                           "Different original source packet or local comparison context")
        session = triage.admit_session(raw["session.json"],
                  triage.make_session(
                      review.parse_packet_data(sources[0]),
                      review.parse_packet_data(sources[1]) if sources[1] is not None else None,
                      *sources))
        signature = digest(raw["session.json"])
        review.require(signature != previous_snapshot,
                       "Identical consecutive HUMAN session bytes cannot show a progression")
        previous_snapshot = signature
        packets.append((summary, session, signature, raw,
                        digest(review.private_read(folder / "manifest.json"))))
    review.require(len({p[2] for p in packets}) == len(packets),
                   "Duplicate HUMAN session bytes cannot form a distinct comparison")

    slots = []
    changes = []
    for idx, (summary, session, _) in enumerate(packets, 1):
        counts = triage.anonymous(session)["stage_counts"]
        slots.append({"slot": idx, "question_count": len(session["records"]),
                      "human_stage_counts": counts,
                      "locally_pending": sum(counts[k] for k in triage.STAGES[:-1])})
        if idx == 1:
            continue
        earlier = packets[idx - 2][1]["records"]
        later = session["records"]
        review.require(len(earlier) == len(later), "Original question membership changed")
        transition = Counter()
        for a, b in zip(earlier, later):
            review.require(a["ordinal"] == b["ordinal"] and
                           a["finding_id"] == b["finding_id"] and
                           a["local_sha256"] == b["local_sha256"] and
                           a["reasons"] == b["reasons"],
                           "HUMAN source question identity drift")
            if a["stage"] != b["stage"]:
                transition["changed_stage"] += 1
                if a["stage"] == "answered_human":
                    transition["reopened_local_human_question"] += 1
                if b["stage"] == "answered_human":
                    transition["locally_answered_since_prior_slot"] += 1
                if b["stage"] == "needs_source_owner":
                    transition["now_needs_source_owner"] += 1
            if a["human_note"] != b["human_note"]:
                transition["changed_private_note_without_note_contents"] += 1
            if a["stage"] == b["stage"] and a["human_note"] == b["human_note"]:
                transition["unchanged_local_human_record"] += 1
        changes.append({
            "from_slot": idx - 1, "to_slot": idx,
            **{k: transition[k] for k in (
                "changed_stage", "reopened_local_human_question",
                "locally_answered_since_prior_slot", "now_needs_source_owner",
                "changed_private_note_without_note_contents",
                "unchanged_local_human_record")},
        })
    for path, (_, _, _, admitted, manifest_hash) in zip(paths, packets):
        review.require(digest(review.private_read(path / "manifest.json")) == manifest_hash,
                       "PRIVATE bundle manifest changed during comparison")
        review.require({p.name for p in path.iterdir()} ==
                       set(admitted) | {"manifest.json"},
                       "PRIVATE source folder changed during comparison")
        for name, original_bytes in admitted.items():
            review.require(review.private_read(path / name) == original_bytes,
                           "PRIVATE workspace bytes changed during comparison")
    return {
        "kind": "lightup.anonymous_private_human_workspace_progression",
        "schema_version": 1, "disposition": "UNVERIFIED_HUMAN_REVIEW_ONLY",
        **{f: False for f in review.FLAGS},
        "snapshots": slots, "adjacent_user_order_transitions": changes,
        "warning": WARNING
    }

def render(value: dict) -> bytes:
    h = lambda x: html.escape(str(x), quote=True)
    rows = []
    for s in value["snapshots"]:
        rows.append("<tr><th>" + str(s["slot"]) + "</th><td>" +
                    str(s["question_count"]) + "</td><td>" +
                    str(s["locally_pending"]) + "</td><td>" +
                    " · ".join(h(k.replace("_", " ")) + ": " +
                               str(s["human_stage_counts"][k])
                               for k in triage.STAGES) + "</td></tr>")
    deltas = []
    for x in value["adjacent_user_order_transitions"]:
        deltas.append("<tr><th>" + str(x["from_slot"]) + " → " +
                      str(x["to_slot"]) + "</th><td>" +
                      str(x["changed_stage"]) + "</td><td>" +
                      str(x["reopened_local_human_question"]) + "</td><td>" +
                      str(x["locally_answered_since_prior_slot"]) + "</td><td>" +
                      str(x["changed_private_note_without_note_contents"]) + "</td></tr>")
    return ("<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
            "style-src 'unsafe-inline'; script-src 'none'; connect-src 'none'; "
            "img-src 'none'; form-action 'none'; base-uri 'none'\">"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>LightUp PRIVATE HUMAN workspace progression</title>"
            "<style>body{font:16px system-ui;background:#f5f6fa;color:#26374a;"
            "max-width:950px;margin:3rem auto;padding:0 1rem}"
            "main>aside,section{background:white;padding:1.2rem;margin:1rem 0;"
            "border-radius:8px;overflow:auto}aside{border-left:5px solid #986000}"
            "table{border-collapse:collapse;width:100%}"
            "th,td{padding:.6rem;border-bottom:1px solid #dde2e9;text-align:left}</style>"
            "<main><h1>PRIVATE HUMAN workspace progression</h1>"
            "<aside><strong>INCUBATE · DRAFT/HOLD · HUMAN ONLY.</strong> Each slot is a "
            "locally admitted full PRIVATE bundle with EXACTLY matching original source "
            "and proposed HUMAN question membership. Slot order is user-chosen, never "
            "a proven timeline. Original source authenticity, identity, consent, fixes "
            "and evidence file bytes remain unverified. No scan, native Apply, "
            "grant, clearance or verified retest.</aside>"
            "<section><h2>Local HUMAN slot overview</h2>"
            "<table><thead><tr><th>Slot</th><th>Questions</th><th>Pending</th>"
            "<th>Local HUMAN stages</th></tr></thead><tbody>" + "".join(rows) +
            "</tbody></table></section>"
            "<section><h2>Between adjacent user-selected slots</h2><table>"
            "<thead><tr><th>Slots</th><th>Stage changed</th><th>Reopened</th>"
            "<th>Locally answered</th><th>Private note changed</th></tr></thead>"
            "<tbody>" + "".join(deltas) + "</tbody></table>"
            "<p>These are only local HUMAN acknowledgements and changed-note counts; "
            "no private note contents are included and no missing record is treated "
            "as fixed.</p></section>"
            "<p>Keep output in a trusted owner-private local folder. No source "
            "identifiers or SHA hashes are printed, but operational aggregate details "
            "may still be sensitive.</p></main></html>\n").encode("utf-8")

def main() -> int:
    p = argparse.ArgumentParser(description=(
        "Compare 2–12 complete matching original PRIVATE HUMAN workspaces offline"))
    p.add_argument("--bundle", type=Path, required=True, action="append",
                   help="PRIVATE 0700 existing bundle; repeat in desired UNVERIFIED order")
    p.add_argument("--html", type=Path, help="New scriptless PRIVATE HTML outside all bundles")
    p.add_argument("--counts", type=Path, help="New source-free aggregate counts JSON")
    args = p.parse_args()
    try:
        review.require(not (args.html and args.counts), "Choose at most one publication")
        dest = args.html or args.counts
        if dest is not None:
            review.require(all(dest.parent != source for source in args.bundle),
                           "Cannot modify original PRIVATE source folder")
            triage.private_parent(dest)
        value = assemble(args.bundle)
        if dest is not None:
            review.private_publish(dest, render(value) if args.html else workspace.pretty(value))
            print("PRIVATE LOCAL HUMAN progression handoff published.")
        print("REVIEW_ONLY: " + str(len(value["snapshots"])) +
              " matched source-bound workspaces; user-chosen order not proven chronology.")
        return 2
    except (review.Hold, OSError, ValueError):
        print("HOLD: PRIVATE source-bundle progression cannot be admitted.", file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
