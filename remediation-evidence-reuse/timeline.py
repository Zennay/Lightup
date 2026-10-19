#!/usr/bin/env python3
"""PRIVATE, networkless human history of unchanged-source Evidence Ledger snapshots.

User-supplied order is NOT independently authenticated chronology.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import html
import json
from pathlib import Path
import sys

from review import (FLAGS, Hold, analyze, parse_packet_data, private_publish,
                    private_read, require)

MAX_SNAPSHOTS = 12
STAGES = ("unreviewed", "human_review", "follow_up", "archived")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def import_snapshots(paths: list[Path]) -> tuple[list[dict], list[str]]:
    require(2 <= len(paths) <= MAX_SNAPSHOTS,
            "Choose 2 to 12 original PRIVATE source snapshots")
    sources = []
    hashes = []
    observed = set()
    for path in paths:
        raw = private_read(path)
        digest = sha256(raw)
        require(digest not in observed, "Repeated exact PRIVATE snapshot bytes; no invented history")
        observed.add(digest)
        source = parse_packet_data(raw)
        if sources:
            for key in ("source_sha256", "source_count", "client_reference",
                        "engagement_reference", "source_contract"):
                require(sources[0][key] == source[key],
                        "Changed original source/context between snapshots: HOLD")
        sources.append(source)
        hashes.append(digest)
    return sources, hashes


def summarize(sources: list[dict]) -> dict:
    references = []
    fingerprint_groups = []
    for source in sources:
        by_key = {(r["finding_id"], r["sha256"]): r for r in source["attachments"]}
        references.append(by_key)
        by_digest = defaultdict(list)
        for record in source["attachments"]:
            by_digest[record["sha256"]].append(record)
        fingerprint_groups.append(by_digest)
    keys = sorted(set().union(*(set(r) for r in references)))
    metrics = []
    for ordinal, (source, group) in enumerate(zip(sources, fingerprint_groups), 1):
        previous = sources[ordinal - 2] if ordinal > 1 else None
        delta = analyze(source, previous)
        reused = [entries for entries in group.values()
                  if len({entry["finding_id"] for entry in entries}) > 1]
        diverse = sum(1 for entries in reused
                      if len({entry["human_stage"] for entry in entries}) > 1)
        metrics.append({
            "source_slot": ordinal,
            "local_links": len(source["attachments"]),
            "distinct_fingerprints": len(group),
            "cross_finding_shared_fingerprints": len(reused),
            "divergent_human_stage_fingerprints": diverse,
            "new_local_links_from_previous_slot": len(delta["added"]),
            "absent_local_links_from_previous_slot": len(delta["removed"]),
            "changed_local_human_metadata_from_previous_slot": len(delta["changed"]),
        })
    entries = []
    for finding, digest in keys:
        timeline = [ref.get((finding, digest)) for ref in references]
        states = [r["human_stage"] if r is not None else None for r in timeline]
        reviewers = [r["human_reviewer"] if r is not None else None for r in timeline]
        reasons = []
        if any(row is None for row in timeline):
            reasons.append("LOCAL_REFERENCE_ABSENT_IN_ONE_OR_MORE_SLOTS")
        if len({state for state in states if state is not None}) > 1:
            reasons.append("CHANGED_HUMAN_STAGE_ACROSS_SLOTS")
        if len({rev for rev in reviewers if rev is not None}) > 1:
            reasons.append("CHANGED_HUMAN_REVIEWER_ACROSS_SLOTS")
        if any(row is not None and
               len({x["finding_id"] for x in fingerprint_groups[slot][digest]}) > 1
               for slot, row in enumerate(timeline)):
            reasons.append("CROSS_FINDING_SHARED_FINGERPRINT")
        if any(row is not None and
               len({x["byte_length"] for x in fingerprint_groups[slot][digest]}) > 1
               for slot, row in enumerate(timeline)):
            reasons.append("CONTRADICTORY_LOCAL_BYTE_LENGTH")
        # A same-source reference disappearing does NOT imply repair.
        entries.append({"finding_id": finding, "local_sha256": digest,
                        "stages": states, "reviewers": reviewers, "reasons": reasons})
    priorities = [v for v in entries if v["reasons"]]
    return {"snapshot_metrics": metrics, "all_links": entries,
            "human_attention_links": priorities, "snapshot_count": len(sources),
            "distinct_local_links": len(entries)}


def counts_only(results: dict) -> dict:
    return {
        "kind": "lightup.anonymous_private_evidence_relationship_timeline",
        "schema_version": 1,
        "disposition": "HUMAN_REVIEW_ONLY_NO_AUTHORITY",
        "user_ordered_snapshot_count": results["snapshot_count"],
        "distinct_local_links_across_supplied_snapshots": results["distinct_local_links"],
        "links_with_proposed_human_attention": len(results["human_attention_links"]),
        "by_source_slot": results["snapshot_metrics"],
        "warning": "User order is not authenticated chronology, counts are local HUMAN claims. No verified fixes, grant or consent.",
    }


def private_handoff(source: dict, results: dict) -> dict:
    return {
        "kind": "lightup.private_human_evidence_relationship_timeline",
        "schema_version": 1, "disposition": "UNVERIFIED_HUMAN_FOLLOWUP_ONLY",
        "source_contract": source["source_contract"],
        "source_sha256": source["source_sha256"],
        "source_count": source["source_count"],
        "client_reference": source["client_reference"],
        "engagement_reference": source["engagement_reference"],
        **{name: False for name in FLAGS},
        "user_ordered_snapshots": results["snapshot_count"],
        "attention": results["human_attention_links"],
        "warning": "Unverified locally imported source/slot order. Advisory only: not source owner, identity, Apply, consent, scan or remediation.",
    }


def html_report(source: dict, results: dict) -> bytes:
    escape = lambda value: html.escape(str(value), quote=True)
    metrics = "".join("<tr><td>" + str(m["source_slot"]) +
        "</td><td>" + str(m["local_links"]) +
        "</td><td>" + str(m["cross_finding_shared_fingerprints"]) +
        "</td><td>" + str(m["divergent_human_stage_fingerprints"]) +
        "</td><td>" + str(m["new_local_links_from_previous_slot"]) +
        "</td><td>" + str(m["absent_local_links_from_previous_slot"]) +
        "</td><td>" + str(m["changed_local_human_metadata_from_previous_slot"]) +
        "</td></tr>" for m in results["snapshot_metrics"])
    def row(item: dict) -> str:
        cells = "".join("<td>" + escape(stage if stage is not None else
                      "NOT IN LOCAL SNAPSHOT") + "</td>" for stage in item["stages"])
        return ("<tr><td><code>" + escape(item["finding_id"]) + "</code></td>"
                "<td><code>" + escape(item["local_sha256"]) + "</code></td>" +
                cells + "<td>" + escape(", ".join(item["reasons"])) + "</td></tr>")
    rows = "".join(row(r) for r in results["human_attention_links"])
    headings = "".join("<th>Local slot " + str(i) + "</th>"
                       for i in range(1, results["snapshot_count"] + 1))
    document = ("<!doctype html><html lang='en'><meta charset='utf-8'>"
                "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
                "style-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; base-uri 'none'; "
                "form-action 'none'\"><meta name='viewport' content='width=device-width,initial-scale=1'>"
                "<title>PRIVATE LightUp evidence relationship timeline</title><style>"
                "body{font:16px system-ui;max-width:1260px;margin:1.5rem auto;padding:0 1rem;"
                "background:#f7f8fa;color:#182738}h1{font-size:1.9rem}"
                "table{border-collapse:collapse;width:100%;background:white;font-size:.9rem}"
                "td,th{border:1px solid #ddd;padding:.6rem;text-align:left;overflow-wrap:anywhere}"
                "aside{padding:1rem;background:#fff0d9;border-left:4px solid #b70}"
                "section{margin:1.4rem 0;overflow-x:auto}code{overflow-wrap:anywhere}</style>"
                "<main><h1>PRIVATE same-source evidence relationship timeline</h1><aside>"
                "<strong>HUMAN ONLY · INCUBATE DRAFT/HOLD.</strong> These are operator-ordered "
                "PRIVATE snapshots, NOT authenticated time sequence. Source labels, fingerprints and "
                "HUMAN stages are unverified. A reference absent from a local snapshot is NOT fixed. "
                "This document never establishes signed review, evidence custody, scan, retest, "
                "consent, grant or execution authority.</aside>"
                "<p>Original source claim: <code>" + escape(source["source_sha256"]) +
                "</code></p><p>Self-declared client / engagement: " +
                escape(source["client_reference"]) + " / " +
                escape(source["engagement_reference"]) + "</p>"
                "<section><h2>Source slot comparison</h2><table><thead><tr><th>Slot</th>"
                "<th>Local links</th><th>Reused fingerprints</th><th>Conflicting HUMAN stage</th>"
                "<th>New local links</th><th>Absent later local links</th><th>Changed HUMAN metadata</th>"
                "</tr></thead><tbody>" + metrics + "</tbody></table></section>"
                "<section><h2>Original finding × fingerprint attention matrix</h2>"
                "<p>" + str(len(results["human_attention_links"])) +
                " local references require HUMAN review. Original source declarations are not verified.</p>"
                "<table><thead><tr><th>Original finding</th><th>Local SHA-256</th>" +
                headings + "<th>Human-only attention reason</th></tr></thead><tbody>" +
                rows + "</tbody></table></section>"
                "<p>Return to original authenticated LightUp workflow for real evidence, consent and "
                "authorized review. Offline report is PRIVATE; never upload to public issue or CI.</p>"
                "</main></html>\n")
    return document.encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="PRIVATE same-source 2–12 snapshot HUMAN drift board, no network")
    parser.add_argument("--snapshot", action="append", required=True, type=Path,
                        help="Original PRIVATE native Ledger v1/unified v2 file, oldest-to-newest USER ORDER")
    parser.add_argument("--format", choices=("inspect", "html", "counts", "handoff"), default="inspect")
    parser.add_argument("--output", type=Path, help="New PRIVATE owner-only output filename")
    args = parser.parse_args()
    try:
        require((args.format == "inspect") == (args.output is None),
                "Supply a new --output only for html, counts or handoff")
        sources, digests = import_snapshots(args.snapshot)
        result = summarize(sources)
        if args.format == "inspect":
            print(json.dumps(counts_only(result), sort_keys=True, indent=2))
        else:
            if args.format == "html":
                payload = html_report(sources[0], result)
            else:
                packet = counts_only(result) if args.format == "counts" else private_handoff(sources[0], result)
                payload = (json.dumps(packet, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
            require(args.output not in args.snapshot,
                    "Never replace an original PRIVATE source file")
            # Fail closed if source content changed while preparing a private publication.
            for path, digest in zip(args.snapshot, digests):
                require(sha256(private_read(path)) == digest,
                        "Original PRIVATE snapshot changed during review")
            private_publish(args.output, payload)
            print("New PRIVATE HUMAN " + args.format + " published; no original source modified.")
        return 2
    except (Hold, OSError, ValueError) as exc:
        print("HOLD: " + str(exc), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
