#!/usr/bin/env python3
"""PRIVATE offline aggregate workload board for separate original HUMAN workspaces.

Every source is verified independently; a slot is not a unique customer or case.
No original labels, findings, file digests, notes or authority leave memory.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import html
from pathlib import Path
import sys

import verify
review = verify.review
triage = verify.triage
workspace = verify.workspace

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def plan(folders: list[Path]) -> dict:
    review.require(2 <= len(folders) <= 12, "Require 2–12 private workspace sources")
    review.require(len(set(folders)) == len(folders), "Repeated original workspace location")
    slots = []
    held = []
    source_to_slots = defaultdict(list)
    snapshot_ids = set()
    for ordinal, folder in enumerate(folders, 1):
        summary, raw = verify.inspect(folder)
        source_key = (sha(raw["current.json"]),
                      sha(raw["previous.json"]) if "previous.json" in raw else None)
        snapshot_key = (source_key, sha(raw["session.json"]))
        review.require(snapshot_key not in snapshot_ids,
                       "Identical source/HUMAN snapshot repeated; would double count local workload")
        snapshot_ids.add(snapshot_key)
        source_to_slots[source_key].append(ordinal)
        slots.append({
            "slot": ordinal,
            "human_questions": summary["human_questions"],
            "locally_pending": sum(
                n for k, n in summary["human_stage_counts"].items() if k != "answered_human"),
            "local_human_stages": summary["human_stage_counts"],
            "pending_human_reasons": summary["reason_counts"],
            "local_attachment_links": summary["local_links"],
            "cross_finding_shared_sha_groups": summary["shared_fingerprints"],
            "human_attention_groups": summary["conflicting_groups"],
        })
        held.append((folder, raw, sha(review.private_read(folder / "manifest.json"))))
    duplicate_groups = [list(v) for v in source_to_slots.values() if len(v) > 1]
    stage_totals = Counter()
    reason_totals = Counter()
    for row in slots:
        stage_totals.update(row["local_human_stages"])
        reason_totals.update(row["pending_human_reasons"])
    # Before publication, demand byte-identical original admitted files again.
    for folder, pinned, manifest_digest in held:
        review.require(sha(review.private_read(folder / "manifest.json")) == manifest_digest,
                       "Workspace manifest changed during aggregate review")
        review.require({p.name for p in folder.iterdir()} ==
                       set(pinned) | {"manifest.json"},
                       "Workspace entries changed during aggregate review")
        for name, payload in pinned.items():
            review.require(review.private_read(folder / name) == payload,
                           "Source/HUMAN workspace changed during aggregate review")
    return {
        "kind": "lightup.anonymous_private_human_evidence_workload_portfolio",
        "schema_version": 1,
        "disposition": "UNVERIFIED_HUMAN_COUNTS_ONLY",
        **{flag: False for flag in review.FLAGS},
        "source_slots": slots,
        "possible_repeated_original_source_slot_groups": duplicate_groups,
        "slot_human_stage_totals_not_unique_cases": {
            k: stage_totals.get(k, 0) for k in triage.STAGES},
        "slot_pending_human_reason_totals_not_unique_cases": {
            k: reason_totals.get(k, 0) for k in sorted(triage.REASONS)},
        "warning": "Counts are per local PRIVATE source SLOT, not unique clients, verified findings, authenticated chronology or remediation. Same original packet may appear in multiple slots; check duplicate groups before staffing decisions. No live execution, consent, review approval or security verdict.",
    }

def render(report: dict) -> bytes:
    esc = lambda x: html.escape(str(x), quote=True)
    def cells(rows: list[tuple[str, str]]) -> str:
        return "".join("<tr><th>" + esc(x) + "</th><td>" + esc(y) + "</td></tr>"
                       for x, y in rows)
    rows = []
    for slot in report["source_slots"]:
        rows.append("<tr><th>" + str(slot["slot"]) + "</th><td>" +
                    str(slot["human_questions"]) + "</td><td>" +
                    str(slot["locally_pending"]) + "</td><td>" +
                    str(slot["human_attention_groups"]) + "</td><td>" +
                    str(slot["local_attachment_links"]) + "</td></tr>")
    repeated = report["possible_repeated_original_source_slot_groups"]
    repeated_msg = ("<p><strong>Source-overlap attention:</strong> " + str(len(repeated)) +
                    " private source-group(s) repeated across separate slots. "
                    "These rows must not be counted as unique cases or clients.</p>"
                    if repeated else "<p>No exact same original packet repeated across slots. "
                    "This does NOT prove unique clients or independent findings.</p>")
    stages = cells([(k.replace("_", " "), str(v)) for k, v in
                    report["slot_human_stage_totals_not_unique_cases"].items()])
    reasons = cells([(k.replace("_", " "), str(v)) for k, v in
                     report["slot_pending_human_reason_totals_not_unique_cases"].items() if v])
    if not reasons:
        reasons = "<tr><th>No locally proposed open reasons</th><td>0</td></tr>"
    return ("<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
            "style-src 'unsafe-inline'; script-src 'none'; img-src 'none'; "
            "connect-src 'none'; form-action 'none'; base-uri 'none'\">"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>LightUp PRIVATE HUMAN portfolio</title>"
            "<style>body{font:16px system-ui;max-width:980px;margin:2rem auto;"
            "padding:0 1rem;background:#f6f7fa;color:#26374d}section,aside{"
            "background:white;margin:1rem 0;padding:1.25rem;border-radius:8px;"
            "overflow:auto}aside{border-left:5px solid #986000}"
            "table{border-collapse:collapse;width:100%}"
            "th,td{text-align:left;padding:.6rem;border-bottom:1px solid #dde3e9}</style>"
            "<main><h1>PRIVATE HUMAN evidence workload portfolio</h1>"
            "<aside><strong>INCUBATE · DRAFT/HOLD · HUMAN ONLY.</strong> "
            "Each slot is a separately verified self-declared original source/HUMAN "
            "workspace. Totals sum slot-workload and are NOT unique clients, "
            "findings, fixes, consent, evidence authenticity, remediation, signed "
            "reviews or verified retests. No scans, grant, native Apply or target access.</aside>"
            "<section><h2>Original PRIVATE workspace slots</h2>"
            "<table><thead><tr><th>Slot</th><th>HUMAN questions</th>"
            "<th>Locally pending</th><th>SHA attention groups</th>"
            "<th>Local links</th></tr></thead><tbody>" + "".join(rows) +
            "</tbody></table>" + repeated_msg + "</section>"
            "<section><h2>Slot workload by HUMAN stage</h2><table>" + stages +
            "</table></section><section><h2>Pending HUMAN reasons, per slot</h2>"
            "<table>" + reasons + "</table><p>A single question may have "
            "multiple reason codes. Totals are NOT deduplicated unique findings.</p>"
            "</section><p>Slot numbers are local order labels only. Output contains "
            "no original source IDs, file names, hashes or private HUMAN notes, "
            "but business workload counts may still be sensitive. Keep this on an "
            "owner-controlled machine.</p></main></html>\n").encode("utf-8")

def main() -> int:
    p = argparse.ArgumentParser(description="Source-separated PRIVATE HUMAN workload board offline")
    p.add_argument("--bundle", type=Path, action="append", required=True,
                   help="One full original 0700 PRIVATE evidence workspace (2–12 total)")
    p.add_argument("--html", type=Path, help="New scriptless PRIVATE owner-only HTML report")
    p.add_argument("--counts", type=Path, help="New source-free aggregate PRIVATE JSON")
    args = p.parse_args()
    try:
        review.require(not (args.html and args.counts), "Choose no more than one output")
        out = args.html or args.counts
        if out is not None:
            review.require(all(out.parent != folder for folder in args.bundle),
                           "Output must not modify any original source folder")
            triage.private_parent(out)
        summary = plan(args.bundle)
        if out is not None:
            review.private_publish(out, render(summary) if args.html else workspace.pretty(summary))
            print("PRIVATE source-separated HUMAN workload portfolio published.")
        print("REVIEW_ONLY: " + str(len(summary["source_slots"])) +
              " owner-private workspace slots admitted, not verified distinct cases.")
        return 2
    except (review.Hold, OSError, ValueError):
        print("HOLD: PRIVATE source-separated portfolio could not be admitted.", file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
