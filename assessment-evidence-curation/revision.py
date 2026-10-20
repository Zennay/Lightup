#!/usr/bin/env python3
"""PRIVATE HUMAN curation revision comparison; original findings always UNVERIFIED.

Only reopens already-produced local original lab JSON + existing source-bound
HUMAN worksheet. Never contacts a target, merges/replaces source, or grants trust.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import sys

from curate import (MAX_CSV_BYTES, MAX_RECEIPT_BYTES, PRIORITIES, UNVERIFIED,
                    digest, read_original, read_receipt, read_selection)
from briefing import CSS, Hold, SEVERITIES, h, json_bytes, publish_new
from human_return import read_limited_file


def admit_revision_inputs(source_path: str, manifest_path: str,
                          worksheet_path: str, receipt_path: str,
                          selection_paths: list[str]):
    """Atomic original-source admission shared by all revision/history views."""
    source, original_sha, worksheet_raw, _ = read_original(
        source_path, manifest_path, worksheet_path)
    worksheet_sha = digest(worksheet_raw)
    read_receipt(read_limited_file(receipt_path, MAX_RECEIPT_BYTES),
                 original_sha, worksheet_sha, source)
    # Each version is independently checked against every original ordinal,
    # source severity and evidence count before ANY output is published.
    versions = []
    for path in selection_paths:
        raw = read_limited_file(path, MAX_CSV_BYTES)
        versions.append((digest(raw), read_selection(raw, source)))
    return source, original_sha, worksheet_sha, versions


def change_records(before: list[dict], after: list[dict], source: dict) -> list[dict]:
    left = {r["ordinal"]: r for r in before}
    right = {r["ordinal"]: r for r in after}
    changes = []
    for ordinal in sorted(left.keys() | right.keys()):
        a, b = left.get(ordinal), right.get(ordinal)
        if a == b:
            continue
        if a is None:
            kind = "HUMAN_ADDED"
        elif b is None:
            kind = "HUMAN_REMOVED"
        elif a["priority"] != b["priority"] and a["question"] != b["question"]:
            kind = "HUMAN_PRIORITY_AND_QUESTION_CHANGED"
        elif a["priority"] != b["priority"]:
            kind = "HUMAN_PRIORITY_CHANGED"
        else:
            kind = "HUMAN_QUESTION_CHANGED"
        finding = source["findings"][ordinal-1]
        changes.append({
            "ordinal": ordinal, "kind": kind, "reported_severity": finding["severity"],
            "original_evidence_reference_count": len(finding["evidence_ids"]),
            "before": a, "after": b,
        })
    return changes


def private_frame(title: str, body: str) -> bytes:
    css_pin = base64.b64encode(hashlib.sha256(CSS.encode("utf-8")).digest()).decode("ascii")
    policy = ("default-src 'none'; style-src 'sha256-" + css_pin +
              "'; script-src 'none'; connect-src 'none'; img-src 'none'; "
              "form-action 'none'; base-uri 'none'; object-src 'none'")
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>" +
            "<meta http-equiv='Content-Security-Policy' content=\"" + h(policy) +
            "\"><meta name='viewport' content='width=device-width,initial-scale=1'>" +
            "<title>" + h(title) + "</title><style>" + CSS +
            "</style></head><body>" + body + "</body></html>\n").encode("utf-8")


def render_changes(changes: list[dict], original_total: int,
                   before_count: int, after_count: int) -> bytes:
    warning = (
        "<header><h1>LightUp · PRIVATE HUMAN selection revision</h1>"
        "<p class='notice'>REVIEW ONLY / HOLD — original source declarations, "
        "reported severity, HUMAN identity, selected priorities, evidence, "
        "consent, remediation and authorization are not independently verified.</p>"
        "<p>A removed selection is NOT a fixed, revoked, retested or absent "
        "original finding. An added selection is NOT a new vulnerability.</p>"
        "<p>This PRIVATE handoff shows original ordinals and HUMAN questions, "
        "which may themselves identify client targets. Do not share publicly.</p>"
        "<p>Source-reported findings: " + str(original_total) +
        " · HUMAN selections: " + str(before_count) + " → " + str(after_count) +
        " · HUMAN changes: " + str(len(changes)) + "</p></header>"
    )
    sections = []
    for item in changes:
        left, right = item["before"], item["after"]
        def state(entry: dict | None) -> str:
            if entry is None:
                return "<p>Not HUMAN selected in this version (never means fixed).</p>"
            return ("<p>HUMAN priority: <strong>" + h(entry["priority"]) +
                    "</strong></p><pre>" + h(entry["question"]) + "</pre>")
        sections.append(
            "<article><h2>Original ordinal #" + str(item["ordinal"]) +
            " · " + h(item["kind"]) + "</h2>"
            "<p>Source-reported severity: " + h(item["reported_severity"]) +
            " · original evidence-reference count: " +
            str(item["original_evidence_reference_count"]) + "</p>"
            "<h3>Prior HUMAN selection</h3>" + state(left) +
            "<h3>Current HUMAN selection</h3>" + state(right) +
            "<div class='worksheet'>PRIVATE HUMAN rationale: ________________ "
            "· original evidence independently reviewed: __________</div></article>"
        )
    return private_frame("PRIVATE HUMAN curation revision",
                         warning + ("".join(sections) if sections else
                                    "<section class='card'>No HUMAN selection changes.</section>"))


def compare(source_path: str, manifest_path: str, worksheet_path: str,
            receipt_path: str, before_path: str, after_path: str,
            destination: str) -> None:
    source, original_sha, worksheet_sha, versions = admit_revision_inputs(
        source_path, manifest_path, worksheet_path, receipt_path,
        [before_path, after_path])
    before_sha, before = versions[0]
    after_sha, after = versions[1]
    changes = change_records(before, after, source)
    kinds = ("HUMAN_ADDED", "HUMAN_REMOVED", "HUMAN_PRIORITY_CHANGED",
             "HUMAN_QUESTION_CHANGED", "HUMAN_PRIORITY_AND_QUESTION_CHANGED")
    counts = {k: sum(item["kind"] == k for item in changes) for k in kinds}
    sev = {k: sum(item["reported_severity"] == k for item in changes)
           for k in SEVERITIES}
    detail = render_changes(changes, len(source["findings"]), len(before), len(after))
    anonymous = {
        "schema": "lightup.private_human_curation_revision_counts.v1",
        "status": "REVIEW_ONLY",
        "original_source_finding_count": len(source["findings"]),
        "human_selected_before_count": len(before),
        "human_selected_after_count": len(after),
        "human_changed_selection_count": len(changes),
        "human_change_categories": counts,
        "changed_source_reported_severity_counts": sev,
        "source_identifiers_included": False,
        **UNVERIFIED,
    }
    private_receipt = {
        "schema": "lightup.private_human_curation_revision_receipt.v1",
        "status": "REVIEW_ONLY",
        "original_source_sha256_unsigned": original_sha,
        "human_worksheet_sha256_unsigned": worksheet_sha,
        "before_human_selection_sha256_unsigned": before_sha,
        "after_human_selection_sha256_unsigned": after_sha,
        "private_human_revision_sha256_unsigned": digest(detail),
        "human_changed_original_ordinals": [item["ordinal"] for item in changes],
        **UNVERIFIED,
    }
    publish_new(destination, {
        "PRIVATE-human-curation-revision.html": detail,
        "PRIVATE-human-curation-revision-receipt.json": json_bytes(private_receipt),
        "human-revision-counts-PRIVATE.json": json_bytes(anonymous),
    })


def main() -> int:
    p = argparse.ArgumentParser(description="Offline PRIVATE HUMAN selection before/after diff, never active testing")
    p.add_argument("--source", required=True)
    p.add_argument("--manifest", required=True)
    p.add_argument("--worksheet", required=True)
    p.add_argument("--selection-receipt", required=True)
    p.add_argument("--before-selection", required=True)
    p.add_argument("--after-selection", required=True)
    p.add_argument("--output-dir", required=True)
    args = p.parse_args()
    try:
        compare(args.source, args.manifest, args.worksheet, args.selection_receipt,
                args.before_selection, args.after_selection, args.output_dir)
    except Hold:
        print("HOLD: Original PRIVATE source or HUMAN selection rejected; no output published", file=sys.stderr)
        return 3
    print("PRIVATE HUMAN selection revisions prepared; REVIEW ONLY, not original finding status")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
