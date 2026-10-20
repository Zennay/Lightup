#!/usr/bin/env python3
"""PRIVATE read-only paged finding reports from one ALREADY produced lab source.

Keeps original ordinal identity across pages. Never executes a scanner or a target.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import sys

from briefing import CSS, DENIAL_FLAGS, Hold, SEVERITIES, h, followup_csv, json_bytes, open_source, publish_new

PER_PAGE = 40
MAX_PAGES = 52


def frame(title: str, body: str) -> str:
    pin = base64.b64encode(hashlib.sha256(CSS.encode("utf-8")).digest()).decode("ascii")
    csp = ("default-src 'none'; style-src 'sha256-" + pin +
           "'; script-src 'none'; connect-src 'none'; img-src 'none'; " +
           "base-uri 'none'; object-src 'none'; form-action 'none'")
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>" +
            "<meta http-equiv='Content-Security-Policy' content=\"" + h(csp) + "\">" +
            "<meta name='viewport' content='width=device-width,initial-scale=1'>" +
            "<title>" + h(title) + "</title><style>" + CSS +
            "</style></head><body>" + body + "</body></html>\n")


def overall_counts(source: dict) -> dict:
    result = {s: 0 for s in SEVERITIES}
    for f in source["findings"]:
        result[f["severity"]] += 1
    return result


def private_page(source: dict, fingerprint: str, start: int, end: int,
                 page_number: int, count: int) -> str:
    sections = []
    for index in range(start, end):
        f = source["findings"][index]
        literal_match = source["targets"].index(f["target"]) + 1 if f["target"] in source["targets"] else None
        declared_match = ("exact declared source endpoint " + str(literal_match)
                          if literal_match else "unmatched source-reported target")
        details = (
            ("Source finding ID", f["finding_id"]),
            ("Source check", f["check_id"]),
            ("Source capability", f["capability_id"]),
            ("Original target literal", f["target"]),
            ("Original impact", f["impact"]),
            ("Original mitigation proposal", f["fix"]),
            ("Original retest proposal", f["retest"]),
            ("Original evidence summary", f["evidence_summary"]),
            ("Original evidence references", ", ".join(f["evidence_ids"])),
        )
        detail_html = "".join("<dt>" + h(name) + "</dt><dd>" + h(value) + "</dd>"
                              for name, value in details)
        sections.append(
            "<article><h3>Original source ordinal #" + str(index + 1) +
            " · <span class='sev " + h(f["severity"]) + "'>" +
            h(f["severity"]) + "</span></h3>" +
            "<p class='muted'>" + h(declared_match) +
            " (never authenticates membership)</p>" +
            "<p>" + h(f["finding"]) + "</p>" +
            "<details><summary>PRIVATE original finding details (unverified)</summary>" +
            "<div><dl>" + detail_html + "</dl></div></details>" +
            "<div class='worksheet'><strong>HUMAN-only follow-up</strong>" +
            "<p>Human reviewer/group: ____________________________________</p>" +
            "<p>Proposed next action: _______________________________________</p>" +
            "<p>Original evidence independently checked by: ________________</p>" +
            "<p>Uncertainty / blocker: ____________________________________</p>" +
            "</div></article>"
        )
    status = (
        "<header><p><a href='index.html'>← Private index</a></p>" +
        "<h1>PRIVATE offline lab findings — page " + str(page_number) + "/" +
        str(count) + "</h1>" +
        "<p class='notice'>REVIEW ONLY: source declarations are not authenticated " +
        "findings, genuine client/operator permission, verified remediation, " +
        "executed work or an approved release.</p>" +
        "<p><strong>Original ordinal interval:</strong> " +
        (("#" + str(start+1) + "–#" + str(end)) if end > start else "none") +
        " of " + str(len(source["findings"])) +
        "</p><p><strong>Original PRIVATE source SHA-256 (UNSIGNED):</strong> <code>" +
        fingerprint + "</code></p>" +
        "<p>Source target strings, evidence and finding descriptions in this page " +
        "are highly PRIVATE. No target is contacted.</p></header>"
    )
    prev_link = ("<a href='page-%04d.html'>← Earlier source ordinals</a>" %
                 (page_number-1) if page_number > 1 else "")
    next_link = ("<a href='page-%04d.html'>Later source ordinals →</a>" %
                 (page_number+1) if page_number < count else "")
    navigation = ("<nav><p><a href='index.html'>Private index</a> &nbsp; " +
                  prev_link + " &nbsp; " + next_link + "</p></nav>")
    return frame("LightUp PRIVATE lab page " + str(page_number),
                 status + (navigation if count > 1 else "") +
                 ("".join(sections) if sections else
                  "<section class='card'>Original source reports zero findings.</section>") +
                 navigation)


def private_index(source: dict, fingerprint: str, count: int) -> str:
    totals = overall_counts(source)
    tiles = "".join("<section class='card'><strong>" + h(s) +
                    "</strong><div class='value'>" + str(n) + "</div></section>"
                    for s, n in totals.items())
    pages = []
    for n in range(count):
        start = n*PER_PAGE
        stop = min(len(source["findings"]),start+PER_PAGE)
        page_severity = {s: 0 for s in SEVERITIES}
        for f in source["findings"][start:stop]:
            page_severity[f["severity"]] += 1
        pages.append(
            "<li><a href='page-%04d.html'>Page %d · original ordinal %s</a> " %
            (n+1, n+1, ("#%d–#%d" % (start+1, stop) if stop > start else "none")) +
            "· " + h(", ".join("%s %d" % (s, v) for s, v in page_severity.items() if v))
            + "</li>")
    header = (
        "<header><h1>LightUp · PRIVATE paged lab review</h1>" +
        "<p class='notice'>Unverified, original source declaration only · " +
        "INCUBATE M3/M7 PLAN/LAB ONLY · NEVER authorization or an active scan.</p>" +
        "<p>Declared endpoint count: " + str(len(source["targets"])) +
        " · Original finding count: " + str(len(source["findings"])) +
        " · Private page count: " + str(count) + "</p>" +
        "<p>Original source SHA-256 (UNSIGNED, not identity/consent): <code>" +
        fingerprint + "</code></p>" +
        "<p>Open linked LOCAL pages below. Their literal targets, source labels, " +
        "evidence references, impacts and finding titles stay PRIVATE. " +
        "Original ordinals are never renumbered between pages.</p></header>"
    )
    return frame("LightUp PRIVATE paged lab index",header +
                 "<section class='card'><h2>Original declared severity distribution</h2>" +
                 "<div class='grid'>" + tiles + "</div></section>" +
                 "<section class='card'><h2>Offline pages by original ordinals</h2>" +
                 "<ol>" + "".join(pages) + "</ol></section>" +
                 "<section class='card'><h2>Private HUMAN follow-up</h2>" +
                 "<p>Use the adjacent original-format human-followup.csv for " +
                 "HUMAN-only proposals; the source SHA in manifest.json is an " +
                 "unsigned byte binder, never source authenticity. The original " +
                 "human_return.py rechecks this exact source + manifest before " +
                 "producing a PRIVATE human follow-up report.</p>" +
                 "</section>")


def make_paged_package(original_path: str, output_dir: str) -> None:
    source, _, fingerprint = open_source(original_path)
    total = len(source["findings"])
    pages = max(1, math.ceil(total / PER_PAGE))
    if pages > MAX_PAGES:
        raise Hold("PRIVATE page output would exceed bounded page count (HOLD)")
    artifacts = {}
    index = private_index(source, fingerprint, pages).encode("utf-8")
    artifacts["index.html"] = index
    page_meta = {}
    for n in range(pages):
        start = n*PER_PAGE
        end = min(total,start+PER_PAGE)
        name = "page-%04d.html" % (n+1)
        data = private_page(source, fingerprint, start, end, n+1, pages).encode("utf-8")
        artifacts[name] = data
        page_meta[name] = {
            "original_first_ordinal": start+1 if end > start else None,
            "original_last_ordinal": end if end > start else None,
            "source_declaration_count": end-start,
            "sha256_unsigned": hashlib.sha256(data).hexdigest()
        }
    worksheet = followup_csv(source).encode("utf-8")
    artifacts["human-followup.csv"] = worksheet
    manifest = {
        "schema": "lightup.private_lab_briefing.v1", "status": "REVIEW_ONLY",
        "layout": "paged_private_source_report",
        "original_source_sha256_unsigned": fingerprint,
        "declared_endpoint_count": len(source["targets"]),
        "declared_finding_count": total,
        "original_report_pages": page_meta,
        "private_artifact_sha256": {
            "index.html": hashlib.sha256(index).hexdigest(),
            "human-followup.csv": hashlib.sha256(worksheet).hexdigest(),
        },
        "source_authenticated": False, "ground_truth_verified": False,
        "client_consent_verified": False, "operator_consent_verified": False,
        **DENIAL_FLAGS,
    }
    artifacts["manifest.json"] = json_bytes(manifest)
    publish_new(output_dir, artifacts)


def main() -> int:
    parser = argparse.ArgumentParser(description="PRIVATE paged offline lab briefing, NO execution")
    parser.add_argument("--source", required=True, help="existing PRIVATE original JSON")
    parser.add_argument("--output-dir", required=True, help="NEW PRIVATE directory")
    args = parser.parse_args()
    try:
        make_paged_package(args.source, args.output_dir)
    except Hold as exc:
        print(str(exc), file=sys.stderr)
        return 3
    print("PRIVATE paged original lab briefing created; HUMAN REVIEW ONLY")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
