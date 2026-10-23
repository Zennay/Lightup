#!/usr/bin/env python3
"""PRIVATE aggregate-only human briefing from an already-produced local lab result.

No target, finding identifier, report title, source SHA or original evidence is exported.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import sys

from briefing import CSS, DENIAL_FLAGS, Hold, SEVERITIES, h, json_bytes, open_source, publish_new


def aggregate(source: dict) -> dict:
    counts = {level: 0 for level in SEVERITIES}
    evidence_references = 0
    evidence_summaries = 0
    for f in source["findings"]:
        counts[f["severity"]] += 1
        evidence_references += int(bool(f["evidence_ids"]))
        evidence_summaries += int(bool(f["evidence_summary"]))
    # No source fingerprint: even an unsigned hash permits cross-party matching.
    return {
        "schema": "lightup.private_lab_aggregate_brief.v1",
        "status": "REVIEW_ONLY", "scope": "declared_offline_lab_result",
        "declared_endpoint_count": len(source["targets"]),
        "declared_finding_count": len(source["findings"]),
        "source_reported_severity_count": counts,
        "findings_with_source_evidence_reference": evidence_references,
        "findings_with_source_evidence_summary": evidence_summaries,
        "human_followup_complete": False,
        "finding_validity_verified": False, "source_authenticated": False,
        "client_consent_verified": False, "operator_consent_verified": False,
        **DENIAL_FLAGS
    }


def render(data: dict) -> str:
    cards = "".join(
        "<section class='card'><h2>" + h(name) + "</h2><p class='value'>" +
        str(value) + "</p><p class='muted'>Source-declared, NOT independently verified</p></section>"
        for name, value in data["source_reported_severity_count"].items()
    )
    metrics = (
        "<p><strong>Declared lab endpoint count:</strong> " +
        str(data["declared_endpoint_count"]) +
        " · <strong>Declared finding count:</strong> " +
        str(data["declared_finding_count"]) + "</p>" +
        "<p><strong>Findings with source evidence reference:</strong> " +
        str(data["findings_with_source_evidence_reference"]) +
        " · <strong>Findings with source summary:</strong> " +
        str(data["findings_with_source_evidence_summary"]) + "</p>"
    )
    note = ("<p class='notice'>PRIVATE HUMAN BRIEF · REVIEW ONLY · NOT VERIFIED.</p>" +
            "<p>These values are declarations inside an original, locally supplied " +
            "offline isolated lab file. They do not prove an assessment occurred, " +
            "targets were accessible, findings are valid, evidence is sufficient, " +
            "or a remediation succeeded. No authorization, client/operator consent, " +
            "active dispatch or production release is established.</p>" +
            "<p>This summary omits original assets, names, IDs, finding text, run, " +
            "scenario, evidence and source fingerprints. Even aggregates may be " +
            "sensitive. Share only through a separately approved private channel.</p>")
    questions = (
        "<section class='card'><h2>Questions for a real human review</h2>" +
        "<ul><li>Is the original client and isolated lab scope separately authenticated?</li>" +
        "<li>Does an authorized owner possess the original evidence and context?</li>" +
        "<li>Which reported records require independent evidence review?</li>" +
        "<li>Are consent, risk approvals and at-use revocation independently established?</li>" +
        "<li>What follow-up is permitted without claiming an actual vulnerability verdict?</li>" +
        "</ul></section>"
    )
    pin = base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode()
    csp = ("default-src 'none'; style-src 'sha256-" + pin +
           "'; script-src 'none'; img-src 'none'; connect-src 'none'; " +
           "base-uri 'none'; form-action 'none'; object-src 'none'")
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>" +
            "<meta http-equiv='Content-Security-Policy' content=\"" + h(csp) + "\">" +
            "<meta name='viewport' content='width=device-width,initial-scale=1'>" +
            "<title>PRIVATE aggregate lab briefing</title><style>" + CSS +
            "</style></head><body><header><h1>LightUp · HUMAN lab declaration brief</h1>" +
            note + metrics + "</header><div class='grid'>" + cards +
            "</div>" + questions + "</body></html>\n")


def create(source_path: str, destination: str) -> None:
    original, _, _ = open_source(source_path)
    data = aggregate(original)
    html_bytes = render(data).encode("utf-8")
    json_data = json_bytes(data)
    publish_new(destination, {
        "private-human-aggregate.html": html_bytes,
        "private-human-aggregate.json": json_data,
    })


def main() -> int:
    p = argparse.ArgumentParser(description="PRIVATE aggregate-only HUMAN briefing; no execution")
    p.add_argument("--source", required=True, help="existing PRIVATE original lab JSON")
    p.add_argument("--output-dir", required=True, help="NEW PRIVATE output directory")
    a = p.parse_args()
    try:
        create(a.source, a.output_dir)
    except Hold as exc:
        print(str(exc), file=sys.stderr)
        return 3
    print("PRIVATE count-only HUMAN briefing created; REVIEW ONLY")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
