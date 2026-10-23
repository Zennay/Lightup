#!/usr/bin/env python3
"""Scriptless private human-only review-change dossier; never security authority."""
from __future__ import annotations

import base64
from collections import Counter
from hashlib import sha256
from html import escape
from pathlib import Path

STAGES = ("needs_review", "investigating", "documented")
FIELDS = ("stage", "reviewer", "next_action", "note")
FLAGS = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")
CSS = (
    "body{font:15px/1.6 system-ui,-apple-system,sans-serif;max-width:1060px;"
    "margin:2rem auto;padding:0 1.2rem;background:#f6f8fc;color:#192943}"
    "header,section{background:white;border:1px solid #d0ddec;padding:1.4rem;"
    "border-radius:10px;margin:1rem 0}h1{font-size:2rem;margin:0}"
    "h2{font-size:1.2rem}.warning{border-left:4px solid #b86b28;padding-left:1rem}"
    "table{width:100%;border-collapse:collapse;table-layout:fixed}"
    "th,td{text-align:left;vertical-align:top;border-bottom:1px solid #d0ddec;"
    "padding:.6rem;overflow-wrap:anywhere;white-space:pre-wrap}"
    "th{font-size:.85rem}code{overflow-wrap:anywhere;font-size:.82rem}"
    "details{margin:.6rem 0}.muted{color:#52627a}"
    "@media print{header,section{break-inside:avoid}body{background:white}}"
)


def _e(value):
    return escape(str(value), quote=True)


def describe(old_links, updated, source_digest):
    """Return private HTML and source-ID-free aggregate-only JSON-compatible dict."""
    changed = []
    count = Counter()
    for number, (old, new) in enumerate(zip(old_links, updated), 1):
        edits = tuple(field for field in FIELDS if old[field] != new[field])
        count["all_original_pairs"] += 1
        count["new_stage_" + new["stage"]] += 1
        if edits:
            changed.append((number, old, new, edits))
            count["changed_human_pairs"] += 1
            for name in edits:
                count["changed_" + name] += 1
    aggregate = {
        "schema": "lightup.assessment_remediation_human_return_counts.v1",
        "review_posture": "HUMAN_ONLY_UNVERIFIED",
        "original_pair_count": count["all_original_pairs"],
        "changed_human_pair_count": count["changed_human_pairs"],
        "changed_field_counts": {name: count["changed_" + name] for name in FIELDS},
        "new_human_stage_counts": {name: count["new_stage_" + name] for name in STAGES},
        **{name: False for name in FLAGS},
    }
    css_hash = base64.b64encode(sha256(CSS.encode("utf-8")).digest()).decode("ascii")
    csp = ("default-src 'none'; style-src 'sha256-" + css_hash +
           "'; base-uri 'none'; connect-src 'none'; form-action 'none'")
    html = [
        "<!doctype html><html lang=en><meta charset=utf-8>",
        "<meta name=viewport content='width=device-width,initial-scale=1'>",
        '<meta http-equiv="Content-Security-Policy" content="' + csp + '">',
        "<title>LightUp · private human team return diff</title><style>",
        CSS, "</style>",
        "<header><h1>LightUp — private human return changes</h1>",
        '<p class="warning"><strong>PRIVATE / HUMAN NOTES ONLY / UNVERIFIED</strong><br>',
        "This is a local before/after review of annotations, not a verified",
        " security finding, a completed retest, a consent decision or approval.",
        " Confirm the reviewer and client engagement out of band.</p>",
        "<p>Unsigned exact original private link baseline SHA-256: <code>",
        _e(source_digest), "</code></p></header>",
        "<section><h2>Human-only update summary</h2><p>",
        str(count["changed_human_pairs"]), " original source pair(s) have human-field changes",
        " out of ", str(count["all_original_pairs"]), " unchanged member IDs.</p>",
        "<p>No source identity, client finding, lab metric, authorization,",
        " scan, consent, grant or original retest status was modified.</p></section>"
    ]
    if not changed:
        html.append("<section><p>No human annotation changed. This alone is not a review verdict.</p></section>")
    else:
        for number, old, new, fields in changed:
            html.extend([
                '<section><h2>Original pair ' + str(number) + '</h2>',
                "<p>Original scenario: <code>", _e(old["scenario_id"]),
                "</code><br>Original finding: <code>", _e(old["finding_id"]),
                "</code></p><p class=muted>",
                "Changed human fields: ", _e(", ".join(fields)), "</p>",
                "<table><thead><tr><th>Human field</th><th>Operator baseline</th>",
                "<th>Returned reviewer note</th></tr></thead><tbody>",
            ])
            for field in fields:
                html.extend([
                    "<tr><th>", _e(field), "</th><td>", _e(old[field]),
                    "</td><td>", _e(new[field]), "</td></tr>"
                ])
            html.extend(["</tbody></table></section>"])
    html.append("<section><p>Original source IDs were retained only for confidential local",
                " owner reconciliation. Do not publish or transmit this dossier publicly.",
                " The returned file and author remain unsigned and unauthenticated.</p></section></html>")
    return "".join(html).encode("utf-8"), aggregate
