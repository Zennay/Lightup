"""Original-ordinal-only printable HUMAN HAR review checklist; no clearance."""
from __future__ import annotations

from html import escape
from private_har_hold_board import HAR_CATEGORIES, inventory

QUESTIONS = {
    "url_or_redirect": "Inspect privately held original URLs, paths, redirect destinations and query identifiers; do not copy them into a handoff.",
    "http_header": "Review every original custom and ordinary header for secret, customer or personal information.",
    "cookie_query_form": "Review original cookies, search parameters, form values and file uploads with the source owner.",
    "body_or_frame": "Review original opaque request, response, multipart, JSON and WebSocket content privately.",
    "file_reference": "Verify that original local filenames, private directories and source paths are never disclosed.",
}


def render(rows: list[dict]) -> bytes:
    records = inventory(rows)
    panels = []
    for record in records:
        ordinal = record["original_ordinal"]
        held = bool(record["whole_derived_copy_withheld"])
        lines = []
        for category, _ in HAR_CATEGORIES:
            markers = record[category + "_literal_markers"]
            if markers:
                lines.append("<li><label><input type='checkbox'> " +
                             escape(QUESTIONS[category]) +
                             " (" + str(markers) + " literal cues)</label></li>")
        lines.extend([
            "<li><label><input type='checkbox'> Independently inspect the complete owner-private original, including material not indicated by any marker.</label></li>",
            "<li><label><input type='checkbox'> Record an explicit HUMAN decision only in the original source-bound private decision workroom.</label></li>",
        ])
        title = ("ENTIRE DERIVED COPY WITHHELD — original owner required"
                 if held else "Independent private human review required")
        panels.append("<details><summary>Original #" + str(ordinal) + " — " +
                      escape(title) + "</summary><ul>" +
                      "".join(lines) + "</ul></details>")
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';form-action 'none';base-uri 'none';object-src 'none'">
<title>LightUp PRIVATE HUMAN HAR checklist</title>
<style>body{max-width:980px;margin:2rem auto;padding:1rem;font:16px/1.55 system-ui;color:#273747}
aside{border-left:5px solid #b05d2e;background:#fff0e5;padding:1rem}
details{border:1px solid #c3cdd7;border-radius:7px;padding:.75rem;margin:1rem 0}
summary{cursor:pointer;font-weight:bold}li{margin:.5rem 0}
input{accent-color:initial}summary:focus-visible{outline:3px solid #915123}
@media print{body{margin:0;max-width:none}details{break-inside:avoid}}</style>
<h1>PRIVATE original HAR HUMAN review checklist</h1>
<aside><b>PLAN/LAB ONLY · REVIEW_ONLY/HOLD · NO PRIVACY VERDICT.</b>
These are suggested manual prompts derived solely from literal placeholder
counts in original PRIVATE derived notes. Marker presence, absence and
ticks are not confirmed data classifications, fixes, privacy clearance,
consent, risk acceptance, authorisation, or evidence of a completed review.
Checkboxes have no persistence, export or automatic effects.</aside>
<p>Original positions: """ + str(len(records)) + """.
Return to the unchanged privately held originals and complete source-bound
HUMAN CSV; this page has no source names, paths, contents, URL, SHA, targets,
reviewer identities or human notes.</p>""" + "".join(panels) +
            """<p>No network, scripts, storage, findings, scan, grant,
recipient message or approval. Do not publish any PRIVATE outputs.</p></html>"""
            ).encode("utf-8")
