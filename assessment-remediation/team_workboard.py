#!/usr/bin/env python3
"""Private scriptless multi-team HUMAN workboard; no original authority or network.

Called only after the original immutable owner mapping and disjoint returned
team snapshots have been admitted by multi_team.py. This is an operator-facing
HUMAN queue, not a finding verdict, source authentication or consent record.
"""
from __future__ import annotations

import base64
from collections import Counter
import csv
from hashlib import sha256
from html import escape
from io import StringIO

from bridge import csv_cell
from team_handoff import FIELDS, STAGES, IDENTITIES

CSS = (
    "body{font:15px/1.5 system-ui,sans-serif;color:#1a2a41;"
    "max-width:1120px;margin:2rem auto;padding:0 1.1rem;background:#f5f7fb}"
    "header,section{background:#fff;border:1px solid #d4deeb;border-radius:10px;"
    "padding:1.2rem;margin:1rem 0}h1,h2{margin:.3rem 0}.muted{color:#435470}"
    "table{width:100%;border-collapse:collapse;table-layout:fixed}"
    "td,th{text-align:left;border-bottom:1px solid #d8e1ed;padding:.6rem;"
    "vertical-align:top;white-space:pre-wrap;overflow-wrap:anywhere}"
    "th{background:#f2f6fb;font-size:.85rem}code{overflow-wrap:anywhere}"
    "nav a{display:inline-block;margin:.2rem .6rem .2rem 0}"
    ".warning{border-left:5px solid #b55e30;padding-left:1rem}"
    ".tag{background:#edf2fc;border-radius:3px;padding:.15rem .45rem}"
    "@media print{body{margin:0;background:#fff}section{break-inside:avoid}}"
)
ROW_CAP = 512
HTML_CAP = 2 * 1024 * 1024
CSV_CAP = 1024 * 1024


def _e(value):
    return escape(str(value), quote=True)


def _pairs(items):
    return {tuple(item[k] for k in IDENTITIES): item for item in items}


def render(original, reviewed, team_records, original_digest):
    """Build owner-private HTML + CSV from already admitted HUMAN-only records."""
    if (not 0 <= len(original) <= ROW_CAP or len(reviewed) != len(original)
            or not 2 <= len(team_records) <= 12):
        raise ValueError("invalid multi-team HUMAN workboard size")
    before = _pairs(original)
    after = _pairs(reviewed)
    if len(before) != len(original) or set(before) != set(after):
        raise ValueError("original and returned team identities diverged")

    assigned = {}
    for ordinal, team in enumerate(team_records, 1):
        if team["team_ordinal"] != ordinal:
            raise ValueError("private team ordinal drift")
        for pair in team["assigned_pairs"]:
            identity = (pair["scenario_id"], pair["finding_id"])
            if identity not in before or identity in assigned:
                raise ValueError("duplicate/foreign private team ownership")
            assigned[identity] = ordinal

    counts = Counter()
    groups = {ordinal: [] for ordinal in range(1, len(team_records) + 1)}
    groups[0] = []
    rows = []
    for index, initial in enumerate(original, 1):
        identity = tuple(initial[key] for key in IDENTITIES)
        current = after[identity]
        ordinal = assigned.get(identity, 0)
        changed_fields = [key for key in FIELDS if initial[key] != current[key]]
        counts["stage_" + current["stage"]] += 1
        counts["assigned" if ordinal else "unassigned"] += 1
        if changed_fields:
            counts["changed"] += 1
        item = (index, ordinal, initial, current, changed_fields)
        groups[ordinal].append(item)
        rows.append(item)

    style_pin = base64.b64encode(sha256(CSS.encode("utf-8")).digest()).decode("ascii")
    csp = ("default-src 'none'; style-src 'sha256-" + style_pin +
           "'; connect-src 'none'; img-src 'none'; form-action 'none'; "
           "object-src 'none'; frame-src 'none'; base-uri 'none'")
    html = [
        "<!doctype html><html lang=en><meta charset=utf-8>",
        "<meta name=viewport content='width=device-width,initial-scale=1'>",
        '<meta http-equiv="Content-Security-Policy" content="' + csp + '">',
        "<title>LightUp PRIVATE HUMAN multi-team owner queue</title>",
        "<style>" + CSS + "</style>",
        "<header><h1>PRIVATE HUMAN multi-team owner queue</h1>",
        "<p class=warning>INCUBATE · DRAFT / HOLD. These are unsigned human "
        "annotations, not client/operator identity, consent, a verified finding, "
        "remediation proof, authorization, permission to scan, or release.</p>",
        "<p>Original complete owner links SHA-256: <code>" + _e(original_digest) +
        "</code></p><p>Team returns: " + str(len(team_records)) +
        " · assigned source pairs: " + str(counts["assigned"]) +
        " · still unassigned: " + str(counts["unassigned"]) +
        " · human-edited pairs: " + str(counts["changed"]) + "</p>",
        "<p>Human stages: " + " · ".join(_e(stage) + ": " +
        str(counts["stage_" + stage]) for stage in STAGES) + "</p>",
        "<p class=muted>Original source bytes and free-text private notes are "
        "not copied into this report. IDs, reviewer names and next actions below "
        "remain confidential: transfer only after separate recipient verification.</p>",
        "<nav aria-label='PRIVATE human team sections'>",
    ]
    order = [0] + list(range(1, len(team_records) + 1))
    for ordinal in order:
        label = "Unassigned HUMAN follow-up" if ordinal == 0 else "Team " + str(ordinal)
        html.append('<a href="#group-' + str(ordinal) + '">' + _e(label) +
                    " (" + str(len(groups[ordinal])) + ")</a>")
    html.append("</nav></header>")
    for ordinal in order:
        label = ("UNASSIGNED — needs human routing, never assume resolution"
                 if ordinal == 0 else "Team " + str(ordinal) + " — unauthenticated HUMAN return")
        html.extend((
            '<section id="group-' + str(ordinal) + '"><h2>' + _e(label) + "</h2>",
            "<p class=muted>All source finding statuses remain source-reported. "
            "A changed HUMAN stage never proves a fix or scope approval.</p>",
            "<table><thead><tr><th>Original # / scenario</th><th>Original finding</th>"
            "<th>HUMAN stage / reviewer</th><th>Next HUMAN action</th>"
            "<th>Human changes</th></tr></thead><tbody>",
        ))
        if not groups[ordinal]:
            html.append("<tr><td colspan=5>No original pairs in this group.</td></tr>")
        for index, _, initial, current, changed in groups[ordinal]:
            html.append("<tr><td>" + str(index) + " · <code>" +
                _e(initial["scenario_id"]) + "</code></td><td><code>" +
                _e(initial["finding_id"]) + "</code></td><td>" +
                _e(current["stage"]) + " · " +
                _e(current["reviewer"] or "(unassigned)") + "</td><td>" +
                _e(current["next_action"] or "(human review needed)") + "</td><td>" +
                _e(", ".join(changed) or "No HUMAN changes") + "</td></tr>")
        html.append("</tbody></table></section>")
    html.append("<footer>AUTHENTICATED=false · CONSENT_VERIFIED=false · "
                "DISPATCH_ALLOWED=false · RELEASE_ALLOWED=false · HUMAN GO REQUIRED</footer></html>")
    html_bytes = "".join(html).encode("utf-8")
    if not 0 < len(html_bytes) <= HTML_CAP:
        raise ValueError("private workboard HTML exceeds bounded size")

    output = StringIO(newline="")
    writer = csv.writer(output, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow(("original_ordinal", "team_ordinal_zero_if_unassigned",
        "scenario_id", "finding_id", "human_stage", "reviewer",
        "human_next_action", "changed_human_fields"))
    for index, ordinal, initial, current, changed in rows:
        writer.writerow(tuple(csv_cell(str(field)) for field in (
            index, ordinal, initial["scenario_id"], initial["finding_id"],
            current["stage"], current["reviewer"], current["next_action"],
            "; ".join(changed))))
    csv_bytes = output.getvalue().encode("utf-8")
    if not 0 < len(csv_bytes) <= CSV_CAP:
        raise ValueError("private HUMAN action CSV exceeds bounded size")
    return html_bytes, csv_bytes
