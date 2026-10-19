#!/usr/bin/env python3
"""Render PRIVATE scriptless local HUMAN follow-up staging chronology.

No client/finding/request identities, local source digests, output paths,
native text or evidence material appear in the generated report.
"""
from __future__ import annotations

from datetime import datetime
from html import escape

MAX_REPORT = 96 * 1024

CSS = """
:root{color-scheme:light}
*{box-sizing:border-box}
body{font:16px/1.55 system-ui,-apple-system,sans-serif;
max-width:1050px;margin:0 auto;padding:clamp(1rem,4vw,3rem);
background:#f2f5f7;color:#17212b}
header,section,footer{background:#fff;border:1px solid #c9d2db;
border-radius:14px;padding:1.35rem 1.6rem;margin-bottom:1rem}
h1,h2{line-height:1.2;margin-top:0}
h1{font-size:clamp(1.5rem,3vw,2.3rem)}
h2{font-size:1.18rem}
p{max-width:78ch}
.note{border-left:5px solid #546274}
.hold{border-left:5px solid #97422c}
.completed{border-left:5px solid #32645c}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:.7rem}
.summary div{background:#e9eff3;border-radius:10px;padding:1rem}
.summary strong{display:block;font-size:1.8rem;font-variant-numeric:tabular-nums}
table{border-collapse:collapse;width:100%;table-layout:fixed}
caption{text-align:left;padding:.4rem 0;font-weight:600}
th,td{text-align:left;border-bottom:1px solid #dce3e8;padding:.7rem .4rem;
word-break:break-word;vertical-align:top}
th{font-size:.85rem}
code{font-size:.9em}
@media(max-width:580px){table{font-size:.85rem}th,td{padding:.4rem .25rem}}
@media print{body{background:#fff;padding:0}header,section,footer{break-inside:avoid}}
"""

ADVICE = {
    "pending": "HOLD: check whether an encrypted output exists. Use recover only for the exact admitted native draft, otherwise independently review and resolve an unpublished attempt.",
    "staged": "HUMAN DRAFT CREATED: use the original native Request Desk for a separate current-source Preview and a distinct manual Apply decision. Local journal is not proof it happened.",
    "reviewed": "HUMAN-REPORTED CLOSED: a later local cycle is possible only when the exact original source still reports all earlier requests closed.",
    "aborted_unpublished": "HUMAN-ACKNOWLEDGED NO OUTPUT: the recorded output was absent when the operator explicitly resolved this pending local attempt.",
    "empty": "No staged HUMAN draft recorded for this current source and material receipt in this private local journal.",
}


def _timestamp(value: object) -> str:
    if type(value) is not str or len(value) != 20 or not value.endswith("Z"):
        raise ValueError("Canonical private UTC timestamp required.")
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ValueError("Noncanonical private UTC timestamp.")
    return value


def build(journal: dict, current_closed: bool) -> bytes:
    """Generate an offline HTML artifact only from verified local journal data."""
    cycles = journal["cycles"]
    latest_state = cycles[-1]["state"] if cycles else "empty"
    total_drafts = sum(len(row["requests"]) for row in cycles)
    open_cycles = sum(row["state"] in ("pending", "staged") for row in cycles)
    held = latest_state in ("pending", "staged")
    rows = []
    for ordinal, row in enumerate(cycles, 1):
        started, changed = _timestamp(row["created"]), _timestamp(row["updated"])
        if changed < started:
            raise ValueError("Local HUMAN chronology timestamps reversed.")
        # HTML purposely never contains original request hashes, owner paths,
        # usernames, tenant/source SHA, HUMAN notes or file contents.
        rows.append("<tr><td>" + str(ordinal) + "</td><td>" +
                    escape(row["state"]) + "</td><td>" +
                    escape(started) + "</td><td>" +
                    escape(changed) + "</td><td>" +
                    str(len(row["requests"])) + "</td></tr>")
    banner = "hold" if held else "completed"
    markup = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy"
content="default-src 'none'; connect-src 'none'; script-src 'none'; img-src 'none';
font-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>PRIVATE HUMAN stage journal</title>
<style>""" + CSS + """</style></head><body>
<header><h1>PRIVATE HUMAN handoff journal</h1>
<p>Source-current local HUMAN record, not proof of original Apply,
reviewer identity, client consent, execution rights, legal retention authority
or a verified remediation/security finding.</p></header>
<section class='""" + banner + """'><h2>Next HUMAN action</h2><p>""" + (
        escape(ADVICE[latest_state])) + """</p></section>
<section><h2>PRIVATE local overview</h2><div class="summary">
<div>Cycles<strong>""" + str(len(cycles)) + """</strong></div>
<div>Staged request references<strong>""" + str(total_drafts) + """</strong></div>
<div>Unresolved cycles<strong>""" + str(open_cycles) + """</strong></div>
<div>Current original HUMAN closure observed<strong>""" + (
        "Yes (unverified HUMAN)" if current_closed else "No"
        ) + """</strong></div></div></section>
<section><h2>Local chronology</h2>
<table><caption>Private HUMAN attempts, no evidence identifiers</caption>
<thead><tr><th>Cycle</th><th>State</th><th>Created UTC</th>
<th>Updated UTC</th><th>Drafts</th></tr></thead>
<tbody>""" + "".join(rows) + """</tbody></table></section>
<footer><p>No source fingerprints, request IDs, private notes, client identities,
local paths, or evidence bytes are present in this HTML. This file is still
owner-private and must not be uploaded or used as a legal or audit certificate.
Human statuses are reported, not independently authenticated. This report
never executes, deletes or publishes source material.</p></footer></body></html>"""
    payload = markup.encode("utf-8", "strict")
    if len(payload) > MAX_REPORT:
        raise ValueError("Bounded local HUMAN chronology exceeded.")
    return payload
