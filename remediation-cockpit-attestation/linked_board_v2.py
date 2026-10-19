#!/usr/bin/env python3
"""Native deterministic offline HUMAN task queue for complete PRIVATE workrooms.

Links point exclusively at the already-admitted source-free cockpit of the
same complete private workroom. This renderer never changes an older standalone
board or original source-owner HTML.
"""
from __future__ import annotations

import html
import coordination

MODE = "complete_workroom_source_free_inbox_v2"


def render(plan: dict) -> bytes:
    # Callers already admit plan and exact source-free inbox. No dynamic dates
    # or browser JS: byte-identical re-render for native admission.
    summary = coordination.overview(plan)
    urgent = {"urgent_review": 0, "attention": 1, "normal": 2}
    order = sorted(plan["slots"], key=lambda row: (
        row["stage"] == "locally_answered",
        urgent[row["priority"]],
        row["due_date"] is None,
        row["due_date"] or "9999-12-31",
        row["slot"],
    ))
    rows = []
    for item in order:
        index = item["slot"]
        # Canonical integer index, not operator-controlled text or a URL.
        destination = f"../inbox/slot-{index:02d}/cockpit/index.html"
        fields = [
            html.escape(item["assignee"] or "Unassigned", quote=True),
            html.escape(item["stage"], quote=True),
            html.escape(item["priority"], quote=True),
            html.escape(item["due_date"] or "Not scheduled", quote=True),
            html.escape(item["private_note"] or "—", quote=True),
        ]
        rows.append(
            '<tr><td><a href="' + destination + '">Open source-free slot ' +
            f'{index:02d}</a></td><td>' + '</td><td>'.join(fields) +
            '</td></tr>'
        )
    cards = "".join(
        '<div class="metric"><strong>' +
        str(summary["local_stage_totals"][stage]) + '</strong><span>' +
        html.escape(stage.replace("_", " ")) + '</span></div>'
        for stage in coordination.STAGES
    )
    markup = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" '
        'content="default-src &#39;none&#39;; script-src &#39;none&#39;; '
        'style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; '
        'form-action &#39;none&#39;;">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>PRIVATE HUMAN Follow-up Queue</title><style>'
        'body{font:16px system-ui,sans-serif;max-width:1120px;margin:2rem auto;'
        'padding:1rem;background:#f3f6fb;color:#17263c;line-height:1.5}'
        'h1{font-size:1.8rem}.banner{background:#fff4dd;padding:1rem;'
        'border-left:4px solid #b5760a}.metrics{display:flex;flex-wrap:wrap;'
        'gap:1rem;margin:1.25rem 0}.metric{min-width:115px;background:white;'
        'border:1px solid #d3ddec;padding:1rem}.metric strong{display:block;'
        'font-size:1.6rem}.metric span{font-size:.9rem;color:#425570}'
        'table{width:100%;border-collapse:collapse;background:#fff}'
        'th,td{text-align:left;border:1px solid #cad4e3;padding:.7rem;'
        'vertical-align:top}th{background:#e6eef9}a{color:#174c96;'
        'font-weight:600}td:last-child{overflow-wrap:anywhere}'
        'small{color:#425570}'
        '@media(max-width:700px){table{display:block;overflow-x:auto}}'
        '</style></head><body><main>'
        '<h1>PRIVATE HUMAN Follow-up Queue</h1>'
        '<p class="banner"><strong>LOCAL / UNVERIFIED / HUMAN ONLY.</strong> ' +
        html.escape(coordination.WARNING, quote=True) + '</p>'
        '<p>Plan revision <strong>' + str(plan["revision"]) + '</strong> · ' +
        str(summary["slots_not_unique_cases"]) + ' separately admitted '
        'source-free workroom slot(s), not unique clients or verified fixes.</p>'
        '<div class="metrics">' + cards + '</div>'
        '<p><strong>' +
        str(summary["pending_local_human_attention_slots"]) +
        '</strong> slots still need local HUMAN coordination. Unanswered '
        'items sort by locally assigned attention level and review date. '
        'These do not establish real risk severity or verified deadlines.</p>'
        '<table><thead><tr><th>Original anonymous cockpit</th>'
        '<th>Local operator</th><th>Local status</th><th>Attention</th>'
        '<th>HUMAN review date</th><th>PRIVATE local note</th>'
        '</tr></thead><tbody>' + "".join(rows) + '</tbody></table>'
        '<p><small>Links stay within this complete owner-private workroom. '
        'A local answer cannot verify a vulnerability fix or retest. '
        'No consent, security verdict, scan, grant or original source update.'
        '</small></p></main></body></html>\n'
    )
    return markup.encode("utf-8")
