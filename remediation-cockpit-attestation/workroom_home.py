#!/usr/bin/env python3
"""Source-bound deterministic PRIVATE HUMAN workroom landing page.

This is a local dashboard over separately admitted anonymous source-free
cockpit slots and locally self-declared HUMAN coordination stages. It never
authorizes a scan, retest, grant or real remediation.
"""
from __future__ import annotations

import html
from collections import Counter
import coordination

MODE = "complete_workroom_source_free_inbox_v2"


def render(plan: dict) -> bytes:
    counts = coordination.overview(plan)
    counts_by_stage = counts["local_stage_totals"]
    pending = counts["pending_local_human_attention_slots"]
    total = counts["slots_not_unique_cases"]
    assigned = counts_by_stage["assigned"] + counts_by_stage["waiting_human"]
    urgent = sum(
        row["priority"] == "urgent_review" and row["stage"] != "locally_answered"
        for row in plan["slots"]
    )
    due = sum(row["due_date"] is not None and
              row["stage"] != "locally_answered" for row in plan["slots"])
    shapes = Counter(x["original_cockpit_manifest_sha256"] for x in plan["slots"])
    extra_matching_shapes = sum(n - 1 for n in shapes.values() if n > 1)
    metrics = (
        ("Original source-free slots", total),
        ("Pending local HUMAN attention", pending),
        ("Locally assigned / waiting", assigned),
        ("Urgent local review (unverified)", urgent),
        ("Pending with local dates", due),
    )
    tiles = "".join(
        '<div class="tile"><strong>' + str(number) +
        '</strong><span>' + html.escape(label, quote=True) +
        '</span></div>'
        for label, number in metrics
    )
    html_page = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" '
        'content="default-src &#39;none&#39;; script-src &#39;none&#39;; '
        'style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; '
        'form-action &#39;none&#39;;">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>PRIVATE HUMAN Workroom Overview</title><style>'
        'body{font:16px system-ui,sans-serif;max-width:1000px;margin:2rem auto;'
        'padding:1rem;background:#f3f6fb;color:#152840;line-height:1.5}'
        'h1{font-size:2rem}.warning{background:#fff1cf;border-left:4px solid #bf7d00;'
        'padding:1rem}.metrics{display:grid;grid-template-columns:'
        'repeat(auto-fit,minmax(160px,1fr));gap:.8rem;margin:1.3rem 0}'
        '.tile{background:white;border:1px solid #ccd9ea;padding:1rem}'
        '.tile strong{display:block;font-size:2rem}.tile span{color:#425470}'
        '.nav{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));'
        'gap:1rem}.nav a{background:white;border:1px solid #d4dfe9;'
        'padding:1.25rem;color:#174c96;font-weight:700;text-decoration:none}'
        '.nav a:focus,.nav a:hover{text-decoration:underline;outline:2px solid #205d9a}'
        'small{color:#425470}</style></head><body><main>'
        '<h1>PRIVATE HUMAN Evidence Workroom</h1>'
        '<p>Local encrypted HUMAN plan revision <strong>' +
        str(plan["revision"]) +
        '</strong>. The counters below describe separately received '
        'source-free workload slots, not distinct clients or verified fixes.</p>'
        '<p class="warning"><strong>INCUBATE · DRAFT/HOLD · HUMAN ONLY.</strong> ' +
        html.escape(coordination.WARNING, quote=True) + '</p>'
        '<div class="metrics">' + tiles + '</div>'
        '<p><strong>' + str(extra_matching_shapes) + '</strong> additional source-free '
        'slot(s) have a matching anonymous manifest shape. Such a match cannot '
        'prove original client identity or duplicate cases; HUMAN review required.</p>'
        '<nav class="nav" aria-label="Offline PRIVATE workroom navigation">'
        '<a href="board/index.html">Open HUMAN follow-up queue and assignments →</a>'
        '<a href="inbox/index.html">Open original source-free evidence cockpit inbox →</a>'
        '</nav>'
        '<p><small>Human priorities and due dates are self-declared, not an '
        'authenticated source finding, verified security risk or client '
        'authorization. The workroom opens local files only; no external '
        'network requests, scans, grants, native Apply or retests.</small></p>'
        '</main></body></html>\n'
    )
    return html_page.encode("utf-8")
