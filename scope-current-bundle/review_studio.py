#!/usr/bin/env python3
"""Compile a PRIVATE offline editable HUMAN workroom from admitted originals.

The original manifest byte admission and all trust policy live in change_brief.
This generator never reads client data independently, grants authority or
contacts a network endpoint. CSP script hash pins the embedded local source.
"""
from __future__ import annotations
import base64
import hashlib
import html
from pathlib import Path

MAX_SCRIPT = 24_000
CSS = """
:root{color-scheme:dark}*{box-sizing:border-box}
body{font:15px/1.55 system-ui,sans-serif;background:#0d1726;color:#f1f6ff;max-width:1300px;margin:0 auto;padding:24px}
h1{font-size:clamp(1.6rem,3.4vw,2.4rem)}h2{font-size:1.25rem}
a{color:#93cdfd}.notice{padding:16px;border:1px solid #6f7358;border-radius:10px;background:#272718;color:#ffe8a3}
section{background:#17263a;padding:18px;border-radius:12px;margin:18px 0}
.controls{display:flex;gap:12px;flex-wrap:wrap;align-items:end}
label{display:block;min-width:150px}label span{display:block;margin-bottom:4px}
input,select,textarea,button{font:inherit;color:#f8fcff;background:#263b53;border:1px solid #6a7e9b;border-radius:6px;padding:8px}
input[type=search]{min-width:220px}textarea{width:100%;min-height:70px;resize:vertical}
input.review-team{max-width:180px}
button,.import{cursor:pointer;background:#315577;font-weight:600}
button:hover{background:#3e719c}.import input{display:block;max-width:240px}
.table-wrap{overflow:auto;max-height:70vh}
table{border-collapse:collapse;width:100%;min-width:1040px}
th,td{text-align:left;border-bottom:1px solid #3d5269;padding:10px;vertical-align:top}
th{position:sticky;top:0;background:#23374b;z-index:1}
td:first-child{max-width:300px;overflow-wrap:anywhere}
td small{display:block;color:#a8c0d5;font-size:12px}
tr:nth-child(even){background:#1e3146}tr[hidden]{display:none}
.flag{color:#ffca86;font-weight:700}
output{display:block;white-space:pre-wrap;margin-top:10px}code{word-break:break-all}
button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:3px solid #a1d3ff}
"""
STAGES = ("unreviewed", "investigating", "escalated", "documented")


def attr(value: str) -> str:
    return html.escape(value, quote=True)


def compile_private_workroom(rows, previous_hash: str, current_hash: str, original_heads_changed: bool) -> bytes:
    js_path = Path(__file__).with_name("review_studio.js")
    if js_path.is_symlink() or not js_path.is_file() or js_path.stat().st_size > MAX_SCRIPT:
        raise ValueError("Missing/unsafe offline HUMAN studio source")
    script = js_path.read_bytes().decode("utf-8", "strict")
    if "</script" in script.lower():
        raise ValueError("Unsafe inline studio JS closing sequence")
    css_hash = base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode("ascii")
    js_hash = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode("ascii")
    html_rows = []
    for filename, changed, before, after in rows:
        if changed not in {"unchanged", "changed", "added", "absent"}:
            raise ValueError("Invalid source delta classification")
        opts = "".join(f'<option value="{attr(stage)}">{html.escape(stage)}</option>' for stage in STAGES)
        html_rows.append(
            f'<tr data-source="{attr(filename)}" data-change="{attr(changed)}" '
            f'data-old="{attr(before)}" data-new="{attr(after)}">'
            f'<td><strong>{html.escape(filename)}</strong><small>SHA-256 before: {html.escape(before or "—")}<br>'
            f'after: {html.escape(after or "—")}</small></td>'
            f'<td class="flag">{html.escape(changed.upper())}</td>'
            f'<td><label><span>HUMAN stage</span><select class="review-stage">{opts}</select></label></td>'
            f'<td><label><span>HUMAN team</span><input class="review-team" maxlength="80" autocomplete="off"></label></td>'
            f'<td><label><span>PRIVATE notes</span><textarea class="review-notes" maxlength="500"></textarea></label></td></tr>'
        )
    csp = ("default-src 'none'; script-src 'sha256-" + js_hash + "'; style-src 'sha256-" +
           css_hash + "'; connect-src 'none'; object-src 'none'; frame-src 'none'; " +
           "base-uri 'none'; form-action 'none'; img-src 'none'")
    content = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="' + attr(csp) + '">'
        '<meta name="referrer" content="no-referrer">'
        '<title>LightUp PRIVATE HUMAN source review desk · DRAFT/HOLD</title><style>' + CSS +
        '</style></head><body><main id="scope-review" data-previous="' + attr(previous_hash) +
        '" data-current="' + attr(current_hash) + '">'
        '<header><h1>LightUp · PRIVATE original-source HUMAN review</h1>'
        '<p class="notice"><b>DRAFT/HOLD · INCUBATE M3/M7 · HUMAN REVIEW ONLY.</b> '
        'No grant, consent, revocation proof, remediation, scan or release. '
        'This file contains confidential original paths/hashes and stays on the local trusted machine. '
        'A file missing from a local selection is never a fixed/revoked security finding.</p>'
        '<p>Original companion declared HEADs changed: <strong>' +
        ('YES — HUMAN re-review needed' if original_heads_changed else 'NO — NOT producer authentication') +
        '</strong></p><p>Previous source manifest SHA-256: <code>' + previous_hash +
        '</code><br>Current source manifest SHA-256: <code>' + current_hash + '</code></p></header>'
        '<section><h2>HUMAN actions (local-only)</h2><div class="controls">'
        '<label><span>Search source or HUMAN team</span><input id="query" type="search" autocomplete="off"></label>'
        '<label><span>Source change</span><select id="change-filter"><option value="">All</option>'
        '<option value="changed">Changed</option><option value="added">Added</option>'
        '<option value="absent">Absent locally</option><option value="unchanged">Unchanged</option></select></label>'
        '<label><span>HUMAN stage</span><select id="stage-filter"><option value="">All</option>' +
        ''.join(f'<option value="{stage}">{stage}</option>' for stage in STAGES) +
        '</select></label></div><p id="summary"></p>'
        '<button type="button" id="export">Export source-bound PRIVATE HUMAN CSV</button>'
        '<label class="import"><span>Restore an exact original HUMAN CSV</span>'
        '<input type="file" id="import" accept=".csv,text/csv"></label>'
        '<output id="status" aria-live="polite">HUMAN edits remain in memory until manually exported. '
        'Encrypted recipient transfer and actual client consent are NOT supplied by this desk.</output></section>'
        '<section class="table-wrap"><table><thead><tr><th>Original private source file</th>'
        '<th>Change</th><th>HUMAN review</th><th>HUMAN team</th><th>PRIVATE notes</th>'
        '</tr></thead><tbody>' + ''.join(html_rows) + '</tbody></table></section>'
        '<p>Original source/tenant authenticity and fresh separately authenticated client+operator permissions '
        'must be verified in the unchanged upstream authorization gates. This desk never invokes an active target.</p>'
        '</main><script>' + script + '</script></body></html>'
    )
    return content.encode("utf-8")
