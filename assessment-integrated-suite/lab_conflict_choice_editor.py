#!/usr/bin/env python3
"""Offline CSP-pinned original HUMAN decision editor, no network or authority."""
from __future__ import annotations

from base64 import b64encode
from hashlib import sha256
import json
from pathlib import Path

STYLE = """:root{color-scheme:dark;background:#0e1d31;color:#eaf7ff;
font:16px/1.65 system-ui}body{max-width:1150px;margin:2rem auto;padding:0 1rem}
header,main,footer{background:#20394f;border:1px solid #557d93;
border-radius:16px;margin:16px 0;padding:24px}strong{color:#ffe1aa}
button{padding:13px;border:2px solid #bad3e9;border-radius:8px;
background:#244e68;color:#fff;font:inherit;cursor:pointer}
button:disabled{opacity:.5;cursor:not-allowed}
button:focus-visible,input:focus-visible{outline:3px solid #ffdc90}
table{width:100%;border-collapse:collapse}th,td{padding:12px;text-align:left;
border-bottom:1px solid #546d7d}input{width:20px;height:20px}
div.table{overflow:auto}p.notice{color:#ffdfaa}
.filters{display:flex;flex-wrap:wrap;gap:12px;margin:12px 0}
.filters label{display:flex;flex-direction:column;gap:4px}
.filters input,.filters select{padding:9px;min-width:150px;
border:1px solid #9cbacf;border-radius:7px;font:inherit;
background:#142f42;color:#fff}.actions{display:flex;flex-wrap:wrap;gap:10px}
tr[hidden]{display:none}"""


def render(rows: list[dict]) -> bytes:
    if not rows or len(rows) > 500:
        raise ValueError("HOLD: original HUMAN conflict choice count invalid")
    script = Path(__file__).with_name("lab_conflict_choice_editor.js")
    if not script.is_file() or script.is_symlink():
        raise ValueError("HOLD: original offline HUMAN choice editor source absent")
    js = script.read_text(encoding="utf-8")
    if len(js) > 25000:
        raise ValueError("HOLD: offline HUMAN choice editor source too large")
    pin = lambda raw: b64encode(sha256(raw.encode("utf-8")).digest()).decode("ascii")
    # JSON remains data-only; every HTML-breaking character is escaped.
    embedded = (json.dumps(rows, ensure_ascii=True, separators=(",", ":"))
                .replace("<", "\\u003c").replace(">", "\\u003e")
                .replace("&", "\\u0026"))
    page = ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';
script-src 'sha256-""" + pin(js) + """';style-src 'sha256-""" + pin(STYLE) +
            """';connect-src 'none';img-src 'none';font-src 'none';frame-src 'none';
object-src 'none';form-action 'none';base-uri 'none'">
<title>LightUp PRIVATE HUMAN choices</title><style>""" + STYLE + """</style>
</head><body><header><strong>ORIGINAL LAB / PRIVATE / HUMAN REVIEW_ONLY</strong>
<h1>Decide one original HUMAN proposal at a time</h1>
<p>Previous decisions are always preserved by default. This is not an
authenticated reviewer, grant, PASS, client consent or security result.</p></header>
<main><p id="feedback" role="status" aria-live="polite">
Reading original private source-bound choices...</p>
<div class="filters" role="group" aria-label="Filter original HUMAN choices">
<label>Assigned HUMAN team<select id="filter-team"><option value="">All teams</option></select></label>
<label>Earlier or new stage<select id="filter-stage"><option value="">All HUMAN stages</option></select></label>
<label>PRIVATE question changed<select id="filter-question">
<option value="">All</option><option value="YES">Yes</option><option value="NO">No</option></select></label>
<label>Original proposal ordinal<input id="filter-ordinal" type="search"
maxlength="10" placeholder="e.g. 4"></label></div>
<div class="actions" role="group" aria-label="Deliberate HUMAN choice actions">
<button id="apply-visible" type="button">Apply only visible</button>
<button id="keep-visible" type="button">Keep previous for visible</button>
<button id="undo-choice" type="button" disabled>Undo</button>
<button id="redo-choice" type="button" disabled>Redo</button>
</div>
<p class="notice">Filtering NEVER removes original rows from the complete
source-bound CSV; all original ordinals are always exported. Undo and redo
remain local to this tab. Applying visible choices requires your confirmation.</p>
<div class="table"><table><thead><tr><th>Source ordinal</th><th>HUMAN team</th>
<th>Earlier stage</th><th>Returned stage</th><th>PRIVATE question changed</th>
<th>Deliberate HUMAN choice</th></tr></thead><tbody id="choices"></tbody></table></div>
<p><button id="export" type="button" disabled>
Export FULL original-source HUMAN choices CSV</button></p>
<p class="notice">Browser export does NOT automatically protect file custody.
Save the CSV under a trusted owner-only 0700 directory with exact 0600 mode.
Native option 69 strictly re-admits the original source and choices; no
automatic FINALIZE or dispatch occurs.</p></main>
<footer><strong>INCUBATE M3/M7 DRAFT/HOLD · NO NETWORK OR ASSESSMENT</strong>
<p>No original client targets, private question text, findings, credentials,
or recipient identities are embedded. This owner-0600 HTML contains exact
unsigned original source/candidate SHA bindings in its in-memory data-only
choice rows to export the complete native source-bound CSV. Keep this entire
HTML and exported CSV strictly private; SHA never authenticates an actor.
Original source-owner, hosted/named CI, security/privacy/browser reviews,
current separate authenticated client/operator consent, at-use revocation
and explicit HUMAN GO remain mandatory.</p></footer>
<script type="application/json" id="original-choices">""" + embedded +
            """</script><script>""" + js + """</script></body></html>""")
    return page.encode("utf-8")
