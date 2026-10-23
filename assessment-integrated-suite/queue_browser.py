#!/usr/bin/env python3
"""Offline, CSP-pinned, HUMAN-only private queue editor from native rows.

The original native session + original file admission are the authority for
the initial rows. Browser edits are NOT authoritative and require normal
owner-private custody and native full CSV re-admission on return.
"""
from __future__ import annotations

import base64
import hashlib
import html
import json
from pathlib import Path

SCRIPT = Path(__file__).with_name("human_queue_editor.js")

CSS = """
:root{color-scheme:dark;background:#0d1625;color:#e8f3f9;
  font:16px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
*{box-sizing:border-box}body{margin:0 auto;max-width:1430px;padding:24px}
header{border:1px solid #46687f;background:linear-gradient(120deg,#1a3b53,#173047);
  padding:30px;border-radius:22px}
h1{font-size:clamp(2rem,4vw,3.4rem);line-height:1.13;margin:.3rem 0}
h2{font-size:1.22rem}p{color:#d1e1ed}
strong,.warn{color:#ffe0ab}a{color:#a2dfff;font-weight:680}
.actions{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0}
button,.file-label{background:#234f67;color:#edf9ff;font:inherit;font-weight:680;
 border:1px solid #7399ac;border-radius:10px;padding:11px 17px;cursor:pointer}
button:focus-visible,input:focus-visible,select:focus-visible,a:focus-visible,
.file-label:focus-within{outline:3px solid #ffe1a0;outline-offset:3px}
button:hover,.file-label:hover{background:#306681}
button:disabled{opacity:.42;cursor:not-allowed}
.file-label input{position:absolute;opacity:0;width:1px;height:1px}
.secondary{background:#34485a}
.filters{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,240px),1fr));
 gap:16px;margin:20px 0}
.filters label,.grid label,.question{display:flex;flex-direction:column;gap:6px;
 font-size:.9rem;font-weight:650;color:#bdd8e8}
input,select{font:inherit;background:#112338;color:#edf7fd;border:1px solid #617f99;
 border-radius:9px;padding:10px;min-height:45px;width:100%}
#list{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,450px),1fr));
 gap:18px;margin-top:20px}
.card{padding:22px;background:#172c42;border:1px solid #46647c;border-radius:16px}
.card h3{margin:0 0 6px;font-size:1.08rem;line-height:1.3}
.card p{font-size:.92rem;margin:.9rem 0}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.grid label:last-child{grid-column:span 2}
.question{margin:14px 0}
.hint{color:#afc8d9}
.attention-tag{color:#ffdfac;font-size:.88rem;font-weight:650}
.attention-panel{border:1px solid #557184;border-radius:14px;
 background:#1b3649;padding:19px;margin:20px 0}
.feedback{background:#193c46;border-left:5px solid #a7e5d5;padding:13px}
.feedback.error{background:#522c33;border-left-color:#ffac9b}
.warning-box{border-left:5px solid #ffce82;background:#342d29;padding:15px}
footer{padding:18px;background:#1a2f43;border-radius:14px;margin:24px 0}
@media(max-width:570px){body{padding:12px}.grid{grid-template-columns:1fr}
 .grid label:last-child{grid-column:auto}header{padding:18px}}
"""


def render(rows: list[dict]) -> bytes:
    source = SCRIPT.read_bytes()
    if not source or len(source) > 32768:
        raise ValueError("HOLD: unexpected signed-source offline editor script size")
    digest = base64.b64encode(hashlib.sha256(source).digest()).decode("ascii")
    source_js = source.decode("utf-8", "strict")
    # This inert JSON is read using textContent, never as interpreted script.
    # Escape HTML separators even in native admitted free HUMAN text.
    data = {
        "schema": "lightup.private.assessment-human-browser-draft.v1",
        "status": "REVIEW_ONLY",
        "may_scan": False, "may_grant": False, "may_release": False,
        "consent_verified": False, "source_authenticated": False,
        "rows": [{
            "snapshot_sha256": row["snapshot_sha256"],
            "workflow_key": row["workflow_key"],
            "human_stage": row["human_stage"],
            "review_team": row["review_team"],
            "followup_date": row["followup_date"],
            "human_question": row["human_question"],
            "local_state": row["local_state"],
            "human_next": row["human_next"],
            "title": row["title"],
            "group": row["group"],
            "local_href": row["local_href"],
        } for row in rows]
    }
    safe_json = json.dumps(data, ensure_ascii=True, separators=(",", ":")).replace(
        "<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    count = len(rows)
    page = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-""" + digest + """'; connect-src 'none'; img-src 'none'; form-action 'none'; base-uri 'none'; object-src 'none'">
<title>LightUp · PRIVATE HUMAN Assessment Queue Studio</title>
<style>""" + CSS + """</style>
<header>
<p class="warn">LIGHTUP · OWNER-PRIVATE · HUMAN ONLY · INCUBATE M3/M7</p>
<h1>Assessment HUMAN Queue Studio</h1>
<p>Make deliberate HUMAN routing choices for """ + str(count) + """ original local workflow rows.
Read and edit locally without server, account, localStorage, network,
scans, models, grants, retests, calendar scheduling, or automatic sharing.</p>
<p class="warn">REVIEW_ONLY / DRAFT-HOLD — every stage is a HUMAN proposal, never a PASS,
authorized target, approved security finding, recipient authentication,
customer consent, permission to scan, or release.</p>
</header>
<section class="warning-box">
<strong>PRIVATE custody warning</strong>
<p>Questions, source-independent review metadata and <code>file:</code> links
may still contain PRIVATE information. Browser CSV downloads may be public
to other local OS users: move manually into an owner-only 0700 directory and
set file permissions to 0600 before original native menu 43 accepts it.
Downloaded CSV is not cryptographically authenticated or auto-imported.
Never share, upload, email, paste into public cloud tools, or run HTTP server.</p>
</section>
<div class="actions">
<button type="button" id="download">Export entire PRIVATE HUMAN CSV</button>
<button class="secondary" type="button" id="saved" disabled>Acknowledge local save</button>
<button class="secondary" type="button" id="undo" disabled>Undo</button>
<button class="secondary" type="button" id="redo" disabled>Redo</button>
<label class="file-label">Import original local HUMAN CSV
<input type="file" id="csv-input" accept=".csv,text/csv"></label>
<button class="secondary" type="button" id="reset">Discard drafts</button>
</div>
<p id="status" class="feedback" role="status" aria-live="polite"></p>
<p id="dirty" class="warn"></p>
<p id="counts"></p>
<section class="attention-panel">
<h2>Live HUMAN attention and capacity (in-memory preview)</h2>
<p>Local HUMAN routing only; no vulnerability severity, authenticated
reviewer, client consent, booked appointment or security authorization.</p>
<label>Operator-declared review date (not scheduled)
<input type="date" id="review-date"></label>
<p id="date-warning" class="warn"></p>
<p id="attention-summary"></p>
<p id="capacity" class="hint"></p>
</section>
<div class="filters">
<label>Search existing workflows<input id="search" type="search" autocomplete="off"></label>
<label>Filter HUMAN stage<select id="stage-filter"></select></label>
<label>Filter assigned team<select id="team-filter"></select></label>
<label>Filter HUMAN attention<select id="priority-filter"></select></label>
</div>
<div class="actions">
<label>Bulk stage for FILTERED visible rows only
<select id="bulk-stage">
<option value="HOLD">HOLD</option>
<option value="NEEDS_INPUT">NEEDS INPUT</option>
</select></label>
<button class="secondary" type="button" id="bulk">Apply HUMAN stage to visible rows</button>
<label>Assign staged visible workflows to one HUMAN team
<select id="bulk-team-select"></select></label>
<button class="secondary" type="button" id="bulk-team">Assign visible staged HUMAN rows</button>
</div>
<p id="visible" class="hint" aria-live="polite"></p>
<main id="list"></main>
<footer>
<strong>Separate original gates remain mandatory:</strong>
source-owner review, permanent named VPS and hosted exact-HEAD CI, independent
security/privacy/browser review, distinct current authenticated client/operator
consent including revocation at action time, and explicit HUMAN GO.
Edits and imports never modify source data or original files. Export
deliberately includes <em>all</em> workflows regardless of visual filters.
No automatic grant, target action, scheduling, dispatch or deployment.
</footer>
<script id="original-data" type="application/json">""" + safe_json + """</script>
<script>""" + source_js + """</script>
</html>"""
    return page.encode("utf-8")
