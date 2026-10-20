#!/usr/bin/env python3
"""Independent offline PRIVATE HUMAN-only Lab Team Reply Studio.

Input is only the source-admitted exact team subset of an existing PRIVATE
finalized HUMAN Lab review; output is a manually downloaded team-only CSV
for strict original native re-admission, never a grant or network action.
"""
from __future__ import annotations

from base64 import b64encode
from hashlib import sha256
import html
import lab_plan_review
import route_queue

STAGES = tuple(x for x in route_queue.STAGES if x != "UNASSESSED")
STYLE = """:root{color-scheme:dark;background:#0f1e32;color:#eff7ff;font:16px/1.5 system-ui}
body{max-width:1080px;margin:2rem auto;padding:1rem}header,main,footer{
background:#1c3650;border:1px solid #5b7693;padding:24px;border-radius:18px;margin:17px 0}
h1{font-size:clamp(1.7rem,4vw,2.7rem)}.warning{color:#ffe1aa;font-weight:bold}
table{border-collapse:collapse;width:100%;min-width:740px}th,td{text-align:left;padding:14px;border-bottom:1px solid #486984}
.wrap{overflow-x:auto}select,input,button{font:inherit;padding:10px;color:#f3fcff;background:#10263b;border:1px solid #94b5c9;border-radius:9px}
input{width:100%}button{cursor:pointer;max-width:100%}.status{color:#bff0d8}
:focus-visible{outline:3px solid #ffe1aa;outline-offset:3px}
@media(max-width:680px){header,main,footer{padding:15px}}"""
JS = r"""'use strict';
(() => {
  const records = Array.from(document.querySelectorAll('[data-workflow-row]'));
  const note = document.querySelector('#feedback');
  const counts = document.querySelector('#stage-counts');
  const filter = document.querySelector('#filter-stage');
  const button = document.querySelector('#download');
  const quote = value => '"' + String(value).replaceAll('"', '""') + '"';
  function update() {
    const stages = {};
    let visible = 0;
    for (const tr of records) {
      const stage = tr.querySelector('select').value;
      stages[stage] = (stages[stage] || 0) + 1;
      tr.hidden = !!filter.value && filter.value !== stage;
      if (!tr.hidden) visible += 1;
    }
    counts.textContent = visible + '/' + records.length +
      ' assigned private tasks visible · ' +
      Object.entries(stages).map(([s,n]) => s + ': ' + n).join(' · ') +
      '. Filter never excludes items from full CSV.';
  }
  filter.addEventListener('change', update);
  for (const tr of records) tr.querySelector('select').addEventListener('change', update);
  update();
  button.addEventListener('click', () => {
    const header = ['source_snapshot_sha256','proposal_slot',
                    'human_stage','human_team','human_question'];
    const lines = [header.map(quote).join(',')];
    for (const tr of records) {
      const stage = tr.querySelector('select').value;
      const humanNote = tr.querySelector('input').value;
      if (!['HOLD','NEEDS_INPUT','HUMAN_REVIEW','HUMAN_FOLLOWUP'].includes(stage) ||
          humanNote.length > 180 || /[\x00-\x1f\x7f]/.test(humanNote) ||
          /^\s*[=+\-@]/.test(humanNote)) {
        note.textContent = 'HOLD: invalid stage or unsafe HUMAN question. Nothing exported.';
        return;
      }
      lines.push([tr.dataset.source,tr.dataset.proposal,stage,
                  tr.dataset.team,humanNote].map(quote).join(','));
    }
    const blob = new Blob([lines.join('\r\n') + '\r\n'],
                          {type:'text/csv;charset=utf-8'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'PRIVATE-LAB-TEAM-REPLY.csv';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    note.textContent = 'PRIVATE CSV download requested, not verified. Place under owner-only 0700/0600 custody before manual native team return.';
  });
})();
"""


def render(team: str, rows: list[dict]) -> bytes:
    esc = lambda value: html.escape(str(value), quote=True)
    if not rows or any(x["human_team"] != team or x["human_stage"] not in STAGES for x in rows):
        raise ValueError("HOLD: source-bound team-only HUMAN rows required")
    items=[]
    for row in rows:
        choices="".join(
            '<option value="' + esc(stage) + '"' +
            (" selected" if row["human_stage"]==stage else "") + ">" +
            esc(stage.replace("_", " ")) + "</option>"
            for stage in STAGES)
        items.append(
            '<tr data-workflow-row data-source="' + esc(row["source_snapshot_sha256"]) +
            '" data-proposal="' + esc(row["proposal_slot"]) +
            '" data-team="' + esc(team) + '"><th scope="row">Original packet #' +
            esc(row["proposal_slot"]) + '</th><td><select aria-label="HUMAN stage for packet ' +
            esc(row["proposal_slot"]) + '">' + choices +
            '</select></td><td><input maxlength="' + str(lab_plan_review.NOTE_MAX) +
            '" aria-label="PRIVATE HUMAN question for packet ' +
            esc(row["proposal_slot"]) + '" value="' +
            esc(row["human_question"]) + '"></td></tr>'
        )
    js_pin=b64encode(sha256(JS.encode("utf-8")).digest()).decode("ascii")
    style_pin=b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    document = ('''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'sha256-''' +
      style_pin + """'; script-src 'sha256-""" + js_pin +
      """'; connect-src 'none'; img-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp · PRIVATE HUMAN Team Reply Studio</title><style>""" + STYLE +
      """</style></head><body>
<header><p class="warning">LIGHTUP / HUMAN LAB / ORIGINAL SOURCE-BOUND /
REVIEW_ONLY</p><h1>PRIVATE HUMAN Team Reply</h1>
<p>Assigned HUMAN team: <strong>""" + esc(team) + """</strong>.
""" + str(len(rows)) + """ original finalized source-bound HUMAN entries.
This does NOT authenticate you, a recipient, client, permission or a finding.</p>
</header><main><h2>Manually proposed HUMAN team decisions</h2>
<p>Every original selected row is exported, even when visually filtered.
Only HUMAN stage and bounded question may change. Original team,
source identity and proposal order remain pinned in this private workroom.</p>
<label>Stage filter <select id="filter-stage">
<option value="">All HUMAN stages</option>""" +
       "".join('<option value="'+esc(s)+'">'+esc(s)+'</option>' for s in STAGES) +
       """</select></label><p class="status" id="stage-counts" role="status" aria-live="polite"></p>
<div class="wrap"><table><thead><tr><th>Original source slot</th><th>HUMAN stage</th>
<th>PRIVATE HUMAN question</th></tr></thead><tbody>""" +
       "".join(items) + """</tbody></table></div>
<button id="download" type="button">Download complete PRIVATE team reply CSV</button>
<p id="feedback" role="status" aria-live="polite">No data transmitted.
Browser downloads do not automatically have Unix 0600 permissions.</p></main>
<footer><p class="warning">DRAFT/HOLD · NO AUTOMATIC ACCEPTANCE</p>
<p>Open only on a trusted local machine and keep exported PRIVATE CSV
under owner-only 0700/0600 custody. The source operator must re-admit
the exact original source-owner Lab packets, original FINAL HUMAN review,
the unchanged original team handoff and this complete returned CSV.
No scan, model, network, contact, grant, authenticated review or
release is performed. Original CI, owner and privacy/security/browser
reviews, independently authenticated client/operator consent,
action-time revocation and HUMAN GO remain mandatory.</p>
</footer><script>""" + JS + """</script></body></html>""")
    return document.encode("utf-8")
