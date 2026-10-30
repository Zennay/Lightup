#!/usr/bin/env python3
"""Source-free in-page HUMAN privacy concern timeline over original review rounds.

Only original ordinal, bounded categorical human labels and Boolean text-change
flags enter the static app. No notes, source hashes or filenames are embedded.
"""
from __future__ import annotations

from base64 import b64encode
from hashlib import sha256
import html
import json


def render(rounds: list[dict]) -> bytes:
    if not 2 <= len(rounds) <= 8:
        raise ValueError("invalid HUMAN review round count")
    number = len(rounds[0]["rows"])
    if not 1 <= number <= 12:
        raise ValueError("invalid original source positions")
    records = []
    for slot in range(number):
        series = []
        for rindex, item in enumerate(rounds):
            row = item["rows"][slot]
            previous = rounds[rindex-1]["rows"][slot] if rindex else None
            series.append({
                "round": rindex + 1,
                "status": row["review_status"],
                "topics": row["privacy_topics"].split("|"),
                "noteChanged": (previous is not None and
                                row["human_followup"] != previous["human_followup"]),
                "labelChanged": (previous is not None and
                                 (row["review_status"] != previous["review_status"]
                                  or row["privacy_topics"] != previous["privacy_topics"])),
            })
        records.append({"ordinal": slot + 1, "rounds": series})
    payload = json.dumps(records, separators=(",", ":"), ensure_ascii=True).replace("<", r"\u003c")
    script = r"""'use strict';
const records = """ + payload + r""";
const byId = id => document.getElementById(id);
const roundInput = byId('round');
const statusInput = byId('status');
const changedInput = byId('changed');
const searchInput = byId('search');
const table = byId('table');
const detail = byId('detail');
const count = byId('count');
const escape = text => String(text); // Only textContent, never innerHTML.
const cell = (tr,value) => { const td = document.createElement('td');
  td.textContent = escape(value); tr.append(td); return td; };
function redraw() {
  table.replaceChildren();
  const at = Number(roundInput.value);
  const stage = statusInput.value;
  const query = searchInput.value.trim();
  let visible = 0;
  for (const record of records) {
    const now = record.rounds[at-1];
    if (stage !== 'ALL' && now.status !== stage) continue;
    if (changedInput.checked && !(now.labelChanged || now.noteChanged)) continue;
    if (query && !String(record.ordinal).includes(query)) continue;
    visible++;
    const tr = document.createElement('tr');
    cell(tr,'#'+record.ordinal);
    cell(tr,now.status.replaceAll('_',' '));
    cell(tr,now.topics.join(', '));
    cell(tr,now.labelChanged ? 'Changed human category/status' : 'Unchanged labels');
    cell(tr,now.noteChanged ? 'Changed note' : 'No note change');
    const actions = document.createElement('td');
    const show = document.createElement('button');
    show.type = 'button'; show.textContent = 'View all rounds';
    show.setAttribute('aria-label','View original '+record.ordinal+' across all HUMAN rounds');
    show.addEventListener('click',() => showDetail(record));
    actions.append(show); tr.append(actions);
    table.append(tr);
  }
  count.textContent = visible + ' of ' + records.length +
    ' original source positions visible. Local HUMAN status changes are NOT fixes.';
}
function showDetail(record) {
  detail.replaceChildren();
  const h = document.createElement('h2');
  h.textContent = 'Original source #' + record.ordinal;
  detail.append(h);
  const note = document.createElement('p');
  note.textContent = 'Manual sequence of human labels only. Free notes and source content are deliberately hidden.';
  detail.append(note);
  const list = document.createElement('ol');
  for (const item of record.rounds) {
    const row = document.createElement('li');
    row.textContent = 'Round ' + item.round + ': ' + item.status +
      ' · ' + item.topics.join(', ') +
      (item.labelChanged ? ' · LABELS CHANGED' : '') +
      (item.noteChanged ? ' · HUMAN NOTE CHANGED (hidden)' : '');
    list.append(row);
  }
  detail.append(list);
  detail.focus();
}
function clearOnLeave() { detail.replaceChildren(); searchInput.value='';
  statusInput.value='ALL'; changedInput.checked=false; roundInput.value='1'; redraw(); }
for (const element of [roundInput,statusInput,changedInput,searchInput])
  element.addEventListener('input',redraw);
window.addEventListener('pagehide',clearOnLeave);
redraw();
"""
    sha = b64encode(sha256(script.encode("utf-8")).digest()).decode("ascii")
    css = """
:root{color-scheme:light;font:16px/1.6 system-ui;background:#eff3f7;color:#243249}
*{box-sizing:border-box}body{max-width:1180px;margin:auto;padding:24px}
header,main,aside{border:1px solid #d2dfe9;border-radius:18px;padding:22px;margin:0 0 18px;background:#fff}
.warning{border-left:5px solid #aa4521;background:#fff1eb}
h1{font-size:clamp(1.6rem,3.5vw,2.6rem)}h2{font-size:1.25rem}
.controls{display:flex;flex-wrap:wrap;gap:12px;align-items:end}
label{display:flex;flex-direction:column;min-width:130px;font-weight:650}
label.check{flex-direction:row;align-items:center;gap:6px}
input,select,button{font:inherit;padding:7px}
button{cursor:pointer;border:1px solid #446585;border-radius:8px;background:#eaf2fb}
button:focus-visible,input:focus-visible,select:focus-visible{outline:3px solid #d88b2b}
table{border-collapse:collapse;width:100%}td,th{padding:10px;border:1px solid #ced8e1;text-align:left}
th{background:#e6eef7}#detail:empty{display:none}
#detail{background:#f6f9fc}#detail:focus{outline:3px solid #d88b2b}
@media(max-width:720px){.scroll{overflow-x:auto}table{min-width:760px}}
@media print{body{padding:0;background:white}button,.controls{display:none}}
"""
    document = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-""" + sha + """'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'">
<title>LightUp PRIVATE HUMAN privacy timeline</title><style>""" + css + """</style>
<header><p class="warning"><b>HOLD · PRIVATE · HUMAN-DECLARED ONLY</b><br>
No labels, fewer concerns, unchanged notes or browser counts establish effective
masking, real source/author identity, confidentiality, consent or permission
to disclose. Original source bytes, SHA identities, private HUMAN note text
and filenames are not embedded in this self-contained offline page.</p>
<h1>PRIVATE HUMAN sensitivity timeline</h1><p>Manually ordered source-bound HUMAN
reviews. Review each original position across all rounds and filter only
the current local human labels; selecting a round does not change anything
in the original saved PRIVATE evidence. This page never sends data.</p></header>
<main><div class="controls">
<label for="round">Show round<select id="round">""" +
        "".join("<option value='" + str(i) + "'>HUMAN round " + str(i) + "</option>"
                for i in range(1, len(rounds) + 1)) + """</select></label>
<label for="status">HUMAN stage<select id="status">
<option value="ALL">All</option><option>PENDING</option>
<option>REVIEW_REQUIRED</option><option>WITHHOLD</option>
</select></label>
<label for="search">Original ordinal contains
<input id="search" type="search" inputmode="numeric" placeholder="e.g. 2"></label>
<label class="check" for="changed"><input type="checkbox" id="changed">
Literal changes since previous round only</label>
</div><p id="count" role="status" aria-live="polite"></p>
<div class="scroll"><table><thead><tr>
<th>Original #</th><th>HUMAN status</th><th>Possible categories</th>
<th>Stage/categories vs previous</th><th>HUMAN note vs previous</th>
<th>History</th></tr></thead><tbody id="table"></tbody></table></div>
</main><aside id="detail" tabindex="-1" aria-label="Original HUMAN round details"></aside>
<footer>Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.
No scans, models, target access, release, grants, authentication, retest,
deletion, exports or external recipients.</footer>
<script>""" + script + """</script></html>""")
    return document.encode("utf-8")
