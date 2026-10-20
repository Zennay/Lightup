#!/usr/bin/env python3
"""Source-free offline browser editor for HUMAN-only PRIVATE sensitivity triage."""
from __future__ import annotations

from base64 import b64encode
from hashlib import sha256
import html
import json


def render(rows: list[dict]) -> bytes:
    """Only original ordinal/SHA labels; no note content or original filenames."""
    source = [{"ordinal": row["source_ordinal"], "digest": row["source_sha256_unsigned"]}
              for row in rows]
    encoded = json.dumps(source, separators=(",", ":"), ensure_ascii=True).replace("<", "\\u003c")
    javascript = """'use strict';
const sources = """ + encoded + """;
const states = ['PENDING','REVIEW_REQUIRED','WITHHOLD'];
const topics = ['CREDENTIALS','PERSONAL_DATA','CLIENT_DATA','OTHER','UNKNOWN'];
const stage = new Map();
const body = document.getElementById('rows');
const count = document.getElementById('count');
const notice = document.getElementById('notice');
const button = document.getElementById('save');
const csvCell = text => '"' + String(text).replaceAll('"','""') + '"';
const banned = value => /^[\\s]*[=+@-]/.test(value) || /[\\x00-\\x08\\x0b-\\x1f\\x7f]/.test(value);
function td(tr, child) {
  const cell = document.createElement('td');
  if (child instanceof Node) cell.append(child); else cell.textContent = child;
  tr.append(cell);
}
function sync() {
  const values = [...stage.values()];
  count.textContent = values.length + ' originals · ' +
    values.filter(x => x.status.value === 'WITHHOLD').length + ' withhold · ' +
    values.filter(x => x.status.value === 'PENDING').length + ' pending';
  notice.textContent = 'LOCAL HUMAN draft only; no privacy verdict or recipient clearance.';
}
for (const source of sources) {
  const tr = document.createElement('tr');
  const select = document.createElement('select');
  select.setAttribute('aria-label', 'HUMAN status original ' + source.ordinal);
  for (const status of states) {
    const option = document.createElement('option');
    option.value = status;
    option.textContent = status.replaceAll('_',' ');
    select.append(option);
  }
  const group = document.createElement('div');
  group.className = 'topics';
  const checks = new Map();
  for (const topic of topics) {
    const label = document.createElement('label');
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.value = topic;
    checkbox.checked = topic === 'UNKNOWN';
    checkbox.addEventListener('change', () => {
      if (checkbox.checked && topic === 'UNKNOWN') {
        for (const [name, box] of checks) if (name !== 'UNKNOWN') box.checked = false;
      }
      if (checkbox.checked && topic !== 'UNKNOWN') checks.get('UNKNOWN').checked = false;
      if (![...checks.values()].some(b => b.checked)) checks.get('UNKNOWN').checked = true;
      sync();
    });
    checks.set(topic, checkbox);
    label.append(checkbox, document.createTextNode(topic.replaceAll('_',' ')));
    group.append(label);
  }
  const note = document.createElement('textarea');
  note.setAttribute('aria-label', 'PRIVATE follow-up original ' + source.ordinal);
  note.maxLength = 300;
  note.rows = 2;
  note.placeholder = 'PRIVATE human question only; no secret values or copied source';
  note.addEventListener('input', sync);
  select.addEventListener('change', sync);
  td(tr, '#' + source.ordinal);
  td(tr, select);
  td(tr, group);
  td(tr, note);
  body.append(tr);
  stage.set(source.ordinal, {source, status:select, checks, note});
}
sync();
button.addEventListener('click', () => {
  try {
    const lines = ['source_ordinal,source_sha256_unsigned,review_status,privacy_topics,human_followup'];
    for (const {source,status,checks,note} of stage.values()) {
      const chosen = topics.filter(name => checks.get(name).checked);
      if (!chosen.length || (chosen.includes('UNKNOWN') && chosen.length !== 1))
        throw new Error('Choose a single UNKNOWN or valid categories at every source');
      const text = note.value;
      if (text.length > 300 || banned(text) || /[\\r\\n]/.test(text))
        throw new Error('PRIVATE note contains prohibited spreadsheet prefix or control text');
      lines.push([source.ordinal,source.digest,status.value,chosen.join('|'),text]
        .map(csvCell).join(','));
    }
    // Exact full original roster; filtering never changes the native CSV.
    const payload = lines.join('\\r\\n') + '\\r\\n';
    const blob = new Blob([payload], {type:'text/csv;charset=utf-8'});
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'PRIVATE-HUMAN-sensitivity-completed.csv';
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 15000);
    notice.textContent = 'Downloaded PRIVATE complete local HUMAN draft. chmod 600 before native finalize.';
  } catch (_) {
    notice.textContent = 'HOLD: fix invalid PRIVATE note/categories; no file was exported.';
  }
});
window.addEventListener('pagehide', () => {
  for (const item of stage.values()) {
    item.note.value = '';
    item.status.value = 'PENDING';
    for (const [name, box] of item.checks) box.checked = name === 'UNKNOWN';
  }
  sync();
});
"""
    digest = b64encode(sha256(javascript.encode("utf-8")).digest()).decode("ascii")
    css = """
:root{color-scheme:light;font:16px/1.55 system-ui;background:#f2f5fa;color:#20324a}
body{max-width:1080px;margin:auto;padding:22px}
header,main{background:white;border:1px solid #ced9e5;border-radius:18px;padding:22px;margin-bottom:18px}
.warning{border-left:5px solid #b64623;background:#fff1e9;padding:12px}
table{width:100%;border-collapse:collapse}th,td{padding:10px;text-align:left;border-bottom:1px solid #ccd8e6;vertical-align:top}
.topics{display:grid;grid-template-columns:1fr 1fr;gap:5px}
label{display:flex;gap:6px;align-items:center;font-size:.9rem}
textarea{width:100%;max-width:320px;font:inherit}select,button{font:inherit;padding:7px}
button{background:#144b75;color:white;border:0;border-radius:9px;padding:13px;cursor:pointer}
button:focus-visible,select:focus-visible,textarea:focus-visible{outline:3px solid #f1a640}
@media(max-width:700px){table,thead,tbody,tr,th,td{display:block}thead{display:none}
tr{border:1px solid #bbcbd7;margin:12px 0;border-radius:10px}}
"""
    page = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-""" + digest + """'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'">
<title>LightUp PRIVATE sensitivity review editor</title><style>""" + css + """</style>
<header><p class="warning"><b>PRIVATE · HUMAN ONLY · HOLD</b> · Unsigned original SHA
and local category choices are NOT proof of privacy clearance, verified source,
recipient authentication, consent, security verdict or permission to share.</p>
<h1>Original-bound HUMAN sensitivity editor</h1><p>No assessment text is embedded
in this editor. Review original locally and classify potential concerns by source
number only. This browser is offline, uses no network, models, storage or files
outside the consciously downloaded PRIVATE CSV. No automatic external transfer.</p>
<p>After download move CSV to an owner-only 0700 parent and chmod 600. Use the
native <code>sensitivity-finalize</code> with unchanged original completed HUMAN
packet and unchanged triage kit. Native re-admission is still required.</p></header>
<main><p id="count"></p><table><thead><tr><th>Original</th><th>HUMAN status</th>
<th>Possible sensitive categories</th><th>PRIVATE follow-up (max 300)</th></tr></thead>
<tbody id="rows"></tbody></table><p><button type="button" id="save">Save full PRIVATE HUMAN draft CSV</button></p>
<p id="notice" role="status" aria-live="polite"></p></main><footer>
Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. No scan, release, privacy PASS or grant.</footer>
<script>""" + javascript + """</script></html>"""
    return page.encode("utf-8")
