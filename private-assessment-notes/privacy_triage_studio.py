#!/usr/bin/env python3
"""Source-free offline browser editor for HUMAN-only PRIVATE sensitivity triage."""
from __future__ import annotations

from base64 import b64encode
from hashlib import sha256
import html
import json


def render(rows: list[dict], cue_rows: list[dict] | None = None) -> bytes:
    """Original ordinal/source SHA plus optional literal-count HUMAN cues.

    No original/masked content, filenames, note text, or privacy verdict.
    """
    if cue_rows is not None and (
            len(cue_rows) != len(rows) or
            any(cue["original_ordinal"] != int(row["source_ordinal"])
                for row, cue in zip(rows, cue_rows))):
        raise ValueError("HOLD: original source/cue roster mismatch")
    keys = ("literal_http_or_shell_markers", "literal_url_or_session_markers",
            "literal_config_markers", "literal_token_or_key_markers")
    source = [{
        "ordinal": row["source_ordinal"],
        "digest": row["source_sha256_unsigned"],
        **({"cues": [cue_rows[index][key] for key in keys]}
           if cue_rows is not None else {}),
    } for index, row in enumerate(rows)]
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
const cueFilter = document.getElementById('cue-filter');
const cueCategory = document.getElementById('cue-category');
const cueReview = document.getElementById('cue-review');
const csvCell = text => '"' + String(text).replaceAll('"','""') + '"';
const banned = value => {
  const text = String(value);
  if (/[\\x00-\\x08\\x0b-\\x1f\\x7f]/.test(text)) return true;
  const badDirection = Array.from(text).some(ch => {
    const n = ch.codePointAt(0);
    return n === 0x061C || (n >= 0x202A && n <= 0x202E) ||
      (n >= 0x2066 && n <= 0x2069) || n === 0x2028 || n === 0x2029;
  });
  const normalized = text.trimStart();
  const first = normalized.codePointAt(0);
  const leadingMark = first !== undefined &&
    ((first >= 0x200B && first <= 0x200F) ||
     (first >= 0x2060 && first <= 0x206F) ||
     (first >= 0x0300 && first <= 0x036F) || first === 0xFEFF);
  return badDirection || leadingMark || /^[=+@-]/.test(
    normalized.normalize('NFKC').trimStart());
};
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
  if (cueFilter) {
    let visible = 0;
    for (const item of stage.values()) {
      const marked = item.source.cues.some(value => value > 0);
      const idx = cueCategory ? ['HTTP','URL','CONFIG','TOKEN']
        .indexOf(cueCategory.value) : -1;
      const categoryMatch = idx < 0 || item.source.cues[idx] > 0;
      item.tr.hidden = (cueFilter.checked && !marked) || !categoryMatch;
      if (!item.tr.hidden) visible++;
    }
    count.textContent += ' · ' + visible + ' visible in local cue view';
  }
  notice.textContent = 'LOCAL HUMAN draft only; zero markers never means clear.';
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
  if (source.cues)
    td(tr, 'HTTP ' + source.cues[0] + ' · URL ' + source.cues[1] +
       ' · Config ' + source.cues[2] + ' · Token ' + source.cues[3]);
  td(tr, select);
  td(tr, group);
  td(tr, note);
  body.append(tr);
  stage.set(source.ordinal, {source, tr, status:select, checks, note});
}
if (cueFilter) cueFilter.addEventListener('change', sync);
if (cueCategory) cueCategory.addEventListener('change', sync);
if (cueReview) cueReview.addEventListener('click', () => {
  const visible = [...stage.values()].filter(item => !item.tr.hidden);
  if (!visible.length) {
    notice.textContent = 'No visible originals to mark for HUMAN review.';
    return;
  }
  if (!window.confirm('Mark exactly ' + visible.length +
      ' VISIBLE original sources REVIEW_REQUIRED for private HUMAN discussion? ' +
      'Nothing is cleared, verified, exported or sent.')) {
    notice.textContent = 'Cancelled: all current HUMAN choices remain unchanged.';
    return;
  }
  for (const item of visible) item.status.value = 'REVIEW_REQUIRED';
  sync();
  notice.textContent = 'Visible HUMAN review proposals updated locally only. ' +
    'Export STILL includes all source positions; finalize is separate.';
});
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
const draftFile = document.getElementById('resume');
draftFile.addEventListener('change', async () => {
  const selected = draftFile.files && draftFile.files[0];
  if (!selected) return;
  try {
    if (selected.size < 80 || selected.size > 65536) throw new Error('size');
    // Fatal UTF-8 avoids silent changed original source identities.
    const content = new TextDecoder('utf-8', {fatal:true})
      .decode(await selected.arrayBuffer());
    const lines = content.split('\\r\\n');
    if (lines.at(-1) !== '' || lines.length !== sources.length + 2) throw new Error('roster');
    const header = 'source_ordinal,source_sha256_unsigned,review_status,privacy_topics,human_followup';
    if (lines[0] !== header) throw new Error('header');
    const rowPattern = /^"((?:[^"]|"")*)","((?:[^"]|"")*)","((?:[^"]|"")*)","((?:[^"]|"")*)","((?:[^"]|"")*)"$/;
    const decoded = [];
    for (let i = 0; i < sources.length; i++) {
      const match = rowPattern.exec(lines[i + 1]);
      if (!match) throw new Error('format');
      const [ordinal,digest,status,topicText,note] = match.slice(1)
        .map(x => x.replaceAll('""', '"'));
      const original = sources[i];
      const category = topicText.split('|');
      if (ordinal !== String(original.ordinal) || digest !== original.digest ||
          !states.includes(status) || category.length === 0 ||
          category.some(x => !topics.includes(x)) ||
          topics.filter(x => category.includes(x)).join('|') !== topicText ||
          (category.includes('UNKNOWN') && category.length !== 1) ||
          note.length > 300 || banned(note) || /[\\r\\n]/.test(note))
        throw new Error('source');
      decoded.push({status,category,note});
    }
    if (!window.confirm('Restore all ' + sources.length +
      ' HUMAN draft choices only? This is not a clearance or authorization.')) {
      notice.textContent = 'Cancelled: existing HUMAN choices left unchanged.';
      return;
    }
    // Apply only after complete exact-source and complete-row admission.
    sources.forEach((source,i) => {
      const target = stage.get(source.ordinal);
      target.status.value = decoded[i].status;
      target.note.value = decoded[i].note;
      for (const [name, box] of target.checks)
        box.checked = decoded[i].category.includes(name);
    });
    sync();
    notice.textContent = 'Complete original-bound LOCAL HUMAN draft restored; native finalize still required.';
  } catch (_) {
    notice.textContent = 'HOLD: incomplete, changed-source or unsupported PRIVATE draft. Current choices untouched.';
  } finally {
    draftFile.value = '';
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
tr[hidden]{display:none!important}
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
<main><p id="count"></p>""" + (
    """<p><a href="PRIVATE-masking-cues.html">Open original PRIVATE masking-cue navigator</a>.
    Counts are only literal placeholder appearances; zero is NOT clean.
    <label><input type="checkbox" id="cue-filter">
    Show only source positions with known literal marker appearances
    (the complete roster is ALWAYS exported)</label>
    <label for="cue-category">Optional literal marker category</label>
    <select id="cue-category" aria-label="Filter local ORIGINAL cue category">
      <option value="ALL">All categories</option>
      <option value="HTTP">HTTP / shell</option>
      <option value="URL">URL / session</option>
      <option value="CONFIG">Structured config / HAR</option>
      <option value="TOKEN">Tokens / keys</option>
    </select>
    <button type="button" id="cue-review">
      Mark VISIBLE originals REVIEW_REQUIRED (confirm)</button>
    <small>Changes only local HUMAN proposals; no authorization or privacy PASS.
    Hidden/unchanged originals stay in the complete final CSV.</small></p>"""
    if cue_rows is not None else "") + """<table><thead><tr><th>Original</th>""" + (
    "<th>Literal PRIVATE masking cues · NOT a verdict</th>" if cue_rows is not None
    else "") + """<th>HUMAN status</th>
<th>Possible sensitive categories</th><th>PRIVATE follow-up (max 300)</th></tr></thead>
<tbody id="rows"></tbody></table><p><label for="resume">Resume exact-source previous PRIVATE HUMAN browser CSV</label>
<input id="resume" type="file" accept=".csv,text/csv" aria-describedby="notice"></p>
<p><button type="button" id="save">Save full PRIVATE HUMAN draft CSV</button></p>
<p id="notice" role="status" aria-live="polite"></p></main><footer>
Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. No scan, release, privacy PASS or grant.</footer>
<script>""" + javascript + """</script></html>"""
    return page.encode("utf-8")
