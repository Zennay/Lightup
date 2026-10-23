#!/usr/bin/env python3
"""Render per-chain PRIVATE offline HUMAN transition editor without remote resources.

The editor runs only inside a freshly owner-private history workroom and
does not authenticate source, grant permission, or read original kit files.
"""
from __future__ import annotations

import base64
import hashlib
import html
import json

from history_human import HEADERS, expected_rows

STAGES = ("needs_review", "owner_followup", "hold", "reference_only")

START = r"""
(() => {
  'use strict';
  const COLUMNS = ["transition","from_ledger_sha256","to_ledger_sha256",
    "kit_ordinal","to_kit_digest","label_changed","added","removed","changed",
    "unchanged","human_stage","human_owner","human_question"];
  const STAGES = ["needs_review","owner_followup","hold","reference_only"];
  const entries = DATA.rows.map((original, i) => ({
    original, label: DATA.labels[i], stage: "needs_review", owner: "", question: ""
  }));
  const list = document.getElementById('rows');
  const notice = document.getElementById('notice');
  const query = document.getElementById('query');
  const stageFilter = document.getElementById('stage-filter');
  const resume = document.getElementById('resume');
  let dirty = false;
  const csv = value => '"' + String(value).replace(/"/g, '""') + '"';
  function admitted(value, limit) {
    return typeof value === 'string' && value.length <= limit &&
      !/[\x00-\x1f]/.test(value) && !/^\s*[=+\-@]/.test(value);
  }
  function show() {
    const q = query.value.trim().toLocaleLowerCase();
    const filter = stageFilter.value;
    let count = 0;
    const stageCounts = Object.fromEntries(STAGES.map(s => [s, 0]));
    entries.forEach(entry => {
      stageCounts[entry.stage] += 1;
      const pass = (filter === 'all' || entry.stage === filter) &&
        (!q || (entry.label + ' ' + entry.original.transition +
                  ' ' + entry.original.kit_ordinal + ' ' +
                  entry.owner + ' ' + entry.question).toLocaleLowerCase().includes(q));
      entry.el.hidden = !pass;
      if (pass) count++;
    });
    notice.textContent = count + ' of ' + entries.length +
      ' PRIVATE historical HUMAN decisions visible · ' +
      STAGES.map(s => s.replaceAll('_', ' ') + ': ' + stageCounts[s]).join(' · ') +
      (dirty ? ' · UNSAVED HUMAN EDITS' : '');
  }
  entries.forEach(entry => {
    const card = document.createElement('article');
    const title = document.createElement('h2');
    title.textContent = 'Step ' + entry.original.transition + ' · original kit ' +
      entry.original.kit_ordinal + ' · ' + entry.label;
    card.append(title);
    const changes = document.createElement('p');
    changes.textContent = 'Historical files: +' + entry.original.added +
      ' / -' + entry.original.removed + ' / changed ' + entry.original.changed +
      ' · label relabeled: ' + (entry.original.label_changed === '1' ? 'YES' : 'No');
    card.append(changes);
    const stage = document.createElement('select');
    STAGES.forEach(s => {
      const o = document.createElement('option');
      o.value = s; o.textContent = s.replaceAll('_', ' ');
      stage.append(o);
    });
    const owner = document.createElement('input');
    owner.type = 'text'; owner.maxLength = 80; owner.autocomplete = 'off';
    const question = document.createElement('textarea');
    question.maxLength = 500; question.rows = 2; question.spellcheck = false;
    [[stage,'HUMAN proposal stage'],[owner,'Proposed HUMAN owner'],
     [question,'Next HUMAN question (PRIVATE)']].forEach(([field,label]) => {
      const wrap = document.createElement('label');
      const heading = document.createElement('span');
      heading.textContent = label;
      wrap.append(heading, field);
      card.append(wrap);
    });
    stage.addEventListener('change', () => { entry.stage = stage.value; dirty = true; show(); });
    owner.addEventListener('input', () => { entry.owner = owner.value; dirty = true; show(); });
    question.addEventListener('input', () => { entry.question = question.value; dirty = true; show(); });
    entry.el = card; entry.fields = {stage,owner,question};
    list.append(card);
  });
  query.addEventListener('input', show);
  stageFilter.addEventListener('change', show);
  window.addEventListener('beforeunload', event => {
    if (dirty) { event.preventDefault(); event.returnValue = ''; }
  });
  function parseCsv(text) {
    if (text.length > 196608 || text.includes('\r') || text.includes('\0'))
      throw Error('Oversized or invalid original PRIVATE CSV');
    const table = [];
    let row = [], field = '', quoted = false, started = false, justClosed = false;
    for (let i=0;i<text.length;i++) {
      const ch = text[i];
      if (quoted) {
        if (ch === '"') {
          if (text[i+1] === '"') { field += '"'; i++; }
          else { quoted = false; justClosed = true; }
        } else {
          if (ch === '\n') throw Error('Multiline HUMAN CSV values forbidden');
          field += ch;
        }
      } else if (ch === ',') {
        row.push(field); field = ''; started = false; justClosed = false;
      } else if (ch === '\n') {
        row.push(field); table.push(row);
        row = []; field = ''; started = false; justClosed = false;
      } else if (ch === '"' && !started && !justClosed && field === '') {
        quoted = true; started = true;
      } else if (ch === '"' || justClosed) {
        throw Error('Invalid HUMAN CSV quoting');
      } else {
        field += ch; started = true;
      }
      if (field.length > 550 || table.length > 145) throw Error('HUMAN CSV bounds');
    }
    if (quoted || row.length || field.length) throw Error('Incomplete final CSV line');
    if (table.length !== entries.length + 1 ||
        JSON.stringify(table[0]) !== JSON.stringify(COLUMNS))
      throw Error('Unexpected headers or source row count');
    const restored = [];
    for (let i=0;i<entries.length;i++) {
      const cells=table[i+1], original=entries[i].original;
      if (cells.length !== COLUMNS.length) throw Error('HUMAN CSV column count');
      for (let k=0;k<10;k++) {
        if (cells[k] !== String(original[COLUMNS[k]]))
          throw Error('Original exact source transition / kit binding changed');
      }
      if (!STAGES.includes(cells[10]) ||
          !admitted(cells[11],80) || !admitted(cells[12],500))
        throw Error('HUMAN stage or content invalid');
      restored.push([cells[10],cells[11],cells[12]]);
    }
    return restored;
  }
  resume.addEventListener('change', async () => {
    const file = resume.files[0]; resume.value = '';
    if (!file) return;
    try {
      if (file.size > 196608) throw Error('Original CSV is oversized');
      const restored = parseCsv(await file.text());
      if (dirty && !confirm('Discard unexported local edits to load exactly matching HUMAN CSV?'))
        return;
      entries.forEach((entry,i) => {
        [entry.stage,entry.owner,entry.question] = restored[i];
        entry.fields.stage.value = entry.stage;
        entry.fields.owner.value = entry.owner;
        entry.fields.question.value = entry.question;
      });
      dirty = true;
      show();
      alert('PRIVATE HUMAN proposal reopened. Export again and use native historical finalizer.');
    } catch (error) {
      alert('PRIVATE HOLD: ' + error.message + '. Existing HUMAN choices unchanged.');
    }
  });
  document.getElementById('export').addEventListener('click', () => {
    for (const row of entries) {
      if (!STAGES.includes(row.stage) ||
          !admitted(row.owner,80) || !admitted(row.question,500)) {
        alert('PRIVATE HOLD: remove control characters and formula-prefixed HUMAN text.');
        return;
      }
    }
    if (!confirm('Export PRIVATE HUMAN proposals only? Browser Downloads may be exposed to other local users. Native exact-source finalization still required.'))
      return;
    const lines = [COLUMNS.join(',')];
    for (const entry of entries) {
      const row = {...entry.original,
        human_stage:entry.stage,human_owner:entry.owner,human_question:entry.question};
      lines.push(COLUMNS.map(key => csv(row[key])).join(','));
    }
    const blob=new Blob([lines.join('\n')+'\n'],{type:'text/csv;charset=utf-8'});
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a');
    a.href=url; a.download='HUMAN-history-review.csv'; a.hidden=true;
    document.body.append(a); a.click();
    setTimeout(() => { a.remove(); URL.revokeObjectURL(url); },1200);
    dirty = false;
    show();
  });
  show();
})();
"""

def render(sources, transitions):
    expected = expected_rows(sources, transitions)
    labels = []
    for step in transitions:
        for kit in step["kits"]:
            labels.append(kit["label"])
    data = json.dumps({"rows": expected, "labels": labels}, ensure_ascii=True,
                      separators=(",", ":")).replace("<", "\\u003c").replace(">", "\\u003e")
    js = START.replace("DATA", data, 1)
    pin = base64.b64encode(hashlib.sha256(js.encode("utf-8")).digest()).decode("ascii")
    title = "LightUp PRIVATE historical HUMAN decision studio · OFFLINE DRAFT/HOLD"
    return (
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "script-src 'sha256-" + pin + "'; style-src 'unsafe-inline'; "
        "connect-src 'none'; img-src 'none'; form-action 'none'; base-uri 'none'\">"
        "<title>" + html.escape(title) + "</title>"
        "<style>body{background:#f5f7fb;color:#1e3346;font:16px system-ui;"
        "line-height:1.5;max-width:1000px;margin:2em auto;padding:0 1rem}"
        "article{background:white;border:1px solid #cdd5dd;border-radius:12px;"
        "padding:1rem;margin:1rem 0}label{display:block;margin:.6rem 0}"
        "label span{display:block;font-weight:600}input,textarea,select,button{font:inherit;"
        "max-width:100%;padding:.4rem}input,textarea{width:90%}"
        "button{padding:.65rem 1rem}article[hidden]{display:none}small{display:block}"
        "</style><main><h1>" + html.escape(title) + "</h1>"
        "<p>ORIGINAL archived ledger transitions only; never original customer kit bytes, "
        "security verification, consent, scope or PASS. HUMAN data stays in this "
        "local browser memory until explicitly exported. This PRIVATE HTML "
        "contains kit labels and unsigned source ledger SHA-256 identities; "
        "store under original 0700/0600 custody, NOT in a public static site.</p>"
        "<p><strong>Every HUMAN export is merely a proposed timeline.</strong> "
        "Use history_human.py with the same 2–12 original ledger files to re-admit "
        "all exact original stored ledger bytes, transitions and this HUMAN CSV "
        "before creating a separate PRIVATE HOLD-only packet.</p>"
        "<p><label>Search HUMAN notes or kit label "
        "<input id='query' type='search' autocomplete='off'></label>"
        "<label>HUMAN stage filter <select id='stage-filter'>"
        "<option value='all'>All stages</option>" +
        "".join("<option value='" + stage + "'>" + stage + "</option>" for stage in STAGES) +
        "</select></label></p>"
        "<p><label>Resume exact same PRIVATE HUMAN-history-review.csv "
        "<input id='resume' type='file' accept='.csv,text/csv'></label></p>"
        "<p id='notice' role='status' aria-live='polite'></p>"
        "<p><button id='export' type='button'>Export PRIVATE HUMAN-history-review.csv</button></p>"
        "<section id='rows'></section><p>PRIVATE, unsigned, offline; nothing "
        "automatically submitted, approved, scanned, published or deleted.</p></main>"
        "<script>" + js + "</script></html>"
    )
