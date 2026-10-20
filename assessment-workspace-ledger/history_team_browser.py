#!/usr/bin/env python3
"""Build a local-only source-identity-bound multi-reviewer HUMAN history editor."""
from __future__ import annotations

import base64
import hashlib
import html
import json

SCRIPT = r"""
(() => {
  'use strict';
  const DATA = __LIGHTUP_DATA__;
  const columns = ["transition","kit_ordinal","to_ledger_sha256","to_kit_digest",
    "chosen_packet_sha256","stage","owner","question"];
  const rows = DATA.rows.map((original, index) => ({
    original, label: DATA.labels[index], candidates: DATA.packets.map(p => p.rows[index]),
    selected: -1
  }));
  const list = document.getElementById('rows');
  const summary = document.getElementById('summary');
  const query = document.getElementById('query');
  const filter = document.getElementById('filter');
  const resume = document.getElementById('resume');
  let dirty = false;
  const csv = value => '"' + String(value).replace(/"/g, '""') + '"';
  const escape = s => String(s).toLocaleLowerCase();
  function agreement(row) {
    return new Set(row.candidates.map(c => JSON.stringify([c.stage,c.owner,c.question]))).size === 1;
  }
  function selected(row) {
    if (row.selected < 0) return {
      chosen_packet_sha256:'none',stage:'needs_review',owner:'',question:''
    };
    const p = DATA.packets[row.selected], v = row.candidates[row.selected];
    return {chosen_packet_sha256:p.sha256,stage:v.stage,owner:v.owner,question:v.question};
  }
  function show() {
    const search = escape(query.value.trim());
    let visible = 0, selectedCount = 0, divergent = 0;
    for (const r of rows) {
      if (r.selected >= 0) selectedCount++;
      if (!agreement(r)) divergent++;
      const matching = !search || escape(r.label + ' ' + r.original.transition +
        ' ' + r.original.kit_ordinal + ' ' +
        r.candidates.map(c => c.owner + ' ' + c.question).join(' ')).includes(search);
      const f = filter.value;
      const ok = matching && (f === 'all' || (f === 'disagree' && !agreement(r)) ||
        (f === 'unselected' && r.selected < 0) ||
        (f === 'selected' && r.selected >= 0));
      r.card.hidden = !ok;
      if (ok) visible++;
    }
    summary.textContent = visible + ' / ' + rows.length + ' PRIVATE original transitions visible · ' +
      divergent + ' divergent HUMAN rows · ' + selectedCount +
      ' explicitly chosen source packets · ' + (rows.length - selectedCount) +
      ' pending HUMAN review' + (dirty ? ' · UNSAVED LOCAL CHOICES' : '');
  }
  rows.forEach(r => {
    const article = document.createElement('article');
    const heading = document.createElement('h2');
    heading.textContent = 'Transition ' + r.original.transition +
      ' · original kit ' + r.original.kit_ordinal + ' · ' + r.label;
    article.append(heading);
    const info = document.createElement('p');
    info.textContent = 'Original file drift + ' + r.original.added +
      ' / - ' + r.original.removed + ' / changed ' + r.original.changed +
      ' · HUMAN packet opinions ' + (agreement(r) ? 'match' : 'DIFFER');
    article.append(info);
    const label = document.createElement('label');
    const title = document.createElement('span');
    title.textContent = 'Explicit HUMAN choice (NONE by default, no automatic verdict)';
    const select = document.createElement('select');
    const none = document.createElement('option');
    none.value = '-1'; none.textContent = 'NONE — fresh HUMAN review';
    select.append(none);
    r.candidates.forEach((candidate, index) => {
      const option = document.createElement('option');
      option.value = String(index);
      option.textContent = 'Reviewer packet ' + (index + 1) +
        ' · ' + candidate.stage + ' · ' + candidate.owner;
      select.append(option);
    });
    label.append(title, select);
    article.append(label);
    const details = document.createElement('div');
    details.className = 'opinions';
    for (const [index, candidate] of r.candidates.entries()) {
      const line = document.createElement('p');
      const strong = document.createElement('strong');
      strong.textContent = 'Original reviewer ' + (index + 1) + ': ' +
        candidate.stage + ' · HUMAN owner ' + candidate.owner;
      line.append(strong);
      const q = document.createElement('span');
      q.textContent = ' · PRIVATE question: ' + (candidate.question || '(none)');
      line.append(q);
      details.append(line);
    }
    article.append(details);
    select.addEventListener('change', () => {
      r.selected = Number(select.value);
      dirty = true; show();
    });
    r.card = article; r.select = select;
    list.append(article);
  });
  query.addEventListener('input', show);
  filter.addEventListener('change', show);
  document.getElementById('unanimous').addEventListener('click', () => {
    if (!confirm('HUMAN-only convenience: explicitly select reviewer packet 1 for matching HUMAN opinions? No PASS, consent, source-authentication or automatic finalization.'))
      return;
    rows.forEach(r => {
      if (agreement(r) && r.selected === -1) {
        r.selected = 0; r.select.value = '0';
      }
    });
    dirty = true; show();
  });
  function parseCsv(text) {
    if (text.length > 196608 || text.includes('\r') || text.includes('\0'))
      throw Error('Invalid or oversized PRIVATE reviewer choice CSV');
    let table=[], row=[], field='', quoted=false, started=false, closed=false;
    for (let i=0;i<text.length;i++) {
      const ch=text[i];
      if (quoted) {
        if (ch === '"') {
          if (text[i+1] === '"') { field += '"'; i++; }
          else { quoted = false; closed = true; }
        } else {
          if (ch === '\n') throw Error('Multiline CSV field refused');
          field += ch;
        }
      } else if (ch === ',') {
        row.push(field); field=''; started=false; closed=false;
      } else if (ch === '\n') {
        row.push(field); table.push(row); row=[]; field=''; started=false; closed=false;
      } else if (ch === '"' && !started && !closed && field === '') {
        quoted=true; started=true;
      } else if (ch === '"' || closed) {
        throw Error('Malformed CSV quoting');
      } else {
        field += ch; started=true;
      }
      if (field.length > 550 || table.length > 145) throw Error('CSV bounds exceeded');
    }
    if (quoted || row.length || field.length) throw Error('CSV incomplete final row');
    if (table.length !== rows.length + 1 ||
      JSON.stringify(table[0]) !== JSON.stringify(columns))
      throw Error('Unexpected native CSV schema or row count');
    const choices=[];
    for (let i=0;i<rows.length;i++) {
      const original=rows[i].original, cells=table[i+1];
      if (cells.length !== columns.length) throw Error('CSV wrong field count');
      for (const [col, key] of columns.slice(0,4).entries()) {
        if (cells[col] !== String(original[key]))
          throw Error('Native original source ledger identity mismatch');
      }
      const id=cells[4];
      if (id === 'none') {
        if (cells[5] !== 'needs_review' || cells[6] || cells[7])
          throw Error('Unselected must remain needs_review');
        choices.push(-1);
        continue;
      }
      const idx=DATA.packets.findIndex(p => p.sha256 === id);
      if (idx < 0) throw Error('Unknown or changed original reviewer SHA');
      const source=rows[i].candidates[idx];
      if (cells[5] !== source.stage || cells[6] !== source.owner ||
          cells[7] !== source.question)
        throw Error('Reviewer HUMAN opinion changed');
      choices.push(idx);
    }
    return choices;
  }
  resume.addEventListener('change', async () => {
    const file=resume.files[0];resume.value='';
    if (!file) return;
    try {
      if (file.size > 196608) throw Error('CSV too large');
      const draft=parseCsv(await file.text());
      if (dirty && !confirm('Discard unexported HUMAN choices and load exact source-bound draft?'))
        return;
      rows.forEach((r,i) => {
        r.selected=draft[i];r.select.value=String(draft[i]);
      });
      dirty=true;show();
      alert('Exact original HUMAN choices restored. Native finalization still required.');
    } catch(error) {
      alert('PRIVATE HOLD: ' + error.message + '. Existing choices unchanged.');
    }
  });
  document.getElementById('export').addEventListener('click', () => {
    if (!confirm('Export PRIVATE HUMAN reviewer selections? Browser Downloads may be exposed. Native source re-admission and human review still required.'))
      return;
    const lines=[columns.join(',')];
    rows.forEach(r => {
      const data={...r.original,...selected(r)};
      lines.push(columns.map(key => csv(data[key])).join(','));
    });
    const blob=new Blob([lines.join('\n')+'\n'],{type:'text/csv;charset=utf-8'});
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a');
    a.href=url;a.download='HUMAN-team-review.csv';a.hidden=true;
    document.body.append(a);a.click();
    setTimeout(() => { a.remove();URL.revokeObjectURL(url); },1200);
    dirty=false;show();
  });
  window.addEventListener('beforeunload', event => {
    if(dirty) {event.preventDefault();event.returnValue='';}
  });
  show();
})();
"""

def render(sources, transitions, expected, packets):
    labels = [row["label"] for step in transitions for row in step["kits"]]
    doc = {
        "rows": [
            {"transition": x["transition"], "kit_ordinal": x["kit_ordinal"],
             "to_ledger_sha256": x["to_ledger_sha256"], "to_kit_digest": x["to_kit_digest"],
             "added": x["added"], "removed": x["removed"], "changed": x["changed"]}
            for x in expected
        ],
        "labels": labels,
        "packets": packets,
    }
    data = json.dumps(doc, ensure_ascii=True, separators=(",", ":"))
    data = data.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    script = SCRIPT.replace("__LIGHTUP_DATA__", data, 1)
    pin = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")
    title = "LightUp PRIVATE original HUMAN reviewer reconciliation — OFFLINE"
    css = ("body{background:#f4f7fb;color:#182f46;font:16px system-ui;line-height:1.5;"
           "max-width:1024px;margin:2em auto;padding:0 1rem}"
           "article{padding:1rem;margin:1rem 0;background:white;border:1px solid #bbc8d7;border-radius:12px}"
           "article[hidden]{display:none}label{display:block;margin:1rem 0}"
           "label span{display:block;font-weight:bold}input,select,button{font:inherit;padding:.45rem}"
           "input{width:95%;max-width:620px}select{width:95%;max-width:650px}"
           ".opinions{padding:.2rem .8rem;background:#f7f9fd;border-radius:8px}"
           ".opinions p{border-bottom:1px solid #d8e1ea;padding-bottom:.45rem;overflow-wrap:anywhere}")
    return (
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "script-src 'sha256-" + pin + "'; style-src 'unsafe-inline'; "
        "img-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'\">"
        "<title>" + html.escape(title) + "</title><style>" + css + "</style>"
        "<main><h1>" + html.escape(title) + "</h1>"
        "<p><strong>PRIVATE ORIGINAL HUMAN OPINIONS ONLY.</strong> Reviewer packets are "
        "UNSIGNED. Matching proposals NEVER establish identity, authorization, "
        "customer consent, safe runtime or verified remediation. This is a local "
        "side-by-side review of OLD ARCHIVED ledger and HUMAN packet bytes, not "
        "a new inspection of customer originals. No network or browser storage.</p>"
        "<p>This generated HTML contains PRIVATE HUMAN owner names, questions, "
        "original kit labels and SHA identities; keep file under 0700/0600 custody. "
        "It is NOT a source-free public distribution asset.</p>"
        "<label>Filter <select id='filter'><option value='all'>All rows</option>"
        "<option value='disagree'>Disagreements</option>"
        "<option value='unselected'>Still needs HUMAN selection</option>"
        "<option value='selected'>Explicit selections</option></select></label>"
        "<label>Search local HUMAN data<input type='search' id='query' autocomplete='off'></label>"
        "<label>Resume same-original HUMAN-team-review.csv<input type='file' id='resume' accept='.csv,text/csv'></label>"
        "<p><button type='button' id='unanimous'>Explicitly select reviewer 1 ONLY when all HUMAN proposals match</button></p>"
        "<p id='summary' role='status' aria-live='polite'></p>"
        "<p><button type='button' id='export'>Export PRIVATE HUMAN-team-review.csv</button></p>"
        "<section id='rows'></section><p>Native history_team.py finalize verifies the "
        "exact original PRIVATE-team-context.json, all original archived ledger "
        "files and original reviewer packet bytes again before a new PRIVATE "
        "HOLD-only HUMAN selection record. Exporting is NEVER approval.</p></main>"
        "<script>" + script + "</script></html>"
    )
