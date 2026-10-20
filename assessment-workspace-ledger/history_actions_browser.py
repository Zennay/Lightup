#!/usr/bin/env python3
"""Render owner-private local-only HUMAN action planning editor (never task dispatch)."""
from __future__ import annotations

import base64
import hashlib
import html
import json

SCRIPT = r"""
(() => {
  'use strict';
  const DATA = __LIGHTUP_HUMAN_ACTIONS__;
  const columns = ["transition","kit_ordinal","original_ledger_sha256",
    "original_kit_digest","original_team_choice_sha256","original_reviewer_sha256",
    "original_human_stage","action_status","human_priority","accountable_human",
    "proposed_day","next_human_step"];
  const STATES = ["unassigned","proposed","waiting_on_human","hold"];
  const PRIORITIES = ["unset","human_urgent","near_term","routine"];
  const view = document.getElementById('rows');
  const search = document.getElementById('search');
  const filter = document.getElementById('filter');
  const summary = document.getElementById('summary');
  const resume = document.getElementById('resume');
  const escape = value => '"' + String(value).replace(/"/g,'""') + '"';
  const safe = (value,max) => typeof value === 'string' && value.length <= max &&
    !/[\x00-\x1f]/.test(value) && !/^\s*[=+\-@]/.test(value);
  const goodDay = value => !value || (/^\d{4}-\d{2}-\d{2}$/.test(value) &&
    Number.isFinite(Date.parse(value + 'T00:00:00Z')) &&
    new Date(value + 'T00:00:00Z').toISOString().slice(0,10) === value);
  let dirty = false;
  const rows = DATA.rows.map((source,index) => ({
    source, original:DATA.history[index],
    state:"unassigned",priority:"unset",owner:"",day:"",next:""
  }));
  function valid(row) {
    if (!STATES.includes(row.state) || !PRIORITIES.includes(row.priority) ||
        !safe(row.owner,80) || !safe(row.next,240) || !goodDay(row.day)) return false;
    if (row.state === 'unassigned' &&
        (row.priority !== 'unset' || row.owner || row.day || row.next)) return false;
    if (['proposed','waiting_on_human'].includes(row.state) && !row.next) return false;
    if (row.state === 'proposed' && !row.owner) return false;
    return true;
  }
  function show() {
    const q=search.value.trim().toLocaleLowerCase(), f=filter.value;
    let shown=0,changed=0;
    for (const row of rows) {
      if (row.state !== 'unassigned') changed++;
      const matches = (!q || (row.source.transition + ' ' + row.source.kit_ordinal + ' ' +
          row.original.human_stage + ' ' + row.original.human_question + ' ' +
          row.owner + ' ' + row.next).toLocaleLowerCase().includes(q)) &&
          (f === 'all' || row.state === f);
      row.card.hidden = !matches;
      if (matches) shown++;
    }
    summary.textContent = shown + ' / ' + rows.length + ' original HUMAN cases visible · ' +
      changed + ' have manually drafted actions · ' + (rows.length - changed) +
      ' unassigned' + (dirty ? ' · UNSAVED HUMAN EDITS' : '');
  }
  function addSelect(card,label,choices,current,onChange) {
    const wrapper=document.createElement('label');
    const name=document.createElement('span');name.textContent=label;
    const input=document.createElement('select');
    choices.forEach(v => {
      const option=document.createElement('option');
      option.value=v;option.textContent=v.replaceAll('_',' ');
      input.append(option);
    });
    input.value=current; input.addEventListener('change', () => {
      onChange(input.value);dirty=true;show();
    });
    wrapper.append(name,input);card.append(wrapper);
    return input;
  }
  function addInput(card,label,current,max,onChange,date=false) {
    const wrapper=document.createElement('label');
    const name=document.createElement('span');name.textContent=label;
    const input = document.createElement(date ? 'input' : 'textarea');
    if (date) input.type='date';
    else {input.rows=2;input.maxLength=max;input.spellcheck=false;}
    input.value=current;
    input.addEventListener('input',() => {
      onChange(input.value);dirty=true;show();
    });
    wrapper.append(name,input);card.append(wrapper);
    return input;
  }
  rows.forEach(row => {
    const card=document.createElement('article');
    const title=document.createElement('h2');
    title.textContent='Archived transition ' + row.source.transition + ' · kit ' +
      row.source.kit_ordinal + ' · original HUMAN stage ' + row.original.human_stage;
    card.append(title);
    const prior=document.createElement('p');
    prior.textContent='Original selected reviewer: ' +
      (row.original.human_selected_packet === 'none' ? 'NONE (manual follow-up)' :
       'one original HUMAN packet') +
      ' · Original HUMAN question: ' + (row.original.human_question || '(none)');
    card.append(prior);
    row.fields = {};
    row.fields.state=addSelect(card,'Draft HUMAN work status (never real dispatch)',
      STATES,row.state,value => {row.state=value;});
    row.fields.priority=addSelect(card,'Proposed HUMAN priority (never verified security severity)',
      PRIORITIES,row.priority,value => {row.priority=value;});
    row.fields.owner=addInput(card,'Proposed accountable HUMAN',row.owner,80,value => {row.owner=value;});
    row.fields.day=addInput(card,'Proposed HUMAN day (not a calendar booking)',row.day,10,value => {row.day=value;},true);
    row.fields.next=addInput(card,'Explicit next HUMAN step (max 240)',row.next,240,value => {row.next=value;});
    row.card=card;view.append(card);
  });
  search.addEventListener('input',show);filter.addEventListener('change',show);
  function parseCsv(text) {
    if (text.length > 196608 || text.includes('\0') || text.includes('\r'))
      throw Error('Oversized or invalid CSV');
    const table=[];
    let row=[],field='',quoted=false,started=false,closed=false;
    for(let i=0;i<text.length;i++) {
      const c=text[i];
      if(quoted) {
        if(c==='"') {
          if(text[i+1]==='"'){field+='"';i++;}
          else{quoted=false;closed=true;}
        } else {
          if(c==='\n')throw Error('Multiline HUMAN values not supported');
          field+=c;
        }
      } else if(c===',') {
        row.push(field);field='';started=false;closed=false;
      } else if(c==='\n') {
        row.push(field);table.push(row);row=[];field='';started=false;closed=false;
      } else if(c==='"' && !started && !closed && field==='') {
        quoted=true;started=true;
      } else if(c==='"' || closed)throw Error('CSV quoting');
      else{field+=c;started=true;}
      if(field.length>500 || table.length>145)throw Error('CSV source bounds');
    }
    if(quoted||row.length||field.length)throw Error('CSV missing final newline');
    if(table.length!==rows.length+1 || JSON.stringify(table[0])!==JSON.stringify(columns))
      throw Error('Wrong original HUMAN CSV schema');
    const drafts=[];
    rows.forEach((source,i) => {
      const v=table[i+1];
      if(v.length!==columns.length)throw Error('Wrong HUMAN fields');
      for(let col=0;col<7;col++) {
        if(v[col]!==String(source.source[columns[col]]))
          throw Error('Original exact source-ledger or reviewer identity changed');
      }
      const draft={state:v[7],priority:v[8],owner:v[9],day:v[10],next:v[11]};
      if(!valid(draft))throw Error('Invalid proposed HUMAN action');
      drafts.push(draft);
    });
    return drafts;
  }
  resume.addEventListener('change',async() => {
    const file=resume.files[0];resume.value='';
    if(!file)return;
    try {
      if(file.size>196608)throw Error('Oversized HUMAN draft');
      const drafts=parseCsv(await file.text());
      if(dirty&&!confirm('Replace unsaved local HUMAN proposals from exact original source-bound CSV?'))
        return;
      rows.forEach((row,i) => {
        Object.assign(row,drafts[i]);
        row.fields.state.value=row.state;row.fields.priority.value=row.priority;
        row.fields.owner.value=row.owner;row.fields.day.value=row.day;
        row.fields.next.value=row.next;
      });
      dirty=true;show();
      alert('Exact original HUMAN plan draft restored. Native finalizer still required.');
    } catch(error) {
      alert('PRIVATE HOLD: '+error.message+'. Existing choices were not changed.');
    }
  });
  document.getElementById('export').addEventListener('click',() => {
    if(rows.some(row => !valid(row))) {
      alert('PRIVATE HOLD: check accountable HUMAN, valid proposed day, explicit next step and safe text.');return;
    }
    if(!confirm('Export PRIVATE HUMAN proposal CSV? The browser Downloads folder may be public-readable. Nothing is scheduled or dispatched.'))
      return;
    const lines=[columns.join(',')];
    rows.forEach(row => {
      const value={...row.source,action_status:row.state,human_priority:row.priority,
        accountable_human:row.owner,proposed_day:row.day,next_human_step:row.next};
      lines.push(columns.map(key => escape(value[key])).join(','));
    });
    const blob=new Blob([lines.join('\n')+'\n'],{type:'text/csv;charset=utf-8'});
    const url=URL.createObjectURL(blob);
    const anchor=document.createElement('a');anchor.hidden=true;anchor.href=url;
    anchor.download='HUMAN-action-plan.csv';document.body.append(anchor);anchor.click();
    setTimeout(() => {anchor.remove();URL.revokeObjectURL(url);},1200);
    dirty=false;show();
  });
  window.addEventListener('beforeunload',event => {
    if(dirty){event.preventDefault();event.returnValue='';}
  });
  show();
})();
"""

def render(case, actions):
    originals = [{
        "human_stage": r["human_stage"],
        "human_selected_packet": r["human_selected_packet"],
        "human_question": r["human_question"],
    } for r in case["rows"]]
    data = json.dumps({"rows":actions,"history":originals},
                      ensure_ascii=True,separators=(",",":"))
    data = data.replace("<","\\u003c").replace(">","\\u003e").replace("&","\\u0026")
    script=SCRIPT.replace("__LIGHTUP_HUMAN_ACTIONS__",data,1)
    pin=base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")
    title="LightUp PRIVATE offline HUMAN follow-up planning desk"
    return (
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "script-src 'sha256-" + pin + "'; style-src 'unsafe-inline'; "
        "connect-src 'none'; img-src 'none'; form-action 'none'; base-uri 'none'\">"
        "<title>" + html.escape(title) + "</title><style>"
        "body{font:16px system-ui;color:#203245;background:#f5f7fa;line-height:1.5;"
        "max-width:1000px;margin:1.5em auto;padding:0 1em}article{border:1px solid #cbd6df;"
        "border-radius:12px;background:white;padding:1em;margin:1em 0}"
        "article[hidden]{display:none}label{display:block;margin:.6em 0}"
        "label span{font-weight:600;display:block}input,select,textarea,button{font:inherit;"
        "padding:.35em;max-width:95%}textarea{width:90%;min-height:3em}"
        "button{padding:.6em 1em}</style><main><h1>" + html.escape(title) + "</h1>"
        "<p><strong>PRIVATE, HUMAN-PROPOSALS ONLY, NO PASS.</strong> This local offline "
        "workroom contains original archived reviewer questions and hashes. "
        "No current customer originals reopened, no authenticated reviewer, "
        "consent, actual calendar booking, dispatched job, verified risk or active scan. "
        "It uses no network, browser storage, models, queue or permissions.</p>"
        "<p>Choose optional HUMAN priority, accountable owner, proposed day and next "
        "manual step. Original stage and source identities are immutable. "
        "Native history_actions.py must reopen exact originals on finalization.</p>"
        "<label>Search originals or HUMAN proposed steps<input id='search' type='search' autocomplete='off'></label>"
        "<label>Filter by HUMAN work status<select id='filter'>"
        "<option value='all'>All</option><option value='unassigned'>Unassigned</option>"
        "<option value='proposed'>Proposed</option>"
        "<option value='waiting_on_human'>Waiting on HUMAN</option>"
        "<option value='hold'>Hold</option></select></label>"
        "<label>Resume identical PRIVATE HUMAN-action-plan.csv<input id='resume' type='file' accept='.csv,text/csv'></label>"
        "<p id='summary' role='status' aria-live='polite'></p>"
        "<button id='export' type='button'>Export PRIVATE HUMAN-action-plan.csv</button>"
        "<section id='rows'></section><p>Browser downloads may be readable by other users. "
        "Native source re-admission and PRIVATE 0600 archive required. "
        "Nothing is actually assigned, scheduled, sent or deleted.</p></main>"
        "<script>" + script + "</script></html>"
    )
