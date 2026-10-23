#!/usr/bin/env python3
"""Standalone CSP-hash-pinned offline PRIVATE HUMAN reviewer CSV editor.

No network, storage, automatically trusted reviews, recipient workflow or grants.
"""
from __future__ import annotations

import base64
import hashlib

from curate import Hold, literal_sha
from briefing import h

NAME = "PRIVATE-HUMAN-continuity-review-studio.html"
CHOICES = (
    ("pending_discussion", "Pending HUMAN discussion"),
    ("ask_for_information", "Ask another HUMAN question"),
    ("independent_review", "Independent review requested"),
    ("no_action_proposed", "No action proposed (not a closed finding)"),
)
CSS = """body{font:16px/1.55 system-ui,sans-serif;margin:0 auto;max-width:930px;padding:1rem;background:#f2f5f8;color:#101828}header,section{background:white;border:1px solid #cbd5e1;padding:1.2rem;border-radius:.55rem;margin:1rem 0}article{padding:1rem;border:1px solid #cbd5e1;margin:1rem 0;border-radius:.35rem}textarea,select{display:block;box-sizing:border-box;width:100%;padding:.6rem;font:inherit;border:1px solid #667085;background:#fff;color:#101828}textarea{min-height:5rem}label{display:block;margin:1rem 0;font-weight:600}pre{white-space:pre-wrap;overflow-wrap:anywhere}button{font:inherit;padding:.8rem 1rem;background:#152d4e;color:#fff;border:0;border-radius:.3rem;cursor:pointer}.warning{border-left:5px solid #b45309;padding:.6rem}#out{font-weight:600}@media print{button{display:none}body{background:#fff}}"""
JS = r"""'use strict';
(()=>{
const root=document.getElementById('rows');
const output=document.getElementById('out');
const binding=document.body.dataset.binding;
const options=new Set(['pending_discussion','ask_for_information','independent_review','no_action_proposed']);
const header=['private_docket_csv_sha256_unsigned','original_human_ordinal','human_review_disposition','human_review_note'];
const quote=value=>'"'+String(value).replaceAll('"','""')+'"';
const cards=()=>Array.from(root.querySelectorAll('[data-human-ordinal]'));
const snapshot=()=>JSON.stringify(cards().map(card=>[
 card.dataset.humanOrdinal,card.querySelector('select').value,
 card.querySelector('textarea').value]));
function acceptable(ordinal,disposition,note){
 const normalized=note.normalize('NFKC').trimStart();
 return /^[1-9][0-9]*$/.test(ordinal)&&options.has(disposition)&&
  note.length<=500&&!/[\u0000-\u001f\u007f]/u.test(note)&&
  !/^[=+@-]/u.test(normalized);
}
function status(){
 let notes=0,decisions=0;
 for(const card of cards()){
  notes+=Number(card.querySelector('textarea').value.length>0);
  decisions+=Number(card.querySelector('select').value!=='pending_discussion');
 }
 document.getElementById('draft-status').textContent=
  notes+' PRIVATE HUMAN notes · '+decisions+
  ' changed HUMAN dispositions in memory only. Not authenticated or saved.';
}
// Exact format emitted by THIS source-bound editor; no best-effort CSV fixes,
// row reassignment, reordered ordinals, or partial replacement on import.
function parseOwnCsv(raw){
 if(raw.length>131072||!raw.endsWith('\r\n')||raw.startsWith('\ufeff'))
  throw Error('file bounds or unsupported CSV encoding');
 const lines=raw.slice(0,-2).split('\r\n'),current=cards();
 if(lines.length!==current.length+1||
    lines[0]!==header.map(quote).join(','))throw Error('header/row count');
 const rowRe=/^"((?:[^"]|"")*)","((?:[^"]|"")*)","((?:[^"]|"")*)","((?:[^"]|"")*)"$/u;
 return lines.slice(1).map((line,i)=>{
  const match=rowRe.exec(line);
  if(!match)throw Error('noncanonical row');
  const values=match.slice(1).map(v=>v.replaceAll('""','"'));
  const [source,ordinal,disposition,note]=values;
  if(line!==values.map(quote).join(',')||source!==binding||
     ordinal!==current[i].dataset.humanOrdinal||
     !acceptable(ordinal,disposition,note))
   throw Error('changed source or HUMAN row');
  return {disposition,note};
 });
}
let importEpoch=0;
root.addEventListener('input',status);
root.addEventListener('change',status);
function forgetInMemory(){
 importEpoch++;
 cards().forEach(card=>{
  card.querySelector('select').value='pending_discussion';
  card.querySelector('textarea').value='';
 });
 document.getElementById('import-file').value='';
 status();
}
window.addEventListener('pagehide',forgetInMemory);
window.addEventListener('pageshow',event=>{
 if(event.persisted)forgetInMemory();
});
document.getElementById('import').addEventListener('click',()=>
 document.getElementById('import-file').click());
document.getElementById('import-file').addEventListener('change',async event=>{
 const file=event.target.files?.[0];event.target.value='';
 if(!file)return;
 const epoch=++importEpoch,previous=snapshot();
 try{
  if(file.size>131072||file.size===0)throw Error('file size');
  const bytes=await file.arrayBuffer();
  // Reject invalid UTF-8 instead of silently accepting replacement characters.
  const raw=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  const restored=parseOwnCsv(raw);
  if(epoch!==importEpoch||previous!==snapshot())
   throw Error('local draft changed while reading');
  const existing=cards();
  const changed=restored.filter((row,i)=>
   row.disposition!==existing[i].querySelector('select').value||
   row.note!==existing[i].querySelector('textarea').value).length;
  const filled=existing.filter(card=>card.querySelector('textarea').value.length>0).length;
  if(!changed){
   output.textContent='This source-bound PRIVATE HUMAN file matches all '+restored.length+
    ' current rows; no changes applied.';
   return;
  }
  if(!window.confirm('Restore '+restored.length+' exact source-bound HUMAN records? '+
    changed+' rows differ; '+filled+' current private notes may be replaced. '+
    'This never verifies a reviewer or sends information.'))
   return;
  if(epoch!==importEpoch||previous!==snapshot())
   throw Error('draft changed during review');
  cards().forEach((card,i)=>{
   card.querySelector('select').value=restored[i].disposition;
   card.querySelector('textarea').value=restored[i].note;
  });
  status();
  output.textContent='Exact source-bound PRIVATE HUMAN CSV restored into memory only ('+
    restored.length+' rows). Review and explicitly export. No identity or authority proof.';
 }catch(_){
  output.textContent='HOLD: use the unchanged source-bound PRIVATE HUMAN CSV with all '+
   'original ordinals in their exact order; current drafts preserved.';
 }
});
document.getElementById('clear').addEventListener('click',()=>{
 if(!window.confirm('Clear all in-memory PRIVATE HUMAN notes and decisions? Existing downloads remain.'))return;
 forgetInMemory();
 output.textContent='In-memory HUMAN drafts cleared; earlier downloaded files remain.';
});
document.getElementById('export').addEventListener('click',()=>{
 const lines=[header.map(quote).join(',')];
 let completed=0;
 for(const card of cards()){
  const ordinal=card.dataset.humanOrdinal;
  const disposition=card.querySelector('select').value;
  const note=card.querySelector('textarea').value;
  if(!acceptable(ordinal,disposition,note)){
   output.textContent='HOLD: unsupported HUMAN note/disposition; no download created.';
   return;
  }
  completed+=Number(note.length>0);
  lines.push([binding,ordinal,disposition,note].map(quote).join(','));
 }
 if(lines.length===1){output.textContent='HOLD: no selected HUMAN rows.';return;}
 const blob=new Blob([lines.join('\r\n')+'\r\n'],{type:'text/csv;charset=utf-8'});
 const url=URL.createObjectURL(blob);
 try{
  const link=document.createElement('a');
  link.href=url;
  link.download='PRIVATE-HUMAN-continuity-review-return.csv';
  document.body.appendChild(link);
  link.click();
  link.remove();
  output.textContent='PRIVATE HUMAN review CSV locally prepared ('+completed+
   ' notes). No data sent, verified, authorized or assigned. Handle as PRIVATE.';
 }finally{setTimeout(()=>URL.revokeObjectURL(url),2500);}
});
status();
})();"""


def pin(s: str) -> str:
    return base64.b64encode(hashlib.sha256(s.encode("utf-8")).digest()).decode("ascii")


def build(rows: list[dict], private_docket_csv_sha: str) -> bytes:
    if (type(rows) is not list or len(rows) > 64 or
        not literal_sha(private_docket_csv_sha)):
        raise Hold("HOLD: PRIVATE HUMAN review studio source invalid")
    seen = set()
    cards = []
    for row in rows:
        if (type(row) is not dict or
            set(row) != {"ordinal", "priority", "bucket", "question",
                         "latest_stage", "latest_reply", "next_question"} or
            type(row["ordinal"]) is not int or not 1 <= row["ordinal"] <= 10000 or
            row["ordinal"] in seen or
            row["priority"] not in ("urgent","soon","routine") or
            not all(type(row[k]) is str and len(row[k]) <= 500 for k in
                    ("bucket","question","latest_stage","latest_reply","next_question"))):
            raise Hold("HOLD: PRIVATE HUMAN review card outside selected scope")
        seen.add(row["ordinal"])
        choices = "".join("<option value='" + h(value) + "'>" + h(label) +
                          "</option>" for value,label in CHOICES)
        cards.append(
            "<article data-human-ordinal='" + str(row["ordinal"]) + "'>"
            "<h2>Original HUMAN ordinal #" + str(row["ordinal"]) +
            " · " + h(row["priority"]) + "</h2><p>HUMAN review category: " +
            h(row["bucket"]) + " · latest unverified stage: " +
            h(row["latest_stage"]) + "</p><h3>Original PRIVATE HUMAN question</h3>"
            "<pre>" + h(row["question"]) + "</pre>"
            "<h3>Latest PRIVATE HUMAN reply (unverified)</h3><pre>" +
            h(row["latest_reply"] or "(none)") + "</pre>"
            "<h3>Latest PRIVATE HUMAN follow-up question</h3><pre>" +
            h(row["next_question"] or "(none)") + "</pre>"
            "<label>HUMAN review disposition<select>" + choices +
            "</select></label><label>PRIVATE HUMAN review note (max 500 safe"
            " characters)<textarea maxlength='500' spellcheck='false'>"
            "</textarea></label><p>Human disposition is a private draft, "
            "not a verified finding or instruction.</p></article>")
    policy = ("default-src 'none'; style-src 'sha256-" + pin(CSS) +
              "'; script-src 'sha256-" + pin(JS) +
              "'; connect-src 'none'; img-src 'none'; object-src 'none'; " +
              "form-action 'none'; base-uri 'none'")
    page = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' content=\"" + h(policy) +
        "\"><title>PRIVATE HUMAN continuity review editor</title><style>" +
        CSS + "</style></head><body data-binding='" +
        private_docket_csv_sha + "'><header>"
        "<h1>LightUp · PRIVATE HUMAN review editor</h1>"
        "<p class='warning'>REVIEW ONLY · this page deliberately contains "
        "PRIVATE original HUMAN questions and replies. Work locally and "
        "handle downloads as confidential. No independent verification, "
        "recipient identity, client/operator consent, authorized scope, "
        "scan, remediation, approval or dispatch is inferred.</p>"
        "<p>Enter fixed HUMAN-only dispositions and brief notes. This editor "
        "does not save notes to the browser or communicate externally. "
        "Restore a previously saved exact-source PRIVATE CSV and review locally; "
        "then explicitly save another CSV only when intended. "
        "The unsigned digest in that CSV is a local lineage reference "
        "only, not a signature or authorization.</p></header>"
        "<section id='rows'>" + "".join(cards) +
        "</section><section><p id='draft-status' role='status'></p>"
        "<button id='import' type='button'>Restore exact PRIVATE HUMAN CSV</button> "
        "<input id='import-file' type='file' accept='.csv,text/csv' hidden>"
        "<button id='clear' type='button'>Clear in-memory HUMAN drafts</button> "
        "<button id='export' type='button'>Save PRIVATE HUMAN review CSV locally</button>"
        "<p id='out' role='status'></p></section><script>" +
        JS + "</script></body></html>\n")
    return page.encode("utf-8")
