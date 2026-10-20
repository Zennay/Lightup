#!/usr/bin/env python3
"""Completely offline, source-identifier-free HUMAN selection studio.

The generated HTML includes ONLY source ordinal, reported severity and number
of evidence references. Its browser cannot authenticate any original source.
"""
from __future__ import annotations

import base64
import hashlib
import html
import json

CSS = r"""
:root{color-scheme:light;font-family:system-ui,sans-serif;color:#14223a;background:#edf2f7}
*{box-sizing:border-box}body{max-width:1120px;margin:auto;padding:24px}
header,.panel,article{background:white;border:1px solid #ccd7e3;border-radius:14px;padding:20px;margin:16px 0}
h1{margin:0}p{line-height:1.5}.muted{color:#59697e}.warning{color:#783911;font-weight:700}
.toolbar{display:flex;flex-wrap:wrap;gap:12px;align-items:center}
input,select,textarea,button{font:inherit;padding:9px;border:1px solid #8799ac;border-radius:7px}
button{background:#173f70;color:#fff;cursor:pointer;border:0}
button.secondary{background:#51677d}button:disabled{opacity:.5;cursor:not-allowed}
textarea{width:100%;min-height:70px;resize:vertical}.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
label{display:block;font-weight:600}label span{display:block;margin:5px 0}
.card-header{display:flex;justify-content:space-between;align-items:center;gap:12px}
.state{font-size:1.1em;font-weight:bold}#summary{font-weight:bold}
.priority{min-width:150px}article[data-selected="true"]{border-left:5px solid #206ca0}
.page{display:flex;gap:14px;align-items:center;justify-content:space-between}
@media(max-width:650px){body{padding:10px}.grid{grid-template-columns:1fr}.page{flex-wrap:wrap}}
@media print{button,.toolbar,.page{display:none}article{break-inside:avoid}}
"""
SCRIPT = r"""
(function () {
"use strict";
const rows = JSON.parse(document.getElementById("source-rows").textContent);
const states = rows.map(() => ({yes:false, priority:"routine", question:""}));
const maxSelected = 64, pageSize = 40;
let currentPage = 0;
const root=document.getElementById("entries"), info=document.getElementById("summary");
const pages=document.getElementById("page-info"), error=document.getElementById("error");
const search=document.getElementById("filter"), severity=document.getElementById("severity");
const onlySelected=document.getElementById("selected-only");
const formula=/^[\s]*[=+@-]/u;
const prohibited=/[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/u;
function selectedCount(){return states.reduce((n,x)=>n+(x.yes?1:0),0);}
function showError(message){error.textContent=message;error.hidden=!message;}
function filtered(){
 const term=search.value.trim().toLowerCase();
 return rows.map((r,i)=>({r,i})).filter(({r,i})=>
  (!term || ("#"+r.ordinal).includes(term)) &&
  (severity.value==="all" || r.severity===severity.value) &&
  (!onlySelected.checked || states[i].yes));
}
function csvCell(value){return '"'+String(value).replace(/"/g,'""')+'"';}
function button(label,action,kind){
 const b=document.createElement("button");b.type="button";b.textContent=label;
 if(kind)b.className=kind;b.addEventListener("click",action);return b;
}
function render(){
 const shown=filtered(), totalPages=Math.max(1,Math.ceil(shown.length/pageSize));
 currentPage=Math.min(Math.max(0,currentPage),totalPages-1);
 const slice=shown.slice(currentPage*pageSize,(currentPage+1)*pageSize);
 root.replaceChildren();
 for(const {r,i} of slice){
  const s=states[i],article=document.createElement("article");article.dataset.selected=String(s.yes);
  const header=document.createElement("div");header.className="card-header";
  const checkLabel=document.createElement("label"), check=document.createElement("input");
  check.type="checkbox";check.checked=s.yes;check.setAttribute("aria-label","Select original ordinal "+r.ordinal);
  check.addEventListener("change",()=>{
   if(check.checked && selectedCount()>=maxSelected){check.checked=false;showError("HOLD: at most 64 original ordinals.");return;}
   s.yes=check.checked;if(!s.yes){s.priority="routine";s.question="";}
   showError("");render();
  });
  checkLabel.append(check,document.createTextNode(" Original source ordinal #"+r.ordinal));
  const descriptor=document.createElement("span");descriptor.className="muted";
  descriptor.textContent="SOURCE-REPORTED "+r.severity+" · "+r.evidence_count+" evidence references";
  header.append(checkLabel,descriptor);article.append(header);
  if(s.yes){
   const grid=document.createElement("div");grid.className="grid";
   const priorityLabel=document.createElement("label"), priorityTitle=document.createElement("span");
   priorityTitle.textContent="HUMAN proposal priority";priorityLabel.append(priorityTitle);
   const priority=document.createElement("select");priority.className="priority";
   for(const item of ["routine","soon","urgent"]){
    const option=document.createElement("option");option.value=item;option.textContent=item;
    option.selected=s.priority===item;priority.append(option);
   }
   priority.addEventListener("change",()=>{s.priority=priority.value;});
   priorityLabel.append(priority);
   const questionLabel=document.createElement("label"),questionTitle=document.createElement("span");
   questionTitle.textContent="HUMAN follow-up question (1–500 characters)";
   const question=document.createElement("textarea");question.maxLength=500;
   question.placeholder="Which ORIGINAL evidence needs independent HUMAN review?";
   question.value=s.question;question.addEventListener("input",()=>{s.question=question.value;});
   questionLabel.append(questionTitle,question);
   grid.append(priorityLabel,questionLabel);article.append(grid);
  }
  root.append(article);
 }
 info.textContent=selectedCount()+" / "+maxSelected+" HUMAN-selected original ordinals · "+shown.length+" visible records of "+rows.length+" original source declarations";
 pages.textContent="Page "+(currentPage+1)+" / "+totalPages;
 document.getElementById("prev").disabled=currentPage<=0;
 document.getElementById("next").disabled=currentPage>=totalPages-1;
}
function batch(yes){
 const shown=filtered();const toChange=shown.filter(({i})=>states[i].yes!==yes);
 if(yes && selectedCount()+toChange.length>maxSelected){showError("HOLD: visible selection would exceed 64. Filter more narrowly.");return;}
 if(!window.confirm("Change "+toChange.length+" visible HUMAN choices? This cannot authorize a target."))return;
 for(const {i} of toChange){states[i].yes=yes;if(!yes){states[i].priority="routine";states[i].question="";}}
 showError("");render();
}
function exportCsv(){
 const count=selectedCount();
 if(!count){showError("HOLD: select at least one original ordinal.");return;}
 for(let i=0;i<states.length;i++){
  const s=states[i];
  if(!s.yes)continue;
  const v=s.question;
  if(!v.trim() || v.length>500 || formula.test(v) || prohibited.test(v) ||
    [...v].some(c=>["Cf","Cs"].includes(c))) {
   showError("HOLD: original ordinal #"+(i+1)+" needs a safe HUMAN question without control/formula prefixes.");
   return;
  }
 }
 if(!window.confirm("Export PRIVATE source-bound HUMAN selection for independent ORIGINAL source and worksheet re-admission? This does not authorize anything."))return;
 const csv=[["original_ordinal","source_reported_severity","evidence_reference_count","select_for_private_dossier","human_priority","human_question"]];
 for(let i=0;i<rows.length;i++){
  const r=rows[i],s=states[i];
  csv.push([r.ordinal,r.severity,r.evidence_count,s.yes?"yes":"",s.yes?s.priority:"",s.yes?s.question:""]);
 }
 const blob=new Blob([csv.map(row=>row.map(csvCell).join(",")).join("\r\n")+"\r\n"],{type:"text/csv;charset=utf-8"});
 const url=URL.createObjectURL(blob);
 const a=document.createElement("a");a.href=url;a.download="PRIVATE-human-selection.csv";a.click();
 setTimeout(()=>URL.revokeObjectURL(url),2000);showError("");
}
for(const x of [search,severity,onlySelected])x.addEventListener(x===search?"input":"change",()=>{currentPage=0;render();});
document.getElementById("prev").addEventListener("click",()=>{currentPage--;render();});
document.getElementById("next").addEventListener("click",()=>{currentPage++;render();});
document.getElementById("pick").addEventListener("click",()=>batch(true));
document.getElementById("clear").addEventListener("click",()=>batch(false));
document.getElementById("export").addEventListener("click",exportCsv);
render();
})();
"""

def source_free_studio(source: dict) -> bytes:
    # This is SOURCE-IDENTIFIER-FREE only, NOT publicly safe: small groups
    # and severity distributions may still be sensitive.
    data = [
        {"ordinal": i, "severity": f["severity"],
         "evidence_count": len(f["evidence_ids"])}
        for i, f in enumerate(source["findings"], 1)
    ]
    source_json = json.dumps(data, ensure_ascii=True, separators=(",", ":")).replace("<", "\\u003c")
    css_pin = base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode()
    js_pin = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
    csp = ("default-src 'none'; script-src 'sha256-" + js_pin +
           "'; style-src 'sha256-" + css_pin +
           "'; connect-src 'none'; img-src 'none'; object-src 'none'; "
           "form-action 'none'; base-uri 'none'; frame-src 'none'")
    result = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"" + html.escape(csp, quote=True) + "\">"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>PRIVATE Lab Selection Studio</title><style>" + CSS + "</style></head><body>"
        "<header><h1>LightUp · PRIVATE Human Evidence Selection Studio</h1>"
        "<p class='warning'>REVIEW ONLY · Original producer, finding, HUMAN identity, consent, authorization, "
        "retest and remediation are NOT verified here. Selecting an ordinal is NOT a grant.</p>"
        "<p>Offline and source-identifier-free: the browser file contains only original ordinals, "
        "reported severities and evidence-reference counts. It does NOT contain original source "
        "URLs, client IDs, original finding names, evidence or human worksheet. "
        "Small-cohort aggregate information remains PRIVATE.</p>"
        "<p>Enter a question and human priority for each selected ordinal, then export a PRIVATE CSV "
        "and provide it to the offline <code>curate.py publish</code> command together with your "
        "original source, manifest, worksheet and unsigned preparation receipt.</p></header>"
        "<section class='panel'><div class='toolbar'>"
        "<label>Original ordinal filter <input id='filter' placeholder='#42' autocomplete='off'></label>"
        "<label>Reported severity <select id='severity'><option value='all'>All</option>"
        "<option>critical</option><option>high</option><option>medium</option>"
        "<option>low</option><option>info</option></select></label>"
        "<label><input id='selected-only' type='checkbox'> Selected only</label></div>"
        "<p id='summary' aria-live='polite'></p><div class='toolbar'>"
        "<button id='pick' type='button'>Select filtered</button>"
        "<button id='clear' class='secondary' type='button'>Clear filtered</button>"
        "<button id='export' type='button'>Export PRIVATE CSV</button></div>"
        "<p id='error' class='warning' role='alert' hidden></p></section>"
        "<main id='entries'></main><nav class='panel page'>"
        "<button id='prev' class='secondary' type='button'>Previous</button>"
        "<span id='page-info'></span><button id='next' class='secondary' type='button'>Next</button>"
        "</nav><script id='source-rows' type='application/json'>" + source_json +
        "</script><script>" + SCRIPT + "</script></body></html>\n"
    )
    return result.encode("utf-8")
