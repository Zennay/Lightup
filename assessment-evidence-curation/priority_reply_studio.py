#!/usr/bin/env python3
"""Offline, source-minimized HUMAN reply editor for ONE priority package.

The generated HTML contains only the identical question rows already present
in the private selected CSV. It never validates recipient identity, evidence,
scope or consent; the native receipt-bound finalizer remains mandatory.
"""
from __future__ import annotations

import base64
import hashlib
import json

from briefing import CSS, h
from priority_reply import admit_rows

SCRIPT = r"""
(() => {
"use strict";
const original=JSON.parse(document.getElementById("source-rows").textContent);
const stages=["","responded_claimed","needs_more_information","blocked_human"];
const head=["original_ordinal","source_reported_severity","evidence_reference_count",
 "original_human_priority","original_human_question",
 "recipient_reported_stage","recipient_human_reply","recipient_human_next_question"];
const current=original.map(() => ({stage:"",reply:"",next:""}));
const main=document.getElementById("rows"), summary=document.getElementById("summary"),
 warning=document.getElementById("warning"), filter=document.getElementById("filter");
const formula=(value)=>/^[=+@-]/u.test(value.normalize("NFKC").replace(/^[\s\p{Mark}]*/u,""));
const forbidden=/[\u0000-\u001f\u007f\p{Cf}\p{Cs}\p{Co}\p{Cn}]/u;
function safe(value){return typeof value==="string"&&value.length<=500&&
 !formula(value)&&!forbidden.test(value);}
function valid(value){
 if(!stages.includes(value.stage)||!safe(value.reply)||!safe(value.next))return false;
 if(value.stage==="")return value.reply===""&&value.next==="";
 if(value.stage==="responded_claimed")return !!value.reply.trim();
 return !!(value.reply.trim()||value.next.trim());
}
function fail(message){warning.textContent=message;warning.hidden=!message;}
function draw(){
 main.replaceChildren();
 let shown=0,answered=0,flagged=0;
 for(let i=0;i<original.length;i++){
  const row=original[i], state=current[i];
  if(state.stage)answered++;
  const q=filter.value.trim().toLowerCase();
  if(q && !("#"+row[0]+" "+row[4]).toLowerCase().includes(q))continue;
  shown++;
  const box=document.createElement("section");box.className="card";
  const title=document.createElement("h2");title.textContent="Original ordinal #"+row[0]+
   " · HUMAN priority "+row[3];box.append(title);
  const note=document.createElement("p");note.textContent=
   "UNVERIFIED source severity: "+row[1]+" · original evidence reference count: "+row[2];
  box.append(note);
  const question=document.createElement("pre");question.textContent=row[4];box.append(question);
  const stageLabel=document.createElement("label");stageLabel.textContent="Self-reported HUMAN stage";
  const stage=document.createElement("select");
  for(const [value,text] of [["","No HUMAN answer"],["responded_claimed","Claimed response (NOT verified)"],
   ["needs_more_information","Needs HUMAN follow-up"],["blocked_human","HUMAN blocked"]]){
   const opt=document.createElement("option");opt.value=value;opt.textContent=text;stage.append(opt);
  }
  stage.value=state.stage;stage.addEventListener("change",()=>{state.stage=stage.value;update();});
  stageLabel.append(stage);box.append(stageLabel);
  for(const [key,label] of [["reply","HUMAN reply (unverified)"],
                            ["next","Follow-up HUMAN question"]]){
   const l=document.createElement("label");l.textContent=label;
   const field=document.createElement("textarea");field.maxLength=500;
   field.value=state[key];field.addEventListener("input",()=>{state[key]=field.value;update();});
   l.append(field);box.append(l);
  }
  main.append(box);
 }
 for(const state of current)if(!valid(state))flagged++;
 summary.textContent="Displayed "+shown+"/"+original.length+" HUMAN questions · "+
  answered+" self-reported stage(s) · "+flagged+" incomplete/unsafe row(s)."+
  " Filters NEVER remove rows from the exported full CSV.";
}
function update(){
 const answered=current.filter(s=>!!s.stage).length;
 const flagged=current.filter(s=>!valid(s)).length;
 summary.textContent="Displayed "+main.children.length+"/"+original.length+
 " HUMAN questions · "+answered+" self-reported stage(s) · "+flagged+
 " incomplete/unsafe row(s). Filters NEVER remove rows from exported CSV.";
 fail("");
}
function csvCell(value){return '"'+String(value).replace(/"/g,'""')+'"';}
function csvFile(){
 if(!current.every(valid))throw Error("Complete or clear all HUMAN response rows before export.");
 const rows=[head, ...original.map((row,i)=>[...row,current[i].stage,current[i].reply,current[i].next])];
 return rows.map(row=>row.map(csvCell).join(",")).join("\r\n")+"\r\n";
}
function download(){
 try{
  const csv=csvFile();
  const url=URL.createObjectURL(new Blob([csv],{type:"text/csv;charset=utf-8"}));
  const link=document.createElement("a");link.href=url;link.download="PRIVATE-priority-human-reply.csv";
  document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
  fail("PRIVATE HUMAN CSV downloaded. This is NOT accepted until the native source-bound receiver validates it. Browser downloads may be readable by others.");
 }catch(e){fail("HOLD: "+e.message);}
}
function parse(text){
 if(text.startsWith("\ufeff"))text=text.slice(1);
 if(text.includes("\u0000") || text.length>64000)throw Error("Invalid or oversized response CSV.");
 const out=[];let row=[],cell="",quote=false,after=false;
 for(let i=0;i<text.length;i++){
  const c=text[i];
  if(quote){
   if(c==='"'&&text[i+1]==='"'){cell+='"';i++;}
   else if(c==='"') {quote=false;after=true;}
   else if(c==="\r"||c==="\n")throw Error("Multiline HUMAN CSV rejected.");
   else cell+=c;
  }else if(after){
   if(c===","){row.push(cell);cell="";after=false;}
   else if(c==="\r"&&text[i+1]==="\n"){row.push(cell);out.push(row);row=[];cell="";after=false;i++;}
   else if(c==="\n"){row.push(cell);out.push(row);row=[];cell="";after=false;}
   else throw Error("Unexpected CSV suffix.");
  }else if(c==='"'){
   if(cell!=="")throw Error("Unexpected quoted CSV field.");quote=true;
  }else if(c===","){row.push(cell);cell="";}
  else if(c==="\r"&&text[i+1]==="\n"){row.push(cell);out.push(row);row=[];cell="";i++;}
  else if(c==="\n"){row.push(cell);out.push(row);row=[];cell="";}
  else if(c==="\r")throw Error("Invalid newline.");
  else cell+=c;
 }
 if(quote)throw Error("Unterminated quoted CSV.");
 if(row.length||cell||after){row.push(cell);out.push(row);}
 return out;
}
async function restore(file){
 if(!file)return;
 try{
  if(file.size>64000)throw Error("Oversized HUMAN CSV.");
  const decoded=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
  const rows=parse(decoded);
  if(rows.length!==original.length+1||JSON.stringify(rows[0])!==JSON.stringify(head))
   throw Error("Different HUMAN response schema or row count.");
  const next=[];
  for(let i=0;i<original.length;i++){
   const row=rows[i+1];
   if(row.length!==8||JSON.stringify(row.slice(0,5))!==JSON.stringify(original[i]))
    throw Error("Original HUMAN question/source order mismatch at ordinal "+original[i][0]+".");
   const item={stage:row[5],reply:row[6],next:row[7]};
   if(!valid(item))throw Error("Unsafe or incomplete HUMAN response at ordinal "+original[i][0]+".");
   next.push(item);
  }
  if(!window.confirm("Replace ALL unsaved local HUMAN answers with this source-matched PRIVATE CSV?"))
   return;
  for(let i=0;i<next.length;i++)Object.assign(current[i],next[i]);
  draw();fail("Source-row-matched HUMAN draft restored in local memory. Native original admission STILL required.");
 }catch(e){fail("HOLD: HUMAN CSV not imported; unsaved choices preserved. "+e.message);}
}
function discard(){
 if(!window.confirm("Discard all UNSAVED local HUMAN response choices? Downloads remain on disk."))return;
 for(const row of current)Object.assign(row,{stage:"",reply:"",next:""});
 draw();fail("Unsaved browser choices discarded; downloaded files and physical-memory erasure are NOT guaranteed.");
}
document.getElementById("export").addEventListener("click",download);
document.getElementById("discard").addEventListener("click",discard);
document.getElementById("restore").addEventListener("change",event=>{
 const file=event.target.files&&event.target.files[0];event.target.value="";
 void restore(file);
});
filter.addEventListener("input",draw);
draw();
})();
"""


def render(template: bytes) -> bytes:
    admitted=admit_rows(template, template)
    rows = [[r["ordinal"],r["source_severity"],r["source_reference_count"],
             r["human_priority"],r["question"]] for r in admitted]
    serialized = json.dumps(rows, ensure_ascii=True, separators=(",", ":")).replace("<", "\\u003c")
    css_pin=base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode("ascii")
    js_pin=base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode("ascii")
    csp=("default-src 'none'; style-src 'sha256-"+css_pin+
         "'; script-src 'sha256-"+js_pin+
         "'; connect-src 'none'; form-action 'none'; base-uri 'none'; "
         "img-src 'none'; object-src 'none'")
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"+
        '<meta http-equiv="Content-Security-Policy" content="'+h(csp)+'">'+
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"+
        "<title>PRIVATE priority HUMAN response editor</title><style>"+CSS+
        "</style></head><body><header><h1>LightUp · PRIVATE HUMAN recipient reply studio</h1>"+
        "<p class='notice'>REVIEW ONLY — original source, findings, HUMAN recipient, "
        "client/operator identity, consent, remediation and disclosure authorization "
        "remain UNVERIFIED. Nothing is uploaded, transmitted or executed.</p>"+
        "<p>This source-minimized LOCAL studio includes only this priority group's "
        "original ordinals, source-reported severity/reference counts and HUMAN "
        "questions; these may STILL identify clients. Edit local HUMAN claims only. "
        "The signed recipient is NOT authenticated by this program.</p>"+
        "<p>Export ALL original rows to CSV; then independently admit the complete "
        "source-bound PRIVATE CSV with priority_reply.py. The offline browser export "
        "is never approval or verification.</p></header>"+
        "<section class='panel'><label>Filter original HUMAN question "
        "<input id='filter' placeholder='ordinal or question'></label>"+
        "<button id='export' type='button'>Export FULL PRIVATE HUMAN reply CSV</button>"+
        "<label>Restore original-bound CSV <input id='restore' type='file' accept='.csv,text/csv'></label>"+
        "<button id='discard' type='button'>Discard unsaved local choices</button>"+
        "<p id='summary' aria-live='polite'></p><p id='warning' role='alert'></p></section>"+
        "<main id='rows'></main>"+
        '<script id="source-rows" type="application/json">'+serialized+"</script>"+
        "<script>"+SCRIPT+"</script></body></html>\n"
    ).encode("utf-8")
