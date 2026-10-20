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
const rows = JSON.parse(document.getElementById("source-rows").content.textContent);
const states = rows.map(() => ({yes:false, priority:"routine", question:""}));
const maxSelected = 64, pageSize = 40;
let currentPage = 0;
const root=document.getElementById("entries"), info=document.getElementById("summary");
const pages=document.getElementById("page-info"), error=document.getElementById("error");
const search=document.getElementById("filter"), severity=document.getElementById("severity");
const onlySelected=document.getElementById("selected-only");
const formula=/^[\s]*[=+@-]/u;
const prohibited=/[\u0000-\u001f\u007f\p{Cf}\p{Cs}\p{Co}\p{Cn}]/u;
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
function selectionCsv(){
 const count=selectedCount();
 if(!count)throw Error("Select at least one original ordinal.");
 for(let i=0;i<states.length;i++){
  const s=states[i];if(!s.yes)continue;
  const v=s.question;
  if(!v.trim() || v.length>500 || formula.test(v) || prohibited.test(v))
   throw Error("Original ordinal #"+(i+1)+" needs a safe HUMAN question without formula/control prefixes.");
 }
 const csv=[["original_ordinal","source_reported_severity","evidence_reference_count","select_for_private_dossier","human_priority","human_question"]];
 for(let i=0;i<rows.length;i++){
  const r=rows[i],s=states[i];
  csv.push([r.ordinal,r.severity,r.evidence_count,s.yes?"yes":"",s.yes?s.priority:"",s.yes?s.question:""]);
 }
 return csv.map(row=>row.map(csvCell).join(",")).join("\r\n")+"\r\n";
}
function privateDownload(bytes,name,type){
 const blob=new Blob([bytes],{type});
 const url=URL.createObjectURL(blob),a=document.createElement("a");
 a.href=url;a.download=name;a.click();
 setTimeout(()=>URL.revokeObjectURL(url),3000);
}
function exportCsv(){
 try{
  const plain=selectionCsv();
  if(!window.confirm("Export UNENCRYPTED PRIVATE HUMAN CSV for original-source admission? Choose an appropriate private disclosure channel."))return;
  privateDownload(plain,"PRIVATE-human-selection.csv","text/csv;charset=utf-8");
  showError("");
 }catch(e){showError("HOLD: "+e.message);}
}

function strictQuotedRow(line){
 // Studio imports only its own canonical all-quoted one-line-per-record format.
 let i=0, fields=[];
 while(i<line.length){
  if(line[i]!=='"')throw Error("Only canonical PRIVATE Studio CSV is accepted for resume.");
  i++;let value="",closed=false;
  while(i<line.length){
   if(line[i]==='"'){
    if(line[i+1]==='"'){value+='"';i+=2;continue;}
    i++;closed=true;break;
   }
   value+=line[i++];
  }
  if(!closed)throw Error("Unterminated PRIVATE CSV quoted field.");
  fields.push(value);
  if(i===line.length)break;
  if(line[i]!==',')throw Error("Invalid PRIVATE CSV field boundary.");
  i++;if(i===line.length)throw Error("Trailing PRIVATE CSV separator.");
 }
 if(fields.length!==6)throw Error("PRIVATE selection has an unexpected column count.");
 return fields;
}
async function resumeSelection(file){
 if(!file || file.size===0)return;
 if(file.size>1024*1024){showError("HOLD: PRIVATE selection exceeds 1 MiB.");return;}
 try{
  const decoded=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
  const raw=decoded.startsWith("\ufeff")?decoded.slice(1):decoded;
  if(!raw.endsWith("\r\n") || /(^|[^\r])\n/u.test(raw) ||
     /\r(?!\n)/u.test(raw))throw Error("Expected canonical CRLF PRIVATE CSV.");
  const lines=raw.slice(0,-2).split("\r\n");
  if(lines.length!==rows.length+1)throw Error("Original ordinal membership changed.");
  const header=strictQuotedRow(lines[0]).join(",");
  if(header!=="original_ordinal,source_reported_severity,evidence_reference_count,select_for_private_dossier,human_priority,human_question"){
   throw Error("Original CSV header mismatch.");
  }
  const incoming=[];let chosen=0;
  for(let i=0;i<rows.length;i++){
   const c=strictQuotedRow(lines[i+1]),r=rows[i];
   if(c[0]!==String(r.ordinal)||c[1]!==r.severity||c[2]!==String(r.evidence_count))
    throw Error("Original ordinal, severity or evidence count differs at #"+(i+1)+".");
   if(c[3]!==""&&c[3]!=="no"&&c[3]!=="yes")throw Error("Unsupported HUMAN selection.");
   const yes=c[3]==="yes";
   if(!yes&&(c[4]!==""||c[5]!==""))throw Error("Unselected HUMAN fields must be blank.");
   if(yes&&(!["routine","soon","urgent"].includes(c[4])||!c[5].trim()||
    c[5].length>500||formula.test(c[5])||prohibited.test(c[5])))
    throw Error("Unsafe or incomplete HUMAN question at #"+(i+1)+".");
   if(yes&&++chosen>maxSelected)throw Error("At most 64 HUMAN selections.");
   incoming.push({yes,priority:yes?c[4]:"routine",question:yes?c[5]:""});
  }
  if(!window.confirm("Restore "+chosen+" PRIVATE HUMAN selections? Replaces current unsaved local choices. Original source identity is NOT verified by this browser."))return;
  for(let i=0;i<incoming.length;i++)states[i]=incoming[i];
  currentPage=0;search.value="";severity.value="all";onlySelected.checked=false;
  showError("");render();
 }catch(error){showError("HOLD: "+String(error.message||"Invalid PRIVATE selection")+". Current choices kept.");}
}
document.getElementById("restore-file").addEventListener("change",event=>{
 const file=event.target.files&&event.target.files[0];
 event.target.value="";
 void resumeSelection(file);
});


const PRIVATE_SCHEMA="lightup.private_lab_curated_selection_encrypted.v1";
const PRIVATE_AAD=new TextEncoder().encode(PRIVATE_SCHEMA+"|REVIEW_ONLY");
const PRIVATE_FALSE=["source_authenticated","human_identity_authenticated","client_consent_verified",
 "operator_consent_verified","authorized","consent_verified","dispatch_allowed","release_allowed"];
function clearPasswords(){
 document.getElementById("private-pass").value="";
 document.getElementById("private-pass-confirm").value="";
}
function getPassword(needConfirm){
 const first=document.getElementById("private-pass").value;
 const second=document.getElementById("private-pass-confirm").value;
 if(first.length<12 || first.length>120)throw Error("PRIVATE passphrase must be 12–120 characters.");
 if(needConfirm&&first!==second)throw Error("PRIVATE passphrase confirmation differs.");
 return first;
}
function toB64(bytes){
 let chars="";const input=new Uint8Array(bytes);
 for(let i=0;i<input.length;i++)chars+=String.fromCharCode(input[i]);
 return btoa(chars);
}
function fromB64(text,expectedLength){
 if(typeof text!=="string"||!text.length||text.length>1500000||
  !/^[A-Za-z0-9+/]+={0,2}$/.test(text))throw Error("Invalid canonical encryption bytes.");
 const decoded=atob(text);
 if(toB64(Uint8Array.from(decoded,ch=>ch.charCodeAt(0)))!==text)
  throw Error("Noncanonical PRIVATE encrypted bytes.");
 if(expectedLength&&decoded.length!==expectedLength)throw Error("Unexpected encryption parameter size.");
 return Uint8Array.from(decoded,ch=>ch.charCodeAt(0));
}
async function deriveKey(password,salt){
 const raw=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),
  "PBKDF2",false,["deriveKey"]);
 return crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:310000,hash:"SHA-256"},
  raw,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
}
function assertCrypto(){
 if(!globalThis.isSecureContext || !crypto || !crypto.subtle || !crypto.getRandomValues)
  throw Error("Browser WebCrypto secure context required; no plaintext fallback.");
}
async function saveEncrypted(){
 let password="";
 try{
  assertCrypto();
  const plain=selectionCsv();
  password=getPassword(true);
  if(!window.confirm("Save encrypted source-free PRIVATE HUMAN selection? This does not authenticate a producer, reviewer, target or permission."))return;
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const nonce=crypto.getRandomValues(new Uint8Array(12));
  const key=await deriveKey(password,salt);
  const ciphertext=await crypto.subtle.encrypt(
   {name:"AES-GCM",iv:nonce,additionalData:PRIVATE_AAD,tagLength:128},
   key,new TextEncoder().encode(plain));
  const envelope={
   schema:PRIVATE_SCHEMA,status:"REVIEW_ONLY",
   kdf:{algorithm:"PBKDF2-SHA256",iterations:310000,salt_b64:toB64(salt)},
   cipher:{algorithm:"AES-256-GCM",nonce_b64:toB64(nonce),ciphertext_b64:toB64(ciphertext)}
  };
  for(const flag of PRIVATE_FALSE)envelope[flag]=false;
  privateDownload(JSON.stringify(envelope)+"\n","PRIVATE-human-selection-encrypted.luec",
   "application/octet-stream");
  showError("");
 }catch(e){showError("HOLD: "+String(e.message||"Encrypted save rejected"));}
 finally{password="";clearPasswords();}
}
async function openEncrypted(file){
 let password="";
 if(!file||!file.size)return;
 if(file.size>1500000){showError("HOLD: encrypted PRIVATE file exceeds admission limit.");return;}
 try{
  assertCrypto();password=getPassword(false);
  const raw=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
  const x=JSON.parse(raw);
  if(JSON.stringify(x)+"\n"!==raw || !x || Array.isArray(x)||
   Object.keys(x).length!==12 || x.schema!==PRIVATE_SCHEMA || x.status!=="REVIEW_ONLY" ||
   Object.keys(x.kdf||{}).join(",")!=="algorithm,iterations,salt_b64" ||
   Object.keys(x.cipher||{}).join(",")!=="algorithm,nonce_b64,ciphertext_b64" ||
   x.kdf.algorithm!=="PBKDF2-SHA256" || x.kdf.iterations!==310000 ||
   x.cipher.algorithm!=="AES-256-GCM" || PRIVATE_FALSE.some(k=>x[k]!==false))
    throw Error("Unsupported or noncanonical encrypted PRIVATE envelope.");
  const salt=fromB64(x.kdf.salt_b64,16),nonce=fromB64(x.cipher.nonce_b64,12);
  const ciphertext=fromB64(x.cipher.ciphertext_b64);
  if(ciphertext.length<16||ciphertext.length>1024*1024)throw Error("Invalid ciphertext length.");
  const key=await deriveKey(password,salt);
  const plain=await crypto.subtle.decrypt(
   {name:"AES-GCM",iv:nonce,additionalData:PRIVATE_AAD,tagLength:128},key,ciphertext);
  if(plain.byteLength>1024*1024)throw Error("Decrypted PRIVATE selection too large.");
  // Reuse exact full original-ordinal/sourced-severity membership admission
  // before any local state replacement or HUMAN confirmation.
  const blob=new Blob([plain],{type:"text/csv;charset=utf-8"});
  await resumeSelection(blob);
 }catch(e){showError("HOLD: encrypted PRIVATE source rejected or passphrase invalid. Current choices kept.");}
 finally{password="";clearPasswords();}
}
document.getElementById("save-encrypted").addEventListener("click",()=>{void saveEncrypted();});
document.getElementById("open-encrypted").addEventListener("change",event=>{
 const file=event.target.files&&event.target.files[0];event.target.value="";
 void openEncrypted(file);
});

function disposeLocalWorkroom(){
 if(!window.confirm("Discard all UNSAVED local HUMAN selection choices and passphrases? Existing downloaded PRIVATE files and this HTML's source-ordinal metadata remain outside this action."))return;
 for(let i=0;i<states.length;i++)states[i]={yes:false,priority:"routine",question:""};
 clearPasswords();
 const resume=document.getElementById("restore-file"),encrypted=document.getElementById("open-encrypted");
 resume.value="";encrypted.value="";search.value="";severity.value="all";onlySelected.checked=false;
 currentPage=0;render();
 showError("Local unsaved HUMAN selections discarded. Previously exported downloads and browser memory disposal are NOT cryptographically guaranteed.");
}
document.getElementById("dispose-local").addEventListener("click",disposeLocalWorkroom);
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
        "<button id='export' type='button'>Export PRIVATE CSV</button>"
        "<label>Resume prior PRIVATE Studio CSV <input id='restore-file' type='file' accept='.csv,text/csv'></label></div>"
        "<div class='toolbar'><label>PRIVATE passphrase (12+ chars) <input id='private-pass' type='password' autocomplete='off'></label>"
        "<label>Confirm passphrase to save <input id='private-pass-confirm' type='password' autocomplete='off'></label>"
        "<button id='save-encrypted' type='button'>Save encrypted PRIVATE draft</button>"
        "<button id='dispose-local' class='secondary' type='button'>Discard unsaved local choices</button>"
        "<label>Open encrypted PRIVATE draft <input id='open-encrypted' type='file' accept='.luec,application/octet-stream'></label></div>"
        "<p id='error' class='warning' role='alert' hidden></p></section>"
        "<main id='entries'></main><nav class='panel page'>"
        "<button id='prev' class='secondary' type='button'>Previous</button>"
        "<span id='page-info'></span><button id='next' class='secondary' type='button'>Next</button>"
        "</nav><template id='source-rows'>" + source_json +
        "</template><script>" + SCRIPT + "</script></body></html>\n"
    )
    return result.encode("utf-8")
