#!/usr/bin/env python3
"""Portable, entirely offline PRIVATE recipient HUMAN reply editor.

The emitted browser app includes only source-free original ordinals, reported
severity/evidence-reference counts and HUMAN questions. Not a grant or verified
finding, source authenticity, respondent identity or remediation.
"""
from __future__ import annotations

import base64
import hashlib
import html
import json

CSS = """
:root{font-family:system-ui,sans-serif;color:#192a40;background:#eaf0f7}
*{box-sizing:border-box}body{max-width:1100px;margin:0 auto;padding:24px}
header,section,article,nav{background:white;border:1px solid #cbd7e5;
border-radius:12px;padding:20px;margin:16px 0}
h1{margin:0 0 12px}h2{font-size:1.1rem}.warning{color:#8a3300;font-weight:bold}
.muted{color:#53677c}p{line-height:1.55;overflow-wrap:anywhere}
.toolbar{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
label{display:block;margin:6px 0;font-weight:600}label span{display:block;margin-bottom:6px}
input,select,textarea,button{font:inherit;border-radius:7px;padding:9px}
input,select,textarea{border:1px solid #899caf}
button{border:0;background:#163f75;color:white;cursor:pointer}button.secondary{background:#576c80}
button:disabled{opacity:.55}textarea{width:100%;height:95px;resize:vertical}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.grid>label{min-width:0}.progress{font-weight:bold}.question{white-space:pre-wrap;overflow-wrap:anywhere}
nav{display:flex;align-items:center;justify-content:space-between;gap:20px}
@media(max-width:700px){body{padding:10px}.grid{grid-template-columns:1fr}
nav{flex-wrap:wrap}}
@media print{button,.toolbar,nav{display:none}article{break-inside:avoid}}
"""

SCRIPT = r"""
(function(){
"use strict";
const rows=JSON.parse(document.getElementById("original-rows").content.textContent);
const states=rows.map(()=>({stage:"",reply:"",followup:""}));
const stageChoices=["","responded_claimed","needs_more_information","blocked_human"];
const headers=["original_ordinal","source_reported_severity","evidence_reference_count",
"original_human_priority","original_human_question","recipient_reported_stage",
"recipient_human_reply","recipient_human_next_question"];
const prohibited=/[\u0000-\u001f\u007f\p{Cf}\p{Cs}\p{Co}\p{Cn}]/u;
const formula=/^\s*[=+@-]/u;
const root=document.getElementById("cards"),feedback=document.getElementById("feedback");
const summary=document.getElementById("summary"),pageLabel=document.getElementById("page");
const filter=document.getElementById("filter"),stageFilter=document.getElementById("stage-filter");
const priorityFilter=document.getElementById("priority-filter");
const size=16;let page=0;
function error(message){feedback.textContent=message;feedback.hidden=!message;}
function admitted(value){
 return value.length<=500&&!prohibited.test(value)&&!formula.test(value);
}
function changed(){return states.filter(s=>s.stage!=="").length;}
function visible(){
 const value=filter.value.trim().toLowerCase();
 return rows.map((r,i)=>({r,i})).filter(({r,i})=>
  (!value||("#"+r.ordinal+" "+r.question.toLowerCase()).includes(value))&&
  (stageFilter.value==="all"||states[i].stage===stageFilter.value)&&
  (priorityFilter.value==="all"||r.priority===priorityFilter.value));
}
function render(){
 const list=visible(),maxPage=Math.max(1,Math.ceil(list.length/size));
 page=Math.max(0,Math.min(page,maxPage-1));root.replaceChildren();
 const frag=document.createDocumentFragment();
 for(const {r,i} of list.slice(page*size,(page+1)*size)){
  const state=states[i],card=document.createElement("article");
  const title=document.createElement("h2");
  title.textContent="Original ordinal #"+r.ordinal+" · HUMAN "+r.priority;
  const meta=document.createElement("p");meta.className="muted";
  meta.textContent="SOURCE-REPORTED severity: "+r.severity+" · evidence references: "+r.evidence_count;
  const q=document.createElement("p");q.className="question";q.textContent=r.question;
  const grid=document.createElement("div");grid.className="grid";
  const stageLabel=document.createElement("label");
  const stageText=document.createElement("span");stageText.textContent="RECIPIENT stage — self-reported";
  const select=document.createElement("select");select.setAttribute("aria-label","Stage for ordinal "+r.ordinal);
  for(const value of stageChoices){const opt=document.createElement("option");
   opt.value=value;opt.textContent=value||"No human response";opt.selected=value===state.stage;select.append(opt);}
  select.addEventListener("change",()=>{state.stage=select.value;render();});
  stageLabel.append(stageText,select);
  const replyLabel=document.createElement("label");
  const replyText=document.createElement("span");replyText.textContent="RECIPIENT reply (max 500 characters)";
  const reply=document.createElement("textarea");reply.maxLength=500;reply.value=state.reply;
  reply.placeholder="Human answer only; not an evidence or remediation verdict";
  reply.addEventListener("input",()=>{state.reply=reply.value;});
  replyLabel.append(replyText,reply);
  const followLabel=document.createElement("label");
  const followText=document.createElement("span");followText.textContent="RECIPIENT follow-up question";
  const follow=document.createElement("textarea");follow.maxLength=500;follow.value=state.followup;
  follow.addEventListener("input",()=>{state.followup=follow.value;});
  followLabel.append(followText,follow);
  grid.append(stageLabel,replyLabel,followLabel);
  card.append(title,meta,q,grid);frag.append(card);
 }
 root.append(frag);
 summary.textContent=changed()+" / "+rows.length+" HUMAN replies classified, "+
  list.length+" rows visible. Original source and recipient identity NOT verified.";
 pageLabel.textContent="Page "+(page+1)+" / "+maxPage;
 document.getElementById("prev").disabled=page===0;
 document.getElementById("next").disabled=page>=maxPage-1;
}
function verify(sets){
 for(let i=0;i<sets.length;i++){
  const s=sets[i];if(!stageChoices.includes(s.stage)||!admitted(s.reply)||
   !admitted(s.followup))throw Error("Unsafe HUMAN reply at ordinal #"+rows[i].ordinal);
  if(s.stage===""&&(s.reply!==""||s.followup!==""))
   throw Error("Set a HUMAN stage before entering a reply, ordinal #"+rows[i].ordinal);
  if(s.stage==="responded_claimed"&&!s.reply.trim())
   throw Error("Claimed reply needs text, ordinal #"+rows[i].ordinal);
  if((s.stage==="needs_more_information"||s.stage==="blocked_human")&&
    !s.reply.trim()&&!s.followup.trim())
   throw Error("Human stage needs a reason/question, ordinal #"+rows[i].ordinal);
 }
}
function cell(v){return '"'+String(v).replace(/"/g,'""')+'"';}
function serialize(sets){
 verify(sets);
 const records=[headers];
 for(let i=0;i<rows.length;i++){
  const r=rows[i],s=sets[i];
  records.push([r.ordinal,r.severity,r.evidence_count,r.priority,r.question,
   s.stage,s.reply,s.followup]);
 }
 return records.map(row=>row.map(cell).join(",")).join("\r\n")+"\r\n";
}
function download(content,name){
 const blob=new Blob([content],{type:"text/csv;charset=utf-8"});
 const url=URL.createObjectURL(blob),a=document.createElement("a");
 a.href=url;a.download=name;a.click();
 setTimeout(()=>URL.revokeObjectURL(url),2500);
}
function exportReply(){
 try{
  const csv=serialize(states);
  if(!window.confirm("Export UNENCRYPTED PRIVATE HUMAN reply CSV? Human answers may identify a client; choose a separately approved private channel."))return;
  download(csv,"PRIVATE-recipient-human-response.csv");error("");
 }catch(e){error("HOLD: "+e.message);}
}
function strictRow(line){
 let i=0,fields=[];
 while(i<line.length){
  if(line[i]!=='"')throw Error("Not canonical source-bound PRIVATE CSV.");
  i++;let value="",closed=false;
  while(i<line.length){if(line[i]==='"'){if(line[i+1]==='"'){value+='"';i+=2;continue;}
    i++;closed=true;break;}value+=line[i++];}
  if(!closed)throw Error("Unterminated quoted field.");
  fields.push(value);
  if(i===line.length)break;
  if(line[i]!==",")throw Error("Invalid field separator.");
  i++;if(i===line.length)throw Error("Trailing separator.");
 }
 if(fields.length!==8)throw Error("Wrong column count.");
 return fields;
}
async function reopen(file){
 if(!file)return;
 if(file.size>1024*1024||!file.size){error("HOLD: PRIVATE reply file size invalid.");return;}
 try{
  const raw=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
  if(!raw.endsWith("\r\n")||/\r(?!\n)|(^|[^\r])\n/u.test(raw))
   throw Error("Not canonical CRLF input.");
  const lines=raw.slice(0,-2).split("\r\n");
  if(lines.length!==rows.length+1)throw Error("Original ordinal membership changed.");
  if(strictRow(lines[0]).join("\u0001")!==headers.join("\u0001"))
   throw Error("Incorrect source-bound header.");
  const incoming=[];
  for(let i=0;i<rows.length;i++){
   const v=strictRow(lines[i+1]),r=rows[i];
   if(v[0]!==String(r.ordinal)||v[1]!==r.severity||
     v[2]!==String(r.evidence_count)||v[3]!==r.priority||v[4]!==r.question)
    throw Error("Original source/proposal membership mismatch at row "+(i+1));
   incoming.push({stage:v[5],reply:v[6],followup:v[7]});
  }
  verify(incoming);
  if(!window.confirm("Replace all unsaved local HUMAN replies with this exact original-row-bound PRIVATE CSV? File contents do not authenticate the source or human respondent."))return;
  for(let i=0;i<states.length;i++)states[i]=incoming[i];
  page=0;filter.value="";stageFilter.value="all";priorityFilter.value="all";
  render();error("");
 }catch(e){error("HOLD: Invalid recipient HUMAN CSV; current local replies preserved.");}
}

const ENCRYPTED_SCHEMA="lightup.private_recipient_human_reply_encrypted.v1";
const PRIVATE_FLAGS=["source_authenticated","human_identity_authenticated",
"client_consent_verified","operator_consent_verified",
"authorized","consent_verified","dispatch_allowed","release_allowed"];
const encoder=new TextEncoder();
function assertCrypto(){
 if(!globalThis.isSecureContext||!globalThis.crypto||!crypto.subtle||!crypto.getRandomValues)
  throw Error("WebCrypto secure browser context required; no plaintext fallback.");
}
function clearPassphrases(){
 document.getElementById("password").value="";
 document.getElementById("confirm-password").value="";
}
function readPassphrase(confirmation){
 const p=document.getElementById("password").value;
 if(p.length<12||p.length>120)throw Error("PRIVATE passphrase must contain 12–120 characters.");
 if(confirmation&&document.getElementById("confirm-password").value!==p)
  throw Error("PRIVATE passphrase confirmation does not match.");
 return p;
}
function to64(bytes){
 let text="";for(const b of new Uint8Array(bytes))text+=String.fromCharCode(b);
 return btoa(text);
}
function from64(value,length){
 if(typeof value!=="string"||!value||value.length>1500000||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value))
  throw Error("Malformed private ciphertext encoding.");
 const encoded=atob(value);
 const bytes=Uint8Array.from(encoded,ch=>ch.charCodeAt(0));
 if(to64(bytes)!==value||(length&&bytes.length!==length))
  throw Error("Noncanonical private ciphertext bytes.");
 return bytes;
}
async function derive(password,salt){
 const raw=await crypto.subtle.importKey("raw",encoder.encode(password),"PBKDF2",
  false,["deriveKey"]);
 return crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:310000,
  hash:"SHA-256"},raw,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
}
async function sourceKey(){
 const hash=new Uint8Array(await crypto.subtle.digest("SHA-256",encoder.encode(JSON.stringify(rows))));
 return Array.from(hash,b=>b.toString(16).padStart(2,"0")).join("");
}
function fromHex(hex){
 if(typeof hex!=="string"||!/^[a-f0-9]{64}$/.test(hex))throw Error("Invalid original rows SHA.");
 return Uint8Array.from(hex.match(/../g),b=>parseInt(b,16));
}
function purposeAAD(originalHash){
 const head=encoder.encode(ENCRYPTED_SCHEMA+"|REVIEW_ONLY|");
 const key=fromHex(originalHash);
 const aad=new Uint8Array(head.length+key.length);
 aad.set(head);aad.set(key,head.length);return aad;
}
async function saveEncrypted(){
 let pass="";
 try{
  assertCrypto();const csv=serialize(states);
  pass=readPassphrase(true);
  if(!window.confirm("Export encrypted PRIVATE HUMAN reply workroom? This does NOT authenticate the respondent, producer, finding or consent."))return;
  const sourceHash=await sourceKey();
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const nonce=crypto.getRandomValues(new Uint8Array(12));
  const key=await derive(pass,salt);
  const ciphertext=await crypto.subtle.encrypt({
   name:"AES-GCM",iv:nonce,additionalData:purposeAAD(sourceHash),tagLength:128
  },key,encoder.encode(csv));
  const doc={
   schema:ENCRYPTED_SCHEMA,status:"REVIEW_ONLY",
   original_human_question_rows_sha256_unsigned:sourceHash,
   kdf:{algorithm:"PBKDF2-SHA256",iterations:310000,salt_b64:to64(salt)},
   cipher:{algorithm:"AES-256-GCM",nonce_b64:to64(nonce),ciphertext_b64:to64(ciphertext)}
  };
  for(const flag of PRIVATE_FLAGS)doc[flag]=false;
  const file=new Blob([JSON.stringify(doc)+"\n"],{type:"application/octet-stream"});
  const url=URL.createObjectURL(file),a=document.createElement("a");
  a.href=url;a.download="PRIVATE-recipient-human-workroom.luer";a.click();
  setTimeout(()=>URL.revokeObjectURL(url),2500);error("");
 }catch(e){error("HOLD: "+String(e.message||"Private encrypted save failed"));}
 finally{pass="";clearPassphrases();}
}
async function openEncrypted(file){
 let pass="";
 if(!file)return;
 if(file.size<1||file.size>1500000){error("HOLD: Encrypted recipient file exceeds admission bounds.");return;}
 try{
  assertCrypto();pass=readPassphrase(false);
  const text=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
  const doc=JSON.parse(text);
  if(JSON.stringify(doc)+"\n"!==text||!doc||Array.isArray(doc)||
    Object.keys(doc).length!==13||doc.schema!==ENCRYPTED_SCHEMA||
    doc.status!=="REVIEW_ONLY"||
    Object.keys(doc.kdf||{}).join(",")!=="algorithm,iterations,salt_b64"||
    Object.keys(doc.cipher||{}).join(",")!=="algorithm,nonce_b64,ciphertext_b64"||
    doc.kdf.algorithm!=="PBKDF2-SHA256"||doc.kdf.iterations!==310000||
    doc.cipher.algorithm!=="AES-256-GCM"||
    PRIVATE_FLAGS.some(key=>doc[key]!==false))
    throw Error("Invalid or unrecognized encrypted PRIVATE recipient envelope.");
  const hash=await sourceKey();
  if(doc.original_human_question_rows_sha256_unsigned!==hash)
   throw Error("Wrong original HUMAN question rows.");
  const salt=from64(doc.kdf.salt_b64,16),nonce=from64(doc.cipher.nonce_b64,12);
  const cipher=from64(doc.cipher.ciphertext_b64);
  if(cipher.length<16||cipher.length>1024*1024)throw Error("Private ciphertext size refused.");
  const key=await derive(pass,salt);
  const plaintext=await crypto.subtle.decrypt({
   name:"AES-GCM",iv:nonce,additionalData:purposeAAD(hash),tagLength:128
  },key,cipher);
  if(plaintext.byteLength>1024*1024)throw Error("Oversize decrypted HUMAN CSV.");
  // Full original ordinal/priority/source-count membership and every HUMAN
  // response stage is re-admitted by the existing atomic browser reopen path.
  await reopen(new Blob([plaintext],{type:"text/csv;charset=utf-8"}));
 }catch(e){error("HOLD: Wrong password, source rows or invalid encrypted PRIVATE package. Current replies kept.");}
 finally{pass="";clearPassphrases();}
}
document.getElementById("save-encrypted").addEventListener("click",()=>{void saveEncrypted();});
document.getElementById("load-encrypted").addEventListener("change",event=>{
 const file=event.target.files&&event.target.files[0];event.target.value="";
 void openEncrypted(file);
});

function dispose(){
 if(!window.confirm("Discard unsaved recipient HUMAN replies in this browser? Existing downloads are NOT erased."))return;
 for(let i=0;i<states.length;i++)states[i]={stage:"",reply:"",followup:""};
 filter.value="";stageFilter.value="all";priorityFilter.value="all";page=0;
 document.getElementById("restore").value="";render();
 error("Local replies reset. Browser/physical memory erasure NOT guaranteed.");
}
for(const f of [filter,stageFilter,priorityFilter])
 f.addEventListener(f===filter?"input":"change",()=>{page=0;render();});
document.getElementById("prev").addEventListener("click",()=>{page--;render();});
document.getElementById("next").addEventListener("click",()=>{page++;render();});
document.getElementById("export").addEventListener("click",exportReply);
document.getElementById("dispose").addEventListener("click",dispose);
document.getElementById("restore").addEventListener("change",e=>{
 const file=e.target.files&&e.target.files[0];e.target.value="";void reopen(file);});
render();
})();
"""

def render_studio(source: dict, selected: list[dict]) -> bytes:
    rows = []
    for item in selected:
        original = source["findings"][item["ordinal"] - 1]
        rows.append({
            "ordinal": item["ordinal"], "severity": original["severity"],
            "evidence_count": len(original["evidence_ids"]),
            "priority": item["priority"], "question": item["question"],
        })
    payload = json.dumps(rows, ensure_ascii=True, separators=(",", ":")).replace("<", "\\u003c")
    css_pin = base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode()
    js_pin = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
    csp = ("default-src 'none'; style-src 'sha256-" + css_pin +
           "'; script-src 'sha256-" + js_pin +
           "'; connect-src 'none'; img-src 'none'; object-src 'none'; "
           "form-action 'none'; base-uri 'none'; object-src 'none'")
    doc = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"" +
        html.escape(csp, quote=True) + "\">"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>PRIVATE HUMAN recipient answer studio</title><style>" + CSS +
        "</style></head><body><header><h1>LightUp · PRIVATE HUMAN recipient reply studio</h1>"
        "<p class='warning'>REVIEW ONLY. Original producer, findings, evidence, "
        "risk, target, permission, recipient identity, remediation and current "
        "client/operator consent are NOT verified. Your reply is NOT a finding verdict.</p>"
        "<p>Offline, without external storage or network. The file contains only "
        "original ordinal, source-reported severity/evidence-count and sender's "
        "HUMAN priority/question. HUMAN text may itself identify confidential clients.</p>"
        "<p>Save responses to PRIVATE CSV locally. The sending HUMAN operator must "
        "independently re-admit the original source, manifest, worksheet, selection "
        "and response binding using the separate CLI return operation. "
        "No recipient browser file establishes source authenticity.</p></header>"
        "<section><div class='toolbar'>"
        "<label>Search HUMAN question / ordinal <input id='filter' type='search' autocomplete='off'></label>"
        "<label>HUMAN stage <select id='stage-filter'><option value='all'>All</option>"
        "<option value=''>No reply</option><option value='responded_claimed'>Responded (claimed)</option>"
        "<option value='needs_more_information'>More information</option>"
        "<option value='blocked_human'>Blocked HUMAN</option></select></label>"
        "<label>HUMAN priority <select id='priority-filter'><option value='all'>All</option>"
        "<option value='routine'>Routine</option><option value='soon'>Soon</option>"
        "<option value='urgent'>Urgent</option></select></label></div>"
        "<p class='progress' id='summary' aria-live='polite'></p>"
        "<div class='toolbar'><button type='button' id='export'>Export PRIVATE reply CSV</button>"
        "<label>Resume exact PRIVATE reply CSV <input type='file' id='restore' accept='.csv,text/csv'></label>"
        "<button class='secondary' type='button' id='dispose'>Discard unsaved replies</button></div>"
        "<div class='toolbar'><label>PRIVATE passphrase (12+ characters) <input type='password' id='password' autocomplete='off'></label>"
        "<label>Confirm passphrase to save <input type='password' id='confirm-password' autocomplete='off'></label>"
        "<button type='button' id='save-encrypted'>Save encrypted PRIVATE workroom</button>"
        "<label>Open encrypted PRIVATE workroom <input type='file' id='load-encrypted' accept='.luer,application/octet-stream'></label></div>"
        "<p id='feedback' class='warning' role='alert' hidden></p></section>"
        "<main id='cards'></main>"
        "<nav><button id='prev' type='button' class='secondary'>Previous</button>"
        "<span id='page'></span><button id='next' type='button' class='secondary'>Next</button></nav>"
        "<template id='original-rows'>" + payload + "</template>"
        "<script>" + SCRIPT + "</script></body></html>\n"
    )
    return doc.encode("utf-8")
