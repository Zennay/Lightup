#!/usr/bin/env python3
"""Completely local, CSP source-pinned PRIVATE HUMAN sender reply triage editor.

Includes only original ordinal, original HUMAN proposal, recipient's HUMAN
response and unsigned text hashes. Not producer or recipient authentication.
"""
from __future__ import annotations

import base64
import hashlib
import html
import json

CSS = """
:root{font-family:system-ui,sans-serif;background:#edf2f8;color:#162a44}
*{box-sizing:border-box}body{max-width:1130px;margin:auto;padding:22px}
header,section,article,nav{background:white;border:1px solid #cfd9e7;padding:18px;
margin:14px 0;border-radius:13px}h1{margin-top:0}
.warning{color:#803509;font-weight:700}.muted{color:#566980}
button{background:#194774;color:white;border:0;cursor:pointer}
button.secondary{background:#596d81}button:disabled{opacity:.55}
button,input,select,textarea{font:inherit;padding:10px;border-radius:6px}
input,select,textarea{border:1px solid #8799ae}
textarea{width:100%;min-height:85px;resize:vertical}
.toolbar{display:flex;flex-wrap:wrap;gap:12px;align-items:center}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
label{display:block;font-weight:600}label span{display:block;margin-bottom:6px}
.question{white-space:pre-wrap;overflow-wrap:anywhere}
.summary{font-weight:700}.cardmeta{color:#52657a}
@media(max-width:750px){body{padding:8px}.grid{grid-template-columns:1fr}}
@media print{nav,.toolbar{display:none}article{break-inside:avoid}}
"""
SCRIPT = r"""
(function(){
"use strict";
const original=JSON.parse(document.getElementById("original-rows").content.textContent);
const routes=["","needs_human_review","request_clarification","route_to_owner",
 "documented_for_followup"];
const headers=["original_ordinal","original_human_priority","recipient_reported_stage",
 "recipient_human_reply_sha256_unsigned",
 "recipient_human_next_question_sha256_unsigned",
 "sender_human_route","sender_human_owner_group","sender_human_next_question"];
const stages=original.map(()=>({route:"",owner:"",next:""}));
const forbidden=/[\u0000-\u001f\u007f\p{Cf}\p{Cs}\p{Co}\p{Cn}]/u;
function formulaText(value){return /^[=+@-]/u.test(value.normalize("NFKC").replace(/^[\s\p{Mark}]*/u,""));}
const root=document.getElementById("entries");
const summary=document.getElementById("summary"),notice=document.getElementById("notice");
const query=document.getElementById("search"),filter=document.getElementById("route-filter");
const size=12;let page=0;
function fail(msg){notice.textContent=msg;notice.hidden=!msg;}
function admissible(s,limit){return s.length<=limit&&!forbidden.test(s)&&!formulaText(s);}
function filtered(){
 const q=query.value.trim().toLowerCase();
 return original.map((r,i)=>({r,i})).filter(({r,i})=>
  (!q||("#"+r.ordinal+" "+r.original_question+" "+r.reply).toLowerCase().includes(q))&&
  (filter.value==="all"||stages[i].route===filter.value));
}
function render(){
 const rows=filtered(),totalPages=Math.max(1,Math.ceil(rows.length/size));
 page=Math.min(Math.max(0,page),totalPages-1);root.replaceChildren();
 for(const {r,i} of rows.slice(page*size,(page+1)*size)){
  const state=stages[i],card=document.createElement("article");
  const head=document.createElement("h2");head.textContent="Original ordinal #"+r.ordinal+" — HUMAN "+r.priority;
  const meta=document.createElement("p");meta.className="cardmeta";
  meta.textContent="RECIPIENT claimed stage: "+r.stage+" · original question ID only, source/identity NOT verified";
  const originalQ=document.createElement("p");originalQ.className="question";
  originalQ.textContent="Sender question: "+r.original_question;
  const humanReply=document.createElement("p");humanReply.className="question";
  humanReply.textContent="Recipient reply: "+(r.reply||"(no HUMAN reply)");
  const recipientNext=document.createElement("p");recipientNext.className="question";
  recipientNext.textContent="Recipient follow-up: "+(r.followup||"(none)");
  const grid=document.createElement("div");grid.className="grid";
  const routeLabel=document.createElement("label"),routeTitle=document.createElement("span");
  routeTitle.textContent="Sender HUMAN route — no approval";
  const select=document.createElement("select");
  for(const route of routes){const option=document.createElement("option");
   option.value=route;option.textContent=route||"Unreviewed";option.selected=state.route===route;select.append(option);}
  select.addEventListener("change",()=>{state.route=select.value;render();});
  routeLabel.append(routeTitle,select);
  const ownerLabel=document.createElement("label"),ownerTitle=document.createElement("span");
  ownerTitle.textContent="Sender HUMAN owner/group (<=120 chars)";
  const owner=document.createElement("textarea");owner.maxLength=120;owner.value=state.owner;
  owner.addEventListener("input",()=>{state.owner=owner.value;});
  ownerLabel.append(ownerTitle,owner);
  const questionLabel=document.createElement("label"),qTitle=document.createElement("span");
  qTitle.textContent="Sender HUMAN next question/action (<=500 chars)";
  const next=document.createElement("textarea");next.maxLength=500;next.value=state.next;
  next.addEventListener("input",()=>{state.next=next.value;});
  questionLabel.append(qTitle,next);
  grid.append(routeLabel,ownerLabel,questionLabel);
  card.append(head,meta,originalQ,humanReply,recipientNext,grid);root.append(card);
 }
 summary.textContent=stages.filter(x=>x.route).length+" / "+stages.length+
  " sender HUMAN routes assigned; "+rows.length+" records visible";
 document.getElementById("page").textContent="Page "+(page+1)+" / "+totalPages;
 document.getElementById("prev").disabled=page===0;
 document.getElementById("next").disabled=page>=totalPages-1;
}
function validate(list){
 for(let i=0;i<list.length;i++){
  const s=list[i];
  if(!routes.includes(s.route)||!admissible(s.owner,120)||!admissible(s.next,500))
   throw Error("Unsupported HUMAN route, owner or question at ordinal #"+original[i].ordinal);
  if(s.route===""&&(s.owner!==""||s.next!==""))
   throw Error("An unreviewed row must have empty HUMAN fields.");
  if(s.route==="route_to_owner"&&(!s.owner.trim()||!s.next.trim()))
   throw Error("HUMAN owner routing needs owner/group and question.");
  if(s.route==="request_clarification"&&!s.next.trim())
   throw Error("HUMAN clarification needs a question.");
  if((s.route==="needs_human_review"||s.route==="documented_for_followup")&&
    !s.owner.trim()&&!s.next.trim())
   throw Error("HUMAN review route needs owner or question.");
 }
}
function encode(v){return '"'+String(v).replace(/"/g,'""')+'"';}
function writeCsv(list){
 validate(list);
 const lines=[headers];
 for(let i=0;i<original.length;i++){
  const r=original[i],s=list[i];
  lines.push([r.ordinal,r.priority,r.stage,r.reply_sha,r.followup_sha,
   s.route,s.owner,s.next]);
 }
 return lines.map(row=>row.map(encode).join(",")).join("\r\n")+"\r\n";
}
function exportCsv(){
 try{
  const csv=writeCsv(stages);
  if(!window.confirm("Export UNENCRYPTED PRIVATE sender HUMAN route CSV? Replies and owner labels may be client-identifying; choose an approved private channel."))return;
  const url=URL.createObjectURL(new Blob([csv],{type:"text/csv;charset=utf-8"}));
  const a=document.createElement("a");a.href=url;a.download="PRIVATE-sender-HUMAN-triage.csv";a.click();
  setTimeout(()=>URL.revokeObjectURL(url),3000);fail("");
 }catch(e){fail("HOLD: "+e.message);}
}
function quoted(line){
 let fields=[],i=0;
 while(i<line.length){
  if(line[i]!=='"')throw Error("Not canonical PRIVATE sender CSV.");
  i++;let value="",closed=false;
  while(i<line.length){
   if(line[i]==='"'){if(line[i+1]==='"'){value+='"';i+=2;continue;}
    i++;closed=true;break;}
   value+=line[i++];
  }
  if(!closed)throw Error("Unterminated PRIVATE CSV quoted field.");
  fields.push(value);
  if(i===line.length)break;
  if(line[i]!==",")throw Error("Malformed CSV field boundary.");
  i++;if(i===line.length)throw Error("Trailing CSV delimiter.");
 }
 if(fields.length!==8)throw Error("Invalid sender triage column count.");
 return fields;
}
async function importCsv(file){
 if(!file)return;
 if(!file.size||file.size>1024*1024){fail("HOLD: PRIVATE CSV size invalid.");return;}
 try{
  const text=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
  if(!text.endsWith("\r\n")||/\r(?!\n)|(^|[^\r])\n/u.test(text))
   throw Error("PRIVATE CSV requires canonical CRLF.");
  const lines=text.slice(0,-2).split("\r\n");
  if(lines.length!==original.length+1)throw Error("Wrong source-bound row count.");
  if(quoted(lines[0]).join("\u0001")!==headers.join("\u0001"))
   throw Error("Wrong source-bound HUMAN triage headers.");
  const incoming=[];
  for(let i=0;i<original.length;i++){
   const row=quoted(lines[i+1]),o=original[i];
   if(row[0]!==String(o.ordinal)||row[1]!==o.priority||row[2]!==o.stage||
     row[3]!==o.reply_sha||row[4]!==o.followup_sha)
    throw Error("Original source-bound recipient reply drift at "+(i+1));
   incoming.push({route:row[5],owner:row[6],next:row[7]});
  }
  validate(incoming);
  if(!window.confirm("Replace all current unsaved HUMAN routes with exact original-recipient-bound CSV? Source producer/consent not verified."))return;
  for(let i=0;i<stages.length;i++)stages[i]=incoming[i];
  page=0;query.value="";filter.value="all";render();fail("");
 }catch(e){fail("HOLD: PRIVATE sender CSV rejected; current in-memory choices unchanged.");}
}

const PRIVATE_SCHEMA="lightup.private_sender_human_triage_encrypted.v1";
const FLAGS=["source_authenticated","human_identity_authenticated",
"client_consent_verified","operator_consent_verified",
"authorized","consent_verified","dispatch_allowed","release_allowed"];
const utf8=new TextEncoder();
function requireCrypto(){
 if(!globalThis.isSecureContext||!globalThis.crypto||!crypto.subtle||!crypto.getRandomValues)
  throw Error("WebCrypto secure context required, no plaintext fallback.");
}
function clearPass(){document.getElementById("password").value="";
 document.getElementById("password-confirm").value="";}
function password(confirm){
 const p=document.getElementById("password").value;
 if(p.length<12||p.length>120)throw Error("PRIVATE password must contain 12–120 characters.");
 if(confirm&&p!==document.getElementById("password-confirm").value)
  throw Error("PRIVATE password confirmation differs.");
 return p;
}
function base64(bytes){let s="";for(const v of new Uint8Array(bytes))s+=String.fromCharCode(v);return btoa(s);}
function admit64(value,length){
 if(typeof value!=="string"||!value||value.length>1500000||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value))throw Error("Malformed PRIVATE base64.");
 const binary=atob(value),bytes=Uint8Array.from(binary,c=>c.charCodeAt(0));
 if(base64(bytes)!==value||(length&&bytes.length!==length))throw Error("Noncanonical PRIVATE ciphertext.");
 return bytes;
}
async function derive(pass,salt){
 const key=await crypto.subtle.importKey("raw",utf8.encode(pass),"PBKDF2",false,["deriveKey"]);
 return crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:310000,hash:"SHA-256"},
  key,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
}
async function sourceHash(){
 const hash=new Uint8Array(await crypto.subtle.digest("SHA-256",utf8.encode(JSON.stringify(original))));
 return Array.from(hash,b=>b.toString(16).padStart(2,"0")).join("");
}
function aad(hash){
 if(!/^[0-9a-f]{64}$/.test(hash))throw Error("Unsupported PRIVATE source hash.");
 const a=utf8.encode(PRIVATE_SCHEMA+"|REVIEW_ONLY|"),
       b=Uint8Array.from(hash.match(/../g),x=>parseInt(x,16));
 const data=new Uint8Array(a.length+b.length);data.set(a);data.set(b,a.length);
 return data;
}
async function saveEncrypted(){
 let secret="";
 try{
  requireCrypto();const csv=writeCsv(stages);
  secret=password(true);
  if(!window.confirm("Encrypt local sender HUMAN triage? This does not authenticate the source or grant permission."))return;
  const binding=await sourceHash(),salt=crypto.getRandomValues(new Uint8Array(16)),
   nonce=crypto.getRandomValues(new Uint8Array(12));
  const key=await derive(secret,salt);
  const raw=await crypto.subtle.encrypt({name:"AES-GCM",iv:nonce,
   additionalData:aad(binding),tagLength:128},key,utf8.encode(csv));
  const envelope={
   schema:PRIVATE_SCHEMA,status:"REVIEW_ONLY",
   original_recipient_rows_sha256_unsigned:binding,
   kdf:{algorithm:"PBKDF2-SHA256",iterations:310000,salt_b64:base64(salt)},
   cipher:{algorithm:"AES-256-GCM",nonce_b64:base64(nonce),ciphertext_b64:base64(raw)}
  };
  for(const name of FLAGS)envelope[name]=false;
  const url=URL.createObjectURL(new Blob([JSON.stringify(envelope)+"\n"],
   {type:"application/octet-stream"}));
  const link=document.createElement("a");link.href=url;link.download="PRIVATE-sender-HUMAN-triage.luts";
  link.click();setTimeout(()=>URL.revokeObjectURL(url),3000);fail("");
 }catch(e){fail("HOLD: "+String(e.message||"Encrypted sender draft refused"));}
 finally{secret="";clearPass();}
}
async function loadEncrypted(file){
 let secret="";
 if(!file)return;
 if(!file.size||file.size>1500000){fail("HOLD: Encrypted sender HUMAN draft file size invalid.");return;}
 try{
  requireCrypto();secret=password(false);
  const raw=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
  const value=JSON.parse(raw);
  if(!value||Array.isArray(value)||JSON.stringify(value)+"\n"!==raw||
    Object.keys(value).length!==13||value.schema!==PRIVATE_SCHEMA||
    value.status!=="REVIEW_ONLY"||
    Object.keys(value.kdf||{}).join(",")!=="algorithm,iterations,salt_b64"||
    Object.keys(value.cipher||{}).join(",")!=="algorithm,nonce_b64,ciphertext_b64"||
    value.kdf.algorithm!=="PBKDF2-SHA256"||value.kdf.iterations!==310000||
    value.cipher.algorithm!=="AES-256-GCM"||
    FLAGS.some(k=>value[k]!==false))
   throw Error("Invalid canonical PRIVATE sender envelope.");
  const source=await sourceHash();
  if(value.original_recipient_rows_sha256_unsigned!==source)
   throw Error("Wrong exact recipient HUMAN source rows.");
  const salt=admit64(value.kdf.salt_b64,16),nonce=admit64(value.cipher.nonce_b64,12),
   ciphertext=admit64(value.cipher.ciphertext_b64);
  if(ciphertext.length<16||ciphertext.length>1024*1024)throw Error("Invalid ciphertext length.");
  const key=await derive(secret,salt);
  const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv:nonce,
   additionalData:aad(source),tagLength:128},key,ciphertext);
  if(plain.byteLength>1024*1024)throw Error("Decrypted sender HUMAN data too large.");
  // Full original source ordinal + recipient reply digest + human decision
  // membership still passes through the same atomic import and HUMAN confirm.
  await importCsv(new Blob([plain],{type:"text/csv;charset=utf-8"}));
 }catch(e){fail("HOLD: Wrong source, password or invalid PRIVATE sender draft; current choices retained.");}
 finally{secret="";clearPass();}
}
document.getElementById("save-encrypted").addEventListener("click",()=>{void saveEncrypted();});
document.getElementById("load-encrypted").addEventListener("change",e=>{
 const file=e.target.files&&e.target.files[0];e.target.value="";void loadEncrypted(file);
});

function dispose(){
 if(!window.confirm("Discard unsaved PRIVATE HUMAN triage edits? Previously downloaded files are not deleted."))return;
 for(let i=0;i<stages.length;i++)stages[i]={route:"",owner:"",next:""};
 query.value="";filter.value="all";page=0;document.getElementById("restore").value="";
 render();fail("Local HUMAN edits reset; browser memory and old downloads are not securely erased.");
}
query.addEventListener("input",()=>{page=0;render();});
filter.addEventListener("change",()=>{page=0;render();});
document.getElementById("prev").addEventListener("click",()=>{page--;render();});
document.getElementById("next").addEventListener("click",()=>{page++;render();});
document.getElementById("export").addEventListener("click",exportCsv);
document.getElementById("dispose").addEventListener("click",dispose);
document.getElementById("restore").addEventListener("change",e=>{
 const file=e.target.files&&e.target.files[0];e.target.value="";void importCsv(file);});
render();
})();
"""

def render_studio(notes: list[dict]) -> bytes:
    rows = [{
        "ordinal": n["ordinal"], "priority": n["priority"],
        "stage": n["recipient_reported_stage"],
        "original_question": n["original_question"],
        "reply": n["recipient_human_reply"],
        "followup": n["recipient_human_next_question"],
        "reply_sha": hashlib.sha256(n["recipient_human_reply"].encode()).hexdigest(),
        "followup_sha": hashlib.sha256(n["recipient_human_next_question"].encode()).hexdigest(),
    } for n in notes]
    content = json.dumps(rows, ensure_ascii=True, separators=(",", ":")).replace("<", "\\u003c")
    css_pin = base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode()
    js_pin = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
    csp = ("default-src 'none'; script-src 'sha256-" + js_pin +
           "'; style-src 'sha256-" + css_pin +
           "'; connect-src 'none'; img-src 'none'; object-src 'none'; "
           "form-action 'none'; base-uri 'none'")
    doc = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"" +
        html.escape(csp, quote=True) + "\">"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>PRIVATE HUMAN sender triage studio</title><style>" + CSS +
        "</style></head><body><header><h1>LightUp · PRIVATE HUMAN sender reply triage</h1>"
        "<p class='warning'>REVIEW ONLY — no original findings, evidence, human "
        "recipient identity, source authenticity, current consent, grant or "
        "remediation verified. HUMAN routing choices never confer authority.</p>"
        "<p>Use an approved PRIVATE channel; incoming HUMAN replies and questions "
        "may identify clients. This app has no original target, finding ID, "
        "source hash, evidence body or network backend. Browser text is local.</p>"
        "<p>Prepare a HUMAN owner group, question and route, export a PRIVATE CSV "
        "and independently reopen it with the original source, worksheet, response "
        "and unsigned binding using response_triage.py return.</p></header>"
        "<section><div class='toolbar'>"
        "<label>Question/answer search <input type='search' id='search' autocomplete='off'></label>"
        "<label>Sender route filter <select id='route-filter'>"
        "<option value='all'>All routes</option><option value=''>Unreviewed</option>"
        "<option value='needs_human_review'>Needs HUMAN review</option>"
        "<option value='request_clarification'>Request clarification</option>"
        "<option value='route_to_owner'>Route to HUMAN owner</option>"
        "<option value='documented_for_followup'>Documented for followup</option>"
        "</select></label></div><p class='summary' id='summary' aria-live='polite'></p>"
        "<div class='toolbar'><button id='export' type='button'>Export PRIVATE HUMAN triage CSV</button>"
        "<label>Restore PRIVATE triage CSV <input id='restore' type='file' accept='.csv,text/csv'></label>"
        "<button id='dispose' class='secondary' type='button'>Discard local edits</button>"
        "<label>PRIVATE passphrase <input id='password' type='password' autocomplete='off'></label>"
        "<label>Confirm passphrase to encrypt <input id='password-confirm' type='password' autocomplete='off'></label>"
        "<button type='button' id='save-encrypted'>Save encrypted PRIVATE triage</button>"
        "<label>Open encrypted PRIVATE triage <input id='load-encrypted' type='file' accept='.luts,application/octet-stream'></label>"
        "</div><p id='notice' class='warning' role='alert' hidden></p></section>"
        "<main id='entries'></main><nav><button id='prev' type='button'>Previous</button>"
        "<span id='page'></span><button id='next' type='button'>Next</button></nav>"
        "<template id='original-rows'>" + content + "</template>"
        "<script>" + SCRIPT + "</script></body></html>\n"
    )
    return doc.encode("utf-8")
