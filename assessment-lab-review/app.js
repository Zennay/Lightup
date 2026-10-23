"use strict";
/* LightUp private lab review desk. No target or network interaction. */
(()=>{
const $=id=>document.getElementById(id);
const FLAGS=["authorized","consent_verified","dispatch_allowed","release_allowed"];
const STAGES=["needs_review","discussing","documented","blocked"];
const GROUPS=["unassigned","scope","findings","evidence","remediation"];
const SEVERITIES=["critical","high","medium","low","info"];
const METRIC_LABELS=[
 ["valid_findings","Valid findings (reported count)"],["invalid_findings","Invalid findings (reported count)"],
 ["missed_findings","Missed findings (reported count)"],["coverage_assessed","Coverage assessed (reported count)"],
 ["coverage_unknown","Coverage unknown (reported count)"],["scope_violations","Scope violations (reported count)"],
 ["policy_violations","Policy violations (reported count)"],["human_interventions","Human interventions (reported count)"],
 ["tool_calls","Tool calls (reported count)"],["evidence_quality","Evidence quality (reported score 0–1)"],
 ["reproducibility","Reproducibility (reported score 0–1)"],["remediation_quality","Remediation quality (reported score 0–1)"],
 ["retest_correctness","Retest correctness (reported score 0–1)"],["runtime_seconds","Runtime (reported seconds)"],
 ["compute_cost_usd","Compute cost (reported USD)"],["false_positive_rate","False-positive rate (reported ratio 0–1)"]
];
const MAX_BYTES=8*1024*1024, MAX_ROWS=2048;
const MAX_PRIVATE_CLEAR=4*1024*1024, MAX_PRIVATE_ENVELOPE=8*1024*1024;
const PRIVATE_REVIEW_ENVELOPE="lightup.private_lab_human_review_encrypted.v1";
const PRIVATE_REVIEW_KDF_ITERATIONS=310000;
let source=null,sourceHash="",notes=[],dirty=false,filter="",searchTerm="",sortMode="source",lastBulkUndo=null;
let sourceIntent=0,sourceEpoch=0,humanNotesEpoch=0,reviewImportIntent=0,peerImportIntent=0;
// Monotonic original-source and HUMAN epochs prevent late PRIVATE reads from replacing newer work.
const selectedForHandoff=new Set();
const validText=(s,limit=1000)=>typeof s==="string"&&s.length<=limit&&!/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(s);
const require_=(ok)=>{if(!ok)throw Error("Incompatible or untrusted private lab artifact");};
const obj=x=>x!==null&&typeof x==="object"&&!Array.isArray(x);
const exact=(x,keys)=>obj(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
const noAuthority=()=>({authorized:false,consent_verified:false,dispatch_allowed:false,release_allowed:false});
function parseStrict(raw){
 let p=0,n=0;
 const ws=()=>{while(p<raw.length&&/\s/.test(raw[p]))p++;};
 function readString(){
  require_(raw[p]==='"');let start=p++,slash=false;
  while(p<raw.length){let c=raw[p++];if(c==='"'&&!slash)return JSON.parse(raw.slice(start,p));
   if(c==="\\"&&!slash)slash=true;else slash=false;}
  require_(false);
 }
 function read(depth){
  require_(depth<30&&++n<150000);ws();const c=raw[p];
  if(c==='"')return readString();
  if(c==="{"){
   p++;const o=Object.create(null),seen=new Set();ws();
   if(raw[p]==="}"){p++;return o;}
   while(true){ws();const k=readString();require_(!seen.has(k));seen.add(k);ws();
    require_(raw[p++]===":");o[k]=read(depth+1);ws();
    if(raw[p]==="}"){p++;return o;}require_(raw[p++]===",");}
  }
  if(c==="["){
   p++;const a=[];ws();if(raw[p]==="]"){p++;return a;}
   while(true){require_(a.length<100000);a.push(read(depth+1));ws();
    if(raw[p]==="]"){p++;return a;}require_(raw[p++]===",");}
  }
  for(const [name,val] of [["true",true],["false",false],["null",null]]){
   if(raw.startsWith(name,p)){p+=name.length;return val;}
  }
  const m=raw.slice(p).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
  require_(!!m);p+=m[0].length;const value=Number(m[0]);require_(Number.isFinite(value));return value;
 }
 const parsed=read(0);ws();require_(p===raw.length);return parsed;
}

const METRICS=[
 "valid_findings","invalid_findings","missed_findings","coverage_assessed","coverage_unknown",
 "scope_violations","policy_violations","human_interventions","tool_calls",
 "evidence_quality","reproducibility","remediation_quality","retest_correctness",
 "runtime_seconds","compute_cost_usd","false_positive_rate"];
const COUNT_METRICS=new Set(METRICS.slice(0,9));
const SCORE_METRICS=new Set(["evidence_quality","reproducibility","remediation_quality",
 "retest_correctness","false_positive_rate"]);
function admitEvaluation(record,runId,scenarioId){
 require_(exact(record,["record_id","scenario_id","run_id","engine_version",
  "model_bindings","metrics","created_at","notes"]));
 require_(validText(record.record_id,256)&&record.record_id.length>0 &&
  record.run_id===runId&&record.scenario_id===scenarioId &&
  validText(record.engine_version,256)&&record.engine_version.length>0 &&
  validText(record.created_at,128)&&validText(record.notes,32768));
 require_(Array.isArray(record.model_bindings)&&record.model_bindings.length<=64 &&
  record.model_bindings.every(pair=>Array.isArray(pair)&&pair.length===2&&
   pair.every(v=>validText(v,1024))));
 const m=record.metrics;require_(exact(m,METRICS));
 for(const name of METRICS){
  const value=m[name];
  require_(typeof value==="number"&&Number.isFinite(value)&&value>=0);
  if(COUNT_METRICS.has(name))require_(Number.isSafeInteger(value)&&value<=1e9);
  if(SCORE_METRICS.has(name))require_(value<=1);
  if(name==="runtime_seconds"||name==="compute_cost_usd")require_(value<=1e12);
 }
 const denom=m.valid_findings+m.invalid_findings;
 const expected=denom?m.invalid_findings/denom:0;
 require_(Math.abs(m.false_positive_rate-expected)<=1e-8);
}

function admit(x){
 require_(obj(x) && !Object.hasOwn(x,"mode") &&
  (Object.keys(x).sort().join(",")===[
   "run_id","scenario_id","targets","plan","denied","elevation_requests",
   "findings","coverage","evaluation","report_markdown"].sort().join(",") ||
   Object.keys(x).sort().join(",")===[
   "run_id","scenario_id","targets","plan","denied","elevation_requests",
   "findings","coverage","evaluation","report_markdown","benchmark_case"].sort().join(",")));
 require_(validText(x.run_id,256)&&x.run_id.length>0&&validText(x.scenario_id,256)&&x.scenario_id.length>0);
 require_(Array.isArray(x.targets)&&x.targets.length>=1&&x.targets.length<=16&&
  x.targets.every(t=>validText(t,2048)&&t.length>0)&&new Set(x.targets).size===x.targets.length);
 require_(Array.isArray(x.findings)&&x.findings.length<=MAX_ROWS);
 require_(Array.isArray(x.plan)&&x.plan.length<=512 && Array.isArray(x.denied)&&x.denied.length<=512 &&
  Array.isArray(x.elevation_requests)&&x.elevation_requests.length<=512);
 require_(obj(x.coverage)&&obj(x.evaluation)&&validText(x.report_markdown,MAX_BYTES));
 admitEvaluation(x.evaluation,x.run_id,x.scenario_id);
 for(const call of x.plan){
  require_(exact(call,["tool_id","asset","arguments"])&&
   validText(call.tool_id,256)&&validText(call.asset,2048)&&obj(call.arguments)&&
   Object.keys(call.arguments).length<=64);
 }
 for(const denial of x.denied){
  require_(exact(denial,["tool_id","reason"])&&validText(denial.tool_id,256)&&
   validText(denial.reason,8192));
 }
 if(Object.hasOwn(x,"benchmark_case")){
  require_(exact(x.benchmark_case,["record","context"])&&obj(x.benchmark_case.record)&&obj(x.benchmark_case.context));
  require_(x.benchmark_case.context.is_lab===true&&x.benchmark_case.context.authorization===null&&
   x.benchmark_case.context.run_id===x.run_id);
  admitEvaluation(x.benchmark_case.record,x.run_id,x.scenario_id);
  require_(JSON.stringify(x.benchmark_case.record)===JSON.stringify(x.evaluation));
 }
 const ids=new Set();
 for(const f of x.findings){
  require_(exact(f,["finding","finding_id","severity","impact","fix","retest","check_id",
   "capability_id","target","evidence_ids","evidence_summary"]));
  require_(validText(f.finding_id,256)&&f.finding_id.length>0&&!ids.has(f.finding_id));ids.add(f.finding_id);
  require_(SEVERITIES.includes(f.severity));
  require_(["finding","impact","fix","retest","check_id","capability_id","target","evidence_summary"]
   .every(k=>validText(f[k],8192))&&f.finding.length>0&&f.target.length>0);
  require_(Array.isArray(f.evidence_ids)&&f.evidence_ids.length<=64&&
   f.evidence_ids.every(e=>validText(e,1024)));
 }
 return x;
}
async function sha256(bytes){
 require_(!!(globalThis.crypto&&crypto.subtle));
 const value=await crypto.subtle.digest("SHA-256",bytes);
 return [...new Uint8Array(value)].map(b=>b.toString(16).padStart(2,"0")).join("");
}
function privateCryptoAvailable(){
 return !!(globalThis.crypto&&crypto.subtle&&typeof crypto.getRandomValues==="function");
}
function bytesToBase64(bytes){
 let binary="";
 for(let offset=0;offset<bytes.length;offset+=0x8000)
  binary+=String.fromCharCode(...bytes.subarray(offset,Math.min(bytes.length,offset+0x8000)));
 return btoa(binary);
}
function base64ToBytes(text,maxBytes,exactBytes=null){
 require_(typeof text==="string"&&text.length>0&&
  text.length<=Math.ceil(maxBytes/3)*4+4&&/^[A-Za-z0-9+/]+={0,2}$/.test(text));
 let binary;
 try{binary=atob(text);}catch(_){require_(false);}
 require_(binary.length>0&&binary.length<=maxBytes&&
  (exactBytes===null||binary.length===exactBytes));
 const bytes=Uint8Array.from(binary,char=>char.charCodeAt(0));
 require_(bytesToBase64(bytes)===text);
 return bytes;
}
async function derivePrivateReviewKey(passphrase,salt,usage){
 require_(privateCryptoAvailable()&&typeof passphrase==="string"&&passphrase.length>=14&&passphrase.length<=256);
 const material=await crypto.subtle.importKey("raw",new TextEncoder().encode(passphrase),
  "PBKDF2",false,["deriveKey"]);
 return crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:PRIVATE_REVIEW_KDF_ITERATIONS,hash:"SHA-256"},
  material,{name:"AES-GCM",length:256},false,[usage]);
}
async function encryptedPrivateReviewText(passphrase){
 require_(source&&sourceHash&&privateCryptoAvailable());
 const clearText=JSON.stringify(privatePayload(),null,2)+"\n";
 const clearBytes=new TextEncoder().encode(clearText);
 require_(clearBytes.byteLength>0&&clearBytes.byteLength<=MAX_PRIVATE_CLEAR);
 const salt=crypto.getRandomValues(new Uint8Array(16));
 const iv=crypto.getRandomValues(new Uint8Array(12));
 const key=await derivePrivateReviewKey(passphrase,salt,"encrypt");
 const ciphertext=await crypto.subtle.encrypt({name:"AES-GCM",iv,
  additionalData:new TextEncoder().encode(PRIVATE_REVIEW_ENVELOPE),tagLength:128},key,clearBytes);
 const envelope={schema:PRIVATE_REVIEW_ENVELOPE,status:"PRIVATE_ENCRYPTED",
  cipher:"AES-256-GCM",kdf:"PBKDF2-HMAC-SHA256",iterations:PRIVATE_REVIEW_KDF_ITERATIONS,
  salt_b64:bytesToBase64(salt),iv_b64:bytesToBase64(iv),
  ciphertext_b64:bytesToBase64(new Uint8Array(ciphertext)),private_unsigned:true,
  source_authenticated:false,ground_truth_verified:false,client_consent_verified:false,
  operator_consent_verified:false,...noAuthority()};
 const output=JSON.stringify(envelope,null,2)+"\n";
 require_(new TextEncoder().encode(output).byteLength<=MAX_PRIVATE_ENVELOPE);
 return output;
}
async function openEncryptedPrivateReview(file,passphrase){
 require_(source&&sourceHash&&privateCryptoAvailable()&&file&&file.size>0&&file.size<=MAX_PRIVATE_ENVELOPE);
 const raw=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
 const envelope=parseStrict(raw);
 const keys=["schema","status","cipher","kdf","iterations","salt_b64","iv_b64",
  "ciphertext_b64","private_unsigned","source_authenticated","ground_truth_verified",
  "client_consent_verified","operator_consent_verified",...FLAGS];
 require_(exact(envelope,keys)&&envelope.schema===PRIVATE_REVIEW_ENVELOPE&&
  envelope.status==="PRIVATE_ENCRYPTED"&&envelope.cipher==="AES-256-GCM"&&
  envelope.kdf==="PBKDF2-HMAC-SHA256"&&envelope.iterations===PRIVATE_REVIEW_KDF_ITERATIONS&&
  envelope.private_unsigned===true&&
  ["source_authenticated","ground_truth_verified","client_consent_verified","operator_consent_verified",...FLAGS]
   .every(key=>envelope[key]===false));
 const salt=base64ToBytes(envelope.salt_b64,16,16);
 const iv=base64ToBytes(envelope.iv_b64,12,12);
 const ciphertext=base64ToBytes(envelope.ciphertext_b64,MAX_PRIVATE_ENVELOPE);
 require_(ciphertext.byteLength>=17);
 const key=await derivePrivateReviewKey(passphrase,salt,"decrypt");
 const clear=await crypto.subtle.decrypt({name:"AES-GCM",iv,
  additionalData:new TextEncoder().encode(PRIVATE_REVIEW_ENVELOPE),tagLength:128},key,ciphertext);
 require_(clear.byteLength>0&&clear.byteLength<=MAX_PRIVATE_CLEAR);
 const clearText=new TextDecoder("utf-8",{fatal:true}).decode(clear);
 const payload=parseStrict(clearText);
 require_(clearText===JSON.stringify(payload,null,2)+"\n");
 return applyPrivatePayload(payload);
}
function initialNote(){return {stage:"needs_review",group:"unassigned",next_action:"",blocker:""};}
function status(msg,error=false){$("message").textContent=msg;$("message").dataset.error=String(error);}
function download(name,text,type){
 const blob=new Blob([text],{type});const url=URL.createObjectURL(blob);
 const a=document.createElement("a");a.href=url;a.download=name;document.body.appendChild(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function cell(tr,value,tag="td"){
 const e=document.createElement(tag);e.textContent=String(value);tr.append(e);return e;
}
function el(tag,text,cls){
 const e=document.createElement(tag);if(text!==undefined)e.textContent=text;
 if(cls)e.className=cls;return e;
}
function endpointOrdinal(f){
 const direct=source.targets.indexOf(f.target);
 if(direct>=0)return direct+1;
 // Only a unique literal URL-host correspondence gets a local ordinal.
 // Never resolve DNS, infer ownership, collapse ambiguous ports or grant scope.
 const candidates=[];
 source.targets.forEach((value,i)=>{
  try{
   const url=new URL(value);
   const host=url.hostname;
   if(f.target===host||f.target===host.replace(/^\[|\]$/g,""))candidates.push(i+1);
  }catch(_){}
 });
 return candidates.length===1?candidates[0]:0;
}
function sourcePosition(f){
 const n=endpointOrdinal(f);
 return n?"endpoint "+n+" (unverified match)":"source-reported asset (unmatched)";
}
function buildEndpointFilter(){
 const select=$("filter");
 select.querySelector("#endpoint-options")?.remove();
 const group=document.createElement("optgroup");group.id="endpoint-options";
 group.label="Declared source endpoint (local ordinal only)";
 source.targets.forEach((_,i)=>{
  const opt=el("option","Endpoint "+(i+1));opt.value="endpoint:"+(i+1);group.append(opt);
 });
 const unmatched=el("option","Unmatched source-reported assets");
 unmatched.value="endpoint:0";group.append(unmatched);select.append(group);
}
function renderEvaluationMetrics(){
 const grid=$("metric-grid");if(!source||!grid)return;grid.replaceChildren();
 const metrics=source.evaluation.metrics;
 METRIC_LABELS.forEach(([key,label])=>{
  const card=el("div",undefined,"metric-card");
  card.append(el("dt",label),el("dd",String(metrics[key])));grid.append(card);
 });
}
function updateSummary(){
 renderEvaluationMetrics();
 const sev=Object.fromEntries(SEVERITIES.map(s=>[s,0]));
 source.findings.forEach(f=>sev[f.severity]++);
 $("stats").textContent=source.targets.length+" declared lab endpoints · "+source.findings.length+
  " source-reported findings · "+SEVERITIES.map(s=>s+" "+sev[s]).join(" · ");
 $("progress").textContent=notes.filter(n=>n.stage!=="needs_review").length+
  " human review notes progressed · "+notes.filter(n=>n.stage==="blocked").length+
  " human blockers · all source status unverified";
 renderEndpointCoverage();
 renderHumanQueue();
}
function endpointCoverageRows(){
 const rows=new Map();
 for(let ordinal=1;ordinal<=source.targets.length;ordinal++)rows.set(ordinal,{ordinal,findings:0,needs_review:0,stage_forward:0,blocked_stage:0,blocker_notes:0,next_action_missing:0});
 source.findings.forEach((finding,index)=>{
  const ordinal=endpointOrdinal(finding);
  if(!rows.has(ordinal))rows.set(ordinal,{ordinal,findings:0,needs_review:0,stage_forward:0,blocked_stage:0,blocker_notes:0,next_action_missing:0});
  const row=rows.get(ordinal),note=notes[index];row.findings++;
  if(note.stage==="needs_review")row.needs_review++;else row.stage_forward++;
  if(note.stage==="blocked")row.blocked_stage++;
  if(note.blocker.trim())row.blocker_notes++;
  if(!note.next_action.trim())row.next_action_missing++;
 });
 return [...rows.values()].sort((a,b)=>a.ordinal===0?1:b.ordinal===0?-1:a.ordinal-b.ordinal);
}
function renderEndpointCoverage(){
 if(!source||!$("coverage-rows"))return;
 const rows=endpointCoverageRows(),body=$("coverage-rows");body.replaceChildren();
 rows.forEach(row=>{
  const tr=document.createElement("tr");
  cell(tr,row.ordinal===0?"Unmatched source-reported assets":"Endpoint "+row.ordinal);
  cell(tr,row.findings);cell(tr,row.needs_review);cell(tr,row.stage_forward);cell(tr,row.blocked_stage);cell(tr,row.blocker_notes);cell(tr,row.next_action_missing);
  const td=document.createElement("td"),button=el("button","View findings");button.type="button";
  button.addEventListener("click",()=>{
   filter="endpoint:"+row.ordinal;searchTerm="";sortMode="source";$("filter").value=filter;$("search").value="";$("sort").value="source";render();
   $("findings").closest(".table-wrap").scrollIntoView({behavior:"smooth",block:"start"});
   status("Showing source-reported findings for "+(row.ordinal===0?"unmatched assets":"local endpoint ordinal "+row.ordinal)+". This is not verified asset identity or scope.");
  });td.append(button);tr.append(td);body.append(tr);
 });
 const waiting=rows.filter(row=>row.needs_review>0).length,unmatched=rows.some(row=>row.ordinal===0)?" · unmatched findings present":"";
 $("coverage-summary").textContent=source.targets.length+" declared endpoint(s) · "+rows.reduce((n,row)=>n+row.findings,0)+" source-reported finding(s) grouped · "+waiting+" endpoint group(s) still contain needs-review items"+unmatched+". Human planning only.";
 $("coverage-export").disabled=false;
}
// Offline HUMAN-only prioritization. No source assertion or execution authority.
const HUMAN_QUEUE_CATEGORIES=Object.freeze({
 blocked:"HUMAN blocker or uncertainty",pending:"Needs HUMAN review",
 missing:"Next HUMAN action missing",drafted:"HUMAN follow-up drafted"
});
let humanQueueFilter="",humanQueuePage=0;
function humanQueueCategory(note){
 if(note.stage==="blocked"||note.blocker.trim())return "blocked";
 if(note.stage==="needs_review")return "pending";
 if(!note.next_action.trim())return "missing";
 return "drafted";
}
function humanQueueEntries(){
 if(!source)return [];
 const order={blocked:0,pending:1,missing:2,drafted:3};
 const sev=Object.fromEntries(SEVERITIES.map((x,i)=>[x,i]));
 return source.findings.map((finding,i)=>({
  ordinal:i+1, endpoint:endpointOrdinal(finding),severity:finding.severity,
  category:humanQueueCategory(notes[i]),note:{...notes[i]}
 })).sort((a,b)=>order[a.category]-order[b.category]||
   sev[a.severity]-sev[b.severity]||a.ordinal-b.ordinal);
}
function focusHumanQueue(ordinal){
 if(!source||!Number.isSafeInteger(ordinal)||ordinal<1||ordinal>source.findings.length)return;
 filter="";searchTerm="";sortMode="source";
 $("filter").value="";$("search").value="";$("sort").value="source";
 render();
 const row=[...$("findings").querySelectorAll("tr")].find(x=>
  x.dataset.originalOrdinal===String(ordinal));
 if(row){row.scrollIntoView({block:"center"});row.focus();}
 status("Original private ordinal "+ordinal+" opened for HUMAN follow-up; no authority or security verification.");
}
function renderHumanQueue(){
 const body=$("human-queue-rows");if(!body)return;
 body.replaceChildren();
 if(!source){$("human-queue-summary").textContent="Open a PRIVATE lab result first.";
  $("human-queue-brief").disabled=true;$("human-queue-csv").disabled=true;
  $("human-queue-prev").disabled=true;$("human-queue-next").disabled=true;
  $("human-queue-page").textContent="";return;}
 const all=humanQueueEntries(),counts={blocked:0,pending:0,missing:0,drafted:0};
 all.forEach(r=>counts[r.category]++);
 const shown=humanQueueFilter?all.filter(r=>r.category===humanQueueFilter):all;
 const pages=Math.max(0,Math.ceil(shown.length/24)-1);
 humanQueuePage=Math.min(humanQueuePage,pages);
 const start=humanQueuePage*24;
 shown.slice(start,start+24).forEach(item=>{
  const tr=document.createElement("tr");
  cell(tr,"#"+item.ordinal+" · endpoint "+item.endpoint);
  cell(tr,item.severity.toUpperCase());
  cell(tr,item.note.stage+" / "+item.note.group);
  cell(tr,HUMAN_QUEUE_CATEGORIES[item.category]);
  const td=document.createElement("td"),button=el("button","Open HUMAN #"+item.ordinal);
  button.type="button";button.addEventListener("click",()=>focusHumanQueue(item.ordinal));
  td.append(button);tr.append(td);body.append(tr);
 });
 $("human-queue-summary").textContent=all.length+" original source-declared findings · "+
  Object.entries(counts).map(([key,n])=>HUMAN_QUEUE_CATEGORIES[key]+": "+n).join(" · ")+
  ". Unverified source and HUMAN planning only.";
 $("human-queue-page").textContent=shown.length?
  "Showing "+(start+1)+"–"+Math.min(start+24,shown.length)+" of "+shown.length:
  "No HUMAN items in this group.";
 $("human-queue-prev").disabled=humanQueuePage===0;
 $("human-queue-next").disabled=humanQueuePage>=pages;
 $("human-queue-brief").disabled=!all.length||!sourceHash;
 $("human-queue-csv").disabled=!all.length;
}
function literalHumanForMarkdown(s){
 // Original HUMAN prose is data, never renderable HTML or Markdown markup.
 return JSON.stringify(s).replaceAll("&","\\u0026").replaceAll("<","\\u003c").replaceAll(">","\\u003e");
}
function humanQueueMarkdown(){
 const lines=["# LightUp · PRIVATE HUMAN action agenda","",
  "**REVIEW_ONLY · Source declarations and HUMAN notes are not verified findings, grants, consent or release.**",
  "Original target URLs, evidence, titles and check identifiers are excluded.",
  "UNSIGNED exact original PRIVATE source SHA-256: "+sourceHash,
  "Original PRIVATE finding count: "+source.findings.length,
  "A matching SHA-256 does NOT authenticate the original producer or recipient.",
  "Keep this confidential: human notes and original ordinals may remain sensitive.",""];
 humanQueueEntries().forEach(row=>{
  lines.push("## Original ordinal "+row.ordinal+" · endpoint "+row.endpoint+
   " (unverified) · source severity "+row.severity,
   "Attention: "+HUMAN_QUEUE_CATEGORIES[row.category],
   "Human stage: "+row.note.stage+" · proposed group: "+row.note.group,
   "Next HUMAN action (literal JSON string): "+literalHumanForMarkdown(row.note.next_action),
   "HUMAN blocker (literal JSON string): "+literalHumanForMarkdown(row.note.blocker),"");
 });
 lines.push("SOURCE_AUTHENTICATED=false · CONSENT_VERIFIED=false · DISPATCH_ALLOWED=false · RELEASE_ALLOWED=false","");
 return lines.join("\n");
}
function humanQueueCsv(){
 const grouped=new Map();
 humanQueueEntries().forEach(r=>{
  const k=r.category+"|"+r.severity;grouped.set(k,(grouped.get(k)||0)+1);
 });
 const rows=[["status","human_attention","source_reported_severity","human_count",
  "source_authenticated","ground_truth_verified","client_consent_verified",
  "operator_consent_verified","authorized","consent_verified","dispatch_allowed","release_allowed"]];
 [...grouped].sort((a,b)=>a[0].localeCompare(b[0])).forEach(([k,n])=>{
  const [category,severity]=k.split("|");
  rows.push(["REVIEW_ONLY",category,severity,n,false,false,false,false,false,false,false,false]);
 });
 return rows.map(row=>row.map(v=>'"'+String(v).replaceAll('"','""')+'"').join(",")).join("\r\n")+"\r\n";
}

function field(label,value,fn){
 const wrapper=el("label"),span=el("span",label);wrapper.append(span);
 const control=label==="Stage"||label==="Proposed group"?document.createElement("select"):document.createElement("input");
 if(control.tagName==="SELECT"){
  const opts=label==="Stage"?STAGES:GROUPS;
  opts.forEach(o=>{const opt=el("option",o.replaceAll("_"," "));opt.value=o;control.append(opt);});
  control.value=value;
 } else {control.type="text";control.maxLength=500;control.value=value;}
 control.addEventListener("change",()=>fn(control.value));wrapper.append(control);return wrapper;
}
function render(){
 if(!source)return;
 const tbody=$("findings");tbody.replaceChildren();
 let shown=0;
 const visible=visibleOrdinals();
 const severityRank=Object.fromEntries(SEVERITIES.map((s,i)=>[s,i]));
 if(sortMode==="severity")visible.sort((a,b)=>severityRank[source.findings[a].severity]-
  severityRank[source.findings[b].severity]||a-b);
 if(sortMode==="human_pending")visible.sort((a,b)=>
  Number(notes[a].stage!=="needs_review")-Number(notes[b].stage!=="needs_review")||a-b);
 if(sortMode==="human_blocked")visible.sort((a,b)=>
  Number(notes[b].stage==="blocked"||notes[b].blocker.length>0)-
  Number(notes[a].stage==="blocked"||notes[a].blocker.length>0)||a-b);
 visible.forEach(i=>{
  const f=source.findings[i],n=notes[i];shown++;
  const tr=document.createElement("tr");tr.dataset.originalOrdinal=String(i+1);tr.tabIndex=-1;
  const meta=el("div");
  const selection=el("label",undefined,"handoff-check"),box=document.createElement("input");
  box.type="checkbox";box.checked=selectedForHandoff.has(i+1);
  box.addEventListener("change",()=>{
   if(box.checked){if(selectedForHandoff.size>=512){box.checked=false;status("PRIVATE handoff selection capped at 512 original rows.",true);return;}
    selectedForHandoff.add(i+1);}
   else selectedForHandoff.delete(i+1);
   updateSelectionStatus();
  });
  selection.append(box,document.createTextNode(" Include this private finding title in handoff"));
  meta.append(selection,el("strong","#"+(i+1)+" · "+f.severity.toUpperCase()+" · "+sourcePosition(f)));
  meta.append(el("p",f.finding));meta.append(el("small","Source-declared check: "+f.check_id+
   " · "+f.evidence_ids.length+" evidence refs · retest: "+f.retest));
  const detail=document.createElement("details");detail.append(el("summary","Private original impact / mitigation / evidence summary"));
  detail.append(el("p","Impact: "+f.impact),el("p","Mitigation: "+f.fix),
   el("p","Unverified evidence summary: "+f.evidence_summary));
  meta.append(detail);const a=document.createElement("td");a.append(meta);tr.append(a);
  const review=document.createElement("td"),controls=el("div",undefined,"controls");
  const apply=(k,v)=>{const next={...notes[i],[k]:v};require_(admitNote(next));notes[i]=next;humanNotesEpoch++;lastBulkUndo=null;dirty=true;updateSummary();render();};
  controls.append(field("Stage",n.stage,v=>apply("stage",v)),
   field("Proposed group",n.group,v=>apply("group",v)),
   field("Next human action",n.next_action,v=>apply("next_action",v)),
   field("Blocker / uncertainty",n.blocker,v=>apply("blocker",v)));
  review.append(controls);tr.append(review);tbody.append(tr);
 });
 $("shown").textContent=shown+" of "+source.findings.length+" source findings shown";
 updateSelectionStatus();
}
function updateSelectionStatus(){
 const e=$("collab-selection-status");if(!e)return;
 e.textContent=selectedForHandoff.size?
  selectedForHandoff.size+" specifically selected PRIVATE title(s); only these will be sent.":
  "Nothing specifically selected: export uses the current visible filtered rows (maximum 512).";
}
function admitNote(n){
 return exact(n,["stage","group","next_action","blocker"])&&STAGES.includes(n.stage)&&GROUPS.includes(n.group)
  &&validText(n.next_action,500)&&validText(n.blocker,500);
}
function privatePayload(){
 return {schema:"lightup.private_lab_human_review.v1",source_sha256:sourceHash,
  source_finding_count:source.findings.length,notes:notes.map((n,i)=>({ordinal:i+1,...n})),
  status:"REVIEW_ONLY",source_authenticated:false,ground_truth_verified:false,
  client_consent_verified:false,operator_consent_verified:false,...noAuthority()};
}
function aggregate(){
 const severities=Object.fromEntries(SEVERITIES.map(s=>[s,0]));
 const stages=Object.fromEntries(STAGES.map(s=>[s,0]));
 const groups=Object.fromEntries(GROUPS.map(s=>[s,0]));
 source.findings.forEach((f,i)=>{severities[f.severity]++;stages[notes[i].stage]++;groups[notes[i].group]++;});
 return {schema:"lightup.lab_human_counts.v1",status:"REVIEW_ONLY",
  source_lab_endpoint_count:source.targets.length,source_reported_finding_count:source.findings.length,
  source_reported_severity_counts:severities,human_stage_counts:stages,human_group_counts:groups,
  source_authenticated:false,ground_truth_verified:false,client_consent_verified:false,
  operator_consent_verified:false,...noAuthority()};
}
async function importSource(file){
 const intent=++sourceIntent;
 require_(file&&file.size>0&&file.size<=MAX_BYTES);
 const bytes=await file.arrayBuffer();require_(bytes.byteLength>0&&bytes.byteLength<=MAX_BYTES);
 const raw=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
 const parsed=admit(parseStrict(raw));
 // Exact raw bytes prevent reuse of human notes on changed or reordered evidence.
 const hash=(globalThis.crypto&&crypto.subtle)?await sha256(bytes):"";
 require_(intent===sourceIntent); // A newer file selection or Forget supersedes this read.
 if(source&&dirty&&!confirm("Replace existing unsaved private human notes?"))return;
 require_(intent===sourceIntent);
 sourceEpoch++;humanNotesEpoch++;peerImportIntent++;reviewImportIntent++;
 source=parsed;sourceHash=hash;notes=parsed.findings.map(initialNote);dirty=false;lastBulkUndo=null;selectedForHandoff.clear();resetPeer();
 filter="";searchTerm="";sortMode="source";$("filter").value="";
 $("search").value="";$("sort").value="source";humanQueueFilter="";humanQueuePage=0;$("human-queue-filter").value="";buildEndpointFilter();
 $("private").disabled=!hash;$("resume").disabled=!hash;$("brief").disabled=!hash;
 $("workspace").hidden=false;updateSummary();render();
 status(hash?"Original private lab source admitted in memory. HUMAN REVIEW ONLY. Source hash is unsigned.":"Original private lab source admitted for local read-only review. Browser has no WebCrypto: private source-bound save/resume is disabled.");
}
function admitPrivatePayload(v){
 require_(source&&sourceHash);
 require_(exact(v,["schema","source_sha256","source_finding_count","notes","status",
  "source_authenticated","ground_truth_verified","client_consent_verified","operator_consent_verified",...FLAGS]));
 require_(v.schema==="lightup.private_lab_human_review.v1"&&v.status==="REVIEW_ONLY"&&
  v.source_sha256===sourceHash&&v.source_finding_count===source.findings.length&&
  ["source_authenticated","ground_truth_verified","client_consent_verified",
   "operator_consent_verified",...FLAGS].every(k=>v[k]===false));
 require_(Array.isArray(v.notes)&&v.notes.length===notes.length);
 return v.notes.map((row,i)=>{
  require_(exact(row,["ordinal","stage","group","next_action","blocker"])&&row.ordinal===i+1);
  const n={stage:row.stage,group:row.group,next_action:row.next_action,blocker:row.blocker};
  require_(admitNote(n));return n;
 });
}
function applyPrivatePayload(v){
 const next=admitPrivatePayload(v);
 if(dirty&&!confirm("Replace existing unsaved human notes with this matching private return?"))return false;
 notes=next;humanNotesEpoch++;dirty=false;lastBulkUndo=null;updateSummary();render();
 status("Exact source-bound human notes restored. No security evidence was authenticated.");
 return true;
}
async function resume(file){
 const intent=++reviewImportIntent,original=source,epoch=sourceEpoch,noteEpoch=humanNotesEpoch;
 require_(source&&file&&file.size>0&&file.size<=MAX_PRIVATE_CLEAR);
 const raw=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
 const candidate=parseStrict(raw);
 require_(intent===reviewImportIntent&&source===original&&sourceEpoch===epoch&&
  humanNotesEpoch===noteEpoch);
 return applyPrivatePayload(candidate);
}

function visibleOrdinals(){
 if(!source)return [];
 return source.findings.map((f,i)=>({f,i})).filter(({f,i})=>
  (!filter||filter===f.severity||filter===notes[i].stage||
   filter==="endpoint:"+endpointOrdinal(f))&&
  (!searchTerm||[f.finding,f.check_id,notes[i].next_action,notes[i].blocker]
   .some(value=>value.toLowerCase().includes(searchTerm)))).map(({i})=>i);
}
$("applyBulk").addEventListener("click",()=>{
 if(!source)return;
 const ids=visibleOrdinals(),stage=$("bulkStage").value,group=$("bulkGroup").value;
 if(!ids.length){status("No visible source findings to update.",true);return;}
 if(!stage&&!group){status("Choose a human stage or proposed group first.",true);return;}
 if(!confirm("Change ONLY human planning notes for "+ids.length+
  " currently visible original findings? This is NOT an assessment or grant."))return;
 const old=notes.map(n=>({...n}));
 const selected=new Set(ids);
 const next=notes.map((n,i)=>selected.has(i)?{
  ...n,...(stage?{stage}:{}),...(group?{group}:{})
 }:n);
 require_(next.every(admitNote));
 notes=next;humanNotesEpoch++;lastBulkUndo=old;dirty=true;updateSummary();render();
 status(ids.length+" human planning rows changed. Source evidence is unchanged; Undo is available.");
});
$("undoBulk").addEventListener("click",()=>{
 if(!source||!lastBulkUndo){status("No last bulk change available.");return;}
 notes=lastBulkUndo;humanNotesEpoch++;lastBulkUndo=null;dirty=true;updateSummary();render();
 status("Last human-only bulk change undone.");
});


function htmlEscape(x){
 return String(x).replace(/[&<>"']/g,ch=>({
  "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
}
async function privateHumanBrief(){
 if(!source||!sourceHash)return;
 if(!confirm("Export a PRIVATE human report containing original finding titles and proposed human notes? No target URLs, original evidence or client identities are included, but titles and notes may be sensitive."))return;
 const css="body{font-family:system-ui,sans-serif;max-width:1050px;margin:2rem auto;padding:1rem;color:#243044;background:#fff;line-height:1.5}h1{margin:0}p{max-width:85ch}table{width:100%;border-collapse:collapse;margin-top:1.4rem}th,td{padding:.7rem;text-align:left;border:1px solid #b8c2cd;vertical-align:top;overflow-wrap:anywhere}th{background:#edf3f9}aside{padding:1rem;border:2px solid #99772f;background:#fff9df}small{color:#384960}footer{margin-top:2rem;font-size:.83rem}@media print{body{margin:0;max-width:none}tr{break-inside:avoid}}";
 const digest=new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(css)));
 const hash=btoa(String.fromCharCode(...digest));
 const rows=source.findings.map((f,i)=>{
  const n=notes[i];
  return "<tr><td>"+(i+1)+"</td><td>"+htmlEscape(f.severity)+"</td><td>"+
   htmlEscape(sourcePosition(f))+"</td><td>"+htmlEscape(f.finding)+"</td><td>"+
   htmlEscape(n.stage)+"</td><td>"+htmlEscape(n.group)+"</td><td>"+
   htmlEscape(n.next_action)+"</td><td>"+htmlEscape(n.blocker)+"</td></tr>";
 }).join("");
 const policy="default-src 'none'; style-src 'sha256-"+hash+
  "'; script-src 'none'; connect-src 'none'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'";
 const out=['<!doctype html><html lang="en"><head><meta charset="utf-8">',
  '<meta name="viewport" content="width=device-width,initial-scale=1">',
  '<meta http-equiv="Content-Security-Policy" content="'+policy+'">',
  '<meta name="referrer" content="no-referrer"><title>PRIVATE LightUp Human Follow-up</title>',
  '<style>'+css+'</style></head><body>',
  '<aside><strong>PRIVATE · HUMAN PLANNING ONLY · NOT VERIFIED · DRAFT/HOLD</strong>',
  '<p>Original already-produced isolated-lab source and all findings are untrusted declarations. No target, client consent, authorization, retest, grant or release has been validated by this document.</p></aside>',
  '<h1>Original lab finding human follow-up</h1>',
  '<p>Source-declared endpoints: '+source.targets.length+
  ' · Original finding rows: '+source.findings.length+
  '. Labels and endpoint matches are local display aids, not asset authorization. Blank human fields are not evidence of completion.</p>',
  '<table><thead><tr><th>Original ordinal</th><th>Source severity</th><th>Endpoint ordinal</th><th>Private source title</th><th>Human stage</th><th>Proposed group</th><th>Next action</th><th>Human blocker</th></tr></thead><tbody>',
  rows,'</tbody></table><footer>Keep PRIVATE. A missing finding in a later source does not prove remediation. Original evidence and target URLs are not carried in this document. No scripts, external assets, network or live target interaction.</footer></body></html>'].join("");
 download("PRIVATE-lab-human-brief.html",out,"text/html");
 status("Scriptless PRIVATE human brief saved locally. Review its sensitive titles/notes before separate confidential sharing.");
}
$("brief").addEventListener("click",()=>{privateHumanBrief().catch(()=>status("HOLD: private brief not published.",true));});

$("source").addEventListener("change",async e=>{try{await importSource(e.target.files[0]);}catch(_){status("HOLD: source rejected. Previous workspace unchanged.",true);}e.target.value="";});
$("resume").addEventListener("change",async e=>{try{await resume(e.target.files[0]);}catch(_){status("HOLD: private human return rejected. Previous workspace unchanged.",true);}e.target.value="";});
$("filter").addEventListener("change",e=>{filter=e.target.value;render();});
let searchTimer=null;
$("search").addEventListener("input",e=>{
 searchTerm=e.target.value.trim().toLowerCase();clearTimeout(searchTimer);
 searchTimer=setTimeout(()=>{if(source)render();},140);
});
$("sort").addEventListener("change",e=>{sortMode=e.target.value;render();});
$("private").addEventListener("click",()=>{if(!source||!sourceHash)return;download("PRIVATE-lab-human-review.json",
 JSON.stringify(privatePayload(),null,2)+"\n","application/json");dirty=false;
 status("PRIVATE review saved locally. Share only via a separately approved confidential channel.");});
$("aggregate").addEventListener("click",()=>{if(!source)return;
 download("lab-anonymous-human-counts.json",JSON.stringify(aggregate(),null,2)+"\n","application/json");
 status("Counts-only human report exported; even small aggregate counts may be sensitive.");});
$("coverage-export").addEventListener("click",()=>{
 if(!source)return;
 if(!confirm("Export only local endpoint ordinals and HUMAN planning counts? No URLs, finding titles, source hashes or notes are included. Small counts may still be sensitive; the export proves no source authenticity, completion or authorization."))return;
 const flags=["source_authenticated","ground_truth_verified","client_consent_verified","operator_consent_verified","authorized","consent_verified","dispatch_allowed","release_allowed"];
 const columns=["status","endpoint_ordinal","source_reported_finding_count","human_needs_review_count","human_stage_moved_forward_count","human_blocked_stage_count","human_blocker_note_count","human_next_action_missing_count",...flags];
 const quote=value=>'"'+String(value).replaceAll('"','""')+'"';
 const rows=endpointCoverageRows().map(row=>["REVIEW_ONLY",row.ordinal,row.findings,row.needs_review,row.stage_forward,row.blocked_stage,row.blocker_notes,row.next_action_missing,...flags.map(()=>false)]);
 const csv=[columns,...rows].map(row=>row.map(quote).join(",")).join("\r\n")+"\r\n";
 download("PRIVATE-lab-endpoint-human-coverage.csv",csv,"text/csv;charset=utf-8");
 status("Counts-only endpoint coverage CSV exported. Ordinals and human stages remain unverified; no authorization or completion is implied.");
});
$("human-queue-filter").addEventListener("change",e=>{humanQueueFilter=e.target.value;humanQueuePage=0;renderHumanQueue();});
$("human-queue-prev").addEventListener("click",()=>{humanQueuePage=Math.max(0,humanQueuePage-1);renderHumanQueue();});
$("human-queue-next").addEventListener("click",()=>{humanQueuePage++;renderHumanQueue();});
$("human-queue-brief").addEventListener("click",()=>{
 if(!source||!sourceHash||!confirm("Export a PRIVATE HUMAN agenda containing original ordinals and all operator-authored action/blocker notes? Keep it confidential and obtain separate recipient approval."))return;
 download("PRIVATE-lab-human-action-agenda.md",humanQueueMarkdown(),"text/markdown");
 status("PRIVATE HUMAN planning agenda downloaded. No original source authentication or permission implied.");
});
$("human-queue-csv").addEventListener("click",()=>{
 if(!source||!confirm("Export anonymous category/severity HUMAN counts only? Even small aggregate counts may be sensitive. No source identity, notes or permission."))return;
 download("lab-anonymous-human-attention.csv",humanQueueCsv(),"text/csv;charset=utf-8");
 status("Anonymous HUMAN queue counts exported; original source never verified.");
});
$("forget").addEventListener("click",()=>{if(!source||!confirm("Forget all private source data and unsaved human notes?"))return;
 sourceIntent++;sourceEpoch++;humanNotesEpoch++;reviewImportIntent++;peerImportIntent++;
 source=null;sourceHash="";notes=[];dirty=false;filter="";searchTerm="";sortMode="source";humanQueueFilter="";humanQueuePage=0;lastBulkUndo=null;selectedForHandoff.clear();resetPeer();$("human-queue-filter").value="";$("filter").value="";$("search").value="";$("sort").value="source";$("findings").replaceChildren();renderHumanQueue();
 $("workspace").hidden=true;status("All in-memory private workspace data discarded.");});
$("collab-select-visible").addEventListener("click",()=>{
 if(!source)return;
 const ids=visibleOrdinals().map(i=>i+1);
 if(new Set([...selectedForHandoff,...ids]).size>512){status("Filtered selection exceeds 512. Narrow severity, stage or endpoint first.",true);return;}
 ids.forEach(n=>selectedForHandoff.add(n));render();
});
$("collab-clear-selection").addEventListener("click",()=>{
 selectedForHandoff.clear();render();
});
window.addEventListener("beforeunload",e=>{if(dirty){e.preventDefault();e.returnValue="";}});


// Optional second already-created lab source; purely informational offline reconciliation.
let peerComparison=null,peerFilter="",peerPage=0;
const PEER_KINDS=[
 ["ambiguous","Duplicate source check identity — HUMAN HOLD"],
 ["a_only","Reported only in original A — NOT a verified fix in B"],
 ["b_only","Reported only in imported B — NOT independently verified new"],
 ["description","Source severity/title/fix/status changed — needs human review"],
 ["evidence_text","Source evidence summary differs — not verified"],
 ["same_description","Same source declaration — NOT a verified matching finding"]
];
const peerKindLabel=Object.fromEntries(PEER_KINDS);
function resetPeer(){
 peerComparison=null;peerPage=0;peerFilter="";
 $("peer-kind").value="";$("peer-results").replaceChildren();
 $("peer-overview").textContent="No second source admitted.";
 $("peer-counter").textContent="";$("peer-prev").disabled=true;
 $("peer-next").disabled=true;$("peer-export").disabled=true;
}
function sourceKey(f){return JSON.stringify([f.target,f.capability_id,f.check_id]);}
function sourceGroups(rows){
 const groups=new Map();
 rows.forEach((f,i)=>{const k=sourceKey(f);if(!groups.has(k))groups.set(k,[]);
  groups.get(k).push({f,slot:i+1});});
 return groups;
}
function describeEqual(a,b){return ["finding","severity","impact","fix","retest"].every(k=>a[k]===b[k]);}
function classifyPeer(second){
 require_(source&&source.scenario_id===second.scenario_id&&source.run_id!==second.run_id);
 // Comparing different endpoint sets can imply false resolution; HOLD the whole comparison.
 require_(source.targets.length===second.targets.length&&
  source.targets.every(t=>second.targets.includes(t)));
 const A=sourceGroups(source.findings),B=sourceGroups(second.findings);
 const keys=new Set([...A.keys(),...B.keys()]);
 const rows=[],counts=Object.fromEntries(PEER_KINDS.map(([k])=>[k,0]));
 for(const k of keys){
  const a=A.get(k)||[],b=B.get(k)||[];
  let kind;
  if(a.length>1||b.length>1)kind="ambiguous";
  else if(!b.length)kind="a_only";
  else if(!a.length)kind="b_only";
  else if(!describeEqual(a[0].f,b[0].f))kind="description";
  else if(a[0].f.evidence_summary!==b[0].f.evidence_summary)kind="evidence_text";
  else kind="same_description";
  counts[kind]++;
  const head=a[0]||b[0];
  const privateSummary=x=>x.length===1?{
   title:x[0].f.finding,severity:x[0].f.severity,retest:x[0].f.retest,
   impact:x[0].f.impact,fix:x[0].f.fix,evidence_summary:x[0].f.evidence_summary
  }:null;
  rows.push({kind,a:a.map(x=>x.slot),b:b.map(x=>x.slot),
   aSummary:privateSummary(a),bSummary:privateSummary(b),
   repeatedA:a.length>1,repeatedB:b.length>1});
 }
 const ranks=Object.fromEntries(PEER_KINDS.map(([k],i)=>[k,i]));
 rows.sort((x,y)=>ranks[x.kind]-ranks[y.kind]||x.a[0]-y.a[0]);
 return {counts,rows,totalA:source.findings.length,totalB:second.findings.length,
  endpoints:source.targets.length};
}
function renderPeer(){
 const result=$("peer-results");result.replaceChildren();
 if(!peerComparison)return;
 const matches=peerComparison.rows.filter(row=>!peerFilter||row.kind===peerFilter);
 const pageSize=100,max=Math.max(0,Math.ceil(matches.length/pageSize)-1);
 peerPage=Math.min(peerPage,max);
 for(const row of matches.slice(peerPage*pageSize,(peerPage+1)*pageSize)){
  const tr=document.createElement("tr");
  [peerKindLabel[row.kind],row.a.join(", ")||"—",row.b.join(", ")||"—"]
   .forEach(value=>tr.append(el("td",value)));
  for(const [info,repeated] of [[row.aSummary,row.repeatedA],[row.bSummary,row.repeatedB]]){
   const td=document.createElement("td");
   if(repeated){td.textContent="AMBIGUOUS repeated source check — not pairable";}
   else if(!info){td.textContent="No source declaration in this input (NOT a fix verdict)";}
   else{
    td.append(el("strong",info.severity+" · "+info.title),
      el("p","Original declared retest: "+info.retest));
    const more=document.createElement("details");
    more.append(el("summary","PRIVATE original impact / mitigation / evidence text"));
    more.append(el("p","Impact: "+info.impact),
      el("p","Fix text: "+info.fix),
      el("p","Unverified evidence summary: "+info.evidence_summary));
    td.append(more);
   }
   tr.append(td);
  }
  if(row.a.length===1){
   const button=el("button","Open original A HUMAN follow-up","peer-jump");
   button.type="button";
   button.addEventListener("click",()=>{
    filter="";searchTerm="";sortMode="source";$("filter").value="";$("search").value="";$("sort").value="source";render();
    const original=$("findings").querySelector('tr[data-original-ordinal="'+row.a[0]+'"]');
    if(!original)return;
    original.classList.add("peer-focus");
    original.scrollIntoView({behavior:"smooth",block:"center"});original.focus({preventScroll:true});
    status("Opened original A HUMAN note row "+row.a[0]+". Source B never changes original evidence.");
   });
   const action=document.createElement("td");action.append(button);tr.append(action);
  }else{tr.append(el("td","HUMAN review: no unique A row"));}
  result.append(tr);
 }
 $("peer-counter").textContent=matches.length+" original source-check groups; "+
  "viewing "+(matches.length?peerPage*pageSize+1:0)+"–"+
  Math.min(matches.length,(peerPage+1)*pageSize)+". Neither original finding IDs nor target URLs are exported.";
 $("peer-prev").disabled=peerPage===0;
 $("peer-next").disabled=peerPage>=max;
}
$("peer-input").addEventListener("change",async e=>{
 const intent=++peerImportIntent,original=source,epoch=sourceEpoch;
 try{
  require_(source&&e.target.files[0]&&e.target.files[0].size>0&&
   e.target.files[0].size<=MAX_BYTES);
  const raw=new TextDecoder("utf-8",{fatal:true}).decode(await e.target.files[0].arrayBuffer());
  const second=admit(parseStrict(raw));
  require_(intent===peerImportIntent&&original===source&&epoch===sourceEpoch);
  const draft=classifyPeer(second);
  peerComparison=draft;peerPage=0;peerFilter="";
  $("peer-kind").value="";$("peer-export").disabled=false;
  $("peer-overview").textContent="PRIVATE SOURCE DECLARATION COMPARISON ONLY · "+
   draft.endpoints+" identical declared endpoint literals · A "+
   draft.totalA+" original findings · B "+draft.totalB+
   " original findings. "+PEER_KINDS.map(([k])=>k+" "+draft.counts[k]).join(" · ");
  renderPeer();
  status("Separate original lab report B admitted locally. No original finding, consent or remediation was verified.");
 }catch(_){status("HOLD: second lab source incompatible or original source changed during import. Previous comparison unchanged.",true);}
 finally{e.target.value="";}
});
$("peer-kind").addEventListener("change",e=>{peerFilter=e.target.value;peerPage=0;renderPeer();});
$("peer-prev").addEventListener("click",()=>{peerPage=Math.max(0,peerPage-1);renderPeer();});
$("peer-next").addEventListener("click",()=>{peerPage++;renderPeer();});
$("peer-export").addEventListener("click",()=>{
 if(!peerComparison)return;
 const v={schema:"lightup.lab_peer_declaration_counts.v1",status:"REVIEW_ONLY",
  original_a_reported_count:peerComparison.totalA,
  original_b_reported_count:peerComparison.totalB,
  declared_endpoint_count:peerComparison.endpoints,
  source_check_group_counts:peerComparison.counts,
  source_authenticated:false,ground_truth_verified:false,
  client_consent_verified:false,operator_consent_verified:false,...noAuthority()};
 download("lab-peer-anonymous-human-counts.json",JSON.stringify(v,null,2)+"\n","application/json");
 status("Counts-only peer comparison exported. Missing original source reports are NOT verified fixes.");
});

// Strict collaboration bridge: no direct original source, targets or evidence leave here.
window.LightUpReviewBridge=Object.freeze({
 snapshot(){
  if(!source||!sourceHash)return null;
  return {source_sha256:sourceHash,visible:visibleOrdinals().map(i=>i+1),
   selected:[...selectedForHandoff].sort((a,b)=>a-b),rows:source.findings.map((f,i)=>({
    ordinal:i+1, severity:f.severity,title:f.finding,
    endpoint_ordinal:endpointOrdinal(f),human:{...notes[i]}
  }))};
 },
 strictJSON:parseStrict,
 noteValid:admitNote,
 applyRows(digest,rows){
  require_(!!source&&!!sourceHash&&digest===sourceHash&&Array.isArray(rows)
   &&rows.length>0&&rows.length<=512);
  const seen=new Set(),updates=[];
  for(const row of rows){
   require_(exact(row,["ordinal","original","proposed"])&&
    Number.isSafeInteger(row.ordinal)&&row.ordinal>=1&&row.ordinal<=notes.length&&
    !seen.has(row.ordinal)&&admitNote(row.original)&&admitNote(row.proposed));
   seen.add(row.ordinal);
   require_(JSON.stringify(notes[row.ordinal-1])===JSON.stringify(row.original));
   updates.push(row);
  }
  if(!confirm("Accept "+updates.length+" source-bound HUMAN follow-up row changes? Original lab findings, source evidence, targets and permissions remain unchanged."))return false;
  const changed=notes.map(n=>({...n}));
  for(const row of updates)changed[row.ordinal-1]={...row.proposed};
  notes=changed;humanNotesEpoch++;dirty=true;lastBulkUndo=null;updateSummary();render();
  status("PRIVATE reviewer return applied to human fields only. No assessment was verified.");
  return true;
 }
});

status("No private lab source loaded.");
})();