"use strict";
/* Source-bound, NON-AUTHORIZING original-finding HUMAN coverage observer. */
(() => {
const $=id=>document.getElementById(id);
const FLAGS=["authenticated","tenant_verified","source_authorized","assessment_authorized","grant","client_consent","operator_consent","execution","scan","audit_verdict","retest_verified","release"];
const CONTRACT="lightup.finding_export._COLUMNS_v1";
const BASE=["kind","schema_version","disposition","source_contract","source_sha256","client_reference","engagement_reference","source_count","warning",...FLAGS];
const PLAN_STAGES=["unplanned","request_evidence_human","clarify_human_reply","coordinate_human_change","await_human_review","human_handoff_prepared"];
const STAGES=["draft_human","needs_human_input","await_human_review","human_handoff_prepared"];
const REQUEST_KINDS=["missing_evidence","patch_change","deployment_record","rollback_plan","retest_request","followup_question","other"];
const RESPONSE_STAGES=["not_reviewed","needs_human_followup","human_triaged"];
const HEAD=["kind","schema_version","disposition","source_contract","source_sha256","client_reference","engagement_reference","recipient_alias","reply_kind","issued_utc","reply_utc","requests",...FLAGS];
const REQUEST_FIELDS=["request_id","finding_id","request_kind","instructions","due_date","human_stage","human_response"];
const rowKeys=["finding_id","stage","owner_alias","tentative_due","next_action","private_note","updated_utc"];
const artifactKeys=["finding_id","file_name","byte_length","sha256","mime","added_utc","human_reviewer","human_stage","human_note"];
const stepKeys=["step_id","kind","description","precondition","responsible_alias","rollback_discussion","verification_question","tentative_date","human_stage"];
const stepKinds=["human_prepare","human_implementation_discussion","human_dependency_coordination","human_rollback_discussion","human_review_request"];
const OWNER_STAGES=["acknowledged_unverified","needs_clarification","cannot_provide"];
const entries={workplan:null,csv:null,artifact:null,runbook:null,response:null};
let rendered=[],revision=0,custodyCoverage=null,humanWindows=null;
const fail=reason=>{throw Error(reason);};
const exact=(o,fields)=>o!==null&&typeof o==="object"&&!Array.isArray(o)&&Object.keys(o).length===fields.length&&fields.every(k=>Object.hasOwn(o,k));
const canonical=(s,max=120,required=false)=>typeof s==="string"&&s.length<=max&&(!required||s.trim().length>0)&&!/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069\ud800-\udfff]/.test(s);
const hex=(s,n)=>typeof s==="string"&&new RegExp("^[0-9a-f]{"+n+"}$").test(s);
function utc(s){
 if(typeof s!=="string"||!/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/.test(s))return false;
 const date=new Date(s);return !Number.isNaN(date.valueOf())&&date.toISOString()===s;
}
function day(s){return s===""||typeof s==="string"&&/^\d{4}-\d\d-\d\d$/.test(s)&&Number.isFinite(Date.parse(s+"T00:00:00Z"))&&new Date(s+"T00:00:00Z").toISOString().slice(0,10)===s;}
function bound(o,kind,count=true){
 if(!o||o.source_contract!==CONTRACT||!hex(o.source_sha256,64)||!canonical(o.client_reference,200,true)||!canonical(o.engagement_reference,200,true)||FLAGS.some(k=>o[k]!==false))fail(kind+" source/authority envelope is unsupported");
 if(count&&(!Number.isSafeInteger(o.source_count)||o.source_count<1||o.source_count>350))fail(kind+" source finding count invalid");
}
function matches(o,base){
 if(o.source_contract!==base.source_contract||o.source_sha256!==base.source_sha256||
    o.client_reference!==base.client_reference||o.engagement_reference!==base.engagement_reference||
    ("source_count" in o && o.source_count!==base.source_count))fail("Exact original source SHA, client, engagement or complete finding count mismatch: HOLD without local changes");
}
function parseStrict(source){
 let p=0,n=0;const l=source.length;
 const skip=()=>{while(p<l&&/[ \n\r\t]/.test(source[p]))p++;};
 function str(){if(source[p]!=='"')fail("Expected JSON text key");const from=p++;let escaping=false;
  while(p<l){const c=source[p++];if(escaping){escaping=false;continue;}if(c==="\\"){escaping=true;continue;}if(c==='"')return JSON.parse(source.slice(from,p));if(c<" ")fail("Invalid JSON control");}fail("JSON string truncated");
 }
 function walk(depth){
  if(++n>50000||depth>24)fail("JSON complexity limit");
  skip();const c=source[p];
  if(c==="{"){p++;skip();const seen=new Set();if(source[p]==="}"){p++;return;}
   for(;;){skip();const key=str();if(seen.has(key))fail("Duplicate JSON key");seen.add(key);skip();if(source[p++]!==":")fail("JSON colon");walk(depth+1);skip();const sep=source[p++];if(sep==="}")return;if(sep!==",")fail("JSON comma");}
  }
  if(c==="["){p++;skip();if(source[p]==="]"){p++;return;}
   for(;;){walk(depth+1);skip();const sep=source[p++];if(sep==="]")return;if(sep!==",")fail("JSON array");}
  }
  if(c==='"'){str();return;}
  const v=/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(source.slice(p));
  if(!v)fail("Invalid JSON primitive");p+=v[0].length;
 }
 walk(0);skip();if(p!==l)fail("Extra JSON content");return JSON.parse(source);
}
function uniqueIds(xs,ids,label){
 const seen=new Set();for(const x of xs){
  if(!ids.has(x.finding_id)||seen.has(x.finding_id))fail("Unknown/repeated ORIGINAL finding in "+label);
  seen.add(x.finding_id);
 }
 if(seen.size!==ids.size)fail("Partial ORIGINAL finding membership in "+label);
}
function validatePlan(p){
 if(!exact(p,BASE.concat(["rows"]))||p.kind!=="lightup.private_human_original_finding_workplan"||p.schema_version!==1||p.disposition!=="UNVERIFIED_HUMAN_PLANNING_ONLY")fail("Not the original exported HUMAN workplan schema");
 bound(p,"Workplan");if(!canonical(p.warning,500,true)||!Array.isArray(p.rows)||p.rows.length!==p.source_count)fail("Original finding membership incomplete");
 const ids=new Set();
 for(const r of p.rows){
  if(!exact(r,rowKeys)||!canonical(r.finding_id,200,true)||ids.has(r.finding_id)||!PLAN_STAGES.includes(r.stage)||
     !canonical(r.owner_alias,120)||!day(r.tentative_due)||!canonical(r.next_action,1000)||
     !canonical(r.private_note,600)||!utc(r.updated_utc))fail("Invalid/repeated original HUMAN finding workplan");
  ids.add(r.finding_id);
 }
 return {source:p,ids,rows:new Map(p.rows.map(r=>[r.finding_id,r]))};
}
function validateArtifact(p,base){
 if(!exact(p,BASE.concat(["attachments"]))||p.kind!=="lightup.private_artifact_ledger"||p.schema_version!==1||p.disposition!=="PRIVATE_HUMAN_EVIDENCE_INDEX_ONLY")fail("Unexpected PRIVATE artifact ledger schema");
 bound(p,"Artifact");matches(p,base.source);
 if(!canonical(p.warning,500,true)||!Array.isArray(p.attachments)||p.attachments.length>120)fail("Artifact evidence index invalid");
 const seen=new Set(),byId=new Map();
 for(const a of p.attachments){
  if(!exact(a,artifactKeys)||!base.ids.has(a.finding_id)||!canonical(a.file_name,240,true)||
    a.file_name.includes("/")||a.file_name.includes("\\")||!Number.isSafeInteger(a.byte_length)||
    a.byte_length<0||a.byte_length>16777216||!hex(a.sha256,64)||
    !canonical(a.mime,120)||!utc(a.added_utc)||!canonical(a.human_reviewer,120)||
    !["unreviewed","human_review","follow_up","archived"].includes(a.human_stage)||!canonical(a.human_note,1200))
    fail("Invalid/foreign PRIVATE artifact metadata");
  const key=JSON.stringify([a.finding_id,a.sha256]);if(seen.has(key))fail("Duplicate artifact fingerprint within original finding");seen.add(key);
  if(!byId.has(a.finding_id))byId.set(a.finding_id,[]);
  byId.get(a.finding_id).push(a);
 }
 return {byId,original:p};
}
function validateRunbook(p,base){
 if(!exact(p,BASE.concat(["finding_ids","runbooks"]))||p.kind!=="lightup.private_human_remediation_runbooks"||
    p.schema_version!==1||p.disposition!=="UNVERIFIED_HUMAN_PLANNING_ONLY")fail("Unexpected HUMAN runbook export");
 bound(p,"Runbook");matches(p,base.source);
 if(!canonical(p.warning,500,true)||!Array.isArray(p.finding_ids)||p.finding_ids.length!==base.ids.size||
    new Set(p.finding_ids).size!==base.ids.size||p.finding_ids.some(x=>!base.ids.has(x))||
    !Array.isArray(p.runbooks)||p.runbooks.length!==base.ids.size)fail("Runbook original finding set changed");
 uniqueIds(p.runbooks,base.ids,"runbooks");const byId=new Map();let total=0;
 for(const b of p.runbooks){
  if(!exact(b,["finding_id","steps"])||!Array.isArray(b.steps)||b.steps.length>8)fail("Invalid ORIGINAL HUMAN book");
  const nums=new Set();for(const s of b.steps){
   if(!exact(s,stepKeys)||!Number.isSafeInteger(s.step_id)||s.step_id<1||s.step_id>8||nums.has(s.step_id)||
      !stepKinds.includes(s.kind)||!STAGES.includes(s.human_stage)||
      !canonical(s.description,1000,true)||!canonical(s.precondition,600)||
      !canonical(s.responsible_alias,120)||!canonical(s.rollback_discussion,750)||
      !canonical(s.verification_question,600)||!day(s.tentative_date))fail("Invalid/repeated HUMAN runbook step");
   nums.add(s.step_id);
  }total+=b.steps.length;byId.set(b.finding_id,b.steps);
 }
 if(total>1600)fail("HUMAN runbook size exceeded");return {byId,original:p};
}
function validateOwnerPacket(p,base,kind){
 if(!exact(p,HEAD)||p.kind!=="lightup.private_human_evidence_owner_handoff"||
    p.schema_version!==1||p.disposition!=="UNVERIFIED_HUMAN_REQUEST_ONLY"||
    !["owner_request","unverified_human_reply"].includes(p.reply_kind)||p.reply_kind!==kind)
    fail("Unexpected original HUMAN request/reply envelope");
 bound(p,"Owner reply",false);matches(p,base.source);
 if(!canonical(p.recipient_alias,120,true)||!utc(p.issued_utc)||!Array.isArray(p.requests)||
    p.requests.length<1||p.requests.length>60||kind==="owner_request"&&p.reply_utc!==null||
    kind==="unverified_human_reply"&&!utc(p.reply_utc))fail("Invalid original owner context");
 const seen=new Set();
 for(const r of p.requests){
  if(!exact(r,REQUEST_FIELDS)||!hex(r.request_id,32)||seen.has(r.request_id)||!base.ids.has(r.finding_id)||
     !REQUEST_KINDS.includes(r.request_kind)||!canonical(r.instructions,1400,true)||!day(r.due_date)||
     (kind==="owner_request"&&(r.human_stage!=="requested_human"||r.human_response!==""))||
     (kind==="unverified_human_reply"&&(!["submitted_unverified","needs_changes"].includes(r.human_stage)||
        !canonical(r.human_response,1800,true))))fail("Invalid original owner request membership");
  seen.add(r.request_id);
 }
 return p;
}
function originalSignature(p,r){return JSON.stringify([p.recipient_alias,p.issued_utc,r.request_id,r.finding_id,r.request_kind,r.instructions,r.due_date]);}
function validateResponse(p,base){
 const fields=["kind","schema_version","disposition","source_contract","source_sha256","client_reference","engagement_reference",...FLAGS,"request_packets","reply_packets","human_reviews","owner_feedback","feedback_history"];
 if(!exact(p,fields)||p.kind!=="lightup.private_human_response_reconciliation"||p.schema_version!==2||
    p.disposition!=="UNVERIFIED_HUMAN_COORDINATION_ONLY")fail("Unexpected PRIVATE response register backup");
 bound(p,"Response",false);matches(p,base.source);
 if(!Array.isArray(p.request_packets)||!Array.isArray(p.reply_packets)||!Array.isArray(p.human_reviews)||
    !Array.isArray(p.owner_feedback)||!Array.isArray(p.feedback_history)||
    p.request_packets.length+p.reply_packets.length>24||p.feedback_history.length>1600)fail("Malformed PRIVATE response register");
 const requests=new Map(),replies=new Map(),byId=new Map();
 for(const raw of p.request_packets){
  const pack=validateOwnerPacket(raw,base,"owner_request");
  for(const r of pack.requests){
   if(requests.has(r.request_id))fail("Reused original HUMAN request ID");
   requests.set(r.request_id,{packet:pack,row:r});
   if(!byId.has(r.finding_id))byId.set(r.finding_id,[]);
   byId.get(r.finding_id).push({recipient_alias:pack.recipient_alias,original:r,reply:null,review:null,feedback:null});
  }
 }
 if(requests.size>800||p.human_reviews.length!==requests.size)fail("Original owner requests incomplete");
 for(const raw of p.reply_packets){
  const pack=validateOwnerPacket(raw,base,"unverified_human_reply");
  for(const row of pack.requests){
   const original=requests.get(row.request_id);
   if(!original||replies.has(row.request_id)||originalSignature(original.packet,original.row)!==originalSignature(pack,row))
     fail("HOLD: owner reply is not the exact original HUMAN request or is duplicated");
   replies.set(row.request_id,row);
  }
 }
 const reviews=new Map();
 for(const r of p.human_reviews){
  if(!exact(r,["request_id","human_stage","note"])||!requests.has(r.request_id)||reviews.has(r.request_id)||
    !RESPONSE_STAGES.includes(r.human_stage)||!canonical(r.note,400))fail("Unknown/duplicate original HUMAN review");
  reviews.set(r.request_id,r);
 }
 const feedback=new Map();
 for(const r of p.owner_feedback){
  if(!exact(r,["request_id","stage","note","submitted_utc"])||!requests.has(r.request_id)||
    feedback.has(r.request_id)||!OWNER_STAGES.includes(r.stage)||!canonical(r.note,1000)||
    !utc(r.submitted_utc)||(r.stage!=="acknowledged_unverified"&&!r.note.trim()))fail("Unknown or malformed HUMAN owner feedback");
  feedback.set(r.request_id,r);
 }
 for(const h of p.feedback_history){
  if(!exact(h,["request_id","stage","note","submitted_utc","superseded_utc"])||
    !requests.has(h.request_id)||!OWNER_STAGES.includes(h.stage)||
    !canonical(h.note,1000)||!utc(h.submitted_utc)||!utc(h.superseded_utc))
    fail("Invalid HUMAN reply history record");
 }
 for(const [fid,items] of byId.entries())
  for(const item of items){
   item.reply=replies.get(item.original.request_id)||null;
   item.review=reviews.get(item.original.request_id)||null;
   item.feedback=feedback.get(item.original.request_id)||null;
  }
 return {byId,requestCount:requests.size,original:p};
}
function loaded(){return Boolean(entries.workplan);}
function sourceLabel(){const p=entries.workplan?.source;if(!p)return "No ORIGINAL HUMAN workplan loaded.";
 return "Self-declared original SHA: "+p.source_sha256+" · client: "+p.client_reference+
    " · engagement: "+p.engagement_reference+" · original findings: "+p.source_count+" · NOT AUTHENTICATED.";}
function stateLabel(kind,text){$(kind+"-state").textContent=text;}
function announce(t,bad=false){$("notice").textContent=t;$("notice").dataset.error=String(bad);}
async function importFile(kind,e){
 const f=e.target.files[0];e.target.value="";if(!f)return;
 if(kind!=="workplan"&&!loaded()){announce("HOLD: import original HUMAN workplan first.",true);return;}
 const max=kind==="response"||kind==="runbook"?8*1048576:1048576;
 if(f.size<1||f.size>max){announce("HOLD: "+kind+" input exceeds source owner's allowed file limit.",true);return;}
 const current=revision;
 try{
  const text=new TextDecoder("utf-8",{fatal:true}).decode(await f.arrayBuffer());
  const raw=kind==="csv"?null:parseStrict(text);
  let next;
  if(kind==="csv"){
    if(!window.LightUpCasework)fail("Original source-owned Casework CSV parser unavailable");
    const findings=window.LightUpCasework.parseCSV(text);
    const sourceDigest=await window.LightUpCasework.digest(findings);
    const base=entries.workplan;
    if(!sourceDigest||sourceDigest!==base.source.source_sha256||findings.length!==base.ids.size||
       findings.some(f=>!base.ids.has(f.finding_id)))fail("Original CSV source SHA or membership disagrees with imported HUMAN workplan");
    next={byId:new Map(findings.map(f=>[f.finding_id,f])),text};
  }else if(kind==="workplan"){next=validatePlan(raw);
    if(loaded()&&!confirm("Replace original HUMAN source and FORGET all imported PRIVATE companion packets? Export external human notes independently. Nothing will be retained."))return;
  }else{
    const base=entries.workplan;
    next=kind==="artifact"?validateArtifact(raw,base):
         kind==="runbook"?validateRunbook(raw,base):validateResponse(raw,base);
  }
  if(revision!==current)fail("Another PRIVATE import changed local state during selection");
  if(kind==="workplan"){
    entries.workplan=next;entries.csv=null;entries.artifact=null;entries.runbook=null;entries.response=null;
    for(const key of ["csv","artifact","runbook","response"])stateLabel(key,"Not imported (previous local data forgotten)");
  }else entries[kind]=next;
  revision++;stateLabel(kind,"Imported locally · source-bound · unverified");
  $("source").textContent=sourceLabel();draw();
  window.dispatchEvent(new Event("lightup:human-sources-changed"));
  announce("Original-source-bound "+kind+" imported in memory. No original evidence, owner reply, action, grant or release changed.");
 }catch(_){announce("HOLD: "+kind+" import invalid, ambiguous, unsupported or source-mismatched. Current data unchanged.",true);}
}
/** Originals-only batch intake: never fabricates a source format or partial state. */
async function batchAdmit(){
 const chosen=Array.from($("batch-intake").files||[]);
 if(!chosen.length){$("batch-status").textContent="Select original PRIVATE export files first.";return;}
 if(chosen.length>5||chosen.some(f=>f.size<1||f.size>8*1048576)||
     chosen.reduce((n,f)=>n+f.size,0)>12*1048576){
  $("batch-status").textContent="HOLD: 1–5 supported original files, max 8 MiB/file and 12 MiB total.";return;
 }
 const captured=revision,current=entries.workplan;
 const payload=new Map(),maxima={workplan:1048576,csv:1048576,artifact:1048576,runbook:8*1048576,response:8*1048576};
 try{
  for(const file of chosen){
   if(file.size>8*1048576)fail("oversized original source file");
   const original=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
   if(revision!==captured)fail("source changed during original file intake");
   let kind,raw;
   if(file.name.toLowerCase().endsWith(".csv")){
    kind="csv";raw=original;
   }else{
    raw=parseStrict(original);
    kind=({"lightup.private_human_original_finding_workplan":"workplan",
      "lightup.private_artifact_ledger":"artifact",
      "lightup.private_human_remediation_runbooks":"runbook",
      "lightup.private_human_response_reconciliation":"response"})[raw?.kind];
    if(!kind)fail("unsupported original PRIVATE source type");
   }
   if(file.size>maxima[kind]||payload.has(kind))fail("duplicate or oversized original source file");
   payload.set(kind,raw);
  }
  if(!payload.has("workplan")&&!current)fail("original HUMAN workplan must be present");
  const source=payload.has("workplan")?validatePlan(payload.get("workplan")):current;
  const admitted={...entries};
  if(payload.has("workplan")){
   for(const key of Object.keys(admitted))admitted[key]=null;
   admitted.workplan=source;
  }
  if(payload.has("csv")){
   if(!window.LightUpCasework)fail("original Casework parser unavailable");
   const findings=window.LightUpCasework.parseCSV(payload.get("csv"));
   const sha=await window.LightUpCasework.digest(findings);
   if(!sha||sha!==source.source.source_sha256||findings.length!==source.ids.size||
      findings.some(f=>!source.ids.has(f.finding_id)))fail("original CSV does not match full source");
   admitted.csv={byId:new Map(findings.map(f=>[f.finding_id,f])),text:payload.get("csv")};
  }
  for(const kind of ["artifact","runbook","response"]){
   if(!payload.has(kind))continue;
   admitted[kind]=kind==="artifact"?validateArtifact(payload.get(kind),source):
     kind==="runbook"?validateRunbook(payload.get(kind),source):
     validateResponse(payload.get(kind),source);
  }
  if(revision!==captured)fail("original source changed during validation");
  const names=[...payload.keys()].join(", ");
  const msg=payload.has("workplan")?
   "Replace the ORIGINAL HUMAN source and ALL previous local companions with "+names+
   "? Missing companions will be UNKNOWN. This cannot confer any security permission.":
   "Replace only selected same-source PRIVATE companion imports ("+names+
   ")? Other local original exports remain. This grants no permissions.";
  if(!confirm(msg)){$("batch-status").textContent="No changes: HUMAN multi-import cancelled.";return;}
  if(revision!==captured)fail("original source changed after HUMAN confirmation");
  for(const kind of Object.keys(entries)){
   entries[kind]=admitted[kind];
   stateLabel(kind,entries[kind]?"Imported locally · source-bound · UNVERIFIED":"Not imported / unknown");
  }
  revision++;
  $("source").textContent=sourceLabel();
  draw();window.dispatchEvent(new Event("lightup:human-sources-changed"));
  $("batch-intake").value="";
  $("batch-status").textContent="IMPORTED atomically: "+names+
   ". Original source membership matched. Not authenticated; no scan/retest/fix/grant.";
  announce("PRIVATE originals admitted together. No original source or authority fields changed.");
 }catch(_){
  $("batch-status").textContent="HOLD: ambiguous, malformed, incomplete or mismatched original source; ALL previous local state preserved.";
 }
}
$("batch-admit").addEventListener("click",batchAdmit);
/** A PRIVATE source-only portable archive of the *original* untouched owner export objects.
    Never implies consent, authenticated source, evidence truth, or permission. */
function originalBundle(){
 if(!entries.workplan)fail("original HUMAN workplan required");
 const source=entries.workplan.source;
 return {
  kind:"lightup.private_original_human_source_session",schema_version:1,
  disposition:"UNVERIFIED_OFFLINE_HUMAN_SOURCE_TRANSFER_ONLY",
  source_contract:source.source_contract,source_sha256:source.source_sha256,
  client_reference:source.client_reference,engagement_reference:source.engagement_reference,
  source_count:source.source_count,
  ...Object.fromEntries(FLAGS.map(k=>[k,false])),
  originals:{
   workplan:source,
   csv:entries.csv?.text??null,
   artifact:entries.artifact?.original??null,
   runbook:entries.runbook?.original??null,
   response:entries.response?.original??null
  },
  warning:"UNENCRYPTED PRIVATE source-export copies. Independently verify safe storage and the real recipient; use encrypted Handoff Vault to transport. All client/owner/source labels and security-fix claims remain UNVERIFIED. No grant, scan, retest, release or consent."
 };
}
function exportSourceSession(){
 if(!loaded())return;
 let body;
 try{body=JSON.stringify(originalBundle(),null,2)+"\n";
  if(new TextEncoder().encode(body).length>12*1048576)fail("private source backup over 12 MiB");
 }catch(_){$("session-status").textContent="HOLD: too much original PRIVATE source data for one session export.";return;}
 if(!confirm("Export UNENCRYPTED PRIVATE original client/engagement/finding/owner notes as a JSON file? It contains sensitive human evidence metadata. Transfer only inside separately confirmed PRIVATE encrypted custody; source labels grant NO authority."))return;
 download("LightUp-UNENCRYPTED-PRIVATE-original-human-source-session.json",body,"application/json");
 $("session-status").textContent="UNENCRYPTED PRIVATE original-source session download requested. Recipient and filesystem security unverified.";
}
async function restoreSourceSession(){
 const file=$("session-import").files[0];
 if(!file){$("session-status").textContent="Choose a PRIVATE source session JSON file first.";return;}
 if(file.size<1||file.size>12*1048576){
  $("session-status").textContent="HOLD: source session must be 1 byte–12 MiB.";return;
 }
 const captured=revision;
 try{
  const text=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
  const packet=parseStrict(text);
  const fields=["kind","schema_version","disposition","source_contract","source_sha256",
   "client_reference","engagement_reference","source_count","originals","warning",...FLAGS];
  if(!exact(packet,fields)||packet.kind!=="lightup.private_original_human_source_session"||
    packet.schema_version!==1||
    packet.disposition!=="UNVERIFIED_OFFLINE_HUMAN_SOURCE_TRANSFER_ONLY"||
    FLAGS.some(k=>packet[k]!==false)||!canonical(packet.warning,600,true))
   fail("invalid PRIVATE non-authorizing source bundle");
  const o=packet.originals;
  if(!exact(o,["workplan","csv","artifact","runbook","response"])||
      !o.workplan||o.csv!==null&&typeof o.csv!=="string")
   fail("incomplete original source session envelope");
  const source=validatePlan(o.workplan);
  if(packet.source_contract!==source.source.source_contract||
     packet.source_sha256!==source.source.source_sha256||
     packet.client_reference!==source.source.client_reference||
     packet.engagement_reference!==source.source.engagement_reference||
     packet.source_count!==source.source.source_count)fail("source identity changed in session");
  const draft={workplan:source,csv:null,artifact:null,runbook:null,response:null};
  if(o.csv!==null){
   if(new TextEncoder().encode(o.csv).length>1048576||!window.LightUpCasework)
    fail("original Casework source parser or size boundary unavailable");
   const findings=window.LightUpCasework.parseCSV(o.csv);
   const digest=await window.LightUpCasework.digest(findings);
   if(!digest||digest!==source.source.source_sha256||
      findings.length!==source.ids.size||findings.some(x=>!source.ids.has(x.finding_id)))
    fail("source CSV SHA / original finding membership mismatch");
   draft.csv={byId:new Map(findings.map(x=>[x.finding_id,x])),text:o.csv};
  }
  if(o.artifact!==null)draft.artifact=validateArtifact(o.artifact,source);
  if(o.runbook!==null)draft.runbook=validateRunbook(o.runbook,source);
  if(o.response!==null)draft.response=validateResponse(o.response,source);
  if(revision!==captured)fail("source changed while reading private source session");
  if(!confirm("REPLACE all currently imported PRIVATE ORIGINAL HUMAN sources with this UNENCRYPTED, UNVERIFIED session? Existing local source overlays/file SHA comparisons will be discarded. This creates no authority, fix, scan, retest or client consent."))return;
  if(revision!==captured)fail("source changed before confirmation");
  for(const kind of Object.keys(entries)){
   entries[kind]=draft[kind];
   stateLabel(kind,entries[kind]?"Restored original PRIVATE source · UNVERIFIED":"Not present / unknown");
  }
  revision++;$("source").textContent=sourceLabel();draw();
  window.dispatchEvent(new Event("lightup:human-sources-changed"));
  $("session-import").value="";
  $("session-status").textContent="Full original PRIVATE source session restored atomically; missing optional originals remain unknown. HUMAN-only, no authority.";
  announce("PRIVATE unverified HUMAN originals restored without changing any source-owning files.");
 }catch(_){
  $("session-status").textContent="HOLD: invalid, inconsistent or ambiguous PRIVATE source bundle. Existing original imports unchanged.";
 }
}
$("session-export").addEventListener("click",exportSourceSession);
$("session-restore").addEventListener("click",restoreSourceSession);
function records(){
 if(!loaded())return [];
 const work=entries.workplan,source=entries.csv?.byId,docs=entries.artifact?.byId,books=entries.runbook?.byId,responses=entries.response?.byId;
 return [...work.ids].map(id=>{
  const plan=work.rows.get(id),files=docs?.get(id)||[],steps=books?.get(id)||[],requests=responses?.get(id)||[];
  const proposed=(humanWindows?.revision===revision?humanWindows.byFinding.get(id):null)||null;
  const needsReply=requests.some(r=>!r.reply);
  const needsHuman=plan.stage==="request_evidence_human"||plan.stage==="clarify_human_reply"||
    requests.some(r=>r.reply?.human_stage==="needs_changes"||
     r.review?.human_stage==="needs_human_followup"||r.feedback?.stage==="needs_clarification")||
    steps.some(s=>s.human_stage==="needs_human_input");
  const today=new Date().toISOString().slice(0,10),due=Boolean(plan.tentative_due&&plan.tentative_due<=today);
  return {id,plan,source:source?.get(id)||null,files,steps,requests,needsReply,needsHuman,due,proposed,
   custody:(!custodyCoverage||custodyCoverage.revision!==revision)?null:custodyCoverage.byFinding.get(id)||null,
   hasDocs:!!docs,hasBooks:!!books,hasResponse:!!responses};
 });
}
function summary(rows){
 const counts=[
  [String(rows.length),"Original HUMAN findings"],
  [String(rows.filter(r=>!r.plan.owner_alias).length),"No locally declared owner"],
  [entries.csv?String(rows.filter(r=>["critical","high"].includes(r.source?.severity)).length):"unknown","Original source CLAIM: critical/high"],
  [entries.artifact?String(rows.filter(r=>!r.files.length).length):"unknown","Zero listed fingerprints"],
  [entries.runbook?String(rows.filter(r=>!r.steps.length).length):"unknown","No HUMAN runbook steps"],
  [entries.response?String(rows.filter(r=>r.needsReply).length):"unknown","Unanswered HUMAN requests"],
  [custodyCoverage&&custodyCoverage.revision===revision?
    String(rows.filter(r=>r.custody?.attention>0).length):"unknown",
    "Local SHA comparisons needing HUMAN review"],
  [String(rows.filter(r=>r.needsHuman).length),"Human input/clarification"],
  [humanWindows&&humanWindows.revision===revision?
    String(rows.filter(r=>r.proposed?.proposed_window>0).length):"unknown","Tentative HUMAN slot allocations"],
  [String(rows.filter(r=>r.due).length),"Tentative dates reached"],
  [String(rows.filter(r=>r.plan.stage==="human_handoff_prepared").length),"Human handoffs prepared"]
 ];
 $("stats").replaceChildren();for(const [value,label] of counts){
  const d=document.createElement("div");d.className="metric";
  const b=document.createElement("b");b.textContent=value;
  const s=document.createElement("span");s.textContent=label;d.append(b,s);$("stats").append(d);
 }
}
function filtered(rows){
 const q=$("query").value.toLowerCase().trim(),mode=$("mode").value,owner=$("owner").value;
 return rows.filter(r=>{
  if(owner&&r.plan.owner_alias!==owner)return false;
  if(q&&![r.id,r.plan.owner_alias,r.plan.next_action,r.plan.private_note].join(" ").toLowerCase().includes(q))return false;
  if(mode==="critical_high"&&(!r.source||!["critical","high"].includes(r.source.severity)))return false;
  if(mode==="missing_docs"&&(!r.hasDocs||r.files.length))return false;
  if(mode==="no_owner"&&r.plan.owner_alias)return false;
  if(mode==="no_steps"&&(!r.hasBooks||r.steps.length))return false;
  if(mode==="needs_reply"&&(!r.hasResponse||!r.needsReply))return false;
  if(mode==="custody_attention"&&(!r.custody||r.custody.attention===0))return false;
  if(mode==="needs_input"&&!r.needsHuman)return false;
  if(mode==="unscheduled_window"&&(!r.proposed||r.proposed.proposed_window!==0))return false;
  if(mode==="window_human_hold"&&(!r.proposed||!r.proposed.needs_human_review))return false;
  if(mode==="due"&&!r.due)return false;
  if(mode==="handoff"&&r.plan.stage!=="human_handoff_prepared")return false;
  return true;
 }).sort((a,b)=>
   Number(b.needsHuman)-Number(a.needsHuman)||
   Number(b.needsReply)-Number(a.needsReply)||
   Number(b.due)-Number(a.due)||
   Number(!b.plan.owner_alias)-Number(!a.plan.owner_alias)||
   (a.source?["critical","high","medium","low","info"].indexOf(a.source.severity):5)-
    (b.source?["critical","high","medium","low","info"].indexOf(b.source.severity):5)||
   a.id.localeCompare(b.id)
 );
}
function tag(box,text,kind=""){const s=document.createElement("span");s.className="tag "+kind;s.textContent=text;box.append(s);}
function draw(){
 $("session-export").disabled=!loaded();
 $("workqueue").hidden=!loaded();if(!loaded())return;
 const rows=records();summary(rows);
 const ownerSelect=$("owner"),prev=ownerSelect.value;
 const aliases=[...new Set(rows.map(r=>r.plan.owner_alias).filter(Boolean))].sort((a,b)=>a.localeCompare(b));
 ownerSelect.replaceChildren(new Option("All owners",""));for(const a of aliases)ownerSelect.append(new Option(a,a));ownerSelect.value=aliases.includes(prev)?prev:"";
 rendered=filtered(rows);$("count").textContent=rendered.length+" ORIGINAL HUMAN findings visible · read-only source-bound inventory";
 const container=$("items");container.replaceChildren();
 if(!rendered.length){const p=document.createElement("p");p.textContent="No ORIGINAL findings match these human filters.";container.append(p);return;}
 for(const row of rendered.slice(0,350)){
  const article=document.createElement("article");article.className="inbox-item";
  const h=document.createElement("h3");h.textContent=row.id;article.append(h);
  tag(article,row.source?"SOURCE CLAIM: "+row.source.severity+" / "+row.source.retest_status:"ORIGINAL findings CSV not imported",row.source?"":"unknown");
  tag(article,"HUMAN: "+row.plan.stage);
  tag(article,row.plan.owner_alias?"Self-declared owner: "+row.plan.owner_alias:"No locally declared owner",row.plan.owner_alias?"":"alert");
  tag(article,row.hasDocs?row.files.length+" artifact fingerprints":"Artifact inventory not imported",row.hasDocs?"":"unknown");
  tag(article,row.hasBooks?row.steps.length+" HUMAN runbook steps":"Runbooks not imported",row.hasBooks?"":"unknown");
  tag(article,row.hasResponse?row.requests.length+" original HUMAN requests":"Response register not imported",row.hasResponse?"":"unknown");
  if(row.custody){
    tag(article,"Local SHA matches: "+row.custody.matched+"/"+row.custody.listed+" Ledger rows");
    if(row.custody.attention>0)tag(article,row.custody.attention+" local SHA comparisons need HUMAN review","alert");
  }else if(row.hasDocs)tag(article,"Local file bytes not compared","unknown");
  if(row.proposed){
    tag(article,row.proposed.proposed_window>0?
      "Proposed HUMAN UTC slot "+row.proposed.proposed_window+" · "+row.proposed.slot_start:
      "No tentative HUMAN change window",row.proposed.proposed_window>0?"":"unknown");
    if(row.proposed.needs_human_review)tag(article,"Change-window source reports HUMAN HOLD","alert");
  }
  if(row.needsReply)tag(article,"Unanswered HUMAN requests","alert");
  if(row.needsHuman)tag(article,"Needs HUMAN input","alert");
  if(row.due)tag(article,"Tentative date reached","alert");
  const detail=document.createElement("div");detail.className="detail";
  for(const [label,value] of [
   ["SOURCE-reported title",row.source?.title||"Unknown (source CSV not imported)"],
   ["SOURCE-reported remediation",row.source?.remediation||"Unknown (source CSV not imported)"],
   ["Tentative change-window discussion",row.proposed?
      (row.proposed.proposed_window?
       "Self-declared slot "+row.proposed.proposed_window+" / "+row.proposed.slot_start+" UTC":
       "Unscheduled local HUMAN slot"):"Unknown (change-window plan not imported)"],
   ["Change-window HUMAN follow-up",row.proposed?
     row.proposed.human_followup_status+" · "+row.proposed.human_followup_due+" · "+row.proposed.human_followup_note:
     "Unknown"],
   ["HUMAN tentative date",row.plan.tentative_due||"Unscheduled"],
   ["HUMAN next action",row.plan.next_action||"Not specified"],
   ["PRIVATE original HUMAN note",row.plan.private_note||"None"],
   ["Unverified replies",row.hasResponse?String(row.requests.filter(x=>Boolean(x.reply)).length):"Unknown"],
   ["Human clarification requests",String(row.requests.filter(x=>x.feedback?.stage==="needs_clarification").length)],
   ["Local file SHA custody",row.custody?row.custody.matched+" listed file fingerprints matched; "+row.custody.attention+
      " need HUMAN review; "+(row.custody.listed-row.custody.matched)+" not independently matched":
      "Unknown / local files not compared"],
   ["Tentative runbook tasks",row.hasBooks?row.steps.map(x=>x.description).join("; ").slice(0,500)||"None":"Unknown"]
  ]){
   const p=document.createElement("p");const strong=document.createElement("strong");strong.textContent=label+": ";
   const span=document.createElement("span");span.textContent=value;p.append(strong,span);detail.append(p);
  }
  article.append(detail);container.append(article);
 }
}
function htmlEsc(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));}
function download(name,content,mime){
 const url=URL.createObjectURL(new Blob([content],{type:mime})),a=document.createElement("a");
 a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),4000);
}
function printable(rows,ownerOnly=false){
 const source=entries.workplan.source;
 const tr=rows.map(r=>"<tr><td>"+htmlEsc(r.id)+"</td><td>"+htmlEsc(r.source?.severity||"unknown")+"</td><td>"+htmlEsc(r.source?.title||"unknown")+"</td><td>"+htmlEsc(r.plan.owner_alias||"unassigned")+"</td><td>"+
  htmlEsc(r.plan.stage)+"</td><td>"+htmlEsc(r.plan.tentative_due)+"</td><td>"+
  htmlEsc(r.plan.next_action)+"</td><td>"+htmlEsc(r.plan.private_note)+"</td><td>"+
  (r.hasDocs?String(r.files.length):"unknown")+"</td><td>"+(r.hasBooks?String(r.steps.length):"unknown")+
  "</td><td>"+(r.hasResponse?String(r.requests.filter(x=>!x.reply).length):"unknown")+
  "</td><td>"+htmlEsc(r.proposed?(r.proposed.proposed_window?
    "Tentative HUMAN UTC slot "+r.proposed.proposed_window+" · "+r.proposed.slot_start:
    "Unscheduled HUMAN discussion"):"unknown")+"</td></tr>").join("");
 return "<!doctype html><html lang='en'><meta charset='utf-8'><meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'\"><title>LightUp PRIVATE HUMAN team brief</title>"+
 "<style>body{font:15px system-ui;max-width:1100px;margin:40px auto;padding:0 20px;color:#111}table{border-collapse:collapse;width:100%;table-layout:fixed}td,th{border:1px solid #777;padding:8px;overflow-wrap:anywhere;vertical-align:top}p{line-height:1.5}</style>"+
 "<h1>PRIVATE HUMAN "+(ownerOnly?"one-owner":"team")+" coordination brief</h1>"+
 "<p><b>NO AUTHORITY:</b> Neither the original source nor owners, permissions, fixes, retests, findings or customer/operator consent have been authenticated. This file is a HUMAN-only discussion aid.</p>"+
 "<p>Self-declared original source SHA: "+htmlEsc(source.source_sha256)+
 " · client: "+htmlEsc(source.client_reference)+" · engagement: "+htmlEsc(source.engagement_reference)+
 " · source finding count: "+source.source_count+"</p>"+
 "<table><thead><tr><th>Original finding ID</th><th>SOURCE CLAIM severity</th><th>SOURCE CLAIM title</th><th>Self-declared HUMAN owner</th><th>HUMAN stage</th><th>Tentative date</th><th>PRIVATE proposed next action</th><th>PRIVATE local HUMAN note</th><th>Listed artifacts</th><th>Runbook steps</th><th>Unanswered requests</th><th>Human UTC change-window (not approved)</th></tr></thead><tbody>"+
 tr+"</tbody></table><p>Source-only and non-authorizing. PRIVATE: verify recipient, custody, printer and delivery channel. No execution or verified security fix.</p></html>";
}
function exportTeam(){
 if(!loaded())return;
 if(!confirm("Export PRIVATE scriptless HTML for the "+rendered.length+" currently filtered ORIGINAL HUMAN findings? Includes source labels/IDs and PRIVATE human notes; verify recipient and confidential storage."))return;
 download("LightUp-PRIVATE-cross-app-HUMAN-team-brief.html",printable(rendered),"text/html");
 announce("PRIVATE team brief requested locally. No grants, fixes or original source records changed.");
}
function exportOwner(){
 if(!loaded())return;const alias=$("owner").value;
 if(!alias){announce("Select ONE self-declared HUMAN owner first; one-owner export is intentionally unavailable for all owners.",true);return;}
 const subset=rendered.filter(r=>r.plan.owner_alias===alias);
 if(!subset.length)return;
 if(!confirm("Export PRIVATE brief for ONLY the selected self-declared owner ("+subset.length+" original findings)? Identity and delivery remain unverified."))return;
 download("LightUp-PRIVATE-one-owner-HUMAN-brief.html",printable(subset,true),"text/html");
 announce("Owner-minimized human brief requested; recipient verification is external.");
}
function anonymous(){
 if(!loaded())return;
 const rows=records(),groups=new Map();
 for(const r of rows){
  const key=[r.plan.stage,r.plan.owner_alias?"assigned":"unassigned",
   r.hasDocs?(r.files.length?"listed":"none"):"unknown",
   r.hasBooks?(r.steps.length?"planned":"none"):"unknown",
   r.hasResponse?(r.needsReply?"unanswered":"no_unanswered"):"unknown",
   r.proposed?(r.proposed.proposed_window?"tentatively_assigned":"unscheduled"):"unknown"].join("|");
  groups.set(key,(groups.get(key)||0)+1);
 }
 const lines=["human_stage,owner_alias_presence,artifact_list_presence,runbook_presence,request_reply_presence,human_window_presence,original_finding_count"];
 for(const [key,n] of [...groups].sort(([a],[b])=>a.localeCompare(b)))lines.push(key.split("|").join(",")+","+n);
 if(!confirm("Export HUMAN-only anonymous group counts? Small groups can still allow inference, so check recipient and privacy context."))return;
 download("LightUp-anonymous-HUMAN-cross-app-coverage.csv",lines.join("\r\n")+"\r\n","text/csv");
 announce("Privacy-minimal HUMAN counts CSV created; no original identifiers, source SHA, owners, dates or notes included.");
}
function receipt(){
 if(!loaded())return;const s=entries.workplan.source;
 const detail={schema:"lightup.private_cross_app_human_receipt_v1",authority:false,client_consent:false,
  operator_consent:false,authenticated:false,source_authorized:false,
  original_source_sha256:s.source_sha256,source_contract:s.source_contract,
  client_reference:s.client_reference,engagement_reference:s.engagement_reference,
  original_finding_ids:[...entries.workplan.ids].sort(),
  included:{original_human_workplan:true,original_csv_sha_matched:!!entries.csv,private_artifact_index:!!entries.artifact,
   original_human_runbooks:!!entries.runbook,private_response_register:!!entries.response},
  warning:"PRIVATE read-only HUMAN coordination snapshot. Hashes and labels do NOT authenticate sources, consent, fixes or release."};
 if(!confirm("Export PRIVATE declared-source membership receipt with ALL original finding IDs? Recipient and source identities remain unverified."))return;
 download("LightUp-PRIVATE-human-cross-app-source-receipt.json",JSON.stringify(detail,null,2)+"\n","application/json");
 announce("PRIVATE original-source membership receipt exported without transmitting data.");
}
for(const key of ["workplan","csv","artifact","runbook","response"])
 $(key).addEventListener("change",e=>importFile(key,e));
for(const key of ["query","mode","owner"])
 $(key).addEventListener(key==="query"?"input":"change",()=>{if(loaded())draw();});
$("forget").addEventListener("click",()=>{
 if(!loaded())return;
 if(!confirm("FORGET ALL locally imported PRIVATE workplan, evidence-index, owner response and runbook data? This cannot delete already exported or separately owned files."))return;
 for(const key of Object.keys(entries)){entries[key]=null;stateLabel(key,"Not imported");}
 rendered=[];revision++;$("session-export").disabled=true;window.dispatchEvent(new Event("lightup:human-sources-changed"));$("workqueue").hidden=true;$("source").textContent=sourceLabel();$("items").replaceChildren();
 announce("All PRIVATE cross-app records forgotten from this page.");
});
$("brief").addEventListener("click",exportTeam);
$("ownerBrief").addEventListener("click",exportOwner);
$("anonymous").addEventListener("click",anonymous);
$("binding").addEventListener("click",receipt);
window.addEventListener("lightup:local-custody",event=>{
  const detail=event.detail;
  if(detail&&detail.revision!==revision)return;
  custodyCoverage=detail?{revision:detail.revision,
    byFinding:new Map(detail.byFinding.map(row=>[row.finding_id,{
      listed:row.listed,matched:row.matched,attention:row.attention
    }]))}:null;
  if(loaded())draw();
});
window.addEventListener("lightup:human-change-windows",event=>{
  const detail=event.detail;
  if(detail&&detail.revision!==revision)return;
  humanWindows=detail?{revision:detail.revision,
    byFinding:new Map(detail.byFinding.map(row=>[row.finding_id,row]))}:null;
  if(loaded())draw();
});
window.LightUpHumanTriageBridge=Object.freeze({actionSnapshot:()=>{
 if(!entries.workplan)return null;
 const c=entries.workplan.source;
 return {revision,source_sha256:c.source_sha256,source_contract:c.source_contract,
  client_reference:c.client_reference,engagement_reference:c.engagement_reference,
  source_count:c.source_count,source_imports:{
   csv:!!entries.csv,artifacts:!!entries.artifact,
   runbooks:!!entries.runbook,responses:!!entries.response},
  findings:records().map(row=>({
    finding_id:row.id,
    source_title:row.source?.title||null,
    source_severity:row.source?.severity||null,
    source_retest_status:row.source?.retest_status||null,
    owner_alias:row.plan.owner_alias,
    human_stage:row.plan.stage,
    tentative_due:row.plan.tentative_due,
    next_action:row.plan.next_action,
    runbook_steps:row.steps.map(s=>({
      step_id:s.step_id,description:s.description,responsible_alias:s.responsible_alias,
      tentative_date:s.tentative_date,human_stage:s.human_stage
    })),
    owner_requests:row.requests.map(r=>({
      recipient_alias:r.recipient_alias,
      request_id:r.original.request_id,
      request_kind:r.original.request_kind,
      due_date:r.original.due_date,
      instructions:r.original.instructions,
      unanswered:!r.reply,
      needs_human_followup:r.review?.human_stage==="needs_human_followup"||
       r.feedback?.stage==="needs_clarification"||
       r.reply?.human_stage==="needs_changes"
    })),
    local_sha_review:row.custody?{listed:row.custody.listed,
      matched:row.custody.matched,attention:row.custody.attention}:null,
    proposed_window:row.proposed?{
      slot:row.proposed.proposed_window,utc:row.proposed.slot_start,
      needs_human_review:row.proposed.needs_human_review}:null
  }))
 };
},sourceSnapshot:()=>{
 if(!entries.workplan||!entries.csv)return null;
 const base=entries.workplan.source;
 return {revision,source_contract:base.source_contract,source_sha256:base.source_sha256,
 client_reference:base.client_reference,engagement_reference:base.engagement_reference,
 source_count:base.source_count,
 original_findings:[...entries.csv.byId.values()].map(row=>({
 finding_id:row.finding_id,severity:row.severity,retest_status:row.retest_status
 }))};
},parseHumanJSON:text=>parseStrict(text),snapshot:()=>{
 if(!entries.workplan||!entries.artifact)return null;
 const base=entries.workplan.source;return {revision,source_sha256:base.source_sha256,
 source_contract:base.source_contract,client_reference:base.client_reference,
 engagement_reference:base.engagement_reference,source_count:base.source_count,
 original_finding_ids:[...entries.workplan.ids].sort(),
 records:[...entries.artifact.byId.entries()].flatMap(([finding_id,rows])=>rows.map(r=>({
 finding_id,file_name:r.file_name,byte_length:r.byte_length,sha256:r.sha256,
 human_stage:r.human_stage}))) };
 }});
window.addEventListener("beforeunload",()=>{for(const key of Object.keys(entries))entries[key]=null;});
})();
