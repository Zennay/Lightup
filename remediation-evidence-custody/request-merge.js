/* Preserve-first PRIVATE original HUMAN Evidence Request Desk v1 handoff. No native Apply. */
(function(){
"use strict";
const $=id=>document.getElementById(id),state=window.LightUpCustodyState;
if(!state)throw Error("Original private source-bound custody context missing.");
const FLAGS=["authenticated","tenant_verified","source_authorized","assessment_authorized","grant","client_consent","operator_consent","execution","scan","audit_verdict","retest_verified","release"];
const KEYS=["request_id","finding_id","request_kind","assignee","due_date","instructions","linked_sha256","human_stage","human_response","created_utc","updated_utc"];
const KINDS=new Set(["missing_evidence","patch_change","deployment_record","rollback_plan","retest_request","followup_question","other"]);
const STAGES=new Set(["draft","requested_human","submitted_unverified","needs_changes","closed_human"]);
let candidate=null,requestGeneration=0;
function fail(s){throw Error(s);}
function exact(o,keys){
 return o&&typeof o==="object"&&!Array.isArray(o)&&
 Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k));
}
function text(s,max,label,required=false){
 if(typeof s!=="string"||s.length>max||s.includes("\u0000")||
 /[\u202a-\u202e\u2066-\u2069]/u.test(s)||(required&&!s.trim()))fail("Invalid original "+label);
 return s;
}
function when(s,label){
 if(typeof s!=="string"||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/u.test(s)||
 Number.isNaN(Date.parse(s)))fail("Invalid original "+label);
 return s;
}
function day(s){
 if(s==="")return s;
 if(typeof s!=="string"||!/^\d{4}-\d\d-\d\d$/u.test(s)||
 Number.isNaN(Date.parse(s+"T00:00:00Z"))||
 new Date(s+"T00:00:00Z").toISOString().slice(0,10)!==s)fail("Invalid original HUMAN due date.");
 return s;
}
function row(r,ids){
 if(!exact(r,KEYS))fail("Original HUMAN request fields changed.");
 if(typeof r.finding_id!=="string"||!ids.has(r.finding_id))fail("HUMAN request points to absent ORIGINAL finding.");
 if(typeof r.request_id!=="string"||!/^[a-f0-9]{32}$/u.test(r.request_id))fail("Invalid original HUMAN request ID.");
 if(!KINDS.has(r.request_kind)||!STAGES.has(r.human_stage))fail("Invalid original HUMAN request category/stage.");
 text(r.assignee,120,"owner");text(r.instructions,1400,"instructions",true);
 text(r.human_response,1800,"response");day(r.due_date);
 when(r.created_utc,"creation time");when(r.updated_utc,"update time");
 if(typeof r.linked_sha256!=="string"||(r.linked_sha256&&!/^[a-f0-9]{64}$/u.test(r.linked_sha256)))
 fail("Invalid original linked file fingerprint.");
 return {...r};
}
function rows(value,ids){
 if(!Array.isArray(value)||value.length>200)fail("Original HUMAN request list exceeds native limit.");
 const known=new Set();
 return value.map(item=>{
  const clean=row(item,ids);
  if(known.has(clean.request_id))fail("Duplicate original HUMAN request identity.");
  known.add(clean.request_id);return clean;
 });
}
function packet(json,ctx,ids){
 const FIELDS=["kind","schema_version","disposition","source_contract","source_sha256",
  "client_reference","engagement_reference",...FLAGS,"requests","warning"];
 if(!exact(json,FIELDS)||json.kind!=="lightup.private_human_evidence_requests"||
 json.schema_version!==1||json.disposition!=="UNVERIFIED_HUMAN_FOLLOW_UP_ONLY"||
 json.source_contract!=="lightup.finding_export._COLUMNS_v1"||
 json.source_sha256!==ctx.source_sha256||
 json.client_reference!==ctx.client_reference||
 json.engagement_reference!==ctx.engagement_reference||
 FLAGS.some(f=>json[f]!==false))fail("Original PRIVATE request packet source/context/authority mismatch.");
 text(json.warning,600,"request warning");
 return rows(json.requests,ids);
}
function canonical(r){
 return JSON.stringify(Object.keys(r).sort().map(k=>[k,r[k]]));
}
function exactSameSet(left,right){
 if(left.length!==right.length)return false;
 const a=left.map(canonical).sort(),b=right.map(canonical).sort();
 return a.every((value,i)=>value===b[i]);
}
function clear(){
 candidate=null;requestGeneration++;$("mergeAck").checked=false;
 $("requestPreview").textContent="No active preserve-first HUMAN merge preview.";
 $("exportMerged").disabled=true;
}
function sync(){
 const s=state.snapshot();
 if(candidate && (!s.verified||s.busy||s.revision!==candidate.revision)){
  clear();
 }
 $("exportMerged").disabled=!candidate||!s.verified||s.busy||!$("mergeAck").checked||!$("confirmPrivate").checked;
}
async function preview(){
 clear();
 const context=state.snapshot(),token=requestGeneration;
 if(!context.verified||context.busy||!context.context||!context.results.length)
  fail("Original source must match and local fingerprints must be compared first.");
 const ctx=context.context,ids=new Set(context.ids),input=$("requestInput").files[0];
 let old=[];
 if(ctx.hasNativeRequests){
  old=rows(ctx.nativeRequests,ids);
 }
 if(input){
  if(input.size>1024*1024)fail("Original PRIVATE Evidence Request Desk export exceeds 1 MiB.");
  const other=packet(state.strictJSON(await input.text()),ctx,ids);
  if(ctx.hasNativeRequests && !exactSameSet(old,other))
   fail("Two original HUMAN request baselines disagree. Resolve conflict in original owner app; nothing merged.");
  old=other;
 }else if(!ctx.hasNativeRequests&&!$("noExistingRequests").checked){
  fail("No original HUMAN request baseline supplied. Import native original PRIVATE requests or explicitly confirm the empty desk.");
 }
 const changed=state.snapshot();
 if(changed.revision!==context.revision||!changed.verified||requestGeneration!==token)
  fail("Source, selected evidence files, or original HUMAN baseline changed while preparing merge.");
 const originals=new Set(old.map(r=>r.request_id)),open=new Set(
  old.filter(r=>r.human_stage!=="closed_human").map(r=>r.finding_id));
 const focus=new Set(context.results.filter(r=>r.finding_id&&
  (r.status==="unlinked"||r.status==="missing"||r.status==="rename")).map(r=>r.finding_id));
 const newIds=[...focus].filter(id=>!open.has(id));
 if(old.length+newIds.length>200)fail("Native original HUMAN request maximum of 200 would be exceeded; no silent trimming.");
 if(!globalThis.crypto||!crypto.getRandomValues)fail("Secure local HUMAN request ID generator unavailable.");
 const now=new Date().toISOString(),newRows=[];
 for(const id of newIds){
  let id32;do{id32=Array.from(crypto.getRandomValues(new Uint8Array(16)),
       x=>x.toString(16).padStart(2,"0")).join("");}while(originals.has(id32));
  originals.add(id32);
  const related=context.results.filter(x=>x.finding_id===id&&
   (x.status==="unlinked"||x.status==="missing"||x.status==="rename"));
  const unlinked=related.some(x=>x.status==="unlinked");
  const renamed=related.some(x=>x.status==="rename");
  const missing=related.some(x=>x.status==="missing");
  const instructions=[
    unlinked?"The original finding has no LOCAL artifact fingerprint indexed; HUMAN search/clarification needed, not evidence absent elsewhere or a proven security issue.":"",
    missing?"Matching original indexed file bytes were NOT in this local selection; HUMAN clarification needed, not proof of absent evidence or a resolved finding.":"",
    renamed?"Some locally selected SHA-256 bytes match the original file index under a different filename; HUMAN context/label review requested.":""
  ].filter(Boolean).join(" ");
  newRows.push(row({request_id:id32,finding_id:id,request_kind:unlinked?"missing_evidence":"followup_question",
   assignee:"",due_date:"",instructions,linked_sha256:"",human_stage:"draft",
   human_response:"",created_utc:now,updated_utc:now},ids));
 }
 const result=[...old,...newRows];
 const next={
  kind:"lightup.private_human_evidence_requests",schema_version:1,
  disposition:"UNVERIFIED_HUMAN_FOLLOW_UP_ONLY",source_contract:"lightup.finding_export._COLUMNS_v1",
  source_sha256:ctx.source_sha256,client_reference:ctx.client_reference,
  engagement_reference:ctx.engagement_reference,
  ...Object.fromEntries(FLAGS.map(f=>[f,false])),
  requests:result,
  warning:"PRIVATE HUMAN follow-up merge from local file selection and original owner requests; no grant, consent, provenance attestation, verified remediation, assessment, retest or automatic native import."
 };
 candidate=Object.freeze({revision:context.revision,packet:next});
 $("requestPreview").textContent=
  "Original HUMAN requests preserved verbatim: "+old.length+
  " · new follow-up questions: "+newRows.length+
  " · findings with an already-open HUMAN request (not duplicated): "+([...focus].length-newRows.length)+
  " · final request count: "+result.length+
  ". Nothing has been imported or applied. Original native import still performs its own exact-source preview and explicit replace-all confirmation.";
 sync();
}
function exportMerged(){
 sync();
 if(!candidate||$("exportMerged").disabled)fail("No current HUMAN merge approval. Preview again.");
 const ready=candidate;
 if(!confirm("Export PRIVATE original-native HUMAN requests preserving ALL prior original records? Check recipient, secure storage and protected backup. No native apply occurs."))return;
 if(!candidate||ready!==candidate||state.snapshot().revision!==ready.revision)fail("Original source or local HUMAN merge preview changed.");
 const json=JSON.stringify(ready.packet,null,2)+"\n";
 if(new TextEncoder().encode(json).length>1024*1024)fail("Native private request packet exceeds original 1 MiB bound.");
 const url=URL.createObjectURL(new Blob([json],{type:"application/json"}));
 const a=document.createElement("a");a.href=url;
 a.download="LightUp-PRIVATE-merged-original-HUMAN-requests.json";
 document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1800);
 clear();$("confirmPrivate").checked=false;
 const notice=$("notice");notice.textContent="PRIVATE preserve-first HUMAN request handoff downloaded. Original owner application must independently re-check source and require separate manual import confirmation.";notice.className="notice";
}
window.LightUpCustodyMerge=Object.freeze({preview});
window.addEventListener("lightup-custody-updated",sync);
$("requestInput").addEventListener("change",clear);
$("noExistingRequests").addEventListener("change",clear);
$("mergeAck").addEventListener("change",sync);
$("confirmPrivate").addEventListener("change",sync);
$("exportMerged").addEventListener("click",()=>{try{exportMerged();}catch(e){const n=$("notice");n.textContent="HUMAN HOLD: "+e.message;n.className="alert";}});
})();
