"use strict";
/* LightUp private lab review desk. No target or network interaction. */
(()=>{
const $=id=>document.getElementById(id);
const FLAGS=["authorized","consent_verified","dispatch_allowed","release_allowed"];
const STAGES=["needs_review","discussing","documented","blocked"];
const GROUPS=["unassigned","scope","findings","evidence","remediation"];
const SEVERITIES=["critical","high","medium","low","info"];
const MAX_BYTES=8*1024*1024, MAX_ROWS=2048;
let source=null,sourceHash="",notes=[],dirty=false,filter="",lastBulkUndo=null;
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
function updateSummary(){
 const sev=Object.fromEntries(SEVERITIES.map(s=>[s,0]));
 source.findings.forEach(f=>sev[f.severity]++);
 $("stats").textContent=source.targets.length+" declared lab endpoints · "+source.findings.length+
  " source-reported findings · "+SEVERITIES.map(s=>s+" "+sev[s]).join(" · ");
 $("progress").textContent=notes.filter(n=>n.stage!=="needs_review").length+
  " human review notes progressed · "+notes.filter(n=>n.stage==="blocked").length+
  " human blockers · all source status unverified";
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
 source.findings.forEach((f,i)=>{
  const n=notes[i];if(filter&&filter!==f.severity&&filter!==n.stage&&filter!=="endpoint:"+endpointOrdinal(f))return;
  shown++;
  const tr=document.createElement("tr");
  const meta=el("div");meta.append(el("strong","#"+(i+1)+" · "+f.severity.toUpperCase()+" · "+sourcePosition(f)));
  meta.append(el("p",f.finding));meta.append(el("small","Source-declared check: "+f.check_id+
   " · "+f.evidence_ids.length+" evidence refs · retest: "+f.retest));
  const detail=document.createElement("details");detail.append(el("summary","Private original impact / mitigation / evidence summary"));
  detail.append(el("p","Impact: "+f.impact),el("p","Mitigation: "+f.fix),
   el("p","Unverified evidence summary: "+f.evidence_summary));
  meta.append(detail);const a=document.createElement("td");a.append(meta);tr.append(a);
  const review=document.createElement("td"),controls=el("div",undefined,"controls");
  const apply=(k,v)=>{const next={...notes[i],[k]:v};require_(admitNote(next));notes[i]=next;lastBulkUndo=null;dirty=true;updateSummary();};
  controls.append(field("Stage",n.stage,v=>apply("stage",v)),
   field("Proposed group",n.group,v=>apply("group",v)),
   field("Next human action",n.next_action,v=>apply("next_action",v)),
   field("Blocker / uncertainty",n.blocker,v=>apply("blocker",v)));
  review.append(controls);tr.append(review);tbody.append(tr);
 });
 $("shown").textContent=shown+" of "+source.findings.length+" source findings shown";
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
 require_(file&&file.size>0&&file.size<=MAX_BYTES);
 const bytes=await file.arrayBuffer();require_(bytes.byteLength>0&&bytes.byteLength<=MAX_BYTES);
 const raw=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
 const parsed=admit(parseStrict(raw));
 // Exact raw bytes prevent reuse of human notes on changed or reordered evidence.
 const hash=(globalThis.crypto&&crypto.subtle)?await sha256(bytes):"";
 if(source&&dirty&&!confirm("Replace existing unsaved private human notes?"))return;
 source=parsed;sourceHash=hash;notes=parsed.findings.map(initialNote);dirty=false;lastBulkUndo=null;
 filter="";$("filter").value="";buildEndpointFilter();
 $("private").disabled=!hash;$("resume").disabled=!hash;
 $("workspace").hidden=false;updateSummary();render();
 status(hash?"Original private lab source admitted in memory. HUMAN REVIEW ONLY. Source hash is unsigned.":"Original private lab source admitted for local read-only review. Browser has no WebCrypto: private source-bound save/resume is disabled.");
}
async function resume(file){
 require_(source&&file&&file.size>0&&file.size<=1024*1024);
 const raw=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
 const v=parseStrict(raw);
 require_(exact(v,["schema","source_sha256","source_finding_count","notes","status",
  "source_authenticated","ground_truth_verified","client_consent_verified","operator_consent_verified",...FLAGS]));
 require_(v.schema==="lightup.private_lab_human_review.v1"&&v.status==="REVIEW_ONLY"&&
  v.source_sha256===sourceHash&&v.source_finding_count===source.findings.length&&
  ["source_authenticated","ground_truth_verified","client_consent_verified",
   "operator_consent_verified",...FLAGS].every(k=>v[k]===false));
 require_(Array.isArray(v.notes)&&v.notes.length===notes.length);
 const next=v.notes.map((row,i)=>{
  require_(exact(row,["ordinal","stage","group","next_action","blocker"])&&row.ordinal===i+1);
  const n={stage:row.stage,group:row.group,next_action:row.next_action,blocker:row.blocker};
  require_(admitNote(n));return n;
 });
 if(dirty&&!confirm("Replace existing unsaved human notes with this matching private return?"))return;
 notes=next;dirty=false;lastBulkUndo=null;updateSummary();render();status("Exact source-bound human notes restored. No security evidence was authenticated.");
}

function visibleOrdinals(){
 if(!source)return [];
 return source.findings.map((f,i)=>({f,i})).filter(({f,i})=>
  !filter||filter===f.severity||filter===notes[i].stage||
  filter==="endpoint:"+endpointOrdinal(f)).map(({i})=>i);
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
 notes=next;lastBulkUndo=old;dirty=true;updateSummary();render();
 status(ids.length+" human planning rows changed. Source evidence is unchanged; Undo is available.");
});
$("undoBulk").addEventListener("click",()=>{
 if(!source||!lastBulkUndo){status("No last bulk change available.");return;}
 notes=lastBulkUndo;lastBulkUndo=null;dirty=true;updateSummary();render();
 status("Last human-only bulk change undone.");
});

$("source").addEventListener("change",async e=>{try{await importSource(e.target.files[0]);}catch(_){status("HOLD: source rejected. Previous workspace unchanged.",true);}e.target.value="";});
$("resume").addEventListener("change",async e=>{try{await resume(e.target.files[0]);}catch(_){status("HOLD: private human return rejected. Previous workspace unchanged.",true);}e.target.value="";});
$("filter").addEventListener("change",e=>{filter=e.target.value;render();});
$("private").addEventListener("click",()=>{if(!source||!sourceHash)return;download("PRIVATE-lab-human-review.json",
 JSON.stringify(privatePayload(),null,2)+"\n","application/json");dirty=false;
 status("PRIVATE review saved locally. Share only via a separately approved confidential channel.");});
$("aggregate").addEventListener("click",()=>{if(!source)return;
 download("lab-anonymous-human-counts.json",JSON.stringify(aggregate(),null,2)+"\n","application/json");
 status("Counts-only human report exported; even small aggregate counts may be sensitive.");});
$("forget").addEventListener("click",()=>{if(!source||!confirm("Forget all private source data and unsaved human notes?"))return;
 source=null;sourceHash="";notes=[];dirty=false;filter="";lastBulkUndo=null;$("filter").value="";$("findings").replaceChildren();
 $("workspace").hidden=true;status("All in-memory private workspace data discarded.");});
window.addEventListener("beforeunload",e=>{if(dirty){e.preventDefault();e.returnValue="";}});
status("No private lab source loaded.");
})();