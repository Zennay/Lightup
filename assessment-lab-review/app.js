"use strict";
/* LightUp private lab review desk. No target or network interaction. */
(()=>{
const $=id=>document.getElementById(id);
const FLAGS=["authorized","consent_verified","dispatch_allowed","release_allowed"];
const STAGES=["needs_review","discussing","documented","blocked"];
const GROUPS=["unassigned","scope","findings","evidence","remediation"];
const SEVERITIES=["critical","high","medium","low","info"];
const COVERAGE_STATUSES=["assessed","partially_assessed","not_applicable","not_authorized","unknown"];
const MAX_BYTES=8*1024*1024, MAX_ROWS=2048;
let source=null,sourceHash="",notes=[],dirty=false,filter="",searchTerm="",sortMode="source",lastBulkUndo=null;
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


function boundedPlanValue(value,depth=0,budget={nodes:0}){
 if(++budget.nodes>2048||depth>6)return false;
 if(value===null||typeof value==="boolean")return true;
 if(typeof value==="number")return Number.isFinite(value)&&Math.abs(value)<=1e12;
 if(typeof value==="string")return validText(value,2048);
 if(Array.isArray(value))return value.length<=64&&value.every(v=>boundedPlanValue(v,depth+1,budget));
 if(obj(value)){
  const keys=Object.keys(value);
  return keys.length<=64&&keys.every(k=>validText(k,256)&&boundedPlanValue(value[k],depth+1,budget));
 }
 return false;
}
function admitCoverage(value){
 require_(exact(value,["domains","counts","clean_bill_of_health","note"])&&obj(value.domains));
 const entries=Object.entries(value.domains);
 require_(entries.length<=256);
 const derived=Object.fromEntries(COVERAGE_STATUSES.map(s=>[s,0]));
 for(const [domain,status] of entries){
  require_(validText(domain,256)&&domain.length>0&&COVERAGE_STATUSES.includes(status));
  derived[status]++;
 }
 require_(exact(value.counts,COVERAGE_STATUSES));
 for(const status of COVERAGE_STATUSES){
  require_(Number.isSafeInteger(value.counts[status])&&value.counts[status]===derived[status]);
 }
 const materiallyUnknown=derived.unknown>derived.assessed+derived.partially_assessed;
 const expectedNote=materiallyUnknown?
  "coverage is materially unknown; zero findings must not be read as a clean bill of health":"";
 require_(value.clean_bill_of_health===(materiallyUnknown?false:null)&&value.note===expectedNote);
 return derived;
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
 require_(obj(x.evaluation)&&validText(x.report_markdown,MAX_BYTES));
 const coverageCounts=admitCoverage(x.coverage);
 admitEvaluation(x.evaluation,x.run_id,x.scenario_id);
 require_(x.evaluation.metrics.coverage_assessed===coverageCounts.assessed&&
  x.evaluation.metrics.coverage_unknown===coverageCounts.unknown);
 require_(Array.isArray(x.elevation_requests)&&x.elevation_requests.length<=512&&
  x.elevation_requests.every(item=>validText(item,8192)));
 for(const call of x.plan){
  require_(exact(call,["tool_id","asset","arguments"])&&
   validText(call.tool_id,256)&&validText(call.asset,2048)&&x.targets.includes(call.asset)&&
   obj(call.arguments)&&Object.keys(call.arguments).length<=64&&boundedPlanValue(call.arguments));
 }
 for(const denial of x.denied){
  require_(exact(denial,["tool_id","reason"])&&validText(denial.tool_id,256)&&
   validText(denial.reason,8192)&&x.plan.some(call=>call.tool_id===denial.tool_id));
 }
 if(Object.hasOwn(x,"benchmark_case")){
  require_(exact(x.benchmark_case,["record","context"])&&obj(x.benchmark_case.record)&&
   exact(x.benchmark_case.context,["run_id","client_id","engagement_id","mode","approved_risk","authorization","is_lab","created_at"]));
  const context=x.benchmark_case.context;
  require_(context.is_lab===true&&context.authorization===null&&context.run_id===x.run_id&&
   validText(context.run_id,256)&&validText(context.mode,128)&&validText(context.approved_risk,128)&&
   validText(context.created_at,128)&&
   (context.client_id===null||validText(context.client_id,256))&&
   (context.engagement_id===null||validText(context.engagement_id,256)));
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

function renderRunContext(){
 const m=source.evaluation.metrics,c=source.coverage;
 const cards=[
  ["Tool calls (source-reported)",m.tool_calls],
  ["Policy denials (source-reported)",source.denied.length],
  ["Elevation requests (source-reported)",source.elevation_requests.length],
  ["Coverage assessed (declared)",c.counts.assessed],
  ["Coverage unknown (declared)",c.counts.unknown],
  ["Valid / invalid / missed",m.valid_findings+" / "+m.invalid_findings+" / "+m.missed_findings],
  ["Runtime (source-reported)",m.runtime_seconds+" s"],
  ["Human interventions (declared)",m.human_interventions]
 ];
 const host=$("run-summary");host.replaceChildren();
 for(const [label,value] of cards){
  const card=el("div",undefined,"run-metric");
  card.append(el("span",label),el("strong",String(value)));host.append(card);
 }
 const body=$("coverage-domains");body.replaceChildren();
 for(const [domain,status] of Object.entries(c.domains).sort((a,b)=>a[0].localeCompare(b[0]))){
  const tr=document.createElement("tr");cell(tr,domain);cell(tr,status);body.append(tr);
 }
 $("run-caution").textContent=c.clean_bill_of_health===false?
  "Source coverage note: "+c.note+" This remains an unverified source claim; this desk does not produce a clean bill of health.":
  "The source reports no materially unknown coverage. This desk still does not verify coverage, findings, remediation or authorization.";
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
  const apply=(k,v)=>{const next={...notes[i],[k]:v};require_(admitNote(next));notes[i]=next;lastBulkUndo=null;dirty=true;updateSummary();};
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
 require_(file&&file.size>0&&file.size<=MAX_BYTES);
 const bytes=await file.arrayBuffer();require_(bytes.byteLength>0&&bytes.byteLength<=MAX_BYTES);
 const raw=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
 const parsed=admit(parseStrict(raw));
 // Exact raw bytes prevent reuse of human notes on changed or reordered evidence.
 const hash=(globalThis.crypto&&crypto.subtle)?await sha256(bytes):"";
 if(source&&dirty&&!confirm("Replace existing unsaved private human notes?"))return;
 source=parsed;sourceHash=hash;notes=parsed.findings.map(initialNote);dirty=false;lastBulkUndo=null;selectedForHandoff.clear();resetPeer();renderRunContext();
 filter="";searchTerm="";sortMode="source";$("filter").value="";
 $("search").value="";$("sort").value="source";buildEndpointFilter();
 $("private").disabled=!hash;$("resume").disabled=!hash;$("brief").disabled=!hash;
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
 notes=next;lastBulkUndo=old;dirty=true;updateSummary();render();
 status(ids.length+" human planning rows changed. Source evidence is unchanged; Undo is available.");
});
$("undoBulk").addEventListener("click",()=>{
 if(!source||!lastBulkUndo){status("No last bulk change available.");return;}
 notes=lastBulkUndo;lastBulkUndo=null;dirty=true;updateSummary();render();
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
$("forget").addEventListener("click",()=>{if(!source||!confirm("Forget all private source data and unsaved human notes?"))return;
 source=null;sourceHash="";notes=[];dirty=false;filter="";searchTerm="";sortMode="source";lastBulkUndo=null;selectedForHandoff.clear();resetPeer();$("filter").value="";$("search").value="";$("sort").value="source";$("findings").replaceChildren();
 $("workspace").hidden=true;$("run-summary").replaceChildren();$("coverage-domains").replaceChildren();$("stats").textContent="";$("progress").textContent="";$("shown").textContent="";status("All in-memory private workspace data discarded.");});
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
 try{
  require_(source&&e.target.files[0]&&e.target.files[0].size>0&&
   e.target.files[0].size<=MAX_BYTES);
  const raw=new TextDecoder("utf-8",{fatal:true}).decode(await e.target.files[0].arrayBuffer());
  const second=admit(parseStrict(raw));
  const draft=classifyPeer(second);
  peerComparison=draft;peerPage=0;peerFilter="";
  $("peer-kind").value="";$("peer-export").disabled=false;
  $("peer-overview").textContent="PRIVATE SOURCE DECLARATION COMPARISON ONLY · "+
   draft.endpoints+" identical declared endpoint literals · A "+
   draft.totalA+" original findings · B "+draft.totalB+
   " original findings. "+PEER_KINDS.map(([k])=>k+" "+draft.counts[k]).join(" · ");
  renderPeer();
  status("Separate original lab report B admitted locally. No original finding, consent or remediation was verified.");
 }catch(_){status("HOLD: second lab source incompatible, same-run or different declared endpoints. Previous comparison unchanged.",true);}
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
  notes=changed;dirty=true;lastBulkUndo=null;updateSummary();render();
  status("PRIVATE reviewer return applied to human fields only. No assessment was verified.");
  return true;
 }
});

status("No private lab source loaded.");
})();