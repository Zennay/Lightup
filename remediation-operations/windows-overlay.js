/* Read-only local original-source HUMAN change-window overlay.
   Imported tentative schedules NEVER authorize execution, deployment or retesting. */
(() => {
"use strict";
const $=id=>document.getElementById(id),BRIDGE=window.LightUpHumanTriageBridge;
const FIELDS=["kind","schema_version","disposition","source_contract","source_sha256","warning",
"windows","meeting_note","assignments","source_refresh","casework_sha256","casework_update",
"casework_packet_hashless"];
const FLAGS=["authenticated","tenant_verified","source_authorized","assessment_authorized","grant",
"client_consent","operator_consent","execution","scan","audit_verdict","retest_verified","release"];
const ROW=["finding_id","original_severity","original_retest_status","human_stage","human_reviewer",
"human_next_step","human_review_sha256","human_reference_gaps","proposed_window","casework_row_sha256",
"human_followup_status","human_followup_due","human_followup_note"];
const GAPS=["change_reference","deployment_reference","rollback_reference","retest_request_reference"];
const STAGES=["missing","submitted","needs_changes","ready_for_authorized_retest"];
const FOLLOWUPS=["untriaged","awaiting_owner","awaiting_evidence","needs_discussion","discussion_logged"];
let epoch=0,admitted=null;
const fail=()=>{throw Error("Invalid or unbound private HUMAN change-window packet");};
function exact(x,k){
 return !!x&&typeof x==="object"&&!Array.isArray(x)&&
 Object.keys(x).length===k.length&&k.every(field=>Object.hasOwn(x,field));
}
function str(s,max,required=false){
 return typeof s==="string"&&s.length<=max&&(!required||s.trim()!=="")&&
 !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069\ud800-\udfff]/.test(s);
}
function sha(s){return typeof s==="string"&&/^[0-9a-f]{64}$/.test(s);}
function utc(v){
 return typeof v==="string"&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:00\.000Z$/.test(v)&&
 Number.isFinite(Date.parse(v))&&new Date(v).toISOString()===v;
}
function date(v){
 return v===""||typeof v==="string"&&/^\d{4}-\d\d-\d\d$/.test(v)&&
 Number.isFinite(Date.parse(v+"T00:00:00Z"))&&new Date(v+"T00:00:00Z").toISOString().slice(0,10)===v;
}
function int(n,max){return Number.isSafeInteger(n)&&n>=0&&n<=max;}
function parsed(p,context){
 if(!exact(p,FIELDS.concat(FLAGS))||
  p.kind!=="lightup.remediation_human_change_windows"||p.schema_version!==1||
  p.disposition!=="DRAFT_UNVERIFIED_HUMAN_COORDINATION"||
  p.source_contract!==context.source_contract||p.source_sha256!==context.source_sha256||
  FLAGS.some(k=>p[k]!==false)||!str(p.warning,800,true)||!str(p.meeting_note,600)||
  !(p.casework_sha256===null||sha(p.casework_sha256))||
  typeof p.casework_packet_hashless!=="boolean")fail();
 if(p.source_refresh!==null){
  const r=p.source_refresh;
  if(!exact(r,["from_sha256","to_sha256","added","changed","absent_unverified","unchanged"])||
   !sha(r.from_sha256)||r.from_sha256===r.to_sha256||r.to_sha256!==context.source_sha256||
   !["added","changed","absent_unverified","unchanged"].every(k=>int(r[k],350))||
   r.added+r.changed+r.unchanged!==context.source_count)fail();
 }
 if(p.casework_update!==null){
  const keys=["from_sha256","to_sha256","source_sha256","total","owner","status",
   "deadline","blocker","action","urgent"];
  const u=p.casework_update;
  if(!exact(u,keys)||!sha(u.from_sha256)||!sha(u.to_sha256)||
    u.to_sha256!==p.casework_sha256||u.from_sha256===u.to_sha256||
    u.source_sha256!==context.source_sha256||
    !keys.slice(3).every(k=>int(u[k],350)))fail();
 }
 if(!Array.isArray(p.windows)||p.windows.length!==4||
    !Array.isArray(p.assignments)||p.assignments.length!==context.source_count)fail();
 const slots=[],active=[];
 for(const [index,entry] of p.windows.entries()){
  const k=["slot","window","findings","critical_high","local_review_holds",
   "local_casework_blocked","locally_past_due","proposed_after_local_due"];
  if(!exact(entry,k)||entry.slot!==index+1||
    !k.slice(2).every(prop=>int(entry[prop],context.source_count))||
    entry.critical_high>entry.findings||entry.local_review_holds>entry.findings||
    entry.local_casework_blocked>entry.findings||entry.locally_past_due>entry.findings||
    entry.proposed_after_local_due>entry.findings)fail();
  if(entry.window===null){slots.push(null);continue;}
  const w=entry.window;
  if(!exact(w,["slot","label","start_utc","minutes"])||
    w.slot!==index+1||!str(w.label,70,true)||!utc(w.start_utc)||
    !int(w.minutes,480)||w.minutes<30)fail();
  active.push(w);slots.push({...w});
 }
 active.sort((a,b)=>a.start_utc.localeCompare(b.start_utc));
 for(let i=1;i<active.length;i++)
  if(Date.parse(active[i].start_utc)<Date.parse(active[i-1].start_utc)+active[i-1].minutes*60000)fail();
 const ids=new Map(context.original_findings.map(f=>[f.finding_id,f])),seen=new Set(),rows=[];
 const actual=Array.from({length:4},()=>({findings:0,critical_high:0,local_review_holds:0}));
 for(const a of p.assignments){
  if(!exact(a,ROW)||!ids.has(a.finding_id)||seen.has(a.finding_id))fail();
  seen.add(a.finding_id);
  const f=ids.get(a.finding_id);
  if(a.original_severity!==f.severity||a.original_retest_status!==f.retest_status||
   !STAGES.includes(a.human_stage)||!str(a.human_reviewer,160)||
   !str(a.human_next_step,1800)||!sha(a.human_review_sha256)||
   !(a.casework_row_sha256===null||sha(a.casework_row_sha256))||
   !Array.isArray(a.human_reference_gaps)||
   a.human_reference_gaps.length>4||
   new Set(a.human_reference_gaps).size!==a.human_reference_gaps.length||
   a.human_reference_gaps.some(k=>!GAPS.includes(k))||
   !int(a.proposed_window,4)||a.proposed_window>0&&!slots[a.proposed_window-1]||
   !FOLLOWUPS.includes(a.human_followup_status)||!date(a.human_followup_due)||
   !str(a.human_followup_note,600))fail();
  if(a.human_followup_status==="discussion_logged"&&!a.human_followup_note.trim())fail();
  const needs_human_review=a.human_stage==="missing"||a.human_stage==="needs_changes"||
   a.human_reference_gaps.length>0;
  if(a.proposed_window){
   const slot=actual[a.proposed_window-1];slot.findings++;
   if(["critical","high"].includes(f.severity))slot.critical_high++;
   if(needs_human_review)slot.local_review_holds++;
  }
  rows.push({finding_id:a.finding_id,proposed_window:a.proposed_window,
    slot_start:a.proposed_window?slots[a.proposed_window-1].start_utc:"",needs_human_review,
    human_followup_status:a.human_followup_status,human_followup_due:a.human_followup_due,
    human_followup_note:a.human_followup_note,
    human_review_stage:a.human_stage,human_reference_gaps:[...a.human_reference_gaps]});
 }
 if(seen.size!==ids.size)fail();
 for(let i=0;i<4;i++){
  for(const k of ["findings","critical_high","local_review_holds"])
   if(actual[i][k]!==p.windows[i][k])fail();
 }
 return {byFinding:rows,windows:slots};
}
function clear(){
 epoch++;admitted=null;
 $("human-windows").value="";
 $("human-windows").disabled=!BRIDGE?.sourceSnapshot();
 $("human-windows-state").textContent=$("human-windows").disabled?
  "Import original workplan + SHA-matched ORIGINAL findings CSV first":
  "No HUMAN window plan imported · scheduled status UNKNOWN";
 window.dispatchEvent(new CustomEvent("lightup:human-change-windows",{detail:null}));
}
async function read(e){
 const file=e.target.files[0];e.target.value="";
 if(!file)return;
 const source=BRIDGE?.sourceSnapshot();
 if(!source){clear();return;}
 if(file.size<1||file.size>2097152){
  $("human-windows-state").textContent="HOLD: HUMAN plan outside 2 MiB bound";return;
 }
 const change=++epoch;
 try{
  const text=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
  if(change!==epoch||BRIDGE.sourceSnapshot()?.revision!==source.revision)fail();
  const payload=BRIDGE.parseHumanJSON(text);
  const candidate=parsed(payload,source);
  if(change!==epoch||BRIDGE.sourceSnapshot()?.revision!==source.revision)fail();
  if(admitted&&!confirm("Replace existing PRIVATE HUMAN change-window overlay? It is a human-only source declaration; no original plan or permission is altered."))return;
  admitted={revision:source.revision,...candidate};
  window.dispatchEvent(new CustomEvent("lightup:human-change-windows",{detail:admitted}));
  const assigned=candidate.byFinding.filter(x=>x.proposed_window>0).length;
  const holds=candidate.byFinding.filter(x=>x.needs_human_review).length;
  $("human-windows-state").textContent="Imported locally: "+assigned+" tentative HUMAN window allocations / "+
    candidate.byFinding.length+" original findings; "+holds+
    " original review notes report HUMAN attention. No deployment or retest authority.";
 }catch(_){
  $("human-windows-state").textContent="HOLD: invalid, source-drifted or ambiguous HUMAN window plan; existing local overlay unchanged.";
 }
}
$("human-windows").addEventListener("change",read);
window.addEventListener("lightup:human-sources-changed",clear);
clear();
})();