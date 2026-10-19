/* LightUp PRIVATE HUMAN action planner; local memory, original IDs, no authority. */
(()=>{"use strict";
const $=id=>document.getElementById(id),BRIDGE=window.LightUpHandoffBridge;
if(!BRIDGE)throw Error("Original HUMAN evidence inbox bridge required");
const FLAGS=["authenticated","tenant_verified","source_authorized","assessment_authorized","grant","client_consent","operator_consent","execution","scan","audit_verdict","retest_verified","release"];
const STAGES=["unplanned","request_evidence_human","clarify_human_reply","coordinate_human_change","await_human_review","human_handoff_prepared"];
const FIELDS=["finding_id","stage","owner_alias","tentative_due","next_action","private_note","updated_utc"];
const PACKET=["kind","schema_version","disposition","source_contract","source_sha256","client_reference","engagement_reference","source_count","rows","warning",...FLAGS];
const MAX=1048576,MAX_FINDINGS=350;
let store={binding:null,rows:new Map(),revision:0,saved:0,selected:new Set(),undo:null};
const fail=s=>{throw Error("HOLD: "+s);};
const exact=(o,k)=>o&&Object.getPrototypeOf(o)===Object.prototype&&Object.keys(o).length===k.length&&Object.keys(o).every(x=>k.includes(x));
const str=(s,n,l,required=false)=>{if(typeof s!=="string"||s.length>n||/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/.test(s)||(required&&!s.trim()))fail("invalid "+l);return s;};
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
function date(v){if(v==="")return "";if(typeof v!=="string"||!/^\d{4}-\d{2}-\d{2}$/.test(v)||!Number.isFinite(Date.parse(v+"T00:00:00Z"))||new Date(v+"T00:00:00Z").toISOString().slice(0,10)!==v)fail("invalid tentative human date");return v;}
function iso(v){if(typeof v!=="string"||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(v)||!Number.isFinite(Date.parse(v))||new Date(v).toISOString()!==v)fail("invalid local human update time");return v;}
function cleanRow(r,ids){
 if(!exact(r,FIELDS)||!ids.has(r.finding_id))fail("unexpected or missing original finding HUMAN workplan record");
 if(!STAGES.includes(r.stage))fail("unsupported human-only planning stage");
 str(r.owner_alias,120,"declared owner");date(r.tentative_due);str(r.next_action,1000,"human next action");str(r.private_note,600,"private human note");iso(r.updated_utc);
 return {...r};
}
function blank(id){return {finding_id:id,stage:"unplanned",owner_alias:"",tentative_due:"",next_action:"",private_note:"",updated_utc:"1970-01-01T00:00:00.000Z"};}
function binding(ctx){return [ctx.source_contract,ctx.source_sha256,ctx.client_reference,ctx.engagement_reference,[...ctx.ids].sort()];}
function active(){const c=BRIDGE.context();if(!c||!c.ids.length)fail("load an ORIGINAL source-bound finding set first");if(!same(binding(c),store.binding))fail("original PRIVATE finding source changed; reopen HUMAN plan");return c;}
function msg(t,bad=false){$("planNotice").textContent=t;$("planNotice").dataset.error=bad?"true":"false";}
function node(tag,v){const e=document.createElement(tag);e.textContent=String(v);return e;}
function allRows(){const c=active(),index=new Map(c.findings.map(f=>[f.id,f]));return c.ids.map(id=>({source:index.get(id),plan:store.rows.get(id)}));}
function visible(){const q=$("planSearch").value.toLowerCase().trim(),mode=$("planFilter").value;
 return allRows().filter(x=>{
  const p=x.plan,source=x.source;
  if(q&&![p.finding_id,p.owner_alias,p.next_action,p.private_note,source?.source_severity||""].join(" ").toLowerCase().includes(q))return false;
  if(mode==="open"&&p.stage==="human_handoff_prepared")return false;
  if(mode==="unplanned"&&p.stage!=="unplanned")return false;
  if(mode==="due"&&(!p.tentative_due||p.tentative_due>=new Date().toISOString().slice(0,10)))return false;
  if(mode==="no_owner"&&p.owner_alias)return false;
  if(mode==="critical"&&!["critical","high"].includes(source?.source_severity))return false;
  if(mode==="handoff"&&p.stage!=="human_handoff_prepared")return false;
  return true;
 }).sort((a,b)=>{const rank={critical:0,high:1,medium:2,low:3,info:4};return (rank[a.source?.source_severity]??5)-(rank[b.source?.source_severity]??5)||a.plan.finding_id.localeCompare(b.plan.finding_id);});
}
function touch(message){store.revision++;store.undo=null;$("planUndo").disabled=true;dirty();if(message)msg(message);}
function dirty(){$("planSaved").textContent=store.revision!==store.saved?"UNSAVED PRIVATE human plan. Export source-bound JSON; browser has NO persistent storage.":"HUMAN workplan is locally unchanged since the last PRIVATE export or restore.";
 $("planSaved").dataset.dirty=String(store.revision!==store.saved);}
function edit(id,field,value){
 const c=active(),p=store.rows.get(id);
 if(!p||!c.ids.includes(id))fail("stale ORIGINAL finding ID");
 const revised={...p,[field]:value,updated_utc:new Date().toISOString()};
 cleanRow(revised,new Set(c.ids));
 store.rows.set(id,revised);touch("Local HUMAN "+field+" recorded for original "+id+". No original owner data or security status changed.");
}
function render(){
 const c=BRIDGE.context();if(!c||!c.ids.length){$("workplan").hidden=true;return;}
 const key=binding(c);
 if(!same(key,store.binding))reset(c);
 $("workplan").hidden=false;
 const list=allRows(),visibleRows=visible(),sel=$("planOwner"),old=sel.value;
 const owners=[...new Set(list.map(x=>x.plan.owner_alias).filter(Boolean))].sort((a,b)=>a.localeCompare(b));
 sel.replaceChildren(new Option("Choose local HUMAN owner",""));
 for(const alias of owners)sel.append(new Option(alias,alias));sel.value=owners.includes(old)?old:"";
 $("planOwnerBrief").disabled=!sel.value;
 const stages=new Map();for(const r of list)stages.set(r.plan.stage,(stages.get(r.plan.stage)||0)+1);
 $("planSummary").textContent=list.length+" ORIGINAL findings · "+(stages.get("unplanned")||0)+" unplanned · "+(stages.get("human_handoff_prepared")||0)+" HUMAN handoffs prepared · "+list.filter(x=>x.plan.owner_alias).length+" local owner assignments (unverified)";
 const body=$("planRows");body.replaceChildren();
 for(const x of visibleRows){
  const p=x.plan,tr=document.createElement("tr"),td=document.createElement("td"),check=document.createElement("input");
  check.type="checkbox";check.checked=store.selected.has(p.finding_id);check.setAttribute("aria-label","Select original HUMAN finding "+p.finding_id);
  check.addEventListener("change",()=>{check.checked?store.selected.add(p.finding_id):store.selected.delete(p.finding_id);render();});td.append(check);tr.append(td);
  const id=node("td",p.finding_id),sm=node("small",x.source?.source_severity?"ORIGINAL source severity: "+x.source.source_severity:"Original severity unavailable");id.append(sm);tr.append(id);
  const stage=document.createElement("select");stage.setAttribute("aria-label","Human planning stage for "+p.finding_id);
  for(const v of STAGES)stage.append(new Option(v.replaceAll("_"," "),v));stage.value=p.stage;
  stage.addEventListener("change",()=>{try{edit(p.finding_id,"stage",stage.value);render();}catch(e){msg(e.message,true);}});
  const st=document.createElement("td");st.append(stage);tr.append(st);
  const fields=[["owner_alias","text",120],["tentative_due","date",10],["next_action","textarea",1000],["private_note","textarea",600]];
  for(const [field,type,length] of fields){
   const col=document.createElement("td"),input=document.createElement(type==="textarea"?"textarea":"input");
   if(type!=="textarea")input.type=type;else input.rows=2;
   input.maxLength=length;input.value=p[field];input.setAttribute("aria-label",field.replaceAll("_"," ")+" for "+p.finding_id);
   input.addEventListener(type==="textarea"?"change":"change",()=>{try{edit(p.finding_id,field,input.value);dirty();}catch(e){msg(e.message,true);input.value=p[field];}});
   col.append(input);tr.append(col);
  }
  body.append(tr);
 }
 $("planVisible").checked=!!visibleRows.length&&visibleRows.every(x=>store.selected.has(x.plan.finding_id));
 $("planVisible").indeterminate=visibleRows.some(x=>store.selected.has(x.plan.finding_id))&&!$("planVisible").checked;
 $("planSelectCount").textContent=visibleRows.length+" visible ORIGINAL human findings · "+store.selected.size+" selected.";
 $("planBulkApply").disabled=!store.selected.size;dirty();
}
function reset(ctx=null){
 store={binding:null,rows:new Map(),revision:0,saved:0,selected:new Set(),undo:null};
 const data=ctx||BRIDGE.context();$("planRows").replaceChildren();$("planImport").value="";$("planSearch").value="";$("planFilter").value="all";$("planBulkStage").value="request_evidence_human";$("planBulkOwner").value="";$("planBulkDue").value="";$("planUndo").disabled=true;
 $("planOwner").replaceChildren(new Option("Choose local HUMAN owner",""));$("planOwnerBrief").disabled=true;
 if(data?.ids.length){store.binding=binding(data);for(const id of data.ids)store.rows.set(id,blank(id));$("workplan").hidden=false;msg("New source-bound local HUMAN plan. Original findings and grants are unchanged.");}
 else{$("workplan").hidden=true;msg("No ORIGINAL finding context loaded.");}
 dirty();
}
function snapshot(){
 const c=active();
 return {kind:"lightup.private_human_original_finding_workplan",schema_version:1,disposition:"UNVERIFIED_HUMAN_PLANNING_ONLY",
  source_contract:c.source_contract,source_sha256:c.source_sha256,client_reference:c.client_reference,engagement_reference:c.engagement_reference,
  source_count:c.ids.length,...Object.fromEntries(FLAGS.map(k=>[k,false])),
  rows:c.ids.map(id=>({...store.rows.get(id)})),
  warning:"LOCAL HUMAN planning only: no real owner identity verification, client/operator consent, grant, fix, retest, scan or release decision."};
}
function admit(p,c){
 if(!exact(p,PACKET)||p.kind!=="lightup.private_human_original_finding_workplan"||p.schema_version!==1||
  p.disposition!=="UNVERIFIED_HUMAN_PLANNING_ONLY"||p.source_contract!==c.source_contract||
  p.source_sha256!==c.source_sha256||p.client_reference!==c.client_reference||p.engagement_reference!==c.engagement_reference||
  p.source_count!==c.ids.length||FLAGS.some(k=>p[k]!==false)||
  !Array.isArray(p.rows)||p.rows.length!==c.ids.length||p.rows.length>MAX_FINDINGS)fail("PRIVATE HUMAN workplan is not exactly bound to the current original source");
 str(p.warning,500,"HUMAN warning",true);
 const ids=new Set(c.ids),seen=new Set(),rows=[];
 for(const r of p.rows){const v=cleanRow(r,ids);if(seen.has(v.finding_id))fail("duplicate original finding in HUMAN workplan");seen.add(v.finding_id);rows.push(v);}
 if(seen.size!==ids.size)fail("missing original HUMAN finding in PRIVATE workplan");return rows;
}
function download(name,content,mime){
 const blob=new Blob([content],{type:mime}),url=URL.createObjectURL(blob),a=document.createElement("a");a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1500);
}
function exportPrivate(){
 const data=snapshot();
 if(!confirm("Save all "+data.rows.length+" PRIVATE HUMAN plan rows (original finding IDs, declared owner aliases, dates, local notes) to your device? Verify confidential storage and recipient independently."))return;
 download("LightUp-PRIVATE-original-HUMAN-workplan.json",JSON.stringify(data,null,2)+"\n","application/json");store.saved=store.revision;dirty();msg("PRIVATE complete HUMAN plan exported. Only local original-source-bound notes, no grant or remediation proof.");
}
async function importPrivate(){
 const f=$("planImport").files[0];if(!f||!f.size||f.size>MAX)fail("choose PRIVATE original HUMAN workplan JSON <= 1 MiB");
 const before=store.revision,key=JSON.stringify(store.binding),fileRef=f;
 const body=new TextDecoder("utf-8",{fatal:true}).decode(await f.arrayBuffer());
 const incoming=BRIDGE.strictJSON(body),ctx=active(),rows=admit(incoming,ctx);
 if(before!==store.revision||key!==JSON.stringify(store.binding)||$("planImport").files[0]!==fileRef)fail("PRIVATE plan context changed during import");
 if(!confirm("REPLACE all "+store.rows.size+" LOCAL HUMAN plan annotations with this source-matched PRIVATE backup? Export current notes first. Does not change original source, responses or permission."))return;
 if(before!==store.revision||key!==JSON.stringify(store.binding))fail("HUMAN plan changed while awaiting import confirmation");
 store.rows=new Map(rows.map(r=>[r.finding_id,r]));store.selected.clear();store.undo=null;store.revision++;store.saved=store.revision;$("planImport").value="";render();msg("PRIVATE HUMAN plan restored for EXACT original source and finding IDs; no security status changed.");
}
function bulkApply(){
 const c=active(),ids=[...store.selected];if(!ids.length)fail("select HUMAN findings");
 if(ids.some(id=>!store.rows.has(id)||!c.ids.includes(id)))fail("source finding selection stale");
 const stage=$("planBulkStage").value,owner=str($("planBulkOwner").value.trim(),120,"bulk declared owner"),due=date($("planBulkDue").value);
 if(!STAGES.includes(stage))fail("invalid HUMAN stage");
 const previous=new Map(ids.map(id=>[id,{...store.rows.get(id)}]));
 const staged=ids.map(id=>cleanRow({...store.rows.get(id),stage,
  ...(owner?{owner_alias:owner}:{}),...(due?{tentative_due:due}:{}),updated_utc:new Date().toISOString()},new Set(c.ids)));
 if(!confirm("Apply HUMAN-only stage "+stage+" to "+ids.length+" exact ORIGINAL findings? "+(owner?"Set local declared owner "+owner+". ":"Keep existing owner aliases. ")+(due?"Set tentative date "+due+". ":"Keep existing dates. ")+"No grant, retest or fix will be created."))return;
 if(!same(binding(active()),store.binding))fail("source changed before HUMAN batch");
 const beforeRevision=store.revision;for(const row of staged)store.rows.set(row.finding_id,row);
 store.revision++;store.undo={beforeRevision,afterRevision:store.revision,binding:JSON.stringify(store.binding),old:previous};
 store.selected.clear();$("planUndo").disabled=false;render();msg(ids.length+" HUMAN-only source-bound planning updates applied locally. Undo available until another edit.");
}
function undoBulk(){
 const p=store.undo;if(!p||p.afterRevision!==store.revision||p.binding!==JSON.stringify(store.binding))fail("last HUMAN bulk change no longer safe to undo");
 if(!confirm("Undo the last HUMAN-only bulk assignment for "+p.old.size+" ORIGINAL findings?"))return;
 for(const [id,row] of p.old)store.rows.set(id,row);
 store.revision++;store.undo=null;render();msg("Last local HUMAN bulk assignment reverted. No original source changed.");
}
function ownerBrief(){
 const c=active(),owner=$("planOwner").value;if(!owner)fail("choose local HUMAN owner");
 const rows=c.ids.map(id=>store.rows.get(id)).filter(r=>r.owner_alias===owner);
 if(!rows.length)fail("no PRIVATE plan rows for selected declared owner");
 if(!confirm("Download PRIVATE "+rows.length+" original HUMAN plan rows for self-declared owner "+owner+" only? Recipient identity/delivery is NOT verified."))return;
 const out={kind:"lightup.private_one_owner_original_human_plan",schema_version:1,
  disposition:"UNVERIFIED_HUMAN_PLANNING_ONLY",source_contract:c.source_contract,
  source_sha256:c.source_sha256,client_reference:c.client_reference,engagement_reference:c.engagement_reference,
  recipient_alias:owner,...Object.fromEntries(FLAGS.map(k=>[k,false])),
  rows:rows.map(r=>({...r})),warning:"Separate PRIVATE human workplan, NOT original owner reply or consent/grant/authenticated identity."};
 download("LightUp-PRIVATE-one-owner-HUMAN-plan.json",JSON.stringify(out,null,2)+"\n","application/json");msg("PRIVATE one-owner human plan exported without another owner's plan rows.");
}
function csv(v){return '"'+String(v).replaceAll('"','""')+'"';}
function aggregate(){
 const c=active(),groups=new Map(),ref=new Map(c.findings.map(f=>[f.id,f.source_severity||"not_provided"]));
 for(const id of c.ids){const r=store.rows.get(id),key=JSON.stringify([r.stage,ref.get(id)||"not_provided",r.owner_alias?"locally_assigned":"unassigned"]);
  groups.set(key,(groups.get(key)||0)+1);}
 const rows=[["human_planning_stage","original_source_severity_claim_or_missing","human_owner_assignment_presence","count"]];
 for(const [key,num] of [...groups].sort((a,b)=>a[0].localeCompare(b[0])))rows.push([...JSON.parse(key),String(num)]);
 if(!confirm("Download counts-only original HUMAN workplan CSV without original IDs, source hash, client, names, dates or notes? Small cohorts may still disclose sensitive patterns."))return;
 download("LightUp-anonymous-HUMAN-workplan-counts.csv",rows.map(r=>r.map(csv).join(",")).join("\r\n")+"\r\n","text/csv;charset=utf-8");msg("Aggregate HUMAN-only planning counts exported. Nothing proves actual fixes.");
}
for(const [id,event,fn] of [
 ["planSearch","input",render],["planFilter","change",render],
 ["planVisible","change",e=>{for(const x of visible())e.target.checked?store.selected.add(x.plan.finding_id):store.selected.delete(x.plan.finding_id);render();}],
 ["planBulkApply","click",bulkApply],["planUndo","click",undoBulk],
 ["planSave","click",exportPrivate],["planRestore","click",()=>importPrivate().catch(e=>msg(e.message,true))],
 ["planOwnerBrief","click",ownerBrief],["planAggregate","click",aggregate],["planOwner","change",()=>{$("planOwnerBrief").disabled=!$("planOwner").value;}]
])$(id).addEventListener(event,e=>{try{fn(e)}catch(err){msg(err.message,true);}});
window.LightUpHandoffHumanPlan=Object.freeze({reset,render});
reset();
})();