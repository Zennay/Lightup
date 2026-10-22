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
let pendingMerge=null,mergeUndo=null;
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
function touch(message){store.revision++;store.undo=null;mergeUndo=null;cancelMerge();$("planUndo").disabled=true;$("planMergeUndo").disabled=true;dirty();if(message)msg(message);}
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
 $("planOwnerBrief").disabled=!sel.value;$("planOwnerPrint").disabled=!sel.value;
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
 pendingMerge=null;mergeUndo=null;
 store={binding:null,rows:new Map(),revision:0,saved:0,selected:new Set(),undo:null};
 const data=ctx||BRIDGE.context();$("planRows").replaceChildren();$("planImport").value="";$("planSearch").value="";$("planFilter").value="all";$("planBulkStage").value="request_evidence_human";$("planBulkOwner").value="";$("planBulkDue").value="";$("planUndo").disabled=true;
 $("planOwner").replaceChildren(new Option("Choose local HUMAN owner",""));$("planOwnerBrief").disabled=true;$("planOwnerPrint").disabled=true;
 $("planMergeFile").value="";cancelMerge();$("planMergeUndo").disabled=true;
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
 store.rows=new Map(rows.map(r=>[r.finding_id,r]));store.selected.clear();store.undo=null;mergeUndo=null;cancelMerge();store.revision++;store.saved=store.revision;$("planImport").value="";render();msg("PRIVATE HUMAN plan restored for EXACT original source and finding IDs; no security status changed.");
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
 store.revision++;mergeUndo=null;cancelMerge();$("planMergeUndo").disabled=true;store.undo={beforeRevision,afterRevision:store.revision,binding:JSON.stringify(store.binding),old:previous};
 store.selected.clear();$("planUndo").disabled=false;render();msg(ids.length+" HUMAN-only source-bound planning updates applied locally. Undo available until another edit.");
}
function undoBulk(){
 const p=store.undo;if(!p||p.afterRevision!==store.revision||p.binding!==JSON.stringify(store.binding))fail("last HUMAN bulk change no longer safe to undo");
 if(!confirm("Undo the last HUMAN-only bulk assignment for "+p.old.size+" ORIGINAL findings?"))return;
 for(const [id,row] of p.old)store.rows.set(id,row);
 store.revision++;store.undo=null;mergeUndo=null;cancelMerge();$("planMergeUndo").disabled=true;render();msg("Last local HUMAN bulk assignment reverted. No original source changed.");
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
/* Scriptless PRIVATE human one-owner briefing; all original/customer text escaped
   and no remote resources, browser actions, evidence verification or grants. */
function htmlEsc(s){return String(s??"").replace(/[&<>"']/g,ch=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));}
function printableOwnerBrief(){
 const c=active(),alias=$("planOwner").value;
 if(!alias)fail("choose an existing locally declared HUMAN owner");
 const source=new Map(c.findings.map(f=>[f.id,f]));
 const rows=c.ids.map(id=>store.rows.get(id)).filter(r=>r.owner_alias===alias);
 if(!rows.length)fail("no PRIVATE HUMAN follow-up for selected declared owner");
 if(!confirm("Download a readable PRIVATE HTML HUMAN plan for "+rows.length+" original findings assigned to self-declared owner "+alias+"? Verify secure recipient, confidential printing and storage independently. No source authenticity or grant."))return;
 const header=[
 '<!doctype html><html lang="en"><head><meta charset="utf-8">',
 '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; img-src &#39;none&#39;; connect-src &#39;none&#39;; script-src &#39;none&#39;; style-src &#39;none&#39;; form-action &#39;none&#39;; base-uri &#39;none&#39;">',
 '<title>LightUp PRIVATE human owner action brief</title></head><body>',
 '<h1>LightUp · PRIVATE HUMAN follow-up</h1>',
 '<p><strong>DRAFT/HOLD · UNVERIFIED HUMAN PLANNING ONLY.</strong> This document is NOT a permission, verified fix, authorized retest, consent, approved scope or source-authenticity proof.</p>',
 '<p>Self-declared recipient alias: <strong>'+htmlEsc(alias)+'</strong></p>',
 '<p>Declared original source SHA-256: '+htmlEsc(c.source_sha256)+'</p>',
 '<p>Declared client: '+htmlEsc(c.client_reference)+' · engagement: '+htmlEsc(c.engagement_reference)+'</p>',
 '<p>Original HUMAN finding assignments: '+rows.length+'. Independently authenticate the original source and recipient before using this private document.</p>'
 ];
 const body=rows.map(r=>{
  const f=source.get(r.finding_id);
  return '<article><h2>Original finding '+htmlEsc(r.finding_id)+'</h2><dl>'+
   '<dt>Original source severity (if independently matched)</dt><dd>'+htmlEsc(f?.source_severity||"not supplied")+'</dd>'+
   '<dt>Local HUMAN follow-up stage</dt><dd>'+htmlEsc(r.stage)+'</dd>'+
   '<dt>Locally declared HUMAN owner</dt><dd>'+htmlEsc(r.owner_alias)+'</dd>'+
   '<dt>Tentative HUMAN date</dt><dd>'+htmlEsc(r.tentative_due||"not set")+'</dd>'+
   '<dt>Human next action</dt><dd><pre>'+htmlEsc(r.next_action||"not set")+'</pre></dd>'+
   '<dt>PRIVATE HUMAN note</dt><dd><pre>'+htmlEsc(r.private_note||"not set")+'</pre></dd></dl><hr></article>';
 }).join("\n");
 const doc=header.join("\n")+"\n"+body+"\n<p>No customer source, original request, original reply, scan authorization, remediation or release status has been changed by creating this human brief.</p></body></html>\n";
 download("LightUp-PRIVATE-one-owner-HUMAN-readable-brief.html",doc,"text/html;charset=utf-8");
 msg("Scriptless PRIVATE single-owner HUMAN briefing downloaded. Previously exported or printed documents remain the operator's responsibility.");
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

/* Operator-to-operator PRIVATE HUMAN workspace merge. No source revision,
   original reply or finding rewrite. No implicit resolution of conflicts. */
function defaultPlan(r){return r.stage==="unplanned"&&!r.owner_alias&&!r.tentative_due&&!r.next_action&&!r.private_note;}
function cancelMerge(){
 pendingMerge=null;$("planMergePanel").hidden=true;$("planMergeApply").disabled=true;
 $("planMergeChoices").replaceChildren();$("planMergeSummary").textContent="";
}
function mergePreviewRows(incoming){
 const changes=[];
 for(const row of incoming){
  const old=store.rows.get(row.finding_id);
  if(!old)fail("incoming PRIVATE HUMAN review references a foreign original ID");
  if(FIELDS.filter(k=>k!=="updated_utc").every(k=>old[k]===row[k]))continue;
  if(defaultPlan(row))continue; // an empty other-reviewer row cannot erase local planning
  const conflict=!defaultPlan(old);
  changes.push({id:row.finding_id,old:{...old},incoming:{...row},
   conflict,choice:conflict?"":"incoming"});
 }
 return changes;
}
function showMerge(){
 const draft=pendingMerge;if(!draft)return;
 const rows=draft.changes,conflicts=rows.filter(c=>c.conflict);
 $("planMergePanel").hidden=false;
 $("planMergeSummary").textContent=
  rows.length+" proposed ORIGINAL HUMAN planning changes · "+conflicts.length+
  " local-vs-incoming HUMAN conflicts requiring an explicit choice. No security status, original evidence, request or reply will change.";
 const box=$("planMergeChoices");box.replaceChildren();
 for(const change of rows){
  const item=document.createElement("div");item.className="planMergeItem";
  item.append(node("strong","Original finding "+change.id+" · "+(change.conflict?"HUMAN CONFLICT":"new HUMAN annotation")));
  const a=document.createElement("p");a.append(node("strong","Current local: "),
   node("span",change.old.stage+" · "+change.old.owner_alias+" · "+change.old.tentative_due+" · "+change.old.next_action+" · "+change.old.private_note));
  const b=document.createElement("p");b.append(node("strong","Other reviewer: "),
   node("span",change.incoming.stage+" · "+change.incoming.owner_alias+" · "+change.incoming.tentative_due+" · "+change.incoming.next_action+" · "+change.incoming.private_note));
  item.append(a,b);
  if(change.conflict){
   const label=node("label","Resolve original finding "+change.id);
   const sel=document.createElement("select");
   sel.append(new Option("Choose how to resolve this HUMAN conflict",""),new Option("KEEP local HUMAN plan","local"),new Option("APPLY other reviewer HUMAN plan","incoming"));
   sel.value=change.choice;
   sel.addEventListener("change",()=>{change.choice=sel.value;showMerge();});
   label.append(sel);item.append(label);
  }
  box.append(item);
 }
 $("planMergeApply").disabled=!rows.length||conflicts.some(c=>!c.choice);
}
async function previewMerge(){
 const f=$("planMergeFile").files[0];if(!f||!f.size||f.size>MAX)fail("select an existing PRIVATE HUMAN workspace backup <= 1 MiB");
 const ctx=active(),before=store.revision,orig=JSON.stringify(store.binding);
 const textValue=new TextDecoder("utf-8",{fatal:true}).decode(await f.arrayBuffer());
 const packet=BRIDGE.strictJSON(textValue),incoming=admit(packet,ctx);
 if(store.revision!==before||JSON.stringify(store.binding)!==orig||$("planMergeFile").files[0]!==f)
  fail("PRIVATE HUMAN local baseline/input changed while reading reviewer merge");
 const changes=mergePreviewRows(incoming);
 pendingMerge={before,source:orig,file:f,changes,packet};
 showMerge();
 msg(changes.length?"Previewed original-source-bound PRIVATE reviewer merge. Choose every HUMAN conflict explicitly before applying.":"No new HUMAN annotations: current local plan already covers every nonblank incoming row.");
}
function applyMerge(){
 const draft=pendingMerge;if(!draft)fail("preview the other PRIVATE HUMAN workplan first");
 if(store.revision!==draft.before||JSON.stringify(store.binding)!==draft.source||
 $("planMergeFile").files[0]!==draft.file)fail("original PRIVATE HUMAN source, selection or local baseline changed after preview");
 const fresh=admit(draft.packet,active()),recomputed=mergePreviewRows(fresh);
 if(!same(recomputed.map(x=>({id:x.id,old:x.old,incoming:x.incoming,conflict:x.conflict})),
 draft.changes.map(x=>({id:x.id,old:x.old,incoming:x.incoming,conflict:x.conflict}))))
  fail("other-reviewer PRIVATE HUMAN plan drifted since preview");
 if(draft.changes.some(x=>x.conflict&&!["local","incoming"].includes(x.choice)))fail("unresolved original HUMAN planning conflict");
 const edits=draft.changes.filter(x=>x.choice==="incoming");
 if(!edits.length){cancelMerge();msg("No HUMAN plan rows were replaced. Existing local annotations retained.");return;}
 if(!confirm("Apply "+edits.length+" source-bound PRIVATE HUMAN workplan annotations and keep "+(draft.changes.length-edits.length)+" locally? No original findings, owner replies, verified remediation or authorization will be updated."))return;
 if(store.revision!==draft.before||JSON.stringify(store.binding)!==draft.source)fail("original HUMAN baseline changed before reviewer merge");
 const before=new Map([...store.rows].map(([id,r])=>[id,{...r}]));
 for(const change of edits)store.rows.set(change.id,{...change.incoming});
 store.revision++;store.undo=null;$("planUndo").disabled=true;
 mergeUndo={before,afterRevision:store.revision,source:draft.source};
 cancelMerge();$("planMergeUndo").disabled=false;render();
 msg("PRIVATE HUMAN reviewer workplans merged for "+edits.length+" original finding IDs. Undo available until another local edit.");
}
function undoMerge(){
 const u=mergeUndo;if(!u||u.afterRevision!==store.revision||u.source!==JSON.stringify(store.binding))
  fail("reviewer workspace was changed after merge; a safe HUMAN undo is unavailable");
 if(!confirm("Undo the last PRIVATE HUMAN reviewer merge, restoring all previous original-ID local annotations?"))return;
 store.rows=new Map([...u.before].map(([id,r])=>[id,{...r}]));
 store.revision++;mergeUndo=null;cancelMerge();$("planMergeUndo").disabled=true;render();
 msg("Previous local HUMAN workplan restored. Already exported PRIVATE downloads remain on the recipient device.");
}
$("planMergeFile").addEventListener("change",()=>{cancelMerge();msg("Selected other-reviewer file changed; generate a new exact-source HUMAN merge preview.");});

for(const [id,event,fn] of [
 ["planSearch","input",render],["planFilter","change",render],
 ["planVisible","change",e=>{for(const x of visible())e.target.checked?store.selected.add(x.plan.finding_id):store.selected.delete(x.plan.finding_id);render();}],
 ["planBulkApply","click",bulkApply],["planUndo","click",undoBulk],
 ["planMergePreview","click",()=>previewMerge().catch(e=>msg(e.message,true))],["planMergeApply","click",applyMerge],["planMergeCancel","click",cancelMerge],["planMergeUndo","click",undoMerge],
 ["planSave","click",exportPrivate],["planRestore","click",()=>importPrivate().catch(e=>msg(e.message,true))],
 ["planOwnerBrief","click",ownerBrief],["planOwnerPrint","click",printableOwnerBrief],["planAggregate","click",aggregate],["planOwner","change",()=>{$("planOwnerBrief").disabled=!$("planOwner").value;$("planOwnerPrint").disabled=!$("planOwner").value;}]
])$(id).addEventListener(event,e=>{try{fn(e)}catch(err){msg(err.message,true);}});
/* Native browser warning is best-effort; users must explicitly export PRIVATE
   source-bound workplan JSON to preserve local HUMAN annotations. */
window.addEventListener("beforeunload",e=>{
 if(store.binding&&store.revision!==store.saved){e.preventDefault();e.returnValue="";}
});
function canDiscard(){
 return !store.binding||store.revision===store.saved||
  confirm("This PRIVATE HUMAN workplan has UNSAVED local changes. Export the complete PRIVATE JSON first if you want to keep them. Discard the current local HUMAN annotations and switch source?");
}
window.LightUpHandoffHumanPlan=Object.freeze({reset,render,canDiscard});
reset();
})();