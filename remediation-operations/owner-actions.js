"use strict";
/* PRIVATE read-only original-finding owner action planning; no source, grants or evidence bytes are modified. */
(() => {
const $=id=>document.getElementById(id),bridge=window.LightUpHumanTriageBridge;
const flags=["authenticated","tenant_verified","source_authorized","assessment_authorized","grant",
"client_consent","operator_consent","execution","scan","audit_verdict","retest_verified","release"];
let source=null,owner="";
function show(s){$("owner-actions-feedback").textContent=s;}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));}
function save(name,body,type){
 const url=URL.createObjectURL(new Blob([body],{type})),a=document.createElement("a");
 a.href=url;a.download=name;document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),4000);
}
function due(s){
 return typeof s==="string"&&s!==""&&s<=new Date().toISOString().slice(0,10);
}
function forOwner(row,alias){
 const requests=row.owner_requests.filter(x=>x.recipient_alias===alias).map(r=>({
  request_id:r.request_id,request_kind:r.request_kind,due_date:r.due_date,
  instructions:r.instructions,unanswered:r.unanswered,
  needs_human_followup:r.needs_human_followup
 }));
 const steps=row.runbook_steps.filter(x=>x.responsible_alias===alias).map(x=>({...x}));
 return {
  original_finding_id:row.finding_id,
  original_reported_title:row.source_title,
  original_reported_severity:row.source_severity,
  original_reported_retest_status:row.source_retest_status,
  human_workplan_stage:row.human_stage,
  tentative_human_due:row.tentative_due,
  proposed_human_next_action:row.next_action,
  assigned_human_runbook_steps:steps,
  intended_human_requests:requests,
  local_evidence_sha_review:row.local_sha_review?{...row.local_sha_review}:null,
  tentative_human_change_window:row.proposed_window?{...row.proposed_window}:null
 };
}
function grouped(rows){
 const groups=new Map();
 for(const row of rows){
  const name=row.owner_alias;
  if(!groups.has(name))groups.set(name,[]);
  groups.get(name).push(row);
 }
 return groups;
}
function level(row){
 let attention=0;
 if(due(row.tentative_due))attention+=2;
 if(["critical","high"].includes(row.source_severity))attention+=1;
 if(row.owner_requests.some(x=>x.unanswered||x.needs_human_followup))attention+=2;
 if(row.local_sha_review?.attention>0)attention+=1;
 if(row.proposed_window?.needs_human_review)attention+=1;
 return attention;
}
function summary(rows){
 const groups=grouped(rows);
 const stats=[
  [String(rows.length),"Original human findings"],
  [String(groups.size-(groups.has("")?1:0)),"Self-declared owners"],
  [String((groups.get("")||[]).length),"No HUMAN owner assigned"],
  [source.source_imports.responses?
   String(rows.filter(r=>r.owner_requests.some(x=>x.unanswered)).length):"unknown",
   "Original human requests awaiting reply"],
  [String(rows.filter(r=>due(r.tentative_due)).length),"Tentative HUMAN dates reached"],
  [source.source_imports.runbooks?
   String(rows.reduce((n,r)=>n+r.runbook_steps.length,0)):"unknown",
   "HUMAN runbook tasks locally listed"]
 ];
 const board=$("owner-actions-summary");board.replaceChildren();
 for(const [number,caption] of stats){
  const el=document.createElement("div");el.className="metric";
  const b=document.createElement("b");b.textContent=number;
  const t=document.createElement("span");t.textContent=caption;
  el.append(b,t);board.append(el);
 }
}
function render(){
 source=bridge?.actionSnapshot()||null;
 const control=$("owner-actions-select"),list=$("owner-actions-list");
 if(!source){
  owner="";control.replaceChildren(new Option("Import original HUMAN source first",""));
  $("owner-actions-summary").replaceChildren();list.replaceChildren();
  $("owner-actions-state").textContent="No original source imported; HUMAN owner handoff unavailable.";
  $("owner-actions-export").disabled=true;
  $("owner-actions-json").disabled=true;
  $("owner-actions-counts").disabled=true;return;
 }
 $("owner-actions-state").textContent="Original-source-bound PRIVATE HUMAN action board · "+
  source.source_count+" findings · declared SHA "+source.source_sha256+
  " · customer/owner identities NOT authenticated.";
 summary(source.findings);
 const owners=[...new Set(source.findings.map(f=>f.owner_alias).filter(Boolean))].sort((a,b)=>a.localeCompare(b));
 if(!owners.includes(owner))owner="";
 control.replaceChildren(new Option("Choose one self-declared owner",""));
 for(const name of owners)control.append(new Option(name,name));
 control.value=owner;
 $("owner-actions-export").disabled=!owner;
 $("owner-actions-json").disabled=!owner;
 $("owner-actions-counts").disabled=false;
 list.replaceChildren();
 if(!owner){
  const group=grouped(source.findings);
  for(const name of owners){
   const rows=group.get(name)||[];
   const item=document.createElement("article");item.className="inbox-item";
   const h=document.createElement("h3");h.textContent="HUMAN owner alias: "+name;item.append(h);
   const p=document.createElement("p");
   p.textContent=rows.length+" original findings · "+rows.filter(r=>level(r)>0).length+
    " with local HUMAN attention indicators · "+rows.filter(r=>due(r.tentative_due)).length+
    " tentative due dates reached · "+
    (source.source_imports.responses?rows.reduce((n,r)=>n+r.owner_requests.filter(x=>x.recipient_alias===name&&x.unanswered).length,0):"unknown")+
    " unanswered same-recipient requests";
   item.append(p);
   const choose=document.createElement("button");choose.type="button";choose.className="quiet";
   choose.textContent="Open exactly this HUMAN owner action group";
   choose.addEventListener("click",()=>{owner=name;render();});
   item.append(choose);list.append(item);
  }
  if(group.has("")){
   const p=document.createElement("p");p.textContent=group.get("").length+
    " original findings have no locally declared owner. They are excluded from owner-specific exports.";
   list.append(p);
  }
  if(!owners.length){
   const p=document.createElement("p");p.textContent="No owner aliases assigned in this original HUMAN workplan.";
   list.append(p);
  }
  return;
 }
 const scoped=source.findings.filter(r=>r.owner_alias===owner).sort((a,b)=>
  level(b)-level(a)||(a.tentative_due||"9999").localeCompare(b.tentative_due||"9999")||
  a.finding_id.localeCompare(b.finding_id));
 for(const row of scoped){
  const item=document.createElement("article");item.className="inbox-item";
  const h=document.createElement("h3");h.textContent=row.finding_id+" · "+(row.source_title||"Original title unavailable");item.append(h);
  const info=document.createElement("p");info.textContent=
   "SOURCE-CLAIMED severity: "+(row.source_severity||"unknown")+
   " · HUMAN stage: "+row.human_stage+
   " · tentative HUMAN date: "+(row.tentative_due||"unassigned")+
   " · local attention indicators: "+level(row);
  item.append(info);
  const p=document.createElement("p");p.textContent="Next HUMAN action: "+(row.next_action||"Not specified");item.append(p);
  const req=row.owner_requests.filter(x=>x.recipient_alias===owner);
  const tasks=row.runbook_steps.filter(x=>x.responsible_alias===owner);
  const outline=document.createElement("p");
  outline.textContent=(source.source_imports.responses?
   req.filter(x=>x.unanswered).length+" unanswered intended HUMAN requests":"Original response register not imported")+
   " · "+(source.source_imports.runbooks?tasks.length+" same-owner runbook steps":"Runbooks not imported")+
   " · "+(row.local_sha_review?row.local_sha_review.attention+" local SHA attention findings":"SHA not compared")+
   " · "+(row.proposed_window?(row.proposed_window.slot?
   "proposed UTC slot "+row.proposed_window.slot:"no tentative UTC slot"):"window plan not imported");
  item.append(outline);
  if(req.length){
   const d=document.createElement("p");d.textContent="Intended owner requests: "+
    req.map(x=>x.request_kind+" ("+(x.unanswered?"unanswered":"human response noted")+
    ", due "+(x.due_date||"none")+")").join("; ");item.append(d);
  }
  if(tasks.length){
   const d=document.createElement("p");d.textContent="Assigned HUMAN runbook steps: "+
    tasks.map(x=>"#"+x.step_id+" "+x.description).join("; ");item.append(d);
  }
  list.append(item);
 }
}
function scopedPacket(){
 const current=bridge?.actionSnapshot();
 if(!current||!owner||current.revision!==source?.revision||
    current.source_sha256!==source.source_sha256)throw Error("stale original source");
 const findings=current.findings.filter(row=>row.owner_alias===owner).map(row=>forOwner(row,owner));
 if(!findings.length)throw Error("no source-bound HUMAN action group");
 return {kind:"lightup.private_owner_human_action_brief",schema_version:1,
  disposition:"UNVERIFIED_HUMAN_COORDINATION_ONLY",
  source_contract:current.source_contract,source_sha256:current.source_sha256,
  client_reference:current.client_reference,engagement_reference:current.engagement_reference,
  declared_human_recipient_alias:owner,original_finding_count:current.source_count,
  optional_import_presence:{...current.source_imports},
  ...Object.fromEntries(flags.map(k=>[k,false])),
  findings,
  warning:"PRIVATE SINGLE RECIPIENT HUMAN planning only. Owner alias, source identity, reported severity/fixes and local SHA hashes are NOT authenticated. No grants, scanners, real consent, approved retest or verified remediation. Verify recipient and channel independently."
 };
}
function htmlBrief(packet){
 const rows=packet.findings.map(r=>{
  const tasks=r.assigned_human_runbook_steps.map(x=>"#"+x.step_id+" "+x.description+
   " [tentative "+(x.tentative_date||"unknown")+"]").join("; ");
  const asks=r.intended_human_requests.map(x=>x.request_kind+" ["+
   (x.unanswered?"awaiting HUMAN reply":"UNVERIFIED HUMAN reply exists")+"] "+
   x.instructions+" (tentative due "+(x.due_date||"unknown")+")").join("; ");
  return "<tr><td>"+esc(r.original_finding_id)+"</td><td>"+esc(r.original_reported_severity||"unknown")+
   "</td><td>"+esc(r.original_reported_title||"unknown")+"</td><td>"+
   esc(r.proposed_human_next_action||"None locally entered")+"</td><td>"+
   esc(r.tentative_human_due||"not scheduled")+"</td><td>"+esc(tasks||"None for this owner")+
   "</td><td>"+esc(asks||"None addressed to this owner")+"</td><td>"+
   esc(r.tentative_human_change_window?.utc||"unknown")+"</td></tr>";
 }).join("");
 return "<!doctype html><html lang='en'><meta charset='utf-8'><meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'\"><title>PRIVATE single HUMAN owner action plan</title>"+
 "<style>body{font:15px system-ui;max-width:1150px;margin:30px auto;padding:20px;color:#111}table{border-collapse:collapse;table-layout:fixed;width:100%}td,th{border:1px solid #777;padding:8px;overflow-wrap:anywhere;vertical-align:top}</style>"+
 "<h1>PRIVATE original-source HUMAN owner action plan</h1><p><b>UNVERIFIED, NON-AUTHORIZING.</b> Explicitly verify recipient identity, customer/engagement and confidential delivery. This is not a security change order, customer permission or approved retest.</p>"+
 "<p>Self-declared original SHA-256: "+esc(packet.source_sha256)+" · customer label: "+
 esc(packet.client_reference)+" · engagement label: "+esc(packet.engagement_reference)+
 " · selected HUMAN alias: "+esc(packet.declared_human_recipient_alias)+"</p>"+
 "<table><thead><tr><th>Original ID</th><th>Source severity claim</th><th>Source title claim</th><th>Private HUMAN next action</th><th>Tentative due</th><th>Same-owner runbook tasks</th><th>Only same-recipient HUMAN requests</th><th>Tentative UTC change window</th></tr></thead><tbody>"+
 rows+"</tbody></table><p>Missing optional source imports are unknown, not proof of no requests. Owner replies and other owners' private notes have intentionally been excluded. Nothing in this handoff verifies a fix or confers execution/retest authority.</p></html>";
}
function exportOwner(format){
 try{
  const p=scopedPacket(),body=format==="json"?JSON.stringify(p,null,2)+"\n":htmlBrief(p);
  if(new TextEncoder().encode(body).length>3*1048576){show("HOLD: owner-specific HUMAN action pack exceeds 3 MiB.");return;}
  if(!confirm("Export a PRIVATE action pack ONLY for self-declared alias "+owner+" ("+p.findings.length+
   " original findings)? This contains customer/engagement labels, original finding IDs, planned tasks and intended-owner requests. Verify the actual recipient and secure channel. Grants NO authorization."))return;
  save(format==="json"?"LightUp-PRIVATE-single-owner-human-action-brief.json":
   "LightUp-PRIVATE-single-owner-human-action-brief.html",body,
   format==="json"?"application/json":"text/html");
  show("PRIVATE single-owner action brief exported locally. No recipient identity or permission has been authenticated.");
 }catch(_){show("HOLD: original source changed or no one-owner scope is available. Select again.");}
}
function exportCounts(){
 if(!source)return;
 const fresh=bridge?.actionSnapshot();
 if(!fresh||fresh.revision!==source.revision)return;
 const present=fresh.findings.filter(r=>r.owner_alias).length,
  missing=fresh.findings.length-present,
  dueCount=fresh.findings.filter(r=>due(r.tentative_due)).length,
  urgent=fresh.findings.filter(r=>level(r)>0).length;
 if(!confirm("Export aggregate HUMAN owner-presence counts only? Small cohorts may still reveal private context. No actual owner alias, client, engagement, SHA or finding IDs included."))return;
 save("LightUp-anonymous-HUMAN-owner-workload-counts.csv",
  "metric,count\r\noriginal_human_findings,"+fresh.findings.length+
  "\r\nself_declared_owner_assigned,"+present+"\r\nno_declared_owner,"+missing+
  "\r\nlocal_attention_indicators,"+urgent+"\r\ntentative_due_dates_reached,"+dueCount+
  "\r\n","text/csv");
 show("Aggregate HUMAN count summary saved without owner aliases or original IDs.");
}
$("owner-actions-select").addEventListener("change",e=>{owner=e.target.value;render();});
$("owner-actions-clear").addEventListener("click",()=>{owner="";render();});
$("owner-actions-export").addEventListener("click",()=>exportOwner("html"));
$("owner-actions-json").addEventListener("click",()=>exportOwner("json"));
$("owner-actions-counts").addEventListener("click",exportCounts);
for(const name of ["lightup:human-sources-changed","lightup:local-custody","lightup:human-change-windows"])
 window.addEventListener(name,()=>{if(name==="lightup:human-sources-changed")owner="";render();});
render();
})();