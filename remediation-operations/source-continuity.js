"use strict";
/* Original HUMAN source continuity: PRIVATE in-memory advisory, never carry data or authorize actions. */
(() => {
const $=id=>document.getElementById(id);
const AUTH=["authenticated","tenant_verified","source_authorized","assessment_authorized","grant","client_consent",
"operator_consent","execution","scan","audit_verdict","retest_verified","release"];
const BASE=["kind","schema_version","disposition","source_contract","source_sha256",
 "client_reference","engagement_reference","source_count","originals","warning",...AUTH];
const HEAD=["kind","schema_version","disposition","source_contract","source_sha256",
 "client_reference","engagement_reference","source_count","rows","warning",...AUTH];
const FIELDS=["finding_id","stage","owner_alias","tentative_due","next_action","private_note","updated_utc"];
const HUMAN_FIELDS=["stage","owner_alias","tentative_due","next_action","private_note"];
const STAGES=["unplanned","request_evidence_human","clarify_human_reply","coordinate_human_change",
 "await_human_review","human_handoff_prepared"];
let oldSource=null,newSource=null,differences=null,counter=0;
const fail=()=>{throw Error("HOLD: invalid, ambiguous or mismatched ORIGINAL source session");};
const exact=(o,keys)=>!!o&&typeof o==="object"&&!Array.isArray(o)&&
 Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k));
function clean(x,n,required=false){
 return typeof x==="string"&&x.length<=n&&(!required||x.trim())&&
 !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069\ud800-\udfff]/.test(x);
}
function sha(x){return typeof x==="string"&&/^[0-9a-f]{64}$/.test(x);}
function date(x){
 return x===""||typeof x==="string"&&/^\d{4}-\d\d-\d\d$/.test(x)&&
 Number.isFinite(Date.parse(x+"T00:00:00Z"))&&
 new Date(x+"T00:00:00Z").toISOString().slice(0,10)===x;
}
function instant(x){
 return typeof x==="string"&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x)&&
 Number.isFinite(Date.parse(x))&&new Date(x).toISOString()===x;
}
function strictJSON(s){
 let i=0,visited=0;const n=s.length;
 const skip=()=>{while(i<n&&/[ \t\r\n]/.test(s[i]))i++;};
 function quoted(){
  if(s[i]!=='"')fail();const start=i++;let esc=false;
  while(i<n){const c=s[i++];
   if(esc){esc=false;continue;}
   if(c==="\\"){esc=true;continue;}
   if(c==='"')return JSON.parse(s.slice(start,i));
   if(c<" ")fail();
  }fail();
 }
 function walk(depth){
  if(++visited>70000||depth>30)fail();
  skip();const c=s[i];
  if(c==="{"){i++;skip();const keys=new Set();if(s[i]==="}"){i++;return;}
   for(;;){
    skip();const k=quoted();if(keys.has(k))fail();keys.add(k);
    skip();if(s[i++]!==":")fail();walk(depth+1);skip();
    const sep=s[i++];if(sep==="}")return;if(sep!==",")fail();
   }
  }
  if(c==="["){i++;skip();if(s[i]==="]"){i++;return;}
   for(;;){walk(depth+1);skip();const sep=s[i++];if(sep==="]")return;if(sep!==",")fail();}
  }
  if(c==='"'){quoted();return;}
  const scalar=/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(s.slice(i));
  if(!scalar)fail();i+=scalar[0].length;
 }
 walk(0);skip();if(i!==n)fail();return JSON.parse(s);
}
function binding(o){
 return !!o&&o.source_contract==="lightup.finding_export._COLUMNS_v1"&&sha(o.source_sha256)&&
 clean(o.client_reference,200,true)&&clean(o.engagement_reference,200,true)&&
 AUTH.every(k=>o[k]===false);
}
function admitted(packet){
 if(!exact(packet,BASE)||packet.kind!=="lightup.private_original_human_source_session"||
  packet.schema_version!==1||
  packet.disposition!=="UNVERIFIED_OFFLINE_HUMAN_SOURCE_TRANSFER_ONLY"||
  !binding(packet)||!clean(packet.warning,600,true)||
  !Number.isSafeInteger(packet.source_count)||packet.source_count<1||packet.source_count>350)fail();
 const source=packet.originals;
 if(!exact(source,["workplan","csv","artifact","runbook","response"]))fail();
 const p=source.workplan;
 if(!exact(p,HEAD)||p.kind!=="lightup.private_human_original_finding_workplan"||
   p.schema_version!==1||p.disposition!=="UNVERIFIED_HUMAN_PLANNING_ONLY"||
   !binding(p)||!clean(p.warning,500,true)||!Array.isArray(p.rows)||
   p.source_count!==packet.source_count||p.rows.length!==packet.source_count||
   ["source_contract","source_sha256","client_reference","engagement_reference"].some(k=>p[k]!==packet[k]))fail();
 const ids=new Set(),rows=new Map();
 for(const row of p.rows){
  if(!exact(row,FIELDS)||!clean(row.finding_id,200,true)||
    ids.has(row.finding_id)||!STAGES.includes(row.stage)||!clean(row.owner_alias,120)||
    !date(row.tentative_due)||!clean(row.next_action,1000)||
    !clean(row.private_note,600)||!instant(row.updated_utc))fail();
  ids.add(row.finding_id);rows.set(row.finding_id,row);
 }
 if(source.csv!==null&&
   (typeof source.csv!=="string"||new TextEncoder().encode(source.csv).length>1048576))fail();
 for(const [key,kind,version] of [
  ["artifact","lightup.private_artifact_ledger",1],
  ["runbook","lightup.private_human_remediation_runbooks",1],
  ["response","lightup.private_human_response_reconciliation",2]
 ]){
  const x=source[key];if(x===null)continue;
  if(!x||typeof x!=="object"||Array.isArray(x)||x.kind!==kind||x.schema_version!==version||
    !binding(x)||["source_contract","source_sha256","client_reference","engagement_reference"].some(k=>x[k]!==packet[k])||
    ("source_count" in x&&x.source_count!==packet.source_count))fail();
  if(key==="artifact"&&(!Array.isArray(x.attachments)||x.attachments.length>120))fail();
  if(key==="runbook"&&(!Array.isArray(x.runbooks)||x.runbooks.length!==packet.source_count))fail();
  if(key==="response"&&(!Array.isArray(x.request_packets)||!Array.isArray(x.reply_packets)))fail();
 }
 return {declared:packet,rows,ids};
}
function resetResults(){
 differences=null;$("results").hidden=true;
 $("source-comparison").textContent="";$("continuity-items").replaceChildren();
 $("shown").textContent="";
}
async function readFile(side){
 const input=$(side),file=input.files[0];input.value="";
 if(!file)return;
 if(file.size<1||file.size>12*1048576){
  $(side+"-status").textContent="HOLD: expected 1 byte–12 MiB PRIVATE JSON";
  return;
 }
 const captured=++counter;
 if(side==="old")oldSource=null;else newSource=null;
 resetResults();$("same-client").checked=false;
 try{
  const text=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
  const candidate=admitted(strictJSON(text));
  if(captured!==counter)return;
  if(side==="old")oldSource=candidate;else newSource=candidate;
  resetResults();$("same-client").checked=false;
  $(side+"-status").textContent="Loaded locally · "+candidate.ids.size+
   " ORIGINAL HUMAN IDs · declared source SHA "+candidate.declared.source_sha256.slice(0,18)+
   "… (NOT authenticated)";
  $("continuity-state").textContent="Source files selected; separately confirm actual client and engagement.";
 }catch(_){
  $(side+"-status").textContent="HOLD: noncanonical, invalid, oversized or ambiguous source session; this side has been forgotten.";
 }
}
function compare(){
 if(!oldSource||!newSource){
  $("continuity-state").textContent="Choose TWO original PRIVATE source sessions first.";return;
 }
 if(!$("same-client").checked){
  $("continuity-state").textContent="HOLD: HUMAN confirmation of same real client and exact engagement is required.";return;
 }
 const a=oldSource.declared,b=newSource.declared;
 if(a.source_contract!==b.source_contract||
    a.client_reference!==b.client_reference||a.engagement_reference!==b.engagement_reference){
  $("continuity-state").textContent="HOLD: source declares different client, engagement or original source contract. Neither snapshot has changed.";return;
 }
 const names=[...new Set([...oldSource.ids,...newSource.ids])].sort();
 const lines=[];
 for(const name of names){
  const from=oldSource.rows.get(name),to=newSource.rows.get(name);
  const kind=!from?"new":!to?"absent":
   HUMAN_FIELDS.some(field=>from[field]!==to[field])?"changed":"same";
  const changed=from&&to?HUMAN_FIELDS.filter(k=>from[k]!==to[k]):[];
  lines.push({finding_id:name,kind,fields:changed,from:from||null,to:to||null});
 }
 const counts={new:0,absent:0,changed:0,same:0};
 for(const line of lines)counts[line.kind]++;
 const sourceChanged=a.source_sha256!==b.source_sha256;
 const optional=["csv","artifact","runbook","response"].map(kind=>{
  const earlier=a.originals[kind],newer=b.originals[kind];
  return {kind,older:earlier!==null,later:newer!==null,
   altered:earlier!==null&&newer!==null&&JSON.stringify(earlier)!==JSON.stringify(newer)};
 });
 differences={lines,counts,sourceChanged,optional,baseline:a.source_sha256,
  newest:b.source_sha256,client:a.client_reference,engagement:a.engagement_reference};
 $("results").hidden=false;
 $("source-comparison").textContent="Earlier declared source SHA "+a.source_sha256+
  " → newer declared source SHA "+b.source_sha256+" · "+
  (sourceChanged?"DIFFERENT original source revisions: same IDs do NOT prove unchanged findings.":
   "SAME declared source SHA: still not authenticated.")+
  " · original optional PRIVATE import content: "+
  optional.map(x=>x.kind+" "+(!x.older&&!x.later?"absent in both":
   x.older&&!x.later?"absent in newer":!x.older&&x.later?"newly present":
   x.altered?"changed":"same")).join(" · ");
 const metrics=[
  [counts.new,"ADDED original IDs (newer)"],
  [counts.absent,"ABSENT original IDs (UNVERIFIED)"],
  [counts.changed,"Changed HUMAN planning fields"],
  [counts.same,"No HUMAN planning field changes"],
  [sourceChanged?"YES":"NO","Declared source SHA changed"]
 ];
 $("continuity-stats").replaceChildren();
 for(const [value,label] of metrics){
  const div=document.createElement("div");div.className="metric";
  const b=document.createElement("b");b.textContent=value;
  const text=document.createElement("span");text.textContent=label;
  div.append(b,text);$("continuity-stats").append(div);
 }
 $("continuity-state").textContent="PRIVATE HUMAN original-source continuity compared locally; no state carried and no findings verified.";
 draw();
}
function draw(){
 if(!differences)return;
 const query=$("finding-search").value.toLowerCase().trim(),kind=$("change-filter").value,values=$("private-values").checked;
 const filtered=differences.lines.filter(r=>
  (kind==="all"||r.kind===kind)&&(!query||r.finding_id.toLowerCase().includes(query)));
 $("shown").textContent=filtered.length+" original ID records shown · PRIVATE human continuity only.";
 const dest=$("continuity-items");dest.replaceChildren();
 if(!filtered.length){
  const p=document.createElement("p");p.textContent="No original ID changes match these local filters.";dest.append(p);return;
 }
 for(const line of filtered.slice(0,350)){
  const card=document.createElement("article");card.className="inbox-item";
  const heading=document.createElement("h3");heading.textContent=line.finding_id;card.append(heading);
  const tag=document.createElement("span");tag.className="tag "+(line.kind==="absent"?"alert":"");
  tag.textContent=line.kind==="absent"?"ABSENT IN NEWER — NOT FIXED":
   line.kind==="new"?"ADDED IN NEWER — SOURCE CLAIM":
   line.kind==="changed"?"PRIVATE HUMAN FIELDS DIFFER":"HUMAN FIELDS UNCHANGED — NOT VERIFIED";
  card.append(tag);
  const fields=document.createElement("p");fields.textContent=line.fields.length?
   "Changed HUMAN fields: "+line.fields.join(", "):
   "No shared HUMAN plan fields changed, or no prior/newer original ID to compare.";
  card.append(fields);
  if(values){
   for(const field of HUMAN_FIELDS){
    if(line.fields.length&&!line.fields.includes(field))continue;
    if(!line.from&&!line.to)continue;
    const p=document.createElement("p");p.textContent=field+
     " · earlier: "+(line.from?.[field]??"(ABSENT)")+
     " · newer: "+(line.to?.[field]??"(ABSENT)");
    card.append(p);
   }
  }
  dest.append(card);
 }
}
function save(name,body,type){
 const url=URL.createObjectURL(new Blob([body],{type})),a=document.createElement("a");
 a.href=url;a.download=name;document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),4000);
}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));}
function exportBrief(){
 if(!differences)return;
 if(!confirm("Export a PRIVATE SCRIPTLESS source-change review containing original IDs, client/engagement and changed HUMAN field names? This is not a security decision. Verify recipient identity and transport."))return;
 const d=differences;
 const rows=d.lines.map(x=>"<tr><td>"+esc(x.finding_id)+"</td><td>"+esc(x.kind==="absent"?"ABSENT UNVERIFIED NOT FIXED":x.kind)+"</td><td>"+
  esc(x.fields.join(", ")||"none or unmatched")+"</td></tr>").join("");
 const text="<!doctype html><html lang='en'><meta charset='utf-8'><meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'\"><title>PRIVATE original HUMAN source change brief</title>"+
 "<style>body{font:15px system-ui;max-width:1000px;margin:35px auto;padding:20px;color:#111}table{border-collapse:collapse;width:100%}td,th{border:1px solid #777;padding:8px;overflow-wrap:anywhere;text-align:left}</style>"+
 "<h1>PRIVATE original HUMAN source continuity</h1><p><strong>UNVERIFIED. ABSENT ORIGINAL FINDINGS ARE NOT VERIFIED FIXED.</strong> No carryover, permissions, client/operator identity verification or approval.</p>"+
 "<p>Earlier source SHA: "+esc(d.baseline)+" → newer source SHA: "+esc(d.newest)+
 " · self-declared client: "+esc(d.client)+" · engagement: "+esc(d.engagement)+
 " · source SHA changed: "+(d.sourceChanged?"YES":"NO")+"</p>"+
 "<table><thead><tr><th>Original ID</th><th>Continuity class</th><th>Changed HUMAN planning fields (values omitted)</th></tr></thead><tbody>"+rows+
 "</tbody></table><p>Original packet differences and changed HUMAN IDs require independent human review before any manual re-entry. Not a migration, client consent, verified remediation, authorization or retest.</p></html>";
 save("LightUp-PRIVATE-HUMAN-original-source-continuity.html",text,"text/html");
 $("continuity-state").textContent="PRIVATE scriptless source continuity brief generated locally.";
}
function exportMinimal(){
 if(!differences)return;
 if(!confirm("Export aggregate original-human-source continuity counts only? Original IDs, client labels, owner names, notes, SHA and dates are omitted. Small cohorts may still reveal context."))return;
 const d=differences;
 save("LightUp-anonymous-original-human-source-continuity.csv",
  "category,count\r\nadded_original_ids,"+d.counts.new+
  "\r\nabsent_unverified_original_ids,"+d.counts.absent+
  "\r\nchanged_human_planning_ids,"+d.counts.changed+
  "\r\nunchanged_human_planning_ids,"+d.counts.same+
  "\r\ndeclared_original_source_sha_changed,"+(d.sourceChanged?1:0)+"\r\n",
  "text/csv");
 $("continuity-state").textContent="Human-only aggregate continuity counts downloaded.";
}
$("old").addEventListener("change",()=>readFile("old"));
$("new").addEventListener("change",()=>readFile("new"));
$("apply-diff").addEventListener("click",compare);
for(const id of ["finding-search","change-filter","private-values"])
 $(id).addEventListener(id==="finding-search"?"input":"change",draw);
$("export-brief").addEventListener("click",exportBrief);
$("export-minimal").addEventListener("click",exportMinimal);
$("clear-diff").addEventListener("click",()=>{
 const confirmed=oldSource||newSource;
 if(confirmed&&!confirm("Forget both PRIVATE original HUMAN source snapshots and all local comparison results?"))return;
 oldSource=null;newSource=null;differences=null;counter++;
 $("old").value="";$("new").value="";$("same-client").checked=false;
 $("old-status").textContent="No earlier source loaded";
 $("new-status").textContent="No newer source loaded";
 $("continuity-state").textContent="Both locally selected PRIVATE HUMAN source sessions forgotten.";
 resetResults();
});
})();