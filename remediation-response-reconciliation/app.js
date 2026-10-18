/* LightUp PRIVATE HUMAN Response Register. Offline only; no authority/consent/scan. */
(() => {
"use strict";
const $=id=>document.getElementById(id);
const FLAGS=["authenticated","tenant_verified","source_authorized","assessment_authorized","grant","client_consent","operator_consent","execution","scan","audit_verdict","retest_verified","release"];
const HEAD=["kind","schema_version","disposition","source_contract","source_sha256","client_reference","engagement_reference","recipient_alias","reply_kind","issued_utc","reply_utc","requests",...FLAGS];
const ROW=["request_id","finding_id","request_kind","instructions","due_date","human_stage","human_response"];
const KINDS=["missing_evidence","patch_change","deployment_record","rollback_plan","retest_request","followup_question","other"];
const STAGES=["not_reviewed","needs_human_followup","human_triaged"];
const LIMIT=1048576,MAX_PACKETS=24,MAX_ROWS=800;
const blank=()=>({binding:null,requestPackets:[],replyPackets:[],notes:{},revision:0});
let db=blank();
function fail(m){throw Error(m);}
function same(a,b){return JSON.stringify(a)===JSON.stringify(b);}
function exact(x,keys){return x&&Object.getPrototypeOf(x)===Object.prototype&&Object.keys(x).length===keys.length&&Object.keys(x).every(k=>keys.includes(k));}
function clean(x,n,label,required=false){
 if(typeof x!=="string"||x.length>n||x.includes("\0")||/[\u202a-\u202e\u2066-\u2069]/.test(x)||(required&&!x.trim()))fail("Invalid "+label);
 return x;
}
function timestamp(x){
 if(typeof x!=="string"||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x)||!Number.isFinite(Date.parse(x))||new Date(x).toISOString()!==x)fail("Invalid HUMAN timestamp");
}
function due(x){
 if(x==="")return;
 if(typeof x!=="string"||!/^\d{4}-\d\d-\d\d$/.test(x)||!Number.isFinite(Date.parse(x+"T00:00:00Z"))||new Date(x+"T00:00:00Z").toISOString().slice(0,10)!==x)fail("Invalid tentative due date");
}
function strictJSON(s){
 if(typeof s!=="string"||new TextEncoder().encode(s).length>LIMIT)fail("PRIVATE JSON exceeds 1 MiB");
 let i=0,n=0;
 const ws=()=>{while(i<s.length&&/[ \r\n\t]/.test(s[i]))i++;};
 function quoted(){
  if(s[i]!=='"')fail("JSON string expected");
  const a=i++;let esc=false;
  while(i<s.length){const c=s[i++];if(esc){esc=false;continue;}if(c==="\\"){esc=true;continue;}
   if(c==='"')return JSON.parse(s.slice(a,i));if(c<" ")fail("JSON control character");}
  fail("Unclosed JSON string");
 }
 function visit(depth){
  if(++n>40000||depth>30)fail("PRIVATE JSON exceeds nesting limit");
  ws();const c=s[i];
  if(c==="{"){i++;ws();const seen=new Set();if(s[i]==="}"){i++;return;}
   while(true){ws();const k=quoted();if(seen.has(k))fail("Duplicate PRIVATE JSON key");seen.add(k);ws();if(s[i++]!==":")fail("JSON colon expected");
    visit(depth+1);ws();const sep=s[i++];if(sep==="}")return;if(sep!==",")fail("JSON comma expected");}
  }
  if(c==="["){i++;ws();if(s[i]==="]"){i++;return;}
   while(true){visit(depth+1);ws();const sep=s[i++];if(sep==="]")return;if(sep!==",")fail("JSON array separator expected");}
  }
  if(c==='"'){quoted();return;}
  const scalar=/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(s.slice(i));
  if(!scalar)fail("Invalid JSON scalar");i+=scalar[0].length;
 }
 visit(0);ws();if(i!==s.length)fail("Trailing JSON content");
 return JSON.parse(s);
}
function admit(p){
 if(!exact(p,HEAD)||p.kind!=="lightup.private_human_evidence_owner_handoff"||
 p.schema_version!==1||p.disposition!=="UNVERIFIED_HUMAN_REQUEST_ONLY"||
 p.source_contract!=="lightup.finding_export._COLUMNS_v1"||
 !/^[0-9a-f]{64}$/.test(p.source_sha256)||FLAGS.some(k=>p[k]!==false)||
 !["owner_request","unverified_human_reply"].includes(p.reply_kind)||
 !Array.isArray(p.requests)||!p.requests.length||p.requests.length>60)
  fail("HOLD: not an exact original non-authorizing owner request/reply packet");
 clean(p.client_reference,120,"client",true);clean(p.engagement_reference,120,"engagement",true);
 clean(p.recipient_alias,120,"recipient alias",true);timestamp(p.issued_utc);
 if(p.reply_kind==="owner_request" ? p.reply_utc!==null : typeof p.reply_utc!=="string")
  fail("HOLD: reply timestamp does not match packet kind");
 if(p.reply_kind==="unverified_human_reply")timestamp(p.reply_utc);
 const seen=new Set();
 for(const r of p.requests){
  if(!exact(r,ROW)||typeof r.request_id!=="string"||!/^[0-9a-f]{32}$/.test(r.request_id)||seen.has(r.request_id))
   fail("Invalid or repeated original HUMAN request ID");
  seen.add(r.request_id);clean(r.finding_id,160,"original finding",true);
  if(!KINDS.includes(r.request_kind))fail("Unknown HUMAN request type");
  clean(r.instructions,1400,"original HUMAN instructions",true);due(r.due_date);
  if(p.reply_kind==="owner_request"){
   if(r.human_stage!=="requested_human"||r.human_response!=="")fail("Original HUMAN request must be unanswered");
  }else{
   if(!["submitted_unverified","needs_changes"].includes(r.human_stage))
    fail("Invalid unverified HUMAN reply stage");
   clean(r.human_response,1800,"unverified HUMAN reply",true);
  }
 }
 return p;
}
const sourceId=p=>[p.source_contract,p.source_sha256,p.client_reference,p.engagement_reference];
const requestId=(p,r)=>[p.recipient_alias,p.issued_utc,r.request_id,r.finding_id,r.request_kind,r.instructions,r.due_date];
function assemble(current,packets){
 const next={binding:current.binding&&[...current.binding],requestPackets:[...current.requestPackets],
  replyPackets:[...current.replyPackets],notes:{...current.notes},revision:current.revision+1};
 const validated=packets.map(admit);
 if(!validated.length)fail("No PRIVATE packets selected");
 const binding=next.binding||sourceId(validated[0]);
 for(const p of validated)if(!same(binding,sourceId(p)))fail("HOLD: original source SHA, client or engagement differs");
 next.binding=binding;
 for(const p of validated.filter(x=>x.reply_kind==="owner_request")){
  const prior=next.requestPackets.find(x=>x.recipient_alias===p.recipient_alias&&x.issued_utc===p.issued_utc);
  if(prior){if(!same(prior,p))fail("HOLD: changed original owner request packet");continue;}
  for(const r of p.requests)if(next.requestPackets.some(x=>x.requests.some(t=>t.request_id===r.request_id)))
   fail("HOLD: same request ID reused by distinct original owner packet");
  next.requestPackets.push(p);
 }
 for(const p of validated.filter(x=>x.reply_kind==="unverified_human_reply")){
  const req=next.requestPackets.find(x=>x.recipient_alias===p.recipient_alias&&x.issued_utc===p.issued_utc);
  if(!req)fail("HOLD: original owner request packet required for each reply");
  for(const r of p.requests){
   const original=req.requests.find(x=>x.request_id===r.request_id);
   if(!original||!same(requestId(req,original),requestId(p,r)))
    fail("HOLD: reply changed original owner/source/request context");
   const existing=next.replyPackets.flatMap(x=>x.requests).find(x=>x.request_id===r.request_id);
   if(existing&&!same(existing,r))fail("HOLD: conflicting partial HUMAN replies; resolve independently");
  }
  if(next.replyPackets.some(x=>same(x,p)))continue;
  // Multiple packets containing a previously seen identical row also have ambiguous issued/reply metadata.
  if(p.requests.some(r=>next.replyPackets.some(x=>x.requests.some(y=>y.request_id===r.request_id))))
   fail("HOLD: duplicate HUMAN response across different reply packets");
  next.replyPackets.push(p);
 }
 if(next.requestPackets.length+next.replyPackets.length>MAX_PACKETS||
 next.requestPackets.reduce((n,p)=>n+p.requests.length,0)>MAX_ROWS)
  fail("Capacity exceeded: 24 packets or 800 HUMAN requests maximum");
 return next;
}
function allRows(store=db){
 const replied=new Map(store.replyPackets.flatMap(p=>p.requests.map(r=>[r.request_id,r])));
 return store.requestPackets.flatMap((p,i)=>p.requests.map(r=>({slot:i+1,packet:p,request:r,
  reply:replied.get(r.request_id)||null,
  review:store.notes[r.request_id]||{stage:"not_reviewed",note:""}})));
}
function msg(m,err=false){$("message").textContent=m;$("message").dataset.error=err?"true":"false";}
function node(tag,value){const n=document.createElement(tag);n.textContent=String(value);return n;}
const selection=new Set();
let pendingBulk=null;
function invalidateBulk(){
 pendingBulk=null;$("bulkDetails").hidden=true;$("bulkApply").disabled=true;
 $("selectShown").checked=false;
}
function filteredRows(){
 const q=$("search").value.toLowerCase().trim(),filter=$("filter").value,
  dateMode=$("dueFilter").value,today=new Date().toISOString().slice(0,10);
 const week=new Date(Date.now()+7*86400000).toISOString().slice(0,10);
 const entries=allRows().filter(x=>{
  if(q&&![x.packet.recipient_alias,x.request.request_id,x.request.finding_id,x.request.request_kind].join(" ").toLowerCase().includes(q))return false;
  if(filter==="unanswered"&&x.reply)return false;
  if(filter==="replied"&&!x.reply)return false;
  if(filter==="needs_changes"&&(!x.reply||x.reply.human_stage!=="needs_changes"))return false;
  if(filter==="triage"&&x.review.stage==="human_triaged")return false;
  const d=x.request.due_date;
  if(dateMode==="overdue"&&(!d||d>=today))return false;
  if(dateMode==="week"&&(!d||d<today||d>week))return false;
  if(dateMode==="undated"&&d)return false;
  return true;
 });
 const sort=$("sort").value;
 if(sort==="due")entries.sort((a,b)=>(a.request.due_date||"9999-12-31").localeCompare(b.request.due_date||"9999-12-31"));
 if(sort==="owner")entries.sort((a,b)=>a.packet.recipient_alias.localeCompare(b.packet.recipient_alias));
 if(sort==="triage")entries.sort((a,b)=>a.review.stage.localeCompare(b.review.stage));
 return entries;
}
function contextDetails(x){
 const cell=document.createElement("td"),details=document.createElement("details"),
  title=node("summary",x.reply?"Review PRIVATE human response":"Review ORIGINAL human request");
 details.append(title);
 for(const [label,value] of [
  ["ORIGINAL request ID",x.request.request_id],
  ["Issued UTC (self-declared)",x.packet.issued_utc],
  ["ORIGINAL HUMAN instructions",x.request.instructions],
  ["HUMAN reply status",x.reply?x.reply.human_stage:"unanswered"],
  ["Unverified owner response",x.reply?x.reply.human_response:"Not received; no fix inferred."]
 ]){
  const row=document.createElement("div"),strong=node("strong",label+": "),
   content=node("span",value);
  row.className="privateDetail";row.append(strong,content);details.append(row);
 }
 cell.append(details);return cell;
}
function draw(){
 const all=allRows(),answered=all.filter(x=>x.reply).length,
  needs=all.filter(x=>x.reply&&x.reply.human_stage==="needs_changes").length;
 $("summary").textContent=all.length+" HUMAN requests · "+answered+" UNVERIFIED replies · "+(all.length-answered)+" unanswered · "+needs+" need changes · "+db.requestPackets.length+" owner packets";
 $("binding").textContent=db.binding?"DECLARED source SHA "+db.binding[1]+" · client "+db.binding[2]+" · engagement "+db.binding[3]:"No source loaded.";
 for(const id of ["download","csv","print","summaryCsv"])$(id).disabled=!all.length;
 const visible=filteredRows();
 $("count").textContent=visible.length+" rows shown; "+selection.size+" selected. All owner labels and replies remain UNVERIFIED.";
 const shown=new Set(visible.map(x=>x.request.request_id));
 $("selectShown").checked=visible.length>0&&visible.every(x=>selection.has(x.request.request_id));
 $("selectShown").indeterminate=visible.some(x=>selection.has(x.request.request_id))&&!$("selectShown").checked;
 $("bulkPreview").disabled=!selection.size;
 const body=$("rows");body.replaceChildren();
 for(const x of visible){
  const tr=node("tr","");
  const choice=document.createElement("td"),check=document.createElement("input");
  check.type="checkbox";check.checked=selection.has(x.request.request_id);
  check.setAttribute("aria-label","Select ORIGINAL HUMAN request "+x.request.request_id);
  check.addEventListener("change",()=>{
   if(check.checked)selection.add(x.request.request_id);else selection.delete(x.request.request_id);
   invalidateBulk();draw();
  });
  choice.append(check);tr.append(choice);
  for(const v of [x.slot,x.packet.recipient_alias,x.request.finding_id,x.request.request_kind,x.request.due_date||"—",x.reply?x.reply.human_stage:"unanswered"])
   tr.append(node("td",v));
  tr.append(contextDetails(x));
  const sel=document.createElement("select");
  sel.setAttribute("aria-label","Human triage for "+x.request.finding_id);
  for(const label of STAGES)sel.append(new Option(label.replaceAll("_"," "),label));
  sel.value=x.review.stage;
  sel.addEventListener("change",()=>{
   db.notes[x.request.request_id]={...db.notes[x.request.request_id]||x.review,stage:sel.value};
   db.revision++;invalidateBulk();msg("Local HUMAN triage changed; original request and reply untouched.");
  });
  const stage=document.createElement("td");stage.append(sel);tr.append(stage);
  const input=document.createElement("textarea");input.rows=2;input.maxLength=400;
  input.setAttribute("aria-label","PRIVATE human note for "+x.request.finding_id);input.value=x.review.note;
  input.addEventListener("input",()=>{
   db.notes[x.request.request_id]={...db.notes[x.request.request_id]||x.review,note:input.value};
   db.revision++;invalidateBulk();
  });
  const note=document.createElement("td");note.append(input);tr.append(note);body.append(tr);
 }
}
function previewBulk(){
 const originals=allRows().filter(x=>selection.has(x.request.request_id));
 if(!originals.length||originals.length!==selection.size)fail("HOLD: selected original IDs are stale; reload");
 const stage=$("bulkStage").value;if(!STAGES.includes(stage))fail("Invalid HUMAN bulk stage");
 const changes=originals.map(x=>({id:x.request.request_id,finding:x.request.finding_id,
  before:x.review.stage,after:stage,owner:x.packet.recipient_alias}));
 pendingBulk={revision:db.revision,binding:JSON.stringify(db.binding),
  ids:JSON.stringify([...selection].sort()),stage,changes};
 const lines=["PRIVATE HUMAN change preview · "+changes.length+" ORIGINAL request IDs",
  "UNVERIFIED source SHA "+db.binding[1],
  "No original evidence, assessment, consent, grant, retest, delivery or verified fix changes.",
  ...changes.map(x=>x.finding+" | "+x.id+" | HUMAN "+x.before+" → "+x.after+" | "+x.owner)];
 $("bulkDetails").textContent=lines.join("\n");
 $("bulkDetails").hidden=false;$("bulkApply").disabled=false;
 msg("Review the original source-bound HUMAN changes before applying them in memory.");
}
function applyBulk(){
 const p=pendingBulk;
 if(!p||p.revision!==db.revision||p.binding!==JSON.stringify(db.binding)||
 p.ids!==JSON.stringify([...selection].sort())||p.stage!==$("bulkStage").value)
  fail("HOLD: HUMAN source, stage, selection or notes changed. Preview again.");
 const map=new Map(allRows().map(x=>[x.request.request_id,x]));
 if(p.changes.some(x=>!map.has(x.id)||map.get(x.id).review.stage!==x.before))
  fail("HOLD: original HUMAN baselines changed. Preview again.");
 if(!confirm("Apply local HUMAN triage status to "+p.changes.length+" ORIGINAL requests? This does NOT verify fixes, authorize a retest or send any notification."))return;
 for(const change of p.changes){
  const existing=map.get(change.id).review;
  db.notes[change.id]={stage:p.stage,note:existing.note};
 }
 db.revision++;selection.clear();invalidateBulk();draw();
 msg("Applied "+p.changes.length+" HUMAN-only local stage changes. Original source and unverified replies untouched.");
}
function anonymousCounts(){
 const groups=new Map();
 for(const x of allRows()){
  const key=[x.request.request_kind,x.reply?x.reply.human_stage:"unanswered",x.review.stage];
  const text=JSON.stringify(key);groups.set(text,(groups.get(text)||0)+1);
 }
 const table=[["human_request_kind","unverified_reply_status","local_human_triage","count"]];
 for(const [key,count] of [...groups.entries()].sort((a,b)=>a[0].localeCompare(b[0])))
  table.push([...JSON.parse(key),count]);
 return table;
}
function exportAnonymous(){
 if(!db.binding)fail("Load original PRIVATE packets first");
 if(!confirm("Export aggregate HUMAN request counts only? Counts do not establish evidence coverage, remediation status or source authenticity."))return;
 save("LightUp-anonymous-human-response-counts.csv",
  anonymousCounts().map(row=>row.map(csv).join(",")).join("\r\n")+"\r\n","text/csv");
}
async function intake(){
 const files=[...$("files").files];
 if(!files.length||files.length>MAX_PACKETS)fail("Select 1–24 PRIVATE JSON files");
 const rev=db.revision,packets=[];
 for(const f of files){
  if(f.size>LIMIT)fail("PRIVATE file exceeds 1 MiB");
  const raw=new TextDecoder("utf-8",{fatal:true}).decode(await f.arrayBuffer());
  packets.push(strictJSON(raw));
 }
 if(db.revision!==rev)fail("HOLD: register changed during asynchronous import");
 if(packets.length===1&&packets[0].kind==="lightup.private_human_response_reconciliation"){
  restore(packets[0],rev);return;
 }
 const next=assemble(db,packets);
 if(!confirm("Import "+packets.length+" PRIVATE human packets? All identities, replies and source labels are UNVERIFIED. No data are sent, no retest or consent is granted."))return;
 if(db.revision!==rev)fail("HOLD: register changed before confirmation");
 db=next;selection.clear();invalidateBulk();$("files").value="";draw();msg("Reconciled PRIVATE HUMAN owner and reply packets atomically.");
}
function snapshot(){
 return {kind:"lightup.private_human_response_reconciliation",schema_version:1,
 disposition:"UNVERIFIED_HUMAN_COORDINATION_ONLY",source_contract:db.binding[0],
 source_sha256:db.binding[1],client_reference:db.binding[2],engagement_reference:db.binding[3],
 ...Object.fromEntries(FLAGS.map(k=>[k,false])),
 request_packets:db.requestPackets,reply_packets:db.replyPackets,
 human_reviews:allRows().map(x=>({request_id:x.request.request_id,human_stage:x.review.stage,note:x.review.note}))};
}
function restore(obj,rev){
 const keys=["kind","schema_version","disposition","source_contract","source_sha256","client_reference","engagement_reference",
 ...FLAGS,"request_packets","reply_packets","human_reviews"];
 if(!exact(obj,keys)||obj.schema_version!==1||
 obj.disposition!=="UNVERIFIED_HUMAN_COORDINATION_ONLY"||
 obj.source_contract!=="lightup.finding_export._COLUMNS_v1"||
 !/^[0-9a-f]{64}$/.test(obj.source_sha256)||FLAGS.some(k=>obj[k]!==false)||
 !Array.isArray(obj.request_packets)||!Array.isArray(obj.reply_packets)||
 !Array.isArray(obj.human_reviews)||obj.human_reviews.length>MAX_ROWS)
  fail("HOLD: invalid PRIVATE register backup");
 clean(obj.client_reference,120,"client",true);clean(obj.engagement_reference,120,"engagement",true);
 const fresh=assemble(blank(),[...obj.request_packets,...obj.reply_packets]);
 if(!same(fresh.binding,[obj.source_contract,obj.source_sha256,obj.client_reference,obj.engagement_reference]))
  fail("HOLD: original source of backup changed");
 const allowed=new Set(allRows(fresh).map(x=>x.request.request_id)),seen=new Set();
 for(const r of obj.human_reviews){
  if(!exact(r,["request_id","human_stage","note"])||!allowed.has(r.request_id)||seen.has(r.request_id)||!STAGES.includes(r.human_stage))
   fail("HOLD: duplicate or unexpected HUMAN review in backup");
  seen.add(r.request_id);clean(r.note,400,"PRIVATE HUMAN note");
  fresh.notes[r.request_id]={stage:r.human_stage,note:r.note};
 }
 if(seen.size!==allowed.size)fail("HOLD: incomplete HUMAN review backup");
 if(db.revision!==rev)fail("HOLD: changed register");
 if(!confirm("REPLACE current PRIVATE register and HUMAN notes with this exact source-bound backup? Export current data first."))return;
 if(db.revision!==rev)fail("HOLD: changed register before replace");
 fresh.revision=rev+1;db=fresh;selection.clear();invalidateBulk();$("files").value="";draw();msg("Restored PRIVATE HUMAN register from original-bound local backup.");
}
function save(filename,body,mime){
 const url=URL.createObjectURL(new Blob([body],{type:mime}));
 const a=document.createElement("a");a.href=url;a.download=filename;document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function csv(x){
 let v=String(x??"");
 const normalized=v.normalize("NFKC").replace(/[\u200b-\u200f\u2060\ufeff]/g,"").replace(/^[\s\u0000-\u001f]+/g,"");
 if(/^[=+\-@]/.test(normalized))v="'"+v;
 return '"'+v.replaceAll('"','""')+'"';
}
function exportCSV(){
 if(!db.binding)fail("Load original HUMAN packets first");
 if(!confirm("Export PRIVATE original IDs and self-declared HUMAN aliases? Confirm secure recipient and channel."))return;
 const table=[["batch","original_request_id","original_finding_id","human_owner_alias","request_kind","tentative_due",
 "unverified_reply","local_human_triage"],...allRows().map(x=>[x.slot,x.request.request_id,x.request.finding_id,
 x.packet.recipient_alias,x.request.request_kind,x.request.due_date,x.reply?x.reply.human_stage:"unanswered",x.review.stage])];
 save("LightUp-PRIVATE-response-register.csv",table.map(row=>row.map(csv).join(",")).join("\r\n")+"\r\n","text/csv");
}
function report(){
 if(!confirm("Open PRIVATE report containing original finding IDs and HUMAN aliases? No data sent."))return;
 const win=window.open("","_blank");
 if(!win)fail("Popup blocked; allow local PRIVATE print window");
 const d=win.document;d.open();
 d.write('<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'"><title>PRIVATE HUMAN review</title><style>body{font:15px system-ui;margin:2em}table{border-collapse:collapse}td,th{border:1px solid gray;padding:8px}</style></head><body><main id="report"></main></body></html>');
 d.close();const main=d.getElementById("report");
 function cell(tag,v){const e=d.createElement(tag);e.textContent=v;return e;}
 main.append(cell("h1","LightUp PRIVATE · Unverified HUMAN response overview"));
 main.append(cell("p","No identity verification, consent, remediation certification, scan or execution authority."));
 main.append(cell("p",db.binding.join(" · ")));
 const t=d.createElement("table"),headers=d.createElement("tr");
 for(const v of ["Owner alias","Original finding","Request","UNVERIFIED reply","Local HUMAN triage","PRIVATE note"])headers.append(cell("th",v));
 t.append(headers);
 for(const x of allRows()){const tr=d.createElement("tr");
  for(const v of [x.packet.recipient_alias,x.request.finding_id,x.request.request_kind,
   x.reply?x.reply.human_stage:"unanswered",x.review.stage,x.review.note])tr.append(cell("td",v));
  t.append(tr);}
 main.append(t);msg("Opened PRIVATE scriptless print brief in a local window.");
}
function listen(id,fn){$(id).addEventListener("click",async()=>{try{await fn();}catch(e){msg(e.message||"Invalid PRIVATE input",true);}});}
listen("load",intake);
listen("download",()=>{if(!db.binding)fail("No PRIVATE register loaded");
 if(!confirm("Download PRIVATE owner identities, original request IDs, unverified replies and HUMAN notes? Confirm secure storage."))return;
 save("LightUp-PRIVATE-response-register.json",JSON.stringify(snapshot(),null,2)+"\n","application/json");});
listen("csv",exportCSV);listen("summaryCsv",exportAnonymous);listen("print",report);
listen("bulkPreview",previewBulk);listen("bulkApply",applyBulk);
$("selectShown").addEventListener("change",e=>{for(const x of filteredRows()){
 if(e.target.checked)selection.add(x.request.request_id);else selection.delete(x.request.request_id);
 }invalidateBulk();draw();});
$("bulkStage").addEventListener("change",invalidateBulk);
listen("forget",()=>{if(!confirm("Clear ALL in-memory human responses and PRIVATE annotations? Saved downloads remain."))return;
 const rev=db.revision+1;db=blank();db.revision=rev;selection.clear();invalidateBulk();$("files").value="";$("search").value="";draw();msg("All locally held PRIVATE HUMAN data forgotten.");});
$("search").addEventListener("input",draw);$("filter").addEventListener("change",draw);
$("dueFilter").addEventListener("change",draw);$("sort").addEventListener("change",draw);
draw();msg("Load original PRIVATE owner-request and partial-reply files. Everything stays in memory.");
})();