"use strict";
/* Operator-only private offline exchange. No scans, grants, networking or persistence. */
(()=>{
const bridge=window.LightUpReviewBridge,$=id=>document.getElementById(id);
const require_=v=>{if(!v)throw Error("Private reviewer packet HOLD");};
const isObject=x=>x!==null&&typeof x==="object"&&!Array.isArray(x);
const exact=(x,keys)=>isObject(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
const FLAGS=["source_authenticated","ground_truth_verified","client_consent_verified",
 "operator_consent_verified","authorized","consent_verified","dispatch_allowed","release_allowed"];
const FIELDS=["stage","group","next_action","blocker"];
const ROW=["ordinal","severity","title","endpoint_ordinal","original","proposed"];
let pending=null;
const marker=(msg,hold=false)=>{$("collab-status").textContent=(hold?"HOLD — ":"")+msg;};
const safeString=(x,n=2048)=>typeof x==="string"&&x.length>0&&x.length<=n&&
 !/[\u0000-\u001f\u007f]/.test(x);
const text=(tag,x)=>{const e=document.createElement(tag);e.textContent=String(x);return e;};
function humanEqual(a,b){return FIELDS.every(k=>a[k]===b[k]);}
function hashBytes(bytes){return crypto.subtle.digest("SHA-256",bytes).then(buffer=>
 [...new Uint8Array(buffer)].map(x=>x.toString(16).padStart(2,"0")).join("")); }
function hashRecord(payload){return hashBytes(new TextEncoder().encode(JSON.stringify({
 source_sha256:payload.source_sha256,
 rows:payload.rows.map(r=>({ordinal:r.ordinal,original:r.original}))
})));}
function download(name,textValue){
 const blob=new Blob([textValue],{type:"application/json"}),url=URL.createObjectURL(blob);
 const a=document.createElement("a");a.href=url;a.download=name;document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function receiptInput(raw){
 require_(exact(raw,["schema","kind","source_sha256","baseline_sha256","rows","status",...FLAGS]));
 require_(raw.schema==="lightup.private_lab_reviewer_exchange.v1"&&
  ["handoff","reply"].includes(raw.kind)&&raw.status==="REVIEW_ONLY");
 require_(FLAGS.every(k=>raw[k]===false)&&/^[a-f0-9]{64}$/.test(raw.source_sha256)&&
 /^[a-f0-9]{64}$/.test(raw.baseline_sha256));
 require_(Array.isArray(raw.rows)&&raw.rows.length>0&&raw.rows.length<=512);
 let prev=0;
 for(const row of raw.rows){
  require_(exact(row,ROW)&&Number.isSafeInteger(row.ordinal)&&row.ordinal>prev&&
   row.ordinal<=2048&&["critical","high","medium","low","info"].includes(row.severity)&&
   safeString(row.title,8192)&&Number.isSafeInteger(row.endpoint_ordinal)&&
   row.endpoint_ordinal>=0&&row.endpoint_ordinal<=16&&
   bridge.noteValid(row.original)&&bridge.noteValid(row.proposed));
  prev=row.ordinal;
  if(raw.kind==="handoff")require_(humanEqual(row.original,row.proposed));
 }
 return raw;
}
function currentMatch(packet,snap){
 require_(snap&&packet.source_sha256===snap.source_sha256);
 for(const row of packet.rows){
  const found=snap.rows[row.ordinal-1];
  require_(found&&found.ordinal===row.ordinal&&found.severity===row.severity&&
   found.title===row.title&&found.endpoint_ordinal===row.endpoint_ordinal&&
   humanEqual(found.human,row.original));
 }
}
async function prepare(){
 pending=null;$("collab-apply").disabled=true;$("collab-preview").replaceChildren();
 const snap=bridge.snapshot();require_(!!snap);
 const ordinals=snap.selected.length?snap.selected:snap.visible;
 require_(ordinals.length>0&&ordinals.length<=512);
 const selected=new Set(ordinals);
 const rows=snap.rows.filter(x=>selected.has(x.ordinal)).map(x=>({
  ordinal:x.ordinal,severity:x.severity,title:x.title,
  endpoint_ordinal:x.endpoint_ordinal,original:{...x.human},proposed:{...x.human}
 }));
 require_(rows.length===ordinals.length);
 if(!confirm("Create PRIVATE reviewer handoff for "+rows.length+
  " selected original source finding titles and human notes? Separately verify the intended recipient and confidential channel."))return;
 const packet={schema:"lightup.private_lab_reviewer_exchange.v1",kind:"handoff",
  source_sha256:snap.source_sha256,baseline_sha256:"",rows,status:"REVIEW_ONLY",
  ...Object.fromEntries(FLAGS.map(k=>[k,false]))};
 packet.baseline_sha256=await hashRecord(packet);
 download("PRIVATE-lab-reviewer-handoff.json",JSON.stringify(packet,null,2)+"\n");
 marker("PRIVATE source-bound reviewer packet saved locally. Share only through a separately approved channel.");
}
async function importReply(file){
 require_(!!file&&file.size>0&&file.size<=2*1024*1024);
 const raw=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
 const packet=receiptInput(bridge.strictJSON(raw));
 require_(packet.kind==="reply");
 const baseline=await hashRecord(packet);
 require_(baseline===packet.baseline_sha256);
 const snap=bridge.snapshot();currentMatch(packet,snap);
 const changes=packet.rows.filter(r=>!humanEqual(r.original,r.proposed));
 require_(changes.length>0);
 // Do not retain stale pending proposals after a rejected admission.
 const table=document.createElement("table"),head=document.createElement("tr");
 ["Original slot","Original source title (PRIVATE)","Human field","Prior human note","Proposed human note"]
  .forEach(x=>head.append(text("th",x)));
 const thead=document.createElement("thead");thead.append(head);table.append(thead);
 const tbody=document.createElement("tbody");let count=0;
 for(const row of changes){
  for(const key of FIELDS){
   if(row.original[key]===row.proposed[key])continue;
   const tr=document.createElement("tr");
   [row.ordinal,row.title,key,row.original[key]||"(blank)",row.proposed[key]||"(blank)"]
    .forEach((x,i)=>{const c=text("td",x);if(i===4)c.className="change-new";tr.append(c);});
   tbody.append(tr);count++;
  }
 }
 table.append(tbody);$("collab-preview").replaceChildren(text("p",
  changes.length+" proposed source-bound human rows; "+count+
  " changed human fields. Original assessment evidence, source reports and permissions are NOT changed."),table);
 pending=packet;$("collab-apply").disabled=false;
 marker("PRIVATE reviewer return admitted; inspect changes and explicitly accept before applying.");
}
async function accept(){
 const packet=pending;require_(!!packet);
 // Explicitly recheck current source and source-bound human baseline at action time.
 const snap=bridge.snapshot();currentMatch(packet,snap);
 require_(await hashRecord(packet)===packet.baseline_sha256);
 const selected=packet.rows.filter(x=>!humanEqual(x.original,x.proposed));
 require_(selected.length>0);
 pending=null;$("collab-apply").disabled=true;
 if(bridge.applyRows(packet.source_sha256,selected.map(r=>({
  ordinal:r.ordinal,original:r.original,proposed:r.proposed
 })))){$("collab-preview").replaceChildren();marker("Changed human notes applied locally. Save a new PRIVATE operator review to retain them.");}
 else marker("Human changes not accepted; original local notes remain untouched.");
}
$("collab-send").addEventListener("click",()=>prepare().catch(()=>marker("Private selection unavailable. Filter to 1–512 admitted rows with original browser SHA-256.",true)));
$("collab-receive").addEventListener("change",e=>{
 pending=null;$("collab-apply").disabled=true;$("collab-preview").replaceChildren();
 importReply(e.target.files[0]).catch(()=>marker("Private reviewer reply rejected. Operator workspace unchanged.",true))
 .finally(()=>{e.target.value="";});
});
$("collab-apply").addEventListener("click",()=>accept().catch(()=>{
 pending=null;$("collab-apply").disabled=true;$("collab-preview").replaceChildren();
 marker("Reviewer return is stale, changed or incomplete. No human note applied.",true);
}));
marker("No reviewer handoff or reply loaded.");
})();