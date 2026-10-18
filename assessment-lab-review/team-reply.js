"use strict";
/* PRIVATE, completely offline recipient editing of source-bound human notes. */
(()=>{
const $=id=>document.getElementById(id);
const FIELDS=["stage","group","next_action","blocker"];
const STAGES=["needs_review","discussing","documented","blocked"];
const GROUPS=["unassigned","scope","findings","evidence","remediation"];
const FLAGS=["source_authenticated","ground_truth_verified","client_consent_verified",
 "operator_consent_verified","authorized","consent_verified","dispatch_allowed","release_allowed"];
const KEYS=["schema","kind","source_sha256","baseline_sha256","rows","status",...FLAGS];
const ROW=["ordinal","severity","title","endpoint_ordinal","original","proposed"];
let packet=null,changedAfterPreview=true,lastBulkUndo=null;
const fail=msg=>{throw Error(msg||"Private review packet HOLD");};
const require_=x=>{if(!x)fail();};
const obj=x=>x!==null&&typeof x==="object"&&!Array.isArray(x);
const exact=(x,ks)=>obj(x)&&Object.keys(x).length===ks.length&&ks.every(k=>Object.hasOwn(x,k));
const valid=x=>typeof x==="string"&&x.length<=500&&!/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(x);
const validNote=n=>exact(n,FIELDS)&&STAGES.includes(n.stage)&&GROUPS.includes(n.group)&&
 valid(n.next_action)&&valid(n.blocker);
const humanEqual=(a,b)=>FIELDS.every(k=>a[k]===b[k]);
const status=(msg,err=false)=>{$("status").textContent=(err?"HOLD — ":"")+msg;$("status").dataset.error=String(err);};
const make=(tag,label)=>{const e=document.createElement(tag);if(label!==undefined)e.textContent=String(label);return e;};
function strictJSON(src){
 let i=0,n=0;
 const ws=()=>{while(i<src.length&&/\s/.test(src[i]))i++;};
 function str(){
  require_(src[i]==='"');const start=i++;let escape=false;
  while(i<src.length){const c=src[i++];
   if(c==='"'&&!escape)return JSON.parse(src.slice(start,i));
   if(c==="\\"&&!escape)escape=true;else escape=false;
  }fail();
 }
 function val(depth){
  require_(depth<30&&++n<=150000);ws();const c=src[i];
  if(c==='"')return str();
  if(c==="{"){
   i++;const o=Object.create(null),seen=new Set();ws();if(src[i]==="}"){i++;return o;}
   while(true){ws();const key=str();require_(!seen.has(key));seen.add(key);ws();
    require_(src[i++] === ":");o[key]=val(depth+1);ws();
    if(src[i]==="}"){i++;return o;}require_(src[i++] === ",");
   }
  }
  if(c==="["){
   i++;const a=[];ws();if(src[i]==="]"){i++;return a;}
   while(true){require_(a.length<150000);a.push(val(depth+1));ws();
    if(src[i]==="]"){i++;return a;}require_(src[i++] === ",");
   }
  }
  for(const [lit,v] of [["true",true],["false",false],["null",null]]){
   if(src.startsWith(lit,i)){i+=lit.length;return v;}
  }
  const m=src.slice(i).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
  require_(m);i+=m[0].length;const value=Number(m[0]);require_(Number.isFinite(value));return value;
 }
 const v=val(0);ws();require_(i===src.length);return v;
}
async function hashRecord(p){
 const value=JSON.stringify({source_sha256:p.source_sha256,
  rows:p.rows.map(r=>({ordinal:r.ordinal,original:r.original}))});
 const buffer=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(value));
 return [...new Uint8Array(buffer)].map(x=>x.toString(16).padStart(2,"0")).join("");
}
async function admit(x,kind="handoff"){
 require_(exact(x,KEYS)&&x.schema==="lightup.private_lab_reviewer_exchange.v1"&&
  x.kind===kind&&x.status==="REVIEW_ONLY"&&FLAGS.every(k=>x[k]===false)&&
  /^[a-f0-9]{64}$/.test(x.source_sha256)&&/^[a-f0-9]{64}$/.test(x.baseline_sha256));
 require_(Array.isArray(x.rows)&&x.rows.length>=1&&x.rows.length<=512);
 let prev=0;for(const row of x.rows){
  require_(exact(row,ROW)&&Number.isSafeInteger(row.ordinal)&&row.ordinal>prev&&row.ordinal<=2048&&
   ["critical","high","medium","low","info"].includes(row.severity)&&
   typeof row.title==="string"&&row.title.length>0&&row.title.length<=8192&&
   !/[\u0000-\u001f\u007f]/.test(row.title)&&
   Number.isSafeInteger(row.endpoint_ordinal)&&row.endpoint_ordinal>=0&&row.endpoint_ordinal<=16&&
   validNote(row.original)&&validNote(row.proposed)&&
   (kind==="reply"||humanEqual(row.original,row.proposed)));
  prev=row.ordinal;
 }
 require_(await hashRecord(x)===x.baseline_sha256);
 return x;
}
function markDirty(){
 changedAfterPreview=true;$("export").disabled=true;$("preview").replaceChildren();
 const count=packet.rows.filter(r=>!humanEqual(r.original,r.proposed)).length;
 $("count").textContent=count+" modified HUMAN rows · PRIVATE / not verified";
}
function field(row,key){
 const label=make("label"),caption=make("span",key.replaceAll("_"," "));
 label.append(caption);let input;
 if(key==="stage"||key==="group"){
  input=make("select");
  (key==="stage"?STAGES:GROUPS).forEach(v=>{
   const opt=make("option",v.replaceAll("_"," "));opt.value=v;input.append(opt);
  });
 }else{input=make("textarea");input.rows=2;input.maxLength=500;}
 input.value=row.proposed[key];input.addEventListener("input",()=>{
  const value=input.value;if(!valid(value))return;
  const n={...row.proposed,[key]:value};if(validNote(n)){
   row.proposed=n;lastBulkUndo=null;markDirty();
  }
 });label.append(input);return label;
}
function render(){
 const wrap=$("rows");wrap.replaceChildren();if(!packet)return;
 const filter=$("filter").value;
 packet.rows.forEach(row=>{
  if(filter&&filter!==row.severity&&filter!==row.proposed.stage)return;
  const card=make("article");card.className="finding";
  card.append(make("h3","Original #"+row.ordinal+" · "+row.severity.toUpperCase()+
   " · "+(row.endpoint_ordinal?"local endpoint "+row.endpoint_ordinal:"unmatched source asset")));
  card.append(make("p",row.title));
  const form=make("div");form.className="grid";
  FIELDS.forEach(k=>form.append(field(row,k)));card.append(form);wrap.append(card);
 });
}
function preview(){
 require_(packet);
 require_(packet.rows.every(r=>validNote(r.proposed)));
 const changed=packet.rows.filter(r=>!humanEqual(r.original,r.proposed));
 require_(changed.length>0);
 const table=make("table"),head=make("tr");
 ["Original slot","Human field","Previous","Proposed"].forEach(x=>head.append(make("th",x)));
 const thead=make("thead");thead.append(head);table.append(thead);
 const body=make("tbody");let diffs=0;
 for(const row of changed)for(const key of FIELDS){
  if(row.original[key]===row.proposed[key])continue;
  const tr=make("tr");
  [row.ordinal,key,row.original[key]||"(blank)",row.proposed[key]||"(blank)"]
   .forEach(x=>tr.append(make("td",x)));body.append(tr);diffs++;
 }
 table.append(body);$("preview").replaceChildren(make("p",
  "PRIVATE proposed HUMAN differences: "+changed.length+" original rows / "+diffs+
  " human fields. No source, evidence, verified remediation or permission changed."),table);
 changedAfterPreview=false;$("export").disabled=false;
 status("Review proposed human changes above before explicitly exporting.");
}
function download(name,text){
 const blob=new Blob([text],{type:"application/json"});const url=URL.createObjectURL(blob);
 const a=make("a");a.href=url;a.download=name;document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),1000);
}
$("upload").addEventListener("change",async e=>{
 try{
  const file=e.target.files[0];require_(file&&file.size>0&&file.size<=2*1024*1024&&
   globalThis.crypto&&crypto.subtle);
  const src=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
  const next=await admit(strictJSON(src));
  if(packet&&!confirm("Replace current unsaved private recipient notes?"))return;
  packet=next;changedAfterPreview=true;lastBulkUndo=null;$("workspace").hidden=false;$("export").disabled=true;
  $("preview").replaceChildren();$("filter").value="";render();markDirty();
  status("Original unsigned PRIVATE human handoff admitted. No authentication or consent proven.");
 }catch(_){status("Private handoff rejected. Previous private notes kept.",true);}
 finally{e.target.value="";}
});

function visibleRows(){
 if(!packet)return [];
 const filter=$("filter").value;
 return packet.rows.filter(row=>!filter||filter===row.severity||filter===row.proposed.stage);
}
$("bulkApply").addEventListener("click",()=>{
 if(!packet)return;
 const stage=$("bulkStage").value,group=$("bulkGroup").value;
 const chosen=visibleRows();
 if(!stage&&!group){status("Choose a human stage or review group for the filtered rows.",true);return;}
 if(!chosen.length){status("No PRIVATE human rows selected by the current filter.",true);return;}
 if(!confirm("Propose HUMAN-only stage/group changes for "+chosen.length+
  " visible original finding rows? This cannot authorize any assessment."))return;
 const selected=new Set(chosen.map(r=>r.ordinal));
 lastBulkUndo=packet.rows.map(r=>({...r.proposed}));
 packet.rows.forEach(row=>{if(!selected.has(row.ordinal))return;
  row.proposed={...row.proposed,...(stage?{stage}:{}),...(group?{group}:{})};
 });
 markDirty();render();status(chosen.length+" filtered human notes updated. Original source and baseline unchanged.");
});
$("bulkUndo").addEventListener("click",()=>{
 if(!packet||!lastBulkUndo){status("No last recipient bulk change to undo.");return;}
 packet.rows.forEach((r,i)=>{r.proposed={...lastBulkUndo[i]};});
 lastBulkUndo=null;markDirty();render();status("Last recipient batch undone. Original source unchanged.");
});
$("resume").addEventListener("change",async e=>{
 try{
  require_(packet&&e.target.files[0]&&e.target.files[0].size>0&&
   e.target.files[0].size<=2*1024*1024);
  const raw=new TextDecoder("utf-8",{fatal:true}).decode(await e.target.files[0].arrayBuffer());
  const draft=await admit(strictJSON(raw),"reply");
  require_(draft.source_sha256===packet.source_sha256&&
   draft.baseline_sha256===packet.baseline_sha256&&draft.rows.length===packet.rows.length);
  for(let i=0;i<draft.rows.length;i++){
   const d=draft.rows[i],p=packet.rows[i];
   require_(d.ordinal===p.ordinal&&d.severity===p.severity&&d.title===p.title&&
    d.endpoint_ordinal===p.endpoint_ordinal&&humanEqual(d.original,p.original));
  }
  if(packet.rows.some(r=>!humanEqual(r.original,r.proposed))&&
    !confirm("Replace unsaved PRIVATE reviewer draft with this exact-handoff reply?"))return;
  packet.rows.forEach((r,i)=>{r.proposed={...draft.rows[i].proposed};});
  lastBulkUndo=null;markDirty();render();
  status("Previously saved PRIVATE reply reopened against the exact unchanged human baseline.");
 }catch(_){status("Saved PRIVATE reviewer reply rejected. Current human notes unchanged.",true);}
 finally{e.target.value="";}
});

$("filter").addEventListener("change",render);
$("previewBtn").addEventListener("click",()=>{try{preview();}catch(_){status("Nothing changed or human input invalid.",true);}});
$("export").addEventListener("click",async()=>{
 try{
  require_(packet&&!changedAfterPreview);
  require_(await hashRecord(packet)===packet.baseline_sha256);
  require_(packet.rows.some(r=>!humanEqual(r.original,r.proposed)));
  if(!confirm("Send PRIVATE reviewer reply containing source-declared titles and changed HUMAN notes? Confirm intended operator and private channel separately."))return;
  // Never mutate the admitted original handoff's pinned baseline.
  const reply={...packet,kind:"reply",rows:packet.rows.map(r=>({
   ...r,original:{...r.original},proposed:{...r.proposed}
  }))};
  download("PRIVATE-lab-reviewer-reply.json",JSON.stringify(reply,null,2)+"\n");
  status("PRIVATE human reply saved. It is not a grant, an assessment finding or authenticated reviewer signature.");
 }catch(_){status("PRIVATE reply not admitted for export.",true);}
});
$("forget").addEventListener("click",()=>{
 if(!packet||!confirm("Forget all local private reviewer content and unsaved human edits?"))return;
 packet=null;changedAfterPreview=true;lastBulkUndo=null;$("workspace").hidden=true;$("rows").replaceChildren();
 $("preview").replaceChildren();status("Recipient workspace cleared from memory.");
});
window.addEventListener("beforeunload",e=>{if(packet&&
 packet.rows.some(r=>!humanEqual(r.original,r.proposed))){e.preventDefault();e.returnValue="";}});
status("Open an original PRIVATE operator handoff.");
})();