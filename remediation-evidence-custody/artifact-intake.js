/* LightUp ORIGINAL human-only PRIVATE artifact append. Untrusted local fingerprints;
   no upload, no original Apply, no scanner, consent, grant or verified result. */
(function(){
"use strict";
const $=id=>document.getElementById(id);
const state=window.LightUpCustodyState;
if(!state)throw Error("Original PRIVATE custody source unavailable.");
const MAX_ARTIFACTS=120, MAX_EXPORT=4*1024*1024;
let shownRevision=-1,preview=null,serial=0;
function fail(message){throw Error(message);}
function note(message,bad=false){$("notice").textContent=message;$("notice").className=bad?"alert":"notice";}
function clean(value,max,label,required=false){
 if(typeof value!=="string"||value.length>max||(required&&!value.trim())||
 /[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u.test(value))
 fail("Invalid "+label+".");
 return value;
}
function cell(tr,value){
 const e=document.createElement("td");if(value!==undefined)e.textContent=value;tr.append(e);return e;
}
function reset(){
 preview=null;serial++;
 $("intakeAck").checked=false;$("intakeExportButton").disabled=true;
 $("intakePreview").textContent="No current append-only PRIVATE artifact intake preview.";
}
function incoming(snapshot){
 return snapshot.results.filter(r=>r.status==="unindexed"&&
  r.finding_id===""&&/^[0-9a-f]{64}$/u.test(r.local_sha)&&
  Number.isSafeInteger(r.byte_length)&&r.byte_length<=16*1024*1024);
}
function enable(){
 const s=state.snapshot();
 $("intakePreviewButton").disabled=!s.verified||s.busy||!incoming(s).length;
 $("intakeBulkAssign").disabled=!s.verified||s.busy||!incoming(s).length||
  !s.ids.includes($("intakeBulkFinding").value);
 $("intakeExportButton").disabled=!preview||!s.verified||s.busy||
  preview.revision!==s.revision||!$("intakeAck").checked||!$("confirmPrivate").checked;
}
function draw(){
 const snapshot=state.snapshot();
 if(snapshot.revision===shownRevision){enable();return;}
 shownRevision=snapshot.revision;reset();
 const root=$("intakeFiles");root.replaceChildren();
 const bulk=$("intakeBulkFinding");bulk.replaceChildren();
 const empty=document.createElement("option");empty.value="";
 empty.textContent="Choose an existing original finding";bulk.append(empty);
 const candidates=incoming(snapshot);
 if(!snapshot.verified||snapshot.busy||!snapshot.results.length){
  $("intakeCount").textContent="HUMAN HOLD — original source and local byte comparison required.";enable();return;
 }
 for(const id of [...snapshot.ids].sort((a,b)=>a.localeCompare(b))){
  const option=document.createElement("option");option.value=id;option.textContent=id.slice(0,140);bulk.append(option);
 }
 const original=snapshot.context?.rows.length??0;
 $("intakeCount").textContent=original+" original PRIVATE fingerprints will be preserved; "+
  candidates.length+" selected local unindexed files available for voluntary HUMAN assignment."+
  " New additions may not exceed "+MAX_ARTIFACTS+" total. Unlinked findings are not automatically assigned.";
 if(!candidates.length){enable();return;}
 const table=document.createElement("table"),heading=document.createElement("tr");
 for(const title of ["Selected local file (bytes only)","SHA-256 prefix / length",
  "HUMAN original finding assignment","HUMAN reviewer override","HUMAN note override"]){
  const th=document.createElement("th");th.textContent=title;heading.append(th);
 }
 const head=document.createElement("thead");head.append(heading);table.append(head);
 const body=document.createElement("tbody"),ids=[...snapshot.ids].sort((a,b)=>a.localeCompare(b));
 candidates.forEach((record,index)=>{
  const tr=document.createElement("tr");cell(tr,record.local_name);
  cell(tr,record.local_sha.slice(0,18)+"… · "+record.byte_length+" bytes");
  const td=cell(tr),select=document.createElement("select");
  select.dataset.localIndex=String(index);
  select.setAttribute("aria-label","Original finding for local file "+record.local_name);
  const none=document.createElement("option");none.value="";none.textContent="Not assigned";select.append(none);
  for(const id of ids){
   const option=document.createElement("option");option.value=id;option.textContent=id.slice(0,125);select.append(option);
  }
  select.addEventListener("change",()=>{reset();enable();});
  td.append(select);
  const rv=document.createElement("input");rv.type="text";rv.maxLength=120;rv.autocomplete="off";
  rv.dataset.intakeReviewer="";rv.setAttribute("aria-label","Reviewer alias for "+record.local_name);
  rv.placeholder="Use default";rv.addEventListener("input",()=>{reset();enable();});cell(tr).append(rv);
  const note=document.createElement("textarea");note.maxLength=1200;note.rows=2;
  note.dataset.intakeNote="";note.setAttribute("aria-label","HUMAN note for "+record.local_name);
  note.placeholder="Use default";note.addEventListener("input",()=>{reset();enable();});
  cell(tr).append(note);body.append(tr);
 });
 table.append(body);root.append(table);enable();
}
function assignment(snapshot){
 const candidates=incoming(snapshot),selects=[...$("intakeFiles").querySelectorAll("select[data-local-index]")];
 if(selects.length!==candidates.length)fail("Original local selection has changed: HUMAN HOLD.");
 const ids=new Set(snapshot.ids),out=[];
 for(const choice of selects){
  const n=Number(choice.dataset.localIndex),fid=choice.value;
  if(!Number.isSafeInteger(n)||n<0||n>=candidates.length)fail("Invalid local file selection.");
  if(!fid)continue;
  if(!ids.has(fid))fail("Original selected finding was not in the admitted exact source.");
  const r=candidates[n];
  const tr=choice.closest("tr");
  if(!tr)fail("Original file-to-finding assignment row disappeared.");
  const reviewer=tr.querySelector("input[data-intake-reviewer]");
  const humanNote=tr.querySelector("textarea[data-intake-note]");
  if(!reviewer||!humanNote)fail("HUMAN note/reviewer input is missing.");
  const alias=clean(reviewer.value.trim(),120,"per-file HUMAN reviewer");
  const explanation=clean(humanNote.value.trim(),1200,"per-file HUMAN note");
  clean(r.local_name,240,"local filename",true);
  if(/[\/\\]/u.test(r.local_name))fail("Local file name has a path: HUMAN HOLD.");
  clean(r.local_mime??"",120,"browser MIME label");
  out.push({finding_id:fid,file_name:r.local_name,
    byte_length:r.byte_length,sha256:r.local_sha,mime:r.local_mime??"",
    added_utc:"",human_reviewer:alias,human_stage:"unreviewed",human_note:explanation});
 }
 return out;
}
function prepare(){
 reset();
 const start=state.snapshot();
 if(!start.verified||start.busy||!start.context||!start.results.length)
  fail("Original CSV source and local SHA-256 comparison are required.");
 if(start.revision!==shownRevision)fail("Selection changed; refresh the original local bytes.");
 const added=assignment(start);
 if(!added.length)fail("Choose an original finding for at least one truly unindexed local file.");
 if(start.context.rows.length+added.length>MAX_ARTIFACTS)
  fail("Original native Artifact Ledger maximum is 120 fingerprints. No silent truncation or overwrite.");
 const seen=new Set(start.context.rows.map(r=>r.finding_id+"|"+r.sha256));
 for(const row of added){
  const key=row.finding_id+"|"+row.sha256;
  if(seen.has(key))fail("Two assignments of identical local bytes to the same finding; choose once.");
  seen.add(key);
 }
 const reviewer=clean($("intakeReviewer").value.trim(),120,"HUMAN reviewer alias");
 const humanNote=clean($("intakeNote").value.trim(),1200,"HUMAN attachment note");
 const stamp=new Date().toISOString();
 const actual=added.map(r=>({...r,added_utc:stamp,
  human_reviewer:r.human_reviewer||reviewer,human_note:r.human_note||humanNote}));
 const copy=JSON.parse(start.context.originalPacketJSON);
 if(!Array.isArray(copy.attachments)||copy.attachments.length!==start.context.rows.length)
  fail("Original PRIVATE index baseline is not available.");
 // Original record order and object payloads remain untouched. New records are
 // in native original Artifact Ledger exact nine-field schema, appended only.
 const before=JSON.stringify(copy.attachments);
 copy.attachments.push(...actual);
 if(JSON.stringify(copy.attachments.slice(0,start.context.rows.length))!==before)
  fail("Original PRIVATE artifact records could not be preserved identically.");
 if(copy.source_sha256!==start.context.source_sha256||
   copy.source_count!==start.context.source_count||
   copy.client_reference!==start.context.client_reference||
   copy.engagement_reference!==start.context.engagement_reference)
  fail("Original context/source identity changed during local HUMAN intake.");
 const finalJSON=JSON.stringify(copy,null,2)+"\n";
 if(new TextEncoder().encode(finalJSON).length>MAX_EXPORT)
  fail("New native PRIVATE Artifact Ledger packet exceeds export size policy.");
 const live=state.snapshot();
 if(live.revision!==start.revision||!live.verified||live.busy)
  fail("Original source/selected files changed while staging. No export allowed.");
 preview=Object.freeze({revision:start.revision,serial:serial,body:finalJSON,
  previous:start.context.rows.length,newFiles:actual.length,total:copy.attachments.length,
  kind:copy.kind,source:start.context.source_sha256});
 $("intakePreview").textContent=
  "Original indexed file references retained: "+preview.previous+
  "\nNew local file fingerprints to append as HUMAN unreviewed: "+preview.newFiles+
  "\nTotal original + new indexed references: "+preview.total+
  "\nOriginal PRIVATE schema preserved: "+(copy.schema_version===2?"Unified HUMAN v2 (Casework, Evidence Review, requests retained)":"Artifact Ledger v1")+
  "\nOriginal source SHA-256 prefix: "+preview.source.slice(0,20)+"…"+
  "\nNo original file references or HUMAN statuses will be changed. Nothing has been imported, sent, verified or applied.";
 enable();note("PRIVATE artifact append preview staged. Confirm PRIVATE recipient, backup and original owner import separately.");
}
function exportFile(){
 enable();
 const snapshot=state.snapshot(),saved=preview;
 if(!saved||$("intakeExportButton").disabled||snapshot.revision!==saved.revision)
  fail("No current PRIVATE append preview; redo source-local file comparison.");
 if(!confirm("Download PRIVATE original source-bound artifact index with ALL original HUMAN records preserved plus "+saved.newFiles+
   " newly assigned UNREVIEWED file fingerprints? It does not copy file bytes or apply changes to the original owner app."))return;
 if(!preview||preview!==saved||state.snapshot().revision!==saved.revision)
  fail("Source or HUMAN staged intake changed during export.");
 const a=document.createElement("a"),url=URL.createObjectURL(new Blob([saved.body],{type:"application/json"}));
 a.href=url;a.download=saved.kind==="lightup.private_unified_human_evidence_workspace"?
  "LightUp-PRIVATE-preserved-unified-evidence-with-HUMAN-intake.json":
  "LightUp-PRIVATE-preserved-artifact-ledger-with-HUMAN-intake.json";
 document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),2000);
 reset();$("confirmPrivate").checked=false;
 note("PRIVATE preserved ORIGINAL evidence packet saved locally. Original source-owner application must independently preview + HUMAN Apply before replacement.");
}
window.LightUpCustodyIntake=Object.freeze({draw});
window.addEventListener("lightup-custody-updated",draw);
$("intakeBulkFinding").addEventListener("change",()=>{reset();enable();});
$("intakeBulkAssign").addEventListener("click",()=>{
 const context=state.snapshot(),fid=$("intakeBulkFinding").value;
 if(!context.verified||context.busy||!context.ids.includes(fid)||context.revision!==shownRevision)
  return note("Original source/local file selection mismatch: HUMAN HOLD.",true);
 let changed=0;
 for(const input of $("intakeFiles").querySelectorAll("select[data-local-index]")){
  if(!input.value){input.value=fid;changed++;}
 }
 reset();enable();note("Assigned "+changed+" formerly unassigned local fingerprints to the selected ORIGINAL finding. Review every row before staging the PRIVATE native export.");
});
$("intakePreviewButton").addEventListener("click",()=>{try{prepare();}catch(e){reset();note("HUMAN HOLD: "+e.message,true);}});
$("intakeExportButton").addEventListener("click",()=>{try{exportFile();}catch(e){reset();note("HUMAN HOLD: "+e.message,true);}});
for(const id of ["intakeNote","intakeReviewer"]){
 $(id).addEventListener("input",()=>{reset();enable();});
}
for(const id of ["intakeAck","confirmPrivate"]){
 $(id).addEventListener("change",enable);
}
draw();
})();