/* PRIVATE one-owner human-only review reader. No network, storage, grants or verification. */
(() => {
"use strict";
const $=id=>document.getElementById(id);
const FLAGS=["authenticated","tenant_verified","source_authorized","assessment_authorized","grant",
 "client_consent","operator_consent","execution","scan","audit_verdict","retest_verified","release"];
const HEAD=["kind","schema_version","disposition","source_contract","source_sha256","client_reference",
 "engagement_reference","recipient_alias",...FLAGS,"requests"];
const FIELDS=["request_id","finding_id","request_kind","tentative_human_due","original_instructions",
 "original_issued_utc","unverified_reply_stage","unverified_reply_text",
 "local_human_triage","local_human_note"];
const V2_FIELDS=[...FIELDS,"received_owner_feedback_stage","received_owner_feedback_note","received_owner_feedback_utc"];
const FEEDBACK_ACK=["acknowledged_unverified","needs_clarification","cannot_provide"];
const TYPES=["missing_evidence","patch_change","deployment_record","rollback_plan",
 "retest_request","followup_question","other"];
const LIMIT=8*1048576;
let packet=null,epoch=0;
const feedbackDrafts=new Map();
const FEEDBACK_STAGES=["acknowledged_unverified","needs_clarification","cannot_provide"];
const fail=m=>{throw Error(m);};
function exact(x,keys){
 return x&&Object.getPrototypeOf(x)===Object.prototype&&Object.keys(x).length===keys.length&&
 Object.keys(x).every(k=>keys.includes(k));
}
function text(x,max,label,required=false){
 if(typeof x!=="string"||x.length>max||x.includes("\0")||
 /[\u202a-\u202e\u2066-\u2069]/.test(x)||(required&&!x.trim()))fail("HOLD: invalid PRIVATE "+label);
 return x;
}
function date(s){
 if(s==="")return;
 if(typeof s!=="string"||!/^\d{4}-\d\d-\d\d$/.test(s)||
 !Number.isFinite(Date.parse(s+"T00:00:00Z"))||
 new Date(s+"T00:00:00Z").toISOString().slice(0,10)!==s)fail("HOLD: invalid HUMAN date");
}
function stamp(s){
 if(typeof s!=="string"||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(s)||
 !Number.isFinite(Date.parse(s))||new Date(s).toISOString()!==s)
  fail("HOLD: invalid self-declared issued timestamp");
}
function strictJSON(s){
 if(typeof s!=="string"||new TextEncoder().encode(s).length>LIMIT)fail("HOLD: file too large");
 let i=0,n=0;const ws=()=>{while(i<s.length&&/[ \r\n\t]/.test(s[i]))i++;};
 function quoted(){
  if(s[i]!=='"')fail("HOLD: malformed JSON string");
  const start=i++;let esc=false;
  while(i<s.length){const c=s[i++];if(esc){esc=false;continue;}
   if(c==="\\"){esc=true;continue;}if(c==='"')return JSON.parse(s.slice(start,i));
   if(c<" ")fail("HOLD: malformed JSON control character");}
  fail("HOLD: unterminated JSON field");
 }
 function value(depth){
  if(++n>50000||depth>30)fail("HOLD: excessive PRIVATE JSON complexity");
  ws();const c=s[i];
  if(c==="{"){i++;ws();let seen=new Set();if(s[i]==="}"){i++;return;}
   while(true){ws();const name=quoted();if(seen.has(name))fail("HOLD: duplicate PRIVATE JSON key");
    seen.add(name);ws();if(s[i++]!==":")fail("HOLD: expected JSON colon");value(depth+1);
    ws();const k=s[i++];if(k==="}")return;if(k!==",")fail("HOLD: invalid JSON separator");}}
  if(c==="["){i++;ws();if(s[i]==="]"){i++;return;}
   while(true){value(depth+1);ws();const k=s[i++];if(k==="]")return;if(k!==",")fail("HOLD: invalid JSON array");}}
  if(c==='"'){quoted();return;}
  const n=/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(s.slice(i));
  if(!n)fail("HOLD: invalid JSON scalar");i+=n[0].length;
 }
 value(0);ws();if(i!==s.length)fail("HOLD: trailing JSON content");
 return JSON.parse(s);
}
function validate(p){
 if(!exact(p,HEAD)||p.kind!=="lightup.private_human_owner_review_brief"||
 ![1,2].includes(p.schema_version)||p.disposition!=="UNVERIFIED_HUMAN_COORDINATION_ONLY"||
 p.source_contract!=="lightup.finding_export._COLUMNS_v1"||
 !/^[0-9a-f]{64}$/.test(p.source_sha256)||FLAGS.some(k=>p[k]!==false)||
 !Array.isArray(p.requests)||!p.requests.length||p.requests.length>800)
  fail("HOLD: not an exact non-authorizing one-owner HUMAN review brief");
 text(p.client_reference,120,"declared client",true);
 text(p.engagement_reference,120,"declared engagement",true);
 text(p.recipient_alias,120,"HUMAN recipient alias",true);
 const seen=new Set();
 for(const r of p.requests){
  if(!exact(r,p.schema_version===1?FIELDS:V2_FIELDS)||typeof r.request_id!=="string"||!/^[0-9a-f]{32}$/.test(r.request_id)||
   seen.has(r.request_id))fail("HOLD: malformed or repeated original HUMAN request");
  seen.add(r.request_id);
  text(r.finding_id,160,"original finding",true);
  if(!TYPES.includes(r.request_kind))fail("HOLD: unknown original HUMAN request kind");
  text(r.original_instructions,1400,"original HUMAN request",true);
  date(r.tentative_human_due);stamp(r.original_issued_utc);
  if(!["unanswered","submitted_unverified","needs_changes"].includes(r.unverified_reply_stage))
   fail("HOLD: invalid unverified reply stage");
  text(r.unverified_reply_text,1800,"HUMAN reply");
  if((r.unverified_reply_stage==="unanswered")!== (r.unverified_reply_text===""))
   fail("HOLD: inconsistent HUMAN response");
  if(!["not_reviewed","needs_human_followup","human_triaged"].includes(r.local_human_triage))
   fail("HOLD: invalid local HUMAN review stage");
  text(r.local_human_note,400,"human-only note");
  if(p.schema_version===2){
   const stage=r.received_owner_feedback_stage;
   if(stage!==""&&!FEEDBACK_ACK.includes(stage))fail("HOLD: invalid stored human feedback status");
   text(r.received_owner_feedback_note,1000,"stored private HUMAN feedback");
   if(stage===""){
    if(r.received_owner_feedback_note!==""||r.received_owner_feedback_utc!=="")
     fail("HOLD: unexpected previous HUMAN feedback");
   }else{
    stamp(r.received_owner_feedback_utc);
    if(stage!=="acknowledged_unverified"&&!r.received_owner_feedback_note.trim())
     fail("HOLD: incomplete previous HUMAN feedback explanation");
   }
  }
 }
 return p;
}
const tag=(name,value)=>{const x=document.createElement(name);x.textContent=value;return x;};
function notice(m,err=false){$("briefMessage").textContent=m;$("briefMessage").dataset.error=err?"true":"false";}
function clear(){
 epoch++;packet=null;feedbackDrafts.clear();$("briefFile").value="";$("briefIdentity").textContent="No PRIVATE source loaded.";
 $("briefSearch").value="";$("briefFilter").value="all";$("briefItems").replaceChildren();
 $("briefCount").textContent="All locally held HUMAN metadata cleared; files on disk remain.";
 $("briefPrint").disabled=true;$("feedbackClear").disabled=true;$("feedbackExport").disabled=true;
 $("draftCount").textContent="No HUMAN feedback drafted.";
 notice("Forgot all browser-memory source, original request and unverified reply content.");
}
function updateFeedbackCount(){
 const ready=[...feedbackDrafts.values()].filter(x=>FEEDBACK_STAGES.includes(x.stage));
 $("draftCount").textContent=ready.length+" unverified HUMAN response(s) drafted for this private source; nothing sent.";
 $("feedbackExport").disabled=!packet||!ready.length;
 $("feedbackClear").disabled=!feedbackDrafts.size;
}
function feedbackEditor(r){
 const wrapper=document.createElement("div");wrapper.className="feedbackEditor";
 const heading=tag("h4","PRIVATE owner HUMAN feedback (not remediation proof)");
 const label=tag("label","Human response status");
 const select=document.createElement("select");
 select.setAttribute("aria-label","HUMAN feedback for original "+r.finding_id);
 select.append(new Option("No HUMAN feedback drafted",""));
 for(const type of FEEDBACK_STAGES)select.append(new Option(type.replaceAll("_"," "),type));
 const existing=feedbackDrafts.get(r.request_id);
 select.value=existing?.stage||"";
 label.append(select);
 const commentLabel=tag("label","PRIVATE HUMAN note (up to 1000 characters)");
 const textarea=document.createElement("textarea");textarea.rows=3;textarea.maxLength=1000;
 textarea.setAttribute("aria-label","Private HUMAN feedback note for "+r.finding_id);
 textarea.value=existing?.note||"";
 commentLabel.append(textarea);
 function update(){
  const stage=select.value;
  if(stage){
   feedbackDrafts.set(r.request_id,{stage,note:textarea.value});
  }else{
   feedbackDrafts.delete(r.request_id);
  }
  epoch++;updateFeedbackCount();
 }
 select.addEventListener("change",update);
 textarea.addEventListener("input",update);
 wrapper.append(heading,label,commentLabel);return wrapper;
}
function downloadLocal(name,content){
 const url=URL.createObjectURL(new Blob([content],{type:"application/json"}));
 const link=document.createElement("a");link.href=url;link.download=name;document.body.append(link);
 link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function exportFeedback(){
 if(!packet||!feedbackDrafts.size)fail("Load an original one-owner PRIVATE brief and draft HUMAN feedback first");
 const rows=[];
 for(const r of packet.requests){
  const form=feedbackDrafts.get(r.request_id);if(!form)continue;
  if(!FEEDBACK_STAGES.includes(form.stage))fail("Invalid HUMAN response status");
  text(form.note,1000,"HUMAN feedback note");
  if(form.stage!=="acknowledged_unverified"&&!form.note.trim())
   fail("Needs clarification/cannot provide requires a nonempty HUMAN explanation");
  rows.push({
   request_id:r.request_id,finding_id:r.finding_id,request_kind:r.request_kind,
   original_issued_utc:r.original_issued_utc,original_instructions:r.original_instructions,
   tentative_human_due:r.tentative_human_due,
   observed_unverified_reply_stage:r.unverified_reply_stage,
   observed_unverified_reply_text:r.unverified_reply_text,
   human_feedback_stage:form.stage,human_feedback_note:form.note.trim()
  });
 }
 if(!rows.length||rows.length>800)fail("Invalid original HUMAN feedback selection");
 const report={kind:"lightup.private_human_owner_followup",schema_version:1,
  disposition:"UNVERIFIED_HUMAN_COORDINATION_ONLY",
  source_contract:packet.source_contract,source_sha256:packet.source_sha256,
  client_reference:packet.client_reference,engagement_reference:packet.engagement_reference,
  recipient_alias:packet.recipient_alias,created_utc:new Date().toISOString(),
  ...Object.fromEntries(FLAGS.map(x=>[x,false])),feedback:rows};
 const body=JSON.stringify(report,null,2)+"\n";
 if(new TextEncoder().encode(body).length>LIMIT)
  fail("PRIVATE HUMAN feedback packet exceeds 8 MiB");
 if(!confirm("Download "+rows.length+" PRIVATE HUMAN feedback statement(s) for declared owner '"+packet.recipient_alias+"'? This does NOT authenticate the owner, send anything, certify remediation, grant consent or authorize retesting. Independently verify your actual operator recipient and secure channel."))return;
 downloadLocal("LightUp-PRIVATE-owner-human-feedback.json",body);
 notice("PRIVATE owner HUMAN feedback exported locally. No messages transmitted or security decisions changed.");
}

function render(){
 const box=$("briefItems");box.replaceChildren();
 if(!packet)return;
 const q=$("briefSearch").value.toLowerCase().trim(),filter=$("briefFilter").value;
 const selected=packet.requests.filter(r=>{
  if(q&&![r.request_id,r.finding_id,r.request_kind].join(" ").toLowerCase().includes(q))return false;
  if(filter==="unanswered"&&r.unverified_reply_stage!=="unanswered")return false;
  if(filter==="needs_changes"&&r.unverified_reply_stage!=="needs_changes")return false;
  if(filter==="followup"&&r.local_human_triage!=="needs_human_followup")return false;
  return true;
 });
 $("briefIdentity").textContent="DECLARED recipient: "+packet.recipient_alias+" · original source SHA-256: "+
 packet.source_sha256+" · DECLARED client: "+packet.client_reference+
 " · DECLARED engagement: "+packet.engagement_reference;
 updateFeedbackCount();
 $("briefCount").textContent=selected.length+" shown of "+packet.requests.length+
 " original HUMAN items · unverified data, not evidence of repair or permission.";
 for(const r of selected){
  const card=tag("article","");card.className="briefCard";
  card.append(tag("h3",r.finding_id+" · "+r.request_kind));
  card.append(tag("p","Original request "+r.request_id+" · HUMAN tentative due "+
   (r.tentative_human_due||"unscheduled")));
  card.append(tag("p","Unverified owner reply: "+r.unverified_reply_stage+
   " · Local human review: "+r.local_human_triage));
  const detail=tag("details",""),sum=tag("summary","Read original HUMAN instruction, reply and follow-up");
  detail.append(sum);
  for(const [heading,content] of [
   ["Original HUMAN instructions",r.original_instructions],
   ["Submitted UNVERIFIED HUMAN reply",r.unverified_reply_text||"No response submitted."],
   ["Original locally declared request issue time",r.original_issued_utc],
   ["Local HUMAN reviewer follow-up note",r.local_human_note||"No additional reviewer note."]
  ]){
   const sec=tag("div","");sec.className="privateDetail";
   sec.append(tag("strong",heading+" : "),tag("span",content));
   detail.append(sec);
  }
  if(packet.schema_version===2&&r.received_owner_feedback_stage){
   const previous=tag("aside","");previous.className="feedbackPrior";
   previous.append(tag("strong","Previously recorded UNVERIFIED owner feedback: "+r.received_owner_feedback_stage));
   previous.append(tag("p",r.received_owner_feedback_note||"No HUMAN explanation was supplied."));
   previous.append(tag("small","Self-declared feedback time "+r.received_owner_feedback_utc));
   card.append(previous);
  }
  card.append(detail,feedbackEditor(r));box.append(card);
 }
}
async function load(){
 const file=$("briefFile").files[0];
 if(!file||file.size>LIMIT)fail("Choose a PRIVATE one-owner brief of at most 8 MiB");
 const before=epoch;
 const data=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
 const next=validate(strictJSON(data));
 if(epoch!==before)fail("HOLD: PRIVATE viewer context changed during file read");
 if(!confirm("View "+next.requests.length+" PRIVATE original HUMAN items for UNVERIFIED alias '"+next.recipient_alias+"'? Verify actual sender, original engagement and your right to receive this data independently."))return;
 if(epoch!==before)fail("HOLD: PRIVATE viewer changed during human confirmation");
 packet=next;feedbackDrafts.clear();epoch++;$("briefFile").value="";render();$("briefPrint").disabled=false;
 notice("Opened PRIVATE one-owner HUMAN brief locally; no transmission, authentication, authorization or verified remediation.");
}
function listen(id,fn){$(id).addEventListener("click",async()=>{try{await fn();}catch(e){notice(e.message||"Invalid PRIVATE source",true);}});}
listen("briefLoad",load);
listen("feedbackExport",exportFeedback);
listen("feedbackClear",()=>{if(!feedbackDrafts.size)return;
 if(!confirm("Discard all local unexported owner HUMAN feedback?"))return;
 feedbackDrafts.clear();epoch++;render();notice("Unexported PRIVATE HUMAN feedback cleared.");
});
listen("briefForget",()=>{if(confirm("Forget all locally held PRIVATE HUMAN briefing data?"))clear();});
listen("briefPrint",()=>{if(!packet)fail("Load original source-bound brief first");
 if(confirm("Print this PRIVATE unverified HUMAN brief? Ensure printer/output are confidential.")){
  for(const details of document.querySelectorAll(".briefCard details"))details.open=true;
  window.print();
 }});
$("briefSearch").addEventListener("input",render);
$("briefFilter").addEventListener("change",render);
clear();
})();