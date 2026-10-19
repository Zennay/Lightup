/* LightUp PRIVATE Human Evidence Handoff Inbox. No network or authorizing behavior. */
(()=>{"use strict";
const $=id=>document.getElementById(id),FLAGS=["authenticated","tenant_verified","source_authorized","assessment_authorized","grant","client_consent","operator_consent","execution","scan","audit_verdict","retest_verified","release"];
const COMMON=["kind","schema_version","disposition","source_contract","source_sha256","client_reference","engagement_reference",...FLAGS],CONTRACT="lightup.finding_export._COLUMNS_v1";
const LEDGER=[...COMMON,"source_count","casework","evidence_review","attachments","human_requests","warning"];
const REGISTER=[...COMMON,"request_packets","reply_packets","human_reviews","owner_feedback","feedback_history"];
const HUMAN_ROW=["request_id","finding_id","request_kind","assignee","due_date","instructions","linked_sha256","human_stage","human_response","created_utc","updated_utc"];
const OWNER_HEAD=[...COMMON,"recipient_alias","reply_kind","issued_utc","reply_utc","requests"];
const OWNER_ROW=["request_id","finding_id","request_kind","instructions","due_date","human_stage","human_response"];
const ATT=["finding_id","file_name","byte_length","sha256","mime","added_utc","human_reviewer","human_stage","human_note"];
const KINDS=["missing_evidence","patch_change","deployment_record","rollback_plan","retest_request","followup_question","other"];
const MAX=8*1024*1024,MAX_ROWS=800;
let current=null,version=0,selected=new Set(),selectedFindings=new Set();
function fail(s){throw Error("HOLD: "+s);}
const plain=x=>x&&Object.getPrototypeOf(x)===Object.prototype;
const exact=(x,fields)=>plain(x)&&Object.keys(x).length===fields.length&&Object.keys(x).every(k=>fields.includes(k));
const hex=x=>typeof x==="string"&&/^[0-9a-f]{64}$/.test(x);
function value(x,max,label,required=false){
 if(typeof x!=="string"||x.length>max||/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/.test(x)||(required&&!x.trim()))fail(label+" is not canonical");
 return x;
}
function distinct(rows,label){if(rows.length!==new Set(rows).size)fail("duplicate "+label);}
function base(obj,label){
 if(obj.source_contract!==CONTRACT||!hex(obj.source_sha256))fail(label+" source format");
 value(obj.client_reference,120,label+" client",true);value(obj.engagement_reference,120,label+" engagement",true);
 if(FLAGS.some(k=>obj[k]!==false))fail(label+" has a claimed permission flag");
}
function strictJSON(text){
 let at=0,nodes=0;const ws=()=>{while(/[ \t\r\n]/.test(text[at]||"X"))at++;};
 function str(){if(text[at]!=='"')fail("expected JSON string");let start=at++,escape=false;
  while(at<text.length){let c=text[at++];if(escape){escape=false;continue;}if(c==="\\"){escape=true;continue;}if(c==='"')return JSON.parse(text.slice(start,at));if(c<" ")fail("JSON control character");}fail("unclosed JSON string");}
 function walk(depth){
  if(depth>30||++nodes>50000)fail("JSON structural limit");
  ws();const c=text[at];
  if(c==="{"){at++;ws();const seen=new Set();if(text[at]==="}"){at++;return;}
   while(true){ws();const k=str();if(seen.has(k))fail("duplicate JSON key: "+k);seen.add(k);ws();if(text[at++]!==":")fail("JSON separator");walk(depth+1);ws();const sep=text[at++];if(sep==="}")return;if(sep!==",")fail("JSON object boundary");}}
  if(c==="["){at++;ws();if(text[at]==="]"){at++;return;}while(true){walk(depth+1);ws();const sep=text[at++];if(sep==="]")return;if(sep!==",")fail("JSON array boundary");}}
  if(c==='"'){str();return;}const m=/^(true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(at));if(!m)fail("JSON value");at+=m[0].length;
 }
 walk(0);ws();if(at!==text.length)fail("trailing JSON");return JSON.parse(text);
}
async function openFile(id){const f=$(id).files[0];if(!f)fail("select both original PRIVATE exports");
 if(f.size===0||f.size>MAX)fail("PRIVATE file is empty or exceeds 8 MiB");
 return strictJSON(new TextDecoder("utf-8",{fatal:true}).decode(await f.arrayBuffer()));
}
function admitLedger(x){
 if(!exact(x,LEDGER)||x.kind!=="lightup.private_unified_human_evidence_workspace"||x.schema_version!==2||x.disposition!=="PRIVATE_HUMAN_REVIEW_ONLY")fail("expected original unified evidence workspace v2");
 base(x,"evidence");
 if(!Number.isSafeInteger(x.source_count)||x.source_count<1||x.source_count>350)fail("original finding count");
 if(!Array.isArray(x.attachments)||x.attachments.length>120)fail("too many local fingerprints");
 for(const kind of ["casework","evidence_review"]){
  if(x[kind]!==null){
   if(!Array.isArray(x[kind])||x[kind].length!==x.source_count)fail("incomplete native "+kind);
   const ids=x[kind].map(r=>{if(!plain(r))fail("invalid native human record");return value(r.finding_id,160,"native finding ID",true);});
   distinct(ids,"native finding identity");
   for(const item of x[kind])inspectNativeRow(kind,item);
   const other=kind==="evidence_review"?x.casework:x.evidence_review;
   if(Array.isArray(other)&&other.length===ids.length){const otherIds=new Set(other.map(r=>r.finding_id));if(ids.some(id=>!otherIds.has(id)))fail("Casework and Evidence Review original finding identities differ");}
  }
 }
 const nativeRows=Array.isArray(x.casework)?x.casework:(Array.isArray(x.evidence_review)?x.evidence_review:null);
 const nativeIds=nativeRows?new Set(nativeRows.map(r=>r.finding_id)):null;
 const fp=[];
 for(const a of x.attachments){
  if(!exact(a,ATT)||!hex(a.sha256)||!Number.isSafeInteger(a.byte_length)||a.byte_length<0||a.byte_length>16*1024*1024)fail("malformed local file fingerprint");
  value(a.finding_id,160,"attachment finding",true);
  if(nativeIds&&!nativeIds.has(a.finding_id))fail("local fingerprint references a finding absent from complete original HUMAN overlays");
  value(a.file_name,240,"file name",true);
  if(/[\/\\\u0000-\u001f]/.test(a.file_name))fail("path-bearing or control-containing local file name");
  value(a.mime,160,"file MIME");value(a.added_utc,70,"file time");
  value(a.human_reviewer,120,"human reviewer");value(a.human_stage,70,"human file stage");value(a.human_note,1200,"human file note");
  fp.push(a.finding_id+"|"+a.sha256);
 }distinct(fp,"original-local fingerprint");
 if(!Array.isArray(x.human_requests)||x.human_requests.length>MAX_ROWS)fail("native request capacity");
 const seen=[];
 for(const r of x.human_requests){
  if(!exact(r,HUMAN_ROW)||typeof r.request_id!=="string"||!/^[0-9a-f]{32}$/.test(r.request_id))fail("native request identity");
  seen.push(r.request_id);value(r.finding_id,160,"finding",true);
  if(nativeIds&&!nativeIds.has(r.finding_id))fail("original HUMAN request references finding absent from complete source-bound HUMAN overlays");
  value(r.assignee,120,"declared owner");
  if(!KINDS.includes(r.request_kind))fail("native request type");
  value(r.instructions,1400,"instructions",true);value(r.due_date,12,"tentative HUMAN date");
  value(r.human_stage,48,"human stage",true);value(r.human_response,1800,"unverified HUMAN reply");
  value(r.created_utc,70,"creation timestamp",true);value(r.updated_utc,70,"update timestamp",true);
  if(r.linked_sha256!==""&&!hex(r.linked_sha256))fail("source local SHA reference");
 }distinct(seen,"native HUMAN request");
 if(typeof x.warning!=="string"||x.warning.length>1500)fail("original source warning");
 return x;
}
function ownerPacket(p,type,r){
 if(!exact(p,OWNER_HEAD)||p.kind!=="lightup.private_human_evidence_owner_handoff"||p.schema_version!==1||p.disposition!=="UNVERIFIED_HUMAN_REQUEST_ONLY")fail("original HUMAN owner packet schema");
 base(p,"owner packet");for(const k of ["source_sha256","client_reference","engagement_reference"])if(p[k]!==r[k])fail("owner packet differs from register source");
 if(p.reply_kind!==type||!Array.isArray(p.requests)||!p.requests.length||p.requests.length>60)fail("original owner reply/request type");
 value(p.recipient_alias,120,"declared owner",true);value(p.issued_utc,70,"owner request issue time",true);
 if(type==="owner_request"&&p.reply_utc!==null)fail("original unanswered request timestamp");
 if(type==="unverified_human_reply")value(p.reply_utc,70,"unverified reply timestamp",true);
 const ids=[];
 for(const o of p.requests){
  if(!exact(o,OWNER_ROW)||!/^[0-9a-f]{32}$/.test(o.request_id))fail("original owner request row");
  ids.push(o.request_id);value(o.finding_id,160,"finding identity",true);
  if(!KINDS.includes(o.request_kind))fail("unknown HUMAN request kind");
  value(o.instructions,1400,"original instructions",true);value(o.due_date,12,"tentative due date");
  if(type==="owner_request"&&(o.human_stage!=="requested_human"||o.human_response!==""))fail("original unanswered request mutated");
  if(type==="unverified_human_reply"){
   if(!["submitted_unverified","needs_changes"].includes(o.human_stage))fail("unknown HUMAN reply stage");
   value(o.human_response,1800,"UNVERIFIED human reply",true);
  }
 }distinct(ids,"owner packet request");return p;
}
function admitRegister(x,l){
 const f=x?.schema_version===1?REGISTER.filter(k=>!["owner_feedback","feedback_history"].includes(k)):REGISTER;
 if(!exact(x,f)||x.kind!=="lightup.private_human_response_reconciliation"||![1,2].includes(x.schema_version)||x.disposition!=="UNVERIFIED_HUMAN_COORDINATION_ONLY")fail("original response register schema");
 base(x,"register");
 for(const k of ["source_sha256","source_contract","client_reference","engagement_reference"])if(x[k]!==l[k])fail("original ledger/register "+k+" mismatch");
 if(!Array.isArray(x.request_packets)||!Array.isArray(x.reply_packets)||x.request_packets.length+x.reply_packets.length>24||
 !Array.isArray(x.human_reviews)||x.human_reviews.length>MAX_ROWS)fail("private register capacity");
 const originals=new Map(),answers=new Map(),packetAliases=[],native=new Map(l.human_requests.map(r=>[r.request_id,r]));
 for(const p of x.request_packets){
  ownerPacket(p,"owner_request",x);packetAliases.push(p.recipient_alias+"|"+p.issued_utc);
  for(const o of p.requests){
   if(originals.has(o.request_id))fail("original request reused across owner packets");
   const source=native.get(o.request_id);if(!source)fail("original request not in evidence ledger");
   for(const k of ["finding_id","request_kind","instructions","due_date"])if(source[k]!==o[k])fail("immutable original request "+k+" changed");
   if(source.assignee!==p.recipient_alias)fail("human owner alias differs from original ledger");
   originals.set(o.request_id,{o,p,source});
  }
 }distinct(packetAliases,"original owner packet identity");
 for(const p of x.reply_packets){
  ownerPacket(p,"unverified_human_reply",x);
  for(const o of p.requests){
   const previous=originals.get(o.request_id);
   if(!previous||previous.p.recipient_alias!==p.recipient_alias||previous.p.issued_utc!==p.issued_utc)fail("orphan HUMAN reply");
   for(const k of ["finding_id","request_kind","instructions","due_date"])if(o[k]!==previous.o[k])fail("reply rewrote original HUMAN request");
   if(answers.has(o.request_id))fail("ambiguous repeated original owner reply");
   answers.set(o.request_id,o);
  }
 }
 if(x.human_reviews.length!==originals.size)fail("incomplete ORIGINAL HUMAN reviewer rows");
 const reviews=new Map();
 for(const a of x.human_reviews){
  if(!exact(a,["request_id","human_stage","note"])||!originals.has(a.request_id)||reviews.has(a.request_id)||
  !["not_reviewed","needs_human_followup","human_triaged"].includes(a.human_stage))fail("invalid HUMAN reviewer annotation");
  value(a.note,400,"HUMAN reviewer note");reviews.set(a.request_id,a);
 }
 const feedback=new Map();
 for(const a of x.owner_feedback||[]){
  if(!exact(a,["request_id","stage","note","submitted_utc"])||!originals.has(a.request_id)||feedback.has(a.request_id)||
  !["acknowledged_unverified","needs_clarification","cannot_provide"].includes(a.stage))fail("invalid human owner followup");
  value(a.note,1000,"owner note");value(a.submitted_utc,70,"owner time",true);feedback.set(a.request_id,a);
 }
 if(!Array.isArray(x.feedback_history||[])||(x.feedback_history||[]).length>1600)fail("owner feedback history limit");
 for(const f of x.feedback_history||[]){
  if(!exact(f,["request_id","stage","note","submitted_utc","superseded_utc"])||!originals.has(f.request_id)||
  !["acknowledged_unverified","needs_clarification","cannot_provide"].includes(f.stage))fail("invalid owner feedback history");
  value(f.note,1000,"history note");value(f.submitted_utc,70,"history timestamp",true);value(f.superseded_utc,70,"history supersession timestamp",true);
 }
 return {originals,answers,reviews,feedback};
}

const CASE_FIELDS=["finding_id","owner","status","due_date","next_action","verification_plan","blocker","note","updated_utc"];
const EVIDENCE_FIELDS=["finding_id","stage","reference","reviewer","next_step","evidence"];
const EVIDENCE_REFERENCE_FIELDS=["change_reference","deployment_reference","rollback_reference","retest_request_reference","review_question"];
const CASE_STAGES=["unassigned","planned","in_progress","blocked","ready_for_retest","deferred","completed"];
const EVIDENCE_STAGES=["missing","submitted","needs_changes","ready_for_authorized_retest"];
function humanDate(v,label){
 if(v===null||v==="")return;
 if(typeof v!=="string"||!/^\d{4}-\d\d-\d\d$/.test(v)||!Number.isFinite(Date.parse(v+"T00:00:00Z"))||
 new Date(v+"T00:00:00Z").toISOString().slice(0,10)!==v)fail("invalid tentative HUMAN "+label);
}
function inspectNativeRow(kind,row){
 if(kind==="casework"){
  if(!exact(row,CASE_FIELDS)||!CASE_STAGES.includes(row.status))fail("invalid original human Casework record");
  value(row.finding_id,160,"original finding ID",true);
  for(const [field,max] of [["owner",120],["next_action",1800],["verification_plan",1600],["blocker",1200],["note",1600]])value(row[field],max,"Casework "+field);
  humanDate(row.due_date,"Casework due date");
  if(row.updated_utc!==null)value(row.updated_utc,64,"Casework timestamp",true);
 }else{
  if(!exact(row,EVIDENCE_FIELDS)||!EVIDENCE_STAGES.includes(row.stage)||!exact(row.evidence,EVIDENCE_REFERENCE_FIELDS))fail("invalid original human Evidence Review record");
  value(row.finding_id,160,"original finding ID",true);
  for(const [field,max] of [["reference",240],["reviewer",120],["next_step",500]])value(row[field],max,"Evidence Review "+field);
  for(const field of EVIDENCE_REFERENCE_FIELDS)value(row.evidence[field],field==="review_question"?700:240,"Evidence Review "+field);
 }
}
function buildFindingRows(source,requests,originalFindings=null){
 const original=originalFindings||source.casework||source.evidence_review;
 if(!original)return [];
 const caseById=new Map((source.casework||[]).map(r=>[r.finding_id,r]));
 const evidenceById=new Map((source.evidence_review||[]).map(r=>[r.finding_id,r]));
 const sourceById=new Map((originalFindings||[]).map(r=>[r.finding_id,r]));
 const filesById=new Map(),requestsById=new Map();
 for(const f of source.attachments){const a=filesById.get(f.finding_id)||[];a.push(f);filesById.set(f.finding_id,a);}
 for(const r of requests){const a=requestsById.get(r.finding)||[];a.push(r);requestsById.set(r.finding,a);}
 const today=new Date().toISOString().slice(0,10);
 return original.map(item=>{
  const id=item.finding_id,casework=caseById.get(id)||null,evidence=evidenceById.get(id)||null,
   files=filesById.get(id)||[],related=requestsById.get(id)||[],signals=[];
  if(!files.length)signals.push("No LOCAL fingerprint");
  if(!related.length)signals.push("No original HUMAN request created");
  if(related.some(r=>!r.answer&&!r.ledgerOnly))signals.push("HUMAN reply awaited");
  if(related.some(r=>r.ledgerOnly))signals.push("Ledger HUMAN request not imported into original response register");
  if(related.some(r=>r.ledgerOnly&&["submitted_unverified","needs_changes"].includes(r.ledgerStatus)))
   signals.push("Unverified ledger HUMAN reply is not independently reconciled");
  if(casework&&!casework.owner)signals.push("No declared Casework owner");
  if(casework?.status==="blocked")signals.push("Casework HUMAN blocker");
  if(casework?.due_date&&casework.due_date<today)signals.push("Tentative Casework date passed");
  if(evidence&&["missing","needs_changes"].includes(evidence.stage))signals.push("Evidence Review HUMAN follow-up");
  if(casework?.status==="completed"&&evidence?.stage==="missing")
   signals.push("HUMAN status disagreement: locally completed vs evidence missing");
  return {id,sourceFinding:sourceById.get(id)||null,casework,evidence,files,requests:related,signals};
 });
}

function sourceFindingRequests(source,registerRows){
 const matched=new Set(registerRows.map(r=>r.id));
 const pending=source.human_requests.filter(r=>!matched.has(r.request_id)).map(r=>({
  id:r.request_id,finding:r.finding_id,owner:r.assignee,kind:r.request_kind,ledgerOnly:true,
  instructions:r.instructions,due:r.due_date,answer:null,ledgerStatus:r.human_stage,signals:[]
 }));
 return [...registerRows,...pending];
}
function evidenceOnly(l){
 const source=admitLedger(l),findingRows=buildFindingRows(source,sourceFindingRequests(source,[]));
 return {source,rows:[],findingRows,originalFindings:null,mode:"ledger_only",version:++version};
}
function combine(l,r){
 const source=admitLedger(l),data=admitRegister(r,source),attached=new Map();
 for(const a of source.attachments){if(!attached.has(a.finding_id))attached.set(a.finding_id,[]);attached.get(a.finding_id).push(a);}
 const today=new Date().toISOString().slice(0,10),rows=[];
 for(const [id,x] of data.originals){
  const local=attached.get(x.o.finding_id)||[],answer=data.answers.get(id)||null,feedback=data.feedback.get(id)||null,notes=data.reviews.get(id);
  const signals=[];
  if(!answer)signals.push("No HUMAN reply received");
  if(answer?.human_stage==="needs_changes")signals.push("HUMAN reply needs changes");
  if(answer&&x.source.human_response&&
     (x.source.human_stage!==answer.human_stage||x.source.human_response!==answer.human_response))
    signals.push("Two HUMAN exports disagree about unverified response; reconcile with original owner");
  if(!local.length)signals.push("No LOCAL file fingerprint");
  if(x.source.linked_sha256&&!local.some(a=>a.sha256===x.source.linked_sha256))signals.push("Linked LOCAL SHA not in this snapshot");
  if(x.o.due_date&&/^\d{4}-\d\d-\d\d$/.test(x.o.due_date)&&x.o.due_date<today)signals.push("Tentative HUMAN date passed");
  if(feedback)signals.push("Separate UNVERIFIED HUMAN follow-up exists");
  rows.push({id,finding:x.o.finding_id,kind:x.o.request_kind,owner:x.p.recipient_alias,instructions:x.o.instructions,due:x.o.due_date,answer,feedback,notes,local,signals});
 }
 return {source,rows,findingRows:buildFindingRows(source,sourceFindingRequests(source,rows)),originalFindings:null,mode:"paired",version:++version};
}
const cell=(tag,content)=>{const e=document.createElement(tag);e.textContent=String(content);return e;};
const info=(s,error=false)=>{$("notice").textContent=s;$("notice").dataset.error=error?"true":"false";};
function filtered(){
 const text=$("search").value.trim().toLowerCase(),filter=$("filter").value;
 return (current?.rows||[]).filter(x=>{
 if(text&&![x.finding,x.id,x.owner,x.kind].join(" ").toLowerCase().includes(text))return false;
 if(filter==="unanswered"&&x.answer)return false;
 if(filter==="missing"&&x.local.length)return false;
 if(filter==="changed"&&x.answer?.human_stage!=="needs_changes")return false;
 if(filter==="sha"&&!x.signals.includes("Linked LOCAL SHA not in this snapshot"))return false;
 if(filter==="late"&&!x.signals.includes("Tentative HUMAN date passed"))return false;
 return true;});
}
function summary(number,label){const e=cell("div","");e.className="number";e.append(cell("strong",number),cell("span",label));return e;}
function draw(){
 if(!current)return;
 window.LightUpHandoffHumanPlan?.render();
 $("sourceEnrichment").hidden=false;
 $("attachOriginal").disabled=false;
 $("detachOriginal").disabled=!current.originalFindings;
 $("review").hidden=current.mode==="ledger_only";$("out").hidden=current.mode==="ledger_only";
 if(current.mode==="ledger_only"){drawFindingBoard();return;}
 const r=current.rows;
 $("binding").textContent="DECLARED original SHA: "+current.source.source_sha256+" · client: "+current.source.client_reference+" · engagement: "+current.source.engagement_reference+" · "+current.source.source_count+" original findings reported. Not authenticated.";
 $("numbers").replaceChildren(summary(r.length,"Matched HUMAN requests"),
 summary(r.filter(x=>x.answer).length,"UNVERIFIED received replies"),
 summary(r.filter(x=>!x.local.length).length,"No LOCAL fingerprint"),
 summary(r.filter(x=>x.answer?.human_stage==="needs_changes").length,"HUMAN replies needing changes"),
 summary(r.filter(x=>x.feedback).length,"Separate owner HUMAN follow-ups"));
 const visible=filtered(),body=$("rows");body.replaceChildren();
 for(const x of visible){
  const tr=document.createElement("tr"),td=document.createElement("td"),cb=document.createElement("input");cb.type="checkbox";cb.checked=selected.has(x.id);
  cb.setAttribute("aria-label","Select original HUMAN request "+x.id);
  cb.addEventListener("change",()=>{cb.checked?selected.add(x.id):selected.delete(x.id);draw();});td.append(cb);tr.append(td);
  const original=cell("td",x.finding);original.append(cell("small",x.id));tr.append(original);
  tr.append(cell("td",x.owner),cell("td",x.kind),cell("td",x.answer?.human_stage||"NOT RECEIVED"),cell("td",x.local.length+" LOCAL files"),cell("td",x.signals.join(" · ")||"No local HUMAN follow-up signal"));
  if(current.findingRows?.some(f=>f.id===x.finding)){
   const go=cell("button","Inspect source-bound finding");go.type="button";go.className="secondary";
   go.addEventListener("click",()=>{
    $("findingSearch").value=x.finding;$("findingFilter").value="all";drawFindingBoard();
    $("findingDesk").scrollIntoView({behavior:"smooth",block:"start"});
   });
   const target=document.createElement("td");target.append(go);tr.append(target);
  }else tr.append(cell("td","No complete native finding overlay"));
  const details=document.createElement("details"),summary=cell("summary","Read original HUMAN context (PRIVATE)");details.append(summary);
  for(const [label,val] of [
   ["Original HUMAN instructions",x.instructions],["Unverified owner reply",x.answer?.human_response||"Not received"],
   ["Local HUMAN reviewer stage",x.notes.human_stage],["Local HUMAN reviewer note",x.notes.note||"None"],
   ["Separate UNVERIFIED owner feedback",x.feedback?x.feedback.stage+": "+x.feedback.note:"No separate HUMAN feedback"],
   ["Tentative HUMAN date",x.due||"Not supplied"]]){
    const line=document.createElement("p");line.append(cell("strong",label+": "),cell("span",val));details.append(line);
  }
  if(x.local.length){const nested=document.createElement("details");nested.append(cell("summary","LOCAL file metadata ("+x.local.length+")"));
   for(const file of x.local){const line=document.createElement("p");line.append(cell("strong",file.file_name+": "),cell("span",file.sha256+" · "+file.byte_length+" bytes · "+file.human_stage+" · "+file.human_note));nested.append(line);}details.append(nested);}
  const detailCell=document.createElement("td");detailCell.append(details);tr.append(detailCell);
  body.append(tr);
 }
 $("selectVisible").checked=!!visible.length&&visible.every(x=>selected.has(x.id));
 $("selectVisible").indeterminate=visible.some(x=>selected.has(x.id))&&!$("selectVisible").checked;
 $("selection").textContent=visible.length+" shown · "+selected.size+" selected for PRIVATE export.";
 const picker=$("ownerRecipient"),prior=picker.value;const owners=[...new Set(r.map(x=>x.owner))].filter(Boolean).sort((a,b)=>a.localeCompare(b));
 picker.replaceChildren(new Option("Choose one original owner alias",""));
 for(const alias of owners)picker.append(new Option(alias,alias));
 picker.value=owners.includes(prior)?prior:"";
 $("downloadOwner").disabled=!r.some(x=>x.owner===picker.value&&selected.has(x.id));
 $("downloadPrivate").disabled=!selected.size;$("downloadAgenda").disabled=!selected.size;
 drawFindingBoard();
}

function visibleFindingRows(){
 const q=$("findingSearch").value.trim().toLowerCase(),mode=$("findingFilter").value;
 return (current?.findingRows||[]).filter(r=>{
  if(q&&![r.id,r.sourceFinding?.title||"",r.sourceFinding?.remediation||"",r.casework?.owner||"",r.casework?.blocker||"",r.evidence?.next_step||""].join(" ").toLowerCase().includes(q))return false;
  if(mode==="no_request"&&r.requests.length)return false;
  if(mode==="critical_high"&&!["critical","high"].includes(r.sourceFinding?.severity))return false;
  if(mode==="source_regression"&&r.sourceFinding?.retest_status!=="regression")return false;
  if(mode==="missing_local"&&r.files.length)return false;
  if(mode==="no_owner"&&(!r.casework||r.casework.owner))return false;
  if(mode==="blocked"&&r.casework?.status!=="blocked")return false;
  if(mode==="waiting"&&!r.requests.some(x=>!x.answer))return false;
  if(mode==="review"&&(!r.evidence||!["missing","needs_changes"].includes(r.evidence.stage)))return false;
  if(mode==="overdue"&&!r.signals.includes("Tentative Casework date passed"))return false;
  if(mode==="conflict"&&!r.signals.some(x=>x.startsWith("HUMAN status disagreement")))return false;
  return true;
 }).sort((a,b)=>{
  const level=["critical","high","medium","low","info"];
  const score=r=>r.sourceFinding?level.indexOf(r.sourceFinding.severity):5;
  const delta=score(a)-score(b);
  if(delta)return delta;
  const blocked=(b.casework?.status==="blocked"?1:0)-(a.casework?.status==="blocked"?1:0);
  if(blocked)return blocked;
  return a.id.localeCompare(b.id);
 });
}
function detailsBlock(title,items){
 const e=document.createElement("details");e.append(cell("summary",title));
 for(const [label,body] of items){const p=document.createElement("p");p.append(cell("strong",label+": "),cell("span",body||"Not declared"));e.append(p);}
 return e;
}
function drawFindingBoard(){
 const data=current?.findingRows||[],available=!!data.length;
 $("findingDesk").hidden=!available;
 if(!available)return;
 $("findingBinding").textContent="DECLARED original source SHA-256: "+current.source.source_sha256+" · client: "+current.source.client_reference+" · engagement: "+current.source.engagement_reference+" · original finding count "+current.source.source_count+" (not authenticated)";
 const stats=$("findingStats");
 stats.replaceChildren(summary(data.length,"Original source-bound HUMAN finding IDs"),
  summary(data.filter(x=>["critical","high"].includes(x.sourceFinding?.severity)).length,"Source-claimed critical/high (only matched CSV)"),
  summary(data.filter(x=>!x.requests.length).length,"No original HUMAN request"),
  summary(data.filter(x=>!x.files.length).length,"No LOCAL fingerprint"),
  summary(data.filter(x=>x.casework?.status==="blocked").length,"Casework HUMAN blocked"),
  summary(data.filter(x=>x.requests.some(r=>!r.answer&&!r.ledgerOnly || r.ledgerOnly&&!["submitted_unverified","needs_changes"].includes(r.ledgerStatus))).length,"Human replies not yet reported locally"));
 const body=$("findingRows"),visible=visibleFindingRows();body.replaceChildren();
 for(const row of visible){
  const tr=document.createElement("tr"),td=document.createElement("td"),check=document.createElement("input");
  check.type="checkbox";check.checked=selectedFindings.has(row.id);
  check.setAttribute("aria-label","Select ORIGINAL finding "+row.id);
  check.addEventListener("change",()=>{check.checked?selectedFindings.add(row.id):selectedFindings.delete(row.id);drawFindingBoard();});
  td.append(check);tr.append(td);
  tr.append(cell("td",row.id));
  tr.append(cell("td",row.sourceFinding?row.sourceFinding.severity+" · source: "+row.sourceFinding.retest_status:"Original CSV not matched"));
  tr.append(cell("td",row.casework?row.casework.status+" · "+(row.casework.owner||"no declared owner"):"No native Casework overlay"));
  tr.append(cell("td",row.evidence?row.evidence.stage+" · "+(row.evidence.reviewer||"no HUMAN reviewer"):"No native Evidence Review overlay"));
  tr.append(cell("td",row.files.length+" LOCAL labels"));
  tr.append(cell("td",row.requests.length+" requests · "+row.requests.filter(r=>r.answer).length+" received UNVERIFIED replies"));
  tr.append(cell("td",row.signals.join(" · ")||"No local HUMAN signal"));
  const cellDetails=document.createElement("td");
  if(row.sourceFinding)cellDetails.append(detailsBlock("PRIVATE ORIGINAL source claims (not verified)",[
   ["Original finding title",row.sourceFinding.title],["Original source severity",row.sourceFinding.severity],
   ["Original retest status claim",row.sourceFinding.retest_status],["Original source remediation description",row.sourceFinding.remediation]
  ]));
  if(row.casework)cellDetails.append(detailsBlock("PRIVATE Casework HUMAN notes",[
   ["Owner",row.casework.owner],["HUMAN status",row.casework.status],["Tentative date",row.casework.due_date],
   ["Blocker",row.casework.blocker],["Next human action",row.casework.next_action],
   ["Human verification PLAN",row.casework.verification_plan],["Human note",row.casework.note]
  ]));
  if(row.evidence)cellDetails.append(detailsBlock("PRIVATE Evidence Review HUMAN notes",[
   ["HUMAN evidence stage",row.evidence.stage],["Human reviewer",row.evidence.reviewer],
   ["Human next step",row.evidence.next_step],["Reference",row.evidence.reference],
   ["Change reference",row.evidence.evidence.change_reference],
   ["Deployment reference",row.evidence.evidence.deployment_reference],
   ["Rollback reference",row.evidence.evidence.rollback_reference],
   ["HUMAN retest REQUEST reference",row.evidence.evidence.retest_request_reference],
   ["Human review question",row.evidence.evidence.review_question]
  ]));
  tr.append(cellDetails);body.append(tr);
 }
 $("selectFindingsVisible").checked=!!visible.length&&visible.every(x=>selectedFindings.has(x.id));
 $("selectFindingsVisible").indeterminate=visible.some(x=>selectedFindings.has(x.id))&&!$("selectFindingsVisible").checked;
 $("findingSelection").textContent=visible.length+" original findings shown · "+selectedFindings.size+" selected for PRIVATE human action.";
 for(const id of ["selectRequestsForFindings","exportFindingPrivate"])$(id).disabled=!selectedFindings.size;
 $("selectRequestsForFindings").disabled=current.mode==="ledger_only"||!selectedFindings.size;
 $("exportFindingCounts").disabled=!data.length;
}
function chosenFindingRows(){
 if(!current||!selectedFindings.size)fail("select original finding IDs first");
 const arr=current.findingRows.filter(x=>selectedFindings.has(x.id));
 if(arr.length!==selectedFindings.size)fail("original finding selection stale");
 return arr;
}
function chooseOriginalRequestsForFindings(){
 const findingRows=chosenFindingRows(),ids=new Set(findingRows.map(f=>f.id));
 const requests=current.rows.filter(r=>ids.has(r.finding));
 if(!requests.length){info(current.mode==="ledger_only"?"No original Response Register is loaded; use paired mode to select existing source-authored requests for human handoff. The evidence-only board never creates original requests.":"These original findings have no original HUMAN requests. Create any new request inside the separate source-owning Evidence Artifact Ledger; nothing was fabricated.");return;}
 if(!confirm("Select "+requests.length+" EXISTING original HUMAN requests across "+findingRows.length+" selected original findings? This selects only; no messages or actions are sent."))return;
 for(const r of requests)selected.add(r.id);
 draw();info(requests.length+" pre-existing original HUMAN requests selected in the request board. No new request or authorization issued.");
}
function exportOriginalFindingPrivate(){
 const entries=chosenFindingRows();
 if(!confirm("Download PRIVATE human Casework/Evidence Review notes, original finding IDs and LOCAL fingerprints for "+entries.length+" selected original findings? The source, recipient and consent remain UNVERIFIED."))return;
 const source=current.source;
 const packet={kind:"lightup.private_original_finding_human_action_desk",schema_version:1,
 disposition:"UNVERIFIED_HUMAN_COORDINATION_ONLY",source_contract:CONTRACT,
 source_sha256:source.source_sha256,client_reference:source.client_reference,
 engagement_reference:source.engagement_reference,...Object.fromEntries(FLAGS.map(k=>[k,false])),
 original_finding_count_reported:source.source_count,
 findings:entries.map(r=>({original_finding_id:r.id,
 original_five_column_source_claims:r.sourceFinding,original_casework_human_only:r.casework,
 original_evidence_review_human_only:r.evidence,
 local_file_labels_only:r.files.map(f=>({file_name:f.file_name,sha256:f.sha256,byte_length:f.byte_length,human_stage:f.human_stage,human_reviewer:f.human_reviewer,human_note:f.human_note})),
 original_human_request_ids:r.requests.map(q=>q.id),
 received_unverified_human_reply_count:r.requests.filter(q=>q.answer).length,
 human_followup_signals:r.signals})),
 warning:"PRIVATE source-declared human follow-up only. Finding visibility and local labels never establish complete external evidence, authorization, retest result or remediation."};
 download("LightUp-PRIVATE-original-finding-action-board.json",JSON.stringify(packet,null,2)+"\n","application/json");
 info("PRIVATE source-bound selected-finding HUMAN action board exported. No original source records changed.");
}
function exportOriginalFindingCounts(){
 if(!current?.findingRows.length)fail("no full original HUMAN overlay available");
 if(!confirm("Export counts-only HUMAN finding coverage without original IDs, source SHA, owners, individual notes, filenames, or client metadata? Small-cohort aggregates can still be sensitive."))return;
 const buckets=new Map();
 for(const f of current.findingRows){
  const key=JSON.stringify([f.casework?.status||"no_casework",f.evidence?.stage||"no_evidence_review",
   f.files.length?"some_local_labels":"no_local_label",f.requests.length?"some_human_requests":"no_human_request"]);
  buckets.set(key,(buckets.get(key)||0)+1);
 }
 const rows=[["human_casework_stage","human_evidence_review_stage","local_fingerprint_label","human_request_presence","count"]];
 for(const [key,value] of [...buckets].sort((a,b)=>a[0].localeCompare(b[0])))rows.push([...JSON.parse(key),value]);
 download("LightUp-anonymous-original-finding-HUMAN-coverage.csv",rows.map(r=>r.map(csvCell).join(",")).join("\r\n")+"\r\n","text/csv;charset=utf-8");
 info("Anonymous aggregate original-finding HUMAN coverage exported. These are local labels only.");
}

function download(name,content,type){
 const blob=new Blob([content],{type}),url=URL.createObjectURL(blob),a=document.createElement("a");
 a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function chosen(){if(!current||!selected.size)fail("select exact original HUMAN requests first");
 const a=current.rows.filter(r=>selected.has(r.id));if(a.length!==selected.size)fail("stale selected original IDs");return a;}
function privateExport(){
 const r=chosen(),s=current.source;
 if(!confirm("Download PRIVATE selected original IDs, human responses, file SHA fingerprints and HUMAN notes? Independently check recipient, real consent and confidential transport. This is not authority."))return;
 const data={kind:"lightup.private_human_evidence_handoff_inbox",schema_version:1,disposition:"UNVERIFIED_HUMAN_COORDINATION_ONLY",
  source_contract:CONTRACT,source_sha256:s.source_sha256,client_reference:s.client_reference,engagement_reference:s.engagement_reference,
  ...Object.fromEntries(FLAGS.map(k=>[k,false])),
  selected_requests:r.map(x=>({request_id:x.id,original_finding_id:x.finding,declared_owner:x.owner,kind:x.kind,
   original_instructions:x.instructions,tentative_human_due_date:x.due,
   unverified_reply_stage:x.answer?.human_stage||"not_received",unverified_reply_text:x.answer?.human_response||"",
   local_human_review_stage:x.notes.human_stage,local_human_review_note:x.notes.note,
   separate_unverified_human_owner_feedback:x.feedback,
   local_file_labels_only:x.local.map(f=>({file_name:f.file_name,sha256:f.sha256,byte_length:f.byte_length,human_stage:f.human_stage,human_note:f.human_note})),
   human_followup_signals:x.signals})),
  warning:"PRIVATE HUMAN draft only. Not authenticated original source, grant, consent, verified retest, remediation certification or release approval."};
 download("LightUp-PRIVATE-selected-HUMAN-handoff.json",JSON.stringify(data,null,2)+"\n","application/json");
 info("Selected PRIVATE human handoff downloaded. No original source or security status was modified.");
}
function oneOwnerExport(){
 const alias=$("ownerRecipient").value,all=chosen();
 if(!alias)fail("choose a declared HUMAN owner first");
 const own=all.filter(x=>x.owner===alias),other=all.length-own.length;
 if(!own.length)fail("no selected original HUMAN request belongs to this declared owner");
 if(!confirm("Export only "+own.length+" original HUMAN requests for declared owner "+alias+"? "+other+" selected requests from other owners will be EXCLUDED. Recipient identity is NOT authenticated."))return;
 const s=current.source;
 const data={kind:"lightup.private_human_single_owner_disclosure",schema_version:1,
  disposition:"UNVERIFIED_HUMAN_COORDINATION_ONLY",source_contract:CONTRACT,
  source_sha256:s.source_sha256,client_reference:s.client_reference,engagement_reference:s.engagement_reference,
  recipient_alias:alias,...Object.fromEntries(FLAGS.map(k=>[k,false])),
  requests:own.map(x=>({request_id:x.id,original_finding_id:x.finding,
   request_kind:x.kind,original_instructions:x.instructions,tentative_human_due_date:x.due,
   unverified_human_response:x.answer?.human_response||"",unverified_reply_stage:x.answer?.human_stage||"not_received",
   local_human_review_stage:x.notes.human_stage,local_human_review_note:x.notes.note,
   separate_unverified_owner_feedback:x.feedback,
   local_file_labels_only:x.local.map(f=>({file_name:f.file_name,sha256:f.sha256,byte_length:f.byte_length,human_stage:f.human_stage,human_note:f.human_note}))})),
  warning:"One self-declared owner only. This is NOT an original owner reply/request packet, no identity verification, no actual consent, no execution or remediation authority."};
 if(current.rows.filter(x=>x.owner===alias&&selected.has(x.id)).length!==own.length)fail("owner selection changed");
 download("LightUp-PRIVATE-one-owner-HUMAN-handoff.json",JSON.stringify(data,null,2)+"\n","application/json");
 info("PRIVATE one-owner handoff exported. "+other+" other owner selections were not included. Original security states remain untouched.");
}
function csvCell(v){return '"'+String(v).replaceAll('"','""')+'"';}
function aggregateExport(){
 if(!current)fail("load original sources");
 const counts=new Map();
 for(const r of current.rows){
  const key=JSON.stringify([r.kind,r.answer?.human_stage||"not_received",r.local.length?"local_label_recorded":"no_local_label"]);
  counts.set(key,(counts.get(key)||0)+1);
 }
 if(!confirm("Download counts-only HUMAN CSV with no original IDs, source SHA, owners, filenames, file hashes or private notes? Counts cannot prove fixes."))return;
 const rows=[["human_request_kind","unverified_human_reply_stage","local_fingerprint_label","count"]];
 for(const [k,n] of [...counts].sort((a,b)=>a[0].localeCompare(b[0])))rows.push([...JSON.parse(k),n]);
 download("LightUp-anonymous-human-evidence-counts.csv",rows.map(x=>x.map(csvCell).join(",")).join("\r\n")+"\r\n","text/csv;charset=utf-8");
 info("Anonymous aggregate HUMAN counts exported, without source or identifying row data.");
}
function agendaExport(){
 const rows=chosen();
 if(!confirm("Download PRIVATE human conversation agenda with original IDs and notes? Secure the recipient and channel separately."))return;
 const body=["PRIVATE LightUp HUMAN follow-up agenda — DRAFT/HOLD","Not authenticated; not an authorization, accepted fix or retest decision.",""];
 for(const r of rows)body.push("Original finding: "+r.finding+" | request: "+r.id,"Declared owner: "+r.owner+" | HUMAN kind: "+r.kind,
  "Instructions: "+r.instructions.replaceAll(/\s+/g," "),
  "UNVERIFIED owner reply: "+(r.answer?.human_response||"Not received").replaceAll(/\s+/g," "),
  "Human reviewer note: "+r.notes.note.replaceAll(/\s+/g," "),
  "LOCAL labels: "+r.local.length+" | signals: "+r.signals.join("; "),"");
 download("LightUp-PRIVATE-human-followup-agenda.txt",body.join("\n"),"text/plain;charset=utf-8");
 info("PRIVATE HUMAN agenda exported. Operator approval or execution is not implied.");
}
async function attachOriginalCSV(){
 if(!current)fail("load PRIVATE unified evidence first");
 const originalFile=$("sourceCsv").files[0];
 if(!originalFile||originalFile.size===0||originalFile.size>1048576)fail("choose a non-empty original CSV no larger than 1 MiB");
 const before=current.version,context=current.source;
 const parser=window.LightUpCasework;
 if(!parser||typeof parser.parseCSV!=="function"||typeof parser.digest!=="function")fail("exact original Casework source parser is unavailable");
 const bytes=await originalFile.arrayBuffer();
 const csv=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
 const findings=parser.parseCSV(csv);
 const originalSHA=await parser.digest(findings);
 if(!originalSHA||originalSHA!==context.source_sha256)fail("ORIGINAL CSV digest differs from selected PRIVATE evidence source; no enrichment applied");
 if(findings.length!==context.source_count)fail("ORIGINAL CSV row count differs from evidence workspace");
 const expected=context.casework||context.evidence_review;
 if(expected){
  const fromCSV=new Set(findings.map(r=>r.finding_id));
  if(expected.some(r=>!fromCSV.has(r.finding_id)))fail("source-native HUMAN findings do not match original CSV member IDs");
 }
 if(!current||current.version!==before||current.source!==context||$("sourceCsv").files[0]!==originalFile)
  fail("PRIVATE source/input changed during original CSV digest computation");
 const rows=buildFindingRows(context,sourceFindingRequests(context,current.rows),findings);
 if(rows.length!==context.source_count)fail("complete original source count disagrees with HUMAN finding coverage");
 current={...current,originalFindings:findings,findingRows:rows,version:++version};
 selectedFindings.clear();$("findingFilter").value="all";$("findingSearch").value="";
 draw();
 $("sourceNotice").textContent="Exact original CSV content SHA-256 matches the current DECLARED evidence source. "+findings.length+" source findings available for HUMAN review; origin, identity and actual fixes are NOT authenticated.";
 info("Local original CSV is content-bound to evidence source SHA-256. Original severity, title, retest claims and remediation descriptions displayed as UNVERIFIED source statements.");
}
function detachOriginalCSV(){
 if(!current)return;
 const old=current.originalFindings;
 if(old&&!confirm("Detach the original five-column CSV from the current HUMAN session? This clears severity, title, source retest and remediation text locally but keeps the originally selected evidence/response snapshots."))return;
 current={...current,originalFindings:null,
  findingRows:buildFindingRows(current.source,sourceFindingRequests(current.source,current.rows)),
  version:++version};
 selectedFindings.clear();$("sourceCsv").value="";$("findingSearch").value="";$("findingFilter").value="all";
 $("sourceNotice").textContent="No local original CSV attached. Source severity and remediation content remain unavailable without exact original content matching.";
 draw();info("Detached original five-column findings content from PRIVATE human review. No original source files were modified.");
}
function clearAllPrivateView(){
 current=null;version++;selected.clear();selectedFindings.clear();
 window.LightUpHandoffHumanPlan?.reset();
 for(const id of ["rows","findingRows","numbers","findingStats"])$(id).replaceChildren();
 $("sourceCsv").value="";$("sourceNotice").textContent="No locally content-matched original CSV loaded.";
 for(const id of ["binding","findingBinding","selection","findingSelection"])$(id).textContent="";
 $("ownerRecipient").replaceChildren(new Option("Choose one original owner alias",""));
 for(const id of ["review","findingDesk","out","sourceEnrichment"])$(id).hidden=true;
 for(const id of ["downloadPrivate","downloadOwner","downloadAgenda","exportFindingPrivate","exportFindingCounts","selectRequestsForFindings","attachOriginal","detachOriginal"])$(id).disabled=true;
}
/* Read-only local ORIGINAL finding context used by the independent HUMAN planning sidecar.
   No runtime authorization, original source edit, scanner or evidence verification. */
window.LightUpHandoffBridge=Object.freeze({
 context(){
  if(!current)return null;
  const findings=current.findingRows.map(x=>({
   id:x.id,source_severity:x.sourceFinding?.severity||"",
   casework_stage:x.casework?.status||"",
   human_owner_declared:x.casework?.owner||"",
   local_fingerprint_count:x.files.length
  }));
  return {source_contract:current.source.source_contract,
   source_sha256:current.source.source_sha256,client_reference:current.source.client_reference,
   engagement_reference:current.source.engagement_reference,
   ids:findings.map(x=>x.id),findings};
 },
 strictJSON
});
$("load").addEventListener("click",async()=>{
 const rev=++version,ledgerInput=$("ledger").files[0],registerInput=$("register").files[0];info("Reading both PRIVATE snapshots locally…");
 try{const [l,r]=await Promise.all([openFile("ledger"),openFile("register")]);
  if(version!==rev||$("ledger").files[0]!==ledgerInput||$("register").files[0]!==registerInput)fail("workspace or selected original files changed during load");
  const next=combine(l,r);if(window.LightUpHandoffHumanPlan&&!window.LightUpHandoffHumanPlan.canDiscard()){info("Original source handoff stopped to preserve unsaved PRIVATE HUMAN planning. Export the workplan before replacing it.");return;}current=next;selected.clear();selectedFindings.clear();window.LightUpHandoffHumanPlan?.reset();$("sourceCsv").value="";$("sourceNotice").textContent="No original five-column CSV locally matched."; $("search").value="";$("filter").value="all";draw();
  info("Matched and admitted original HUMAN requests and replies within the same DECLARED source. This does not authenticate source, author or permission.");
 }catch(e){info(e.message||String(e),true);}
});
$("attachOriginal").addEventListener("click",()=>{attachOriginalCSV().catch(e=>{info(e.message||String(e),true);$("sourceNotice").textContent=e.message||String(e);});});
$("detachOriginal").addEventListener("click",()=>{try{detachOriginalCSV();}catch(e){info(e.message||String(e),true);}});
$("sourceCsv").addEventListener("change",()=>{
 if(current?.originalFindings){
  current={...current,originalFindings:null,findingRows:buildFindingRows(current.source,sourceFindingRequests(current.source,current.rows)),version:++version};
  selectedFindings.clear();draw();
 }
 $("sourceNotice").textContent="Changed ORIGINAL CSV selection. Previous source details were detached; match exact original SHA-256 again before interpreting any severity.";
});
$("loadEvidenceOnly").addEventListener("click",async()=>{
 const rev=++version,ledgerInput=$("ledger").files[0];
 info("Reading original PRIVATE evidence workspace for HUMAN-only coverage…");
 try{
  const l=await openFile("ledger");
  if(version!==rev||$("ledger").files[0]!==ledgerInput)fail("original PRIVATE evidence input changed during reading");
  const next=evidenceOnly(l);if(window.LightUpHandoffHumanPlan&&!window.LightUpHandoffHumanPlan.canDiscard()){info("Evidence-only switch stopped to preserve unsaved PRIVATE HUMAN workplan.");return;}current=next;selected.clear();selectedFindings.clear();window.LightUpHandoffHumanPlan?.reset();$("sourceCsv").value="";$("sourceNotice").textContent="No original five-column CSV locally matched.";
  $("search").value="";$("filter").value="all";$("findingSearch").value="";$("findingFilter").value="all";draw();
  info(next.findingRows.length?"Original-source-declared HUMAN coverage opened WITHOUT a response register. No original request or authorization created.":"Original ledger loaded without complete native HUMAN source records. To enumerate all findings, attach the original five-column CSV and match its exact content SHA; no fake coverage inferred.");
 }catch(e){info(e.message||String(e),true);}
});
$("forget").addEventListener("click",()=>{
 if(window.LightUpHandoffHumanPlan&&!window.LightUpHandoffHumanPlan.canDiscard()){info("Forget cancelled; export your unsaved PRIVATE HUMAN planning first.");return;}
 clearAllPrivateView();
 for(const id of ["ledger","register","search","findingSearch"])$(id).value="";
 $("filter").value="all";$("findingFilter").value="all";
 info("All PRIVATE working state, visible/hidden detail text, owner choices and file-picker references cleared. Previous downloads must be secured or deleted separately.");
});
for(const id of ["ledger","register"])$(id).addEventListener("change",()=>{
 if(window.LightUpHandoffHumanPlan&&!window.LightUpHandoffHumanPlan.canDiscard()){
  $(id).value="";info("Changed source selection cancelled. Export unsaved PRIVATE HUMAN notes before choosing a new source.");return;
 }
 clearAllPrivateView();
 info("PRIVATE source selection changed. All prior HUMAN details, owner choices, summaries and exports were cleared. Inspect the new sources again.");
});
$("ownerRecipient").addEventListener("change",draw);
$("search").addEventListener("input",draw);$("filter").addEventListener("change",draw);
$("findingSearch").addEventListener("input",drawFindingBoard);$("findingFilter").addEventListener("change",drawFindingBoard);
$("selectFindingsVisible").addEventListener("change",e=>{for(const f of visibleFindingRows())e.target.checked?selectedFindings.add(f.id):selectedFindings.delete(f.id);drawFindingBoard();});
for(const [id,handler] of [["selectRequestsForFindings",chooseOriginalRequestsForFindings],["exportFindingPrivate",exportOriginalFindingPrivate],["exportFindingCounts",exportOriginalFindingCounts]])$(id).addEventListener("click",()=>{try{handler();}catch(e){info(e.message||String(e),true);}});
$("selectVisible").addEventListener("change",e=>{for(const x of filtered())e.target.checked?selected.add(x.id):selected.delete(x.id);draw();});
for(const [id,handler] of [["downloadPrivate",privateExport],["downloadOwner",oneOwnerExport],["downloadAggregate",aggregateExport],["downloadAgenda",agendaExport]]){
 $(id).addEventListener("click",()=>{try{handler();}catch(e){info(e.message||String(e),true);}});
}
})();