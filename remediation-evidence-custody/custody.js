/* Offline local custody reconciliation. Never an authorization or remediation verdict. */
(function(){
"use strict";
const $=id=>document.getElementById(id),MAX_FILE=16*1024*1024,MAX_INDEX=2*1024*1024;
const FLAGS=["authenticated","tenant_verified","source_authorized","assessment_authorized","grant","client_consent","operator_consent","execution","scan","audit_verdict","retest_verified","release"];
const FIELDS=["finding_id","file_name","byte_length","sha256","mime","added_utc","human_reviewer","human_stage","human_note"];
let current=null,results=[],busy=false,revision=0;
function fail(s){throw Error(s);}
function announce(s,bad){$("notice").textContent=s;$("notice").className=bad?"alert":"notice";}
function clean(s,max,label,required=false){if(typeof s!=="string"||s.length>max||/[\u0000-\u001f\u007f]/u.test(s)||(required&&!s.trim()))fail("Invalid "+label);return s;}
function strictJSON(raw){
 if(typeof raw!=="string"||new TextEncoder().encode(raw).length>MAX_INDEX)fail("PRIVATE import exceeds 2 MiB.");
 const obj=JSON.parse(raw),stack=[];let quoted=false,esc=false,start=0;
 for(let i=0;i<raw.length;i++){
  const c=raw[i];if(quoted){
   if(esc){esc=false;continue;}if(c==="\\"){esc=true;continue;}
   if(c==='"'){quoted=false;let j=i+1;while(/\s/u.test(raw[j]||""))j++;
    if(raw[j]===":"){const frame=stack[stack.length-1];if(!frame||frame.type!=="{")fail("Malformed JSON key.");
     const name=JSON.parse(raw.slice(start,i+1));if(frame.keys.has(name))fail("Duplicate JSON property rejected.");
     frame.keys.add(name);
    }
   }continue;
  }if(c==='"'){quoted=true;start=i;continue;}
  if(c==="{"||c==="["){stack.push({type:c,keys:new Set()});if(stack.length>40)fail("Nested JSON exceeds limit.");}
  if(c==="}"||c==="]"){const frame=stack.pop();if(!frame||frame.type!==(c==="}"?"{":"["))fail("Malformed JSON structure.");}
 }
 if(quoted||stack.length)fail("Unbalanced JSON.");return obj;
}
function validate(p){
 if(!p||typeof p!=="object"||Array.isArray(p))fail("Expected PRIVATE LightUp JSON object.");
 const ledger=p.kind==="lightup.private_artifact_ledger"&&p.schema_version===1&&p.disposition==="PRIVATE_HUMAN_EVIDENCE_INDEX_ONLY";
 const unified=p.kind==="lightup.private_unified_human_evidence_workspace"&&p.schema_version===2&&p.disposition==="PRIVATE_HUMAN_REVIEW_ONLY";
 if(!ledger&&!unified)fail("Unsupported original Artifact Ledger/Unified HUMAN schema.");
 if(p.source_contract!=="lightup.finding_export._COLUMNS_v1"||typeof p.source_sha256!=="string"||!/^[0-9a-f]{64}$/u.test(p.source_sha256))fail("Invalid original source digest.");
 if(!Number.isSafeInteger(p.source_count)||p.source_count<1||p.source_count>350)fail("Invalid original source row count.");
 clean(p.client_reference,120,"client label",true);clean(p.engagement_reference,120,"engagement label",true);
 if(FLAGS.some(f=>p[f]!==false))fail("All authority/consent/verified fields must literally be false.");
 if(!Array.isArray(p.attachments)||p.attachments.length>120)fail("Artifact index must contain 0–120 records.");
 const seen=new Set(),rows=[];
 for(const row of p.attachments){
  if(!row||typeof row!=="object"||Array.isArray(row)||Object.keys(row).length!==FIELDS.length||FIELDS.some(k=>!Object.hasOwn(row,k)))fail("Unexpected record shape.");
  clean(row.finding_id,180,"finding ID",true);clean(row.file_name,240,"file label",true);
  if(/[\/\\]/u.test(row.file_name))fail("File label must not contain a path.");
  if(!Number.isSafeInteger(row.byte_length)||row.byte_length<0||row.byte_length>MAX_FILE)fail("Indexed file length outside bounds.");
  if(typeof row.sha256!=="string"||!/^[0-9a-f]{64}$/u.test(row.sha256))fail("Malformed SHA-256.");
  clean(row.mime,120,"MIME");clean(row.human_reviewer,120,"HUMAN reviewer");clean(row.human_note,1200,"HUMAN note");
  if(!["unreviewed","human_review","follow_up","archived"].includes(row.human_stage))fail("Invalid HUMAN review stage.");
  if(typeof row.added_utc!=="string"||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/u.test(row.added_utc)||Number.isNaN(Date.parse(row.added_utc)))fail("Invalid timestamp.");
  const key=row.finding_id+"|"+row.sha256;if(seen.has(key))fail("Duplicate finding / fingerprint.");seen.add(key);
  rows.push(Object.freeze({...row}));
 }
 return Object.freeze({source_sha256:p.source_sha256,source_count:p.source_count,
 client_reference:p.client_reference,engagement_reference:p.engagement_reference,rows:Object.freeze(rows)});
}
function refresh(){
 $("import").disabled=busy;$("run").disabled=busy||!current;
 $("private").disabled=busy||!results.length;$("anonymous").disabled=busy||!results.length;
 $("forget").disabled=busy;$("confirmPrivate").disabled=busy;
 $("context").textContent=current?
  "PRIVATE self-declared context: "+current.client_reference+" / "+current.engagement_reference+
  " · source SHA-256 "+current.source_sha256+" · "+current.source_count+" original finding rows · "+current.rows.length+" fingerprints. No live authentication or client consent.":
  "No PRIVATE original evidence index loaded.";
}
function node(tag,value){const e=document.createElement(tag);if(value!==undefined)e.textContent=value;return e;}
function render(){
 const root=$("results");root.replaceChildren();
 if(!results.length){$("summary").textContent="No local comparison yet.";return;}
 const counts={match:0,rename:0,missing:0,unindexed:0,rejected:0};
 results.forEach(x=>counts[x.status]++);
 $("summary").textContent="Indexed: "+current.rows.length+" · same bytes and label: "+counts.match+
 " · same bytes, different label: "+counts.rename+" · not selected: "+counts.missing+
 " · unindexed local files: "+counts.unindexed+" · oversized files: "+counts.rejected+
 ". Local comparison is not verification of evidence origin or actual remediation.";
 const table=node("table"),thead=node("thead"),h=node("tr");
 ["Original finding / local file label","Indexed digest","Local digest","Length","HUMAN local check"].forEach(x=>h.append(node("th",x)));
 thead.append(h);table.append(thead);
 const body=node("tbody");
 results.forEach(r=>{
  const tr=node("tr");tr.className=r.status==="match"?"match":r.status==="rename"?"warn":"unknown";
  [r.finding_id?r.finding_id+" / "+r.indexed_name:r.local_name,
   r.indexed_sha?r.indexed_sha.slice(0,16)+"…":"—",r.local_sha?r.local_sha.slice(0,16)+"…":"—",r.byte_length,r.reason]
   .forEach(v=>tr.append(node("td",String(v))));
  body.append(tr);
 });
 table.append(body);root.append(table);
}
function evaluate(index,files){
 const byDigest=new Map(),byName=new Map(),used=new Set(),output=[];
 for(const f of files){
  const k=f.sha+"|"+f.size;if(!byDigest.has(k))byDigest.set(k,[]);byDigest.get(k).push(f);
  if(!byName.has(f.name))byName.set(f.name,[]);byName.get(f.name).push(f);
 }
 for(const r of index.rows){
  const hits=byDigest.get(r.sha256+"|"+r.byte_length)||[];
  const exact=hits.find(f=>f.name===r.file_name),hit=exact||hits[0];
  if(hit)used.add(hit.n);
  const status=hit?(exact?"match":"rename"):"missing";
  const reason=status==="match"?"Local bytes + label match (HUMAN only)":
   status==="rename"?"Bytes match; filename differs — HUMAN review":
   (byName.get(r.file_name)||[]).length?"Same label with other bytes/size — HUMAN HOLD":
   "Not in this selection (NOT evidence globally missing)";
  output.push({finding_id:r.finding_id,indexed_name:r.file_name,local_name:hit?hit.name:"",
   indexed_sha:r.sha256,local_sha:hit?hit.sha:"",byte_length:r.byte_length,status,reason});
 }
 for(const f of files)if(!used.has(f.n))output.push({finding_id:"",indexed_name:"",local_name:f.name,
  indexed_sha:"",local_sha:f.sha,byte_length:f.size,status:f.error?"rejected":"unindexed",
  reason:f.error||"Local file bytes not in selected private index — HUMAN review"});
 return output;
}
async function loadIndex(){
 if(busy)return;const f=$("manifest").files[0];if(!f)return announce("Select a PRIVATE JSON manifest.",true);
 busy=true;refresh();
 try{
  if(f.size>MAX_INDEX)fail("Index exceeds 2 MiB.");const item=validate(strictJSON(await f.text()));
  current=item;revision++;results=[];$("localFiles").value="";$("confirmPrivate").checked=false;
  render();announce("Private index loaded in memory. No source or account authentication has occurred.");
 }catch(e){announce("Index refused: "+e.message,true);}
 finally{busy=false;refresh();}
}
async function run(){
 if(busy||!current)return;const list=[...$("localFiles").files];
 if(!list.length)return announce("Select local files.",true);
 if(list.length>240)return announce("Maximum 240 local files per comparison.",true);
 busy=true;refresh();announce("Hashing selected local files in browser memory.");
 const candidate=[],token=revision,initial=current;
 try{
  if(typeof crypto==="undefined"||!crypto.subtle)fail("Browser WebCrypto not available.");
  for(let n=0;n<list.length;n++){
   const f=list[n];let sha="",problem="";
   if(f.size>MAX_FILE)problem="File over 16 MiB was NOT hashed";
   else sha=Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",await f.arrayBuffer())),
    x=>x.toString(16).padStart(2,"0")).join("");
   candidate.push({n,name:f.name,size:f.size,sha,error:problem});
   if((n+1)%12===0){announce("Processed "+(n+1)+" of "+list.length+" local files.");await new Promise(ok=>setTimeout(ok,0));}
  }
  if(current!==initial||token!==revision)fail("Index changed during file read.");
  results=evaluate(initial,candidate);$("confirmPrivate").checked=false;render();
  announce("Local comparison available. This is a HUMAN-only file byte check, not a security or consent decision.");
 }catch(e){announce("Comparison refused: "+e.message,true);}
 finally{busy=false;refresh();}
}
function escapeCell(value){
 let s=String(value??"");
 if(/^[\s\uFEFF\u200B-\u200F\u202A-\u202E\u2060-\u206F]*[=+\-@]/u.test(s))s="'"+s;
 return '"'+s.replaceAll('"','""')+'"';
}
function csv(rows){return rows.map(r=>r.map(escapeCell).join(",")).join("\r\n")+"\r\n";}
function download(name,data){
 const blob=new Blob([data],{type:"text/csv;charset=utf-8"}),url=URL.createObjectURL(blob),a=node("a");
 a.href=url;a.download=name;document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),1500);
}
function anonymous(){
 const counts={match:0,rename:0,missing:0,unindexed:0,rejected:0};
 results.forEach(x=>counts[x.status]++);
 download("LightUp-local-custody-anonymous-counts.csv",csv([["local_human_category","count"],...Object.entries(counts)]));
 announce("Counts-only CSV exported, without names, source IDs, digests or client context.");
}
function privateReport(){
 if(!$("confirmPrivate").checked)return announce("Confirm private recipient and storage before exporting.",true);
 if(!confirm("Export PRIVATE HUMAN file reconciliation? Includes original IDs, filenames and local file digests. No permission, provenance signature, or verified remediation."))return;
 download("LightUp-PRIVATE-local-custody.csv",csv([
 ["private_source_sha256","original_finding_id","indexed_file_name","local_file_name",
 "indexed_sha256","local_sha256","byte_length","human_local_result","human_note"],
 ...results.map(r=>[current.source_sha256,r.finding_id,r.indexed_name,r.local_name,
 r.indexed_sha,r.local_sha,r.byte_length,r.status,r.reason])]));
 $("confirmPrivate").checked=false;announce("PRIVATE local HUMAN report downloaded. Handle through an independently approved secure channel.");
}
function forget(){
 if(!confirm("Forget all PRIVATE index and local comparison data in this tab? Existing downloads are NOT removed."))return;
 current=null;revision++;results=[];$("manifest").value="";$("localFiles").value="";$("confirmPrivate").checked=false;
 render();refresh();announce("Private memory cleared; previously downloaded files are unaffected.");
}
$("import").addEventListener("click",()=>loadIndex().catch(e=>announce(e.message,true)));
$("run").addEventListener("click",()=>run().catch(e=>announce(e.message,true)));
$("anonymous").addEventListener("click",anonymous);
$("private").addEventListener("click",privateReport);
$("forget").addEventListener("click",forget);
refresh();render();
})();