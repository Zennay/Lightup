/* LightUp offline PRIVATE local-file checksum desk. Human-only, non-authorizing.
   Source ledger is read from the local HUMAN triage app; file bytes never persist. */
(() => {
"use strict";
const $ = id => document.getElementById(id);
const BRIDGE = window.LightUpHumanTriageBridge;
const FLAGS = ["authenticated","tenant_verified","source_authorized","assessment_authorized","grant",
 "client_consent","operator_consent","execution","scan","audit_verdict","retest_verified","release"];
const MAX_FILE = 16 * 1024 * 1024, MAX_FILES = 120;
let epoch=0,review=null;
function status(s){$("custody-progress").textContent=s;}
function clear(preserveFiles=false) {
 epoch++;review=null;
 if(!preserveFiles)$("custody-files").value="";
 $("custody-results").replaceChildren();
 $("custody-summary").textContent="";
 $("custody-export").disabled=true;
 $("custody-brief").disabled=true;
 status("No local bytes compared; previous results forgotten.");
 window.dispatchEvent(new CustomEvent("lightup:local-custody", {detail:null}));
}
function snapshot() {return BRIDGE?.snapshot()||null;}
function sync(){
 clear();
 const ctx=snapshot();
 $("custody-files").disabled=!ctx;
 $("custody-review").disabled=!ctx;
 $("custody-state").textContent=ctx?
   "Loaded local PRIVATE source-bound Ledger: "+ctx.records.length+
   " registered artifact fingerprints across "+ctx.source_count+
   " ORIGINAL findings. Source identity remains UNVERIFIED.":
   "HOLD: import ORIGINAL HUMAN workplan and the same-source PRIVATE Artifact Ledger first.";
}
function hex(buffer) {
 return Array.from(new Uint8Array(buffer), x=>x.toString(16).padStart(2,"0")).join("");
}
function key(r) {return JSON.stringify([r.finding_id,r.sha256,r.byte_length,r.file_name]);}
function classify(name,length,digest,records) {
 const sameName=records.filter(r=>r.file_name===name);
 const exact=sameName.filter(r=>r.byte_length===length&&r.sha256===digest);
 const sameContents=records.filter(r=>r.byte_length===length&&r.sha256===digest);
 if(exact.length===1)return {kind:"local_fingerprint_matches_one_ledger_row",
   candidates:exact.map(r=>({finding_id:r.finding_id,file_name:r.file_name,sha256:r.sha256,byte_length:r.byte_length}))};
 if(exact.length>1)return {kind:"ambiguous_same_fingerprint_multiple_original_findings",
   candidates:exact.map(r=>({finding_id:r.finding_id,file_name:r.file_name,sha256:r.sha256,byte_length:r.byte_length}))};
 if(sameContents.length)return {kind:"content_digest_matches_different_filename_or_finding",
   candidates:sameContents.map(r=>({finding_id:r.finding_id,file_name:r.file_name,sha256:r.sha256,byte_length:r.byte_length}))};
 if(sameName.some(r=>r.byte_length===length))return {kind:"local_bytes_differ_from_listed_sha",
   candidates:sameName.filter(r=>r.byte_length===length).map(r=>({finding_id:r.finding_id,file_name:r.file_name,sha256:r.sha256,byte_length:r.byte_length}))};
 if(sameName.length)return {kind:"local_size_differs_from_listed_bytes",
   candidates:sameName.map(r=>({finding_id:r.finding_id,file_name:r.file_name,sha256:r.sha256,byte_length:r.byte_length}))};
 return {kind:"not_present_in_selected_original_ledger",candidates:[]};
}
function draw(){
 const root=$("custody-results");root.replaceChildren();
 if(!review)return;
 const exact=review.rows.filter(r=>r.kind==="local_fingerprint_matches_one_ledger_row");
 const unique=new Set(exact.map(r=>key(r.candidates[0])));
 const report=review.rows.reduce((acc,r)=>{acc[r.kind]=(acc[r.kind]||0)+1;return acc;},{});
 $("custody-summary").textContent=review.rows.length+" local files considered · "+unique.size+
 " distinct original Ledger rows with local byte-fingerprint agreement · "+review.ledgerRows+
 " Ledger rows total · "+(review.ledgerRows-unique.size)+" Ledger rows not independently compared. "+
 "No source authenticity or security remediation verified.";
 for(const row of review.rows){
  const item=document.createElement("article");item.className="inbox-item";
  const title=document.createElement("h3");title.textContent=row.local_name+" · "+row.local_bytes+" bytes";item.append(title);
  const badge=document.createElement("span");badge.className="tag "+
   (row.kind==="local_fingerprint_matches_one_ledger_row"?"":"alert");
  badge.textContent=row.kind.replaceAll("_"," ");item.append(badge);
  const digest=document.createElement("p");digest.textContent="Locally computed SHA-256: "+row.local_sha256;item.append(digest);
  const context=document.createElement("p");
  context.textContent=row.candidates.length?
    "Matching or conflicting Ledger references (HUMAN review): "+row.candidates.map(x=>x.finding_id+" / "+x.file_name).join(" · "):
    "No matching original ledger reference. This does NOT mean absent security evidence.";
  item.append(context);
  if(row.kind==="local_fingerprint_matches_one_ledger_row"){
    const go=document.createElement("button");go.className="quiet";go.type="button";
    go.textContent="Open original finding in HUMAN queue";
    go.addEventListener("click",()=>{
      $("query").value=row.candidates[0].finding_id;
      $("mode").value="all";$("owner").value="";$("query").dispatchEvent(new Event("input"));
      $("workqueue").scrollIntoView({behavior:"smooth",block:"start"});
    });
    item.append(go);
  }
  root.append(item);
 }
 $("custody-export").disabled=false;
 $("custody-brief").disabled=false;
 const byFinding=new Map();
 for(const original of review.source.original_finding_ids)byFinding.set(original,{listed:0,matched:0,attention:0});
 for(const original of review.source.records)byFinding.get(original.finding_id).listed++;
 for(const result of review.rows){
   const affected=new Set(result.candidates.map(c=>c.finding_id));
   for(const fid of affected){
     const item=byFinding.get(fid);if(!item)continue;
     if(result.kind==="local_fingerprint_matches_one_ledger_row")item.matched++;
     else item.attention++;
   }
 }
 window.dispatchEvent(new CustomEvent("lightup:local-custody",{detail:{
   revision:review.source.revision,byFinding:[...byFinding.entries()].map(([finding_id,v])=>({finding_id,...v}))
 }}));
}
async function compare(){
 if(!snapshot()){status("HOLD: original workplan / Ledger source missing.");return;}
 const inputs=Array.from($("custody-files").files||[]);
 if(!inputs.length){status("Select local evidence files first.");return;}
 if(inputs.length>MAX_FILES){status("HOLD: no more than 120 local files at once.");return;}
 if(inputs.some(f=>f.size>MAX_FILE)){status("HOLD: one or more local files exceed 16 MiB.");return;}
 if(!globalThis.crypto?.subtle){status("HOLD: SHA-256 unavailable in this browser context. No comparison performed.");return;}
 const ctx=snapshot(),localEpoch=++epoch;
 review=null;$("custody-export").disabled=true;$("custody-brief").disabled=true;
 $("custody-summary").textContent="";$("custody-results").replaceChildren();
 $("custody-review").disabled=true;
 const seen=new Set(),rows=[];
 try{
  for(const [index,file] of inputs.entries()){
   if(epoch!==localEpoch||snapshot()?.revision!==ctx.revision)throw Error("source changed during checksum");
   status("Hashing locally selected file "+(index+1)+" / "+inputs.length+"; no upload.");
   const content=await file.arrayBuffer();
   if(epoch!==localEpoch||snapshot()?.revision!==ctx.revision)throw Error("source changed while reading");
   const digest=hex(await crypto.subtle.digest("SHA-256",content));
   if(epoch!==localEpoch||snapshot()?.revision!==ctx.revision)throw Error("source changed while hashing");
   const detected=classify(file.name,file.size,digest,ctx.records);
   const localKey=JSON.stringify([file.name,file.size,digest]);
   if(seen.has(localKey))detected.kind="repeated_local_file_selection";
   seen.add(localKey);
   rows.push({local_name:file.name.slice(0,240),local_bytes:file.size,
    local_sha256:digest,kind:detected.kind,candidates:detected.candidates});
  }
  review={source:ctx,rows,ledgerRows:ctx.records.length};
  status("PRIVATE local file fingerprints compared. All original files and ledger rows unchanged.");
  draw();
 }catch(_){review=null;status("HOLD: comparison interrupted or original source changed. No partial results retained.");}
 finally{
  $("custody-review").disabled=!snapshot();
  $("custody-files").value=""; // release browser File references after compare, keep only bounded metadata.
 }
}
function packet(){
 if(!review||snapshot()?.revision!==review.source.revision)throw Error("Original evidence source changed");
 const ctx=review.source;
 return {kind:"lightup.private_local_evidence_custody_review",schema_version:1,
  disposition:"UNVERIFIED_LOCAL_FILE_FINGERPRINT_COMPARISON",source_contract:ctx.source_contract,
  source_sha256:ctx.source_sha256,client_reference:ctx.client_reference,
  engagement_reference:ctx.engagement_reference,source_count:ctx.source_count,
  original_finding_ids:ctx.original_finding_ids,ledger_row_count:review.ledgerRows,
  ...Object.fromEntries(FLAGS.map(k=>[k,false])),
  compared_files:review.rows.map(r=>({...r,candidates:r.candidates.map(c=>({...c}))})),
  warning:"PRIVATE local byte fingerprint comparison only: no authenticated chain of custody, evidence truth, verified security finding, client or operator consent, retest, fix or release."};
}
function save(name,text,contentType){
 const url=URL.createObjectURL(new Blob([text],{type:contentType}));
 const a=document.createElement("a");a.href=url;a.download=name;document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),4000);
}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>
 ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));}
function exportJson(){
 try{
  const p=packet();
  if(!confirm("Export PRIVATE file names, computed SHA-256 and original finding IDs into local JSON? Recipient and chain of custody remain UNVERIFIED."))return;
  save("LightUp-PRIVATE-local-file-custody-review.json",JSON.stringify(p,null,2)+"\n","application/json");
  status("PRIVATE HUMAN local-file fingerprint report requested.");
 }catch(_){status("HOLD: original Ledger source changed; compare again.");}
}
function exportBrief(){
 try{
  const p=packet();
  if(!confirm("Export PRIVATE readable checksum review with file names, original IDs and SHA-256? Verify recipient and safe storage."))return;
  const rows=p.compared_files.map(r=>"<tr><td>"+escapeHtml(r.local_name)+"</td><td>"+
   r.local_bytes+"</td><td>"+escapeHtml(r.local_sha256)+"</td><td>"+
   escapeHtml(r.kind)+"</td><td>"+escapeHtml(r.candidates.map(c=>c.finding_id).join(", "))+"</td></tr>").join("");
  const html="<!doctype html><html lang='en'><meta charset='utf-8'><meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'\"><title>PRIVATE HUMAN checksum discussion</title>"+
   "<style>body{font:15px system-ui;max-width:1100px;margin:40px auto;padding:15px;color:#111}table{border-collapse:collapse}td,th{border:1px solid #666;padding:8px;overflow-wrap:anywhere}</style>"+
   "<h1>PRIVATE local source-bound checksum discussion</h1><p><b>NON-AUTHORIZING.</b> Local bytes were compared against a self-declared original Ledger. Match does not prove authentic evidence, source ownership, remediation, retest or consent.</p>"+
   "<p>Source SHA declaration: "+escapeHtml(p.source_sha256)+" · client declaration: "+escapeHtml(p.client_reference)+
   " · engagement: "+escapeHtml(p.engagement_reference)+"</p><table><thead><tr><th>Local file</th><th>Bytes</th><th>Computed SHA-256</th><th>Comparison result</th><th>Original finding candidate(s)</th></tr></thead><tbody>"+
   rows+"</tbody></table><p>Unselected Ledger rows are not independently compared; unknown does not mean missing evidence or security failure.</p></html>";
  save("LightUp-PRIVATE-file-custody-human-brief.html",html,"text/html");
  status("PRIVATE scriptless human checksum discussion requested.");
 }catch(_){status("HOLD: original Ledger source changed; compare again.");}
}
window.addEventListener("lightup:human-sources-changed",sync);
$("custody-files").addEventListener("change",()=>{
 clear(true);status($("custody-files").files.length+" local files selected for PRIVATE on-device SHA comparison.");
});
$("custody-review").addEventListener("click",compare);
$("custody-forget").addEventListener("click",()=>{
 if(review&&!confirm("Forget all current PRIVATE fingerprint comparison results?"))return;
 clear();status("Local selected files and SHA-256 results forgotten.");
});
$("custody-export").addEventListener("click",exportJson);
$("custody-brief").addEventListener("click",exportBrief);
sync();
})();