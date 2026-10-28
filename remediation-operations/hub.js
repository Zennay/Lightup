"use strict";
/* Local, non-authorizing HUMAN coordination only. Nothing reaches the network or browser storage. */
const STAGES=Object.freeze([
  ["evidence","Original evidence","Evidence Ledger"],
  ["responses","Owner responses","Response Reconciliation"],
  ["handoff","HUMAN handoff","Evidence Handoff Inbox"],
  ["runbooks","Planned remediation","HUMAN Runbook Editor"]
]);
const STATUSES=Object.freeze(["not-started","preparing","needs-human-input","handed-off"]);
const AUTHORITY=Object.freeze({
  authorized:false,client_consent:false,operator_consent:false,grant_issued:false,
  permission_to_scan:false,retest_approved:false,fix_verified:false,source_authenticated:false,
  owner_authenticated:false,release_approved:false,security_review_approved:false,ci_verified:false
});
const SOURCE_HEADS=Object.freeze({
  "1642":"6a8cd3baf6535705a7baca77dc3dc5067f862b3d",
  "1643":"58ad10f0b8cfb949287d4751b782221fc4ff9948",
  "1644":"933a0a4e278c957bbeaa564c3effcab6d1ae8a31",
  "1645":"f08fb96f7094d021493a39aa5d1a3eed025509f3",
  "1640":"1a1ec2b95db5fdb15716e5c7dde21d22322bbb54",
  "1631":"b7291f4cf560638509cac414207a5e126b4f07de"
});
const VERSION=1;
let state=STAGES.map(([id])=>({id,status:"not-started",note:""}));
let dirty=false;
const get=id=>document.getElementById(id);
function announce(message){get("message").textContent=message;}
function showCoverage(){
  get("coverage").textContent=state.filter(x=>x.status!=="not-started").length+
  " of 4 HUMAN workflow markers prepared · purely self-declared";
}
function render(){
  get("rows").replaceChildren();
  for(const [index,stage] of STAGES.entries()){
    const row=document.createElement("section");row.className="row";
    const left=document.createElement("div"),right=document.createElement("div");
    const title=document.createElement("h3");title.textContent=stage[1];left.append(title);
    const subtitle=document.createElement("p");subtitle.textContent=stage[2]+" · HUMAN planning only";
    left.append(subtitle);
    const lab=document.createElement("label");lab.textContent="HUMAN coordination status";
    lab.htmlFor="status-"+stage[0];
    const select=document.createElement("select");select.id=lab.htmlFor;
    for(const [key,name] of [
      ["not-started","Not started"],["preparing","Local preparation"],["needs-human-input","Needs HUMAN input"],["handed-off","Self-declared handoff"]
    ]){const o=document.createElement("option");o.value=key;o.textContent=name;select.append(o);}
    select.value=state[index].status;
    select.addEventListener("change",()=>{state[index].status=select.value;dirty=true;showCoverage();announce("Unsaved PRIVATE local changes. Export before closing.");});
    right.append(lab,select);
    const noteLabel=document.createElement("label");noteLabel.htmlFor="note-"+stage[0];noteLabel.textContent="PRIVATE human note (max 512 characters)";
    const note=document.createElement("textarea");note.id=noteLabel.htmlFor;note.maxLength=512;note.value=state[index].note;
    note.setAttribute("aria-label",stage[1]+" private note");
    note.addEventListener("input",()=>{state[index].note=note.value;dirty=true;announce("Unsaved PRIVATE local changes. Export before closing.");});
    right.append(noteLabel,note);
    row.append(left,right);get("rows").append(row);
  }
  showCoverage();
}
function download(name,content,mime){
  const blob=new Blob([content],{type:mime});
  const url=URL.createObjectURL(blob),a=document.createElement("a");
  a.href=url;a.download=name;document.body.append(a);a.click();a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),3000);
}
function currentPacket(){
  return {schema:"lightup-private-human-coordination-v1",version:VERSION,
    source_heads:SOURCE_HEADS,authority:AUTHORITY,stages:state.map(x=>({...x})),
    notice:"HUMAN planning only. No authenticated source, consent, grant, security finding, fixed issue, or release claim."};
}
function htmlEscape(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));}
function exportJson(){
  download("lightup-private-human-coordination.json",JSON.stringify(currentPacket(),null,2)+"\n","application/json");
  dirty=false;announce("PRIVATE export requested. Verify the saved file and its recipient independently.");
}
function exportHtml(){
  const lines=state.map((x,i)=>"<tr><th scope='row'>"+htmlEscape(STAGES[i][1])+"</th><td>"+
    htmlEscape(x.status)+"</td><td>"+htmlEscape(x.note).replace(/\n/g,"<br>")+"</td></tr>").join("");
  const html="<!doctype html><html lang='en'><meta charset='utf-8'><meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; form-action 'none'\"><title>PRIVATE HUMAN coordination</title>"+
    "<style>body{font:16px system-ui;max-width:900px;margin:40px auto;padding:0 20px;color:#111}td,th{border:1px solid #999;padding:12px;text-align:left;overflow-wrap:anywhere;vertical-align:top}table{border-collapse:collapse;width:100%}.warning{border:2px solid #333;padding:16px}p{line-height:1.5}</style>"+
    "<h1>PRIVATE HUMAN Remediation Coordination</h1><p class='warning'><b>Non-authorizing private human planning.</b> No authenticated identity, customer permission, scan approval, retest, verified fix or release. Manually verify source and recipient.</p>"+
    "<table><thead><tr><th>Original workflow</th><th>Self-declared stage</th><th>PRIVATE human coordination note</th></tr></thead><tbody>"+lines+"</tbody></table>"+
    "<p>Exact imported source-owner PR references: #1642, #1643, #1644, #1645. This brief is not evidence of authority.</p></html>";
  download("lightup-private-human-coordination.html",html,"text/html");
  announce("Scriptless PRIVATE human brief export requested. Confirm destination and recipient.");
}
/* Bounded exact-key parser: unlike JSON.parse alone, reject duplicate keys in any object. */
function parseNoDuplicateKeys(source){
  let p=0;const n=source.length;
  const ws=()=>{while(p<n&&/\s/.test(source[p]))p++;};
  function parseString(){
    const start=p;if(source[p]!=='"')throw Error("Expected JSON string");
    p++;while(p<n){
      if(source[p]==="\\"){p+=2;continue;}
      if(source[p++]==='"')return JSON.parse(source.slice(start,p));
    }
    throw Error("Unterminated string");
  }
  function value(depth){
    if(depth>16)throw Error("Excessive nesting");
    ws();const c=source[p];
    if(c==='"')return parseString();
    if(c==='{'){
      p++;const o=Object.create(null),seen=new Set();ws();
      if(source[p]==='}'){p++;return o;}
      for(;;){
        ws();const k=parseString();if(seen.has(k))throw Error("Duplicate JSON key");seen.add(k);
        ws();if(source[p++]!==':')throw Error("Missing colon");
        o[k]=value(depth+1);ws();const next=source[p++];
        if(next==='}')break;if(next!==',')throw Error("Malformed object");
      }
      return o;
    }
    if(c==='['){
      p++;const a=[];ws();if(source[p]===']'){p++;return a;}
      for(;;){
        a.push(value(depth+1));ws();const next=source[p++];
        if(next===']')break;if(next!==',')throw Error("Malformed array");
      }return a;
    }
    const start=p;while(p<n&&!/[\s,}\]]/.test(source[p]))p++;
    if(start===p)throw Error("Malformed value");
    const primitive=source.slice(start,p);
    if(!/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)$/.test(primitive))throw Error("Invalid primitive");
    return JSON.parse(primitive);
  }
  const obj=value(0);ws();if(p!==n)throw Error("Trailing content");return obj;
}
function exactKeys(obj,keys){
  return obj!==null&&typeof obj==="object"&&!Array.isArray(obj)&&
    Object.keys(obj).length===keys.length&&keys.every(k=>Object.hasOwn(obj,k));
}
function validatePacket(doc){
  if(!exactKeys(doc,["schema","version","source_heads","authority","stages","notice"])||
     doc.schema!=="lightup-private-human-coordination-v1"||doc.version!==VERSION||
     typeof doc.notice!=="string"||doc.notice.length>350)throw Error("Invalid envelope");
  if(!exactKeys(doc.source_heads,Object.keys(SOURCE_HEADS))||
     Object.keys(SOURCE_HEADS).some(k=>doc.source_heads[k]!==SOURCE_HEADS[k]))
     throw Error("Original imported app revisions differ");
  if(!exactKeys(doc.authority,Object.keys(AUTHORITY))||
     Object.keys(AUTHORITY).some(k=>doc.authority[k]!==false))
     throw Error("An authority field is not literally false");
  if(!Array.isArray(doc.stages)||doc.stages.length!==STAGES.length)throw Error("Incomplete stage set");
  return doc.stages.map((x,i)=>{
    if(!exactKeys(x,["id","status","note"])||x.id!==STAGES[i][0]||
      !STATUSES.includes(x.status)||typeof x.note!=="string"||x.note.length>512||
      /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(x.note))throw Error("Invalid stage row");
    return {id:x.id,status:x.status,note:x.note};
  });
}
async function restore(event){
  const file=event.target.files[0];event.target.value="";
  if(!file)return;
  if(file.size>65536){announce("HOLD: PRIVATE desk file exceeds 64 KiB.");return;}
  try{
    const text=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
    const draft=validatePacket(parseNoDuplicateKeys(text));
    if(!confirm("Replace ALL current PRIVATE HUMAN coordination markers and notes with this locally selected unverified file? This grants NO authority."))return;
    state=draft;dirty=false;render();announce("PRIVATE HUMAN coordination restored locally. Source labels and identities remain unauthenticated.");
  }catch(_){announce("HOLD: PRIVATE desk import invalid, mismatched, or ambiguous. Nothing was changed.");}
}
get("export-json").addEventListener("click",exportJson);
get("export-html").addEventListener("click",exportHtml);
get("import-json").addEventListener("change",restore);
get("clear").addEventListener("click",()=>{
  if(!confirm("Forget all PRIVATE local HUMAN coordination markers and notes?"))return;
  state=STAGES.map(([id])=>({id,status:"not-started",note:""}));dirty=false;render();announce("Local HUMAN coordination cleared.");
});
window.addEventListener("beforeunload",e=>{if(dirty){e.preventDefault();e.returnValue="";}});
render();
