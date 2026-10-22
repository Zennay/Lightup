"use strict";
/* PRIVATE source-file delta viewer. All inputs are untrusted, no authority inferred. */
const loaded={before:null,after:null};
let changes=null,revisionDeltas=null;
const id=n=>document.getElementById(n);
const PRS=["1642","1643","1644","1645","1640","1631"];
const KEYS=["schema","release","authentication","client_consent","operator_consent","active_execution","security_fix_verified","production_release_approved","original_source_pr_heads","privacy","start","files"];
function setStatus(s){id("compare-status").textContent=s;}
function exact(o,keys){return o!==null&&typeof o==="object"&&!Array.isArray(o)&&Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k));}
function parseStrict(s){
  let i=0;const len=s.length;const skip=()=>{while(i<len&&/\s/.test(s[i]))i++;};
  function string(){if(s[i]!=='"')throw Error("json string");let a=i++;while(i<len){if(s[i]==="\\"){i+=2;continue;}if(s[i++]==='"')return JSON.parse(s.slice(a,i));}throw Error("json string");}
  function value(d){
    if(d>14)throw Error("deep json");
    skip();if(s[i]==='"')return string();
    if(s[i]==='{'){
      i++;skip();const result=Object.create(null),keys=new Set();if(s[i]==='}'){i++;return result;}
      while(i<len){skip();const k=string();if(keys.has(k))throw Error("duplicate key");keys.add(k);skip();if(s[i++]!==':')throw Error("colon");result[k]=value(d+1);skip();const ch=s[i++];if(ch==='}')return result;if(ch!==',')throw Error("object comma");}
      throw Error("unterminated object");
    }
    if(s[i]==='['){
      i++;skip();const a=[];if(s[i]===']'){i++;return a;}
      while(i<len){a.push(value(d+1));skip();const ch=s[i++];if(ch===']')return a;if(ch!==',')throw Error("array comma");}
      throw Error("unterminated array");
    }
    const start=i;while(i<len&&!/[\s,}\]]/.test(s[i]))i++;
    if(i===start)throw Error("json token");
    const token=s.slice(start,i);
    if(!/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)$/.test(token))throw Error("primitive");
    return JSON.parse(token);
  }
  const result=value(0);skip();if(i!==len)throw Error("trailing JSON");return result;
}
function validate(o){
  if(!exact(o,KEYS)||o.schema!=="lightup-private-human-evidence-integration-v1"||
      o.start!=="remediation-operations/index.html"||
      o.release!=="INCUBATE M3/M7 - PLAN/LAB ONLY - DRAFT/HOLD"||
      ![o.authentication,o.client_consent,o.operator_consent,o.active_execution,o.security_fix_verified,o.production_release_approved].every(x=>x===false)||
      typeof o.privacy!=="string"||o.privacy.length>500)throw Error("unrecognized non-authorizing manifest");
  if(!exact(o.original_source_pr_heads,PRS)||PRS.some(k=>!(/^[a-f0-9]{40}$/.test(o.original_source_pr_heads[k]))))throw Error("source owners");
  if(!Array.isArray(o.files)||o.files.length<39||o.files.length>1000)throw Error("unexpected file inventory");
  const files=new Map();
  for(const f of o.files){
    if(!exact(f,["path","bytes","sha256"])||typeof f.path!=="string"||f.path.length>240||
       !/^remediation-[a-z-]+\/[A-Za-z0-9_./-]+$/.test(f.path)||
       f.path.split("/").some(x=>x===""||x==="."||x==="..")||
       !Number.isSafeInteger(f.bytes)||f.bytes<0||f.bytes>8388608||
       typeof f.sha256!=="string"||!(/^[a-f0-9]{64}$/.test(f.sha256))||files.has(f.path))throw Error("invalid original file inventory");
    files.set(f.path,{bytes:f.bytes,sha256:f.sha256});
  }
  for(const prefix of ["remediation-artifact-ledger/","remediation-response-reconciliation/","remediation-handoff-inbox/","remediation-human-runbooks/","remediation-operations/"]){
    if(![...files.keys()].some(k=>k.startsWith(prefix)))throw Error("incomplete original application set");
  }
  return {sources:{...o.original_source_pr_heads},files};
}
async function load(event,side){
  changes=null;revisionDeltas=null;id("results").hidden=true;id("export-brief").disabled=true;
  loaded[side]=null;const file=event.target.files[0];event.target.value="";
  if(!file){id(side+"-state").textContent="No file loaded";return;}
  if(file.size>2*1024*1024){id(side+"-state").textContent="HOLD · over 2 MiB";setStatus("HOLD: file exceeds size limit.");return;}
  try{
    const bytes=await file.arrayBuffer();
    const txt=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
    loaded[side]=validate(parseStrict(txt));
    id(side+"-state").textContent="Loaded locally · "+loaded[side].files.size+" source files (untrusted)";
    setStatus("PRIVATE local manifest loaded. Choose Compare when both inputs are ready.");
  }catch(_){
    id(side+"-state").textContent="HOLD · invalid, ambiguous or incomplete manifest";
    setStatus("HOLD: malformed input never enters the comparison. Original sources not changed.");
  }
}
function compare(){
  if(!loaded.before||!loaded.after){setStatus("Select two valid complete PRIVATE manifests first.");return;}
  revisionDeltas=PRS.map(pr=>({pr,from:loaded.before.sources[pr],to:loaded.after.sources[pr]}));
  const names=[...new Set([...loaded.before.files.keys(),...loaded.after.files.keys()])].sort();
  changes=names.map(name=>{
    const before=loaded.before.files.get(name),after=loaded.after.files.get(name);
    const kind=!before?"added":!after?"removed":before.sha256!==after.sha256||before.bytes!==after.bytes?"changed":"unchanged";
    return {name,kind,before,after};
  });
  const counts={added:0,removed:0,changed:0,unchanged:0};
  for(const c of changes)counts[c.kind]++;
  id("delta-summary").textContent=
    counts.changed+" changed / "+counts.added+" added / "+counts.removed+" removed / "+counts.unchanged+
    " unchanged source files · "+revisionDeltas.filter(r=>r.from!==r.to).length+" declared source-owner revisions differ";
  const rows=id("revision-rows");rows.replaceChildren();
  for(const r of revisionDeltas){
    const element=document.createElement("p");
    element.textContent="Original PR #"+r.pr+" · "+r.from.slice(0,12)+" → "+r.to.slice(0,12)+
      (r.from===r.to?" (same declared revision)":" (declared revision differs)");
    rows.append(element);
  }
  id("results").hidden=false;id("export-brief").disabled=false;renderChanges();
  setStatus("Advisory source delta calculated locally. It does NOT indicate trusted source or release approval.");
}
function renderChanges(){
  const list=id("difference-rows");list.replaceChildren();
  if(!changes)return;let visible=0;
  for(const row of changes){
    if(row.kind==="unchanged"||(id("change-filter").value!=="all"&&row.kind!==id("change-filter").value))continue;
    if(++visible>500){const p=document.createElement("p");p.textContent="Additional changed paths omitted from screen display. All are represented in counts.";list.append(p);break;}
    const container=document.createElement("div");container.className="row";
    const title=document.createElement("strong");title.textContent=row.kind.toUpperCase()+" · "+row.name;
    const detail=document.createElement("p");detail.textContent=
      "Earlier "+(row.before?row.before.sha256.slice(0,16)+" / "+row.before.bytes+" bytes":"absent")+
      " → Later "+(row.after?row.after.sha256.slice(0,16)+" / "+row.after.bytes+" bytes":"absent");
    container.append(title,detail);list.append(container);
  }
  if(visible===0){const p=document.createElement("p");p.textContent="No source-file differences in this filter.";list.append(p);}
}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));}
function exportBrief(){
  if(!changes||!revisionDeltas)return;
  const rows=changes.filter(x=>x.kind!=="unchanged").map(x=>"<tr><td>"+esc(x.kind)+"</td><td>"+esc(x.name)+"</td><td>"+esc(x.before?x.before.sha256:"absent")+"</td><td>"+esc(x.after?x.after.sha256:"absent")+"</td></tr>").join("");
  const rs=revisionDeltas.map(x=>"<li>PR #"+esc(x.pr)+": "+esc(x.from)+" → "+esc(x.to)+"</li>").join("");
  const doc="<!doctype html><html lang='en'><meta charset='utf-8'><meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>PRIVATE source-change review</title><style>body{max-width:1050px;margin:40px auto;padding:20px;font:15px system-ui;color:#111}table{border-collapse:collapse}td,th{border:1px solid #777;padding:8px;overflow-wrap:anywhere}</style><h1>PRIVATE HUMAN Source-Change Review</h1>"+
    "<p><b>NOT AUTHENTICATED, NOT AN AUTHORIZATION OR RELEASE DECISION.</b> Local self-declared manifests; source signatures, reviewers, CI, consent, fixes, and revocation unverified.</p><h2>Declared original PR heads</h2><ul>"+rs+"</ul><h2>File SHA-256 changes</h2><table><thead><tr><th>Classification</th><th>Source path</th><th>Earlier SHA</th><th>Later SHA</th></tr></thead><tbody>"+rows+"</tbody></table><p>PRIVATE HUMAN data only. Do not merge/deploy or authorize targeting from this document.</p></html>";
  const blob=new Blob([doc],{type:"text/html"}),url=URL.createObjectURL(blob),anchor=document.createElement("a");
  anchor.href=url;anchor.download="lightup-private-source-change-review.html";document.body.append(anchor);anchor.click();anchor.remove();setTimeout(()=>URL.revokeObjectURL(url),3000);
  setStatus("PRIVATE scriptless change review requested. Independently verify recipient and source provenance.");
}
for(const side of ["before","after"])id(side).addEventListener("change",e=>load(e,side));
id("compare").addEventListener("click",compare);
id("change-filter").addEventListener("change",renderChanges);
id("export-brief").addEventListener("click",exportBrief);
id("clear-compare").addEventListener("click",()=>{
  loaded.before=null;loaded.after=null;changes=null;revisionDeltas=null;
  id("results").hidden=true;id("export-brief").disabled=true;
  for(const side of ["before","after"]){id(side+"-state").textContent="No file loaded";id(side).value="";}
  setStatus("Both PRIVATE manifests forgotten from this page.");
});
