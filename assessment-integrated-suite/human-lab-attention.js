"use strict";
/* Offline HUMAN role/follow-up proposals from UNTRUSTED source-free Lab Route exports.
   No active targets, HTTP, source evidence, consent, approvals or dispatch. */
(() => {
 const SCHEMA="lightup.private.human-lab-route.self-report.v1";
 const NO_AUTH={scan_authorized:false,grant_authorized:false,consent_verified:false,human_go:false};
 const STATE={NOT_REVIEWED:"Not reviewed",IN_PROGRESS:"Discussing",NEEDS_INPUT:"Needs original input",DISCUSSED:"Discussed only"};
 const ROLE={UNASSIGNED:"Unassigned",SOURCE_OWNER:"Source-holder proposal",LAB_OPERATOR:"Lab operator proposal",SECURITY_REVIEWER:"Security reviewer proposal",PRIVACY_REVIEWER:"Privacy reviewer proposal"};
 const PLAN={UNCLASSIFIED:"Not triaged",NEEDS_ORIGINAL:"Request original input",HUMAN_DISCUSSION:"Request HUMAN discussion",DEFERRED:"Defer for HUMAN decision"};
 const PHASE=[
  ["Offline proposals",[[52,"Prepare isolated-lab proposal"],[53,"Reopen original owner-private proposal"],[54,"Compare two original proposals"],[55,"Review 3–8 original proposals"]]],
  ["Source-bound human review",[[56,"Prepare review Studio"],[57,"Manually finalize original HUMAN proposal choices"],[58,"Reopen original HUMAN choices"],[59,"Compare 2–8 original HUMAN review rounds"]]],
  ["Team feedback",[[60,"Prepare assigned-team workrooms"],[61,"Read one exact source-bound HUMAN reply"],[62,"Assemble 1–4 replies with explicit withholding"],[63,"Reopen a complete original team batch"],[64,"Compare original team batches"]]],
  ["Multi-round continuation",[[65,"Prepare explicit next HUMAN review round"],[66,"Reopen complete original continuation chain"],[67,"Inspect source-minimal HUMAN changes"]]],
  ["Conflict reconciliation",[[68,"Prepare per-ordinal HUMAN conflict editor"],[69,"Publish selected HUMAN choices to a NEW draft"],[70,"Reopen published draft against originals"],[71,"Open NEW original HUMAN Review Studio"]]]
 ];
 const ITEMS=PHASE.flatMap((p,i)=>p[1].map(a=>({id:a[0],label:a[1],phase:i})));
 const $=id=>document.getElementById(id), el=(tag,caption)=>{const x=document.createElement(tag);if(caption!==undefined)x.textContent=caption;return x;};
 let rounds=null, proposals=Object.create(null);
 function exact(x,keys){return !!x&&typeof x==="object"&&!Array.isArray(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));}
 function uniqueKeys(raw){
  const val=JSON.parse(raw),stack=[];
  for(let i=0;i<raw.length;){
   let c=raw[i];
   if(c==='"'){
    let end=i+1;
    for(;end<raw.length;end++){if(raw[end]==="\\"){end++;continue;}if(raw[end]==='"')break;}
    if(end>=raw.length)throw Error("string");
    let next=end+1;while(next<raw.length&&/\s/.test(raw[next]))next++;
    if(raw[next]===":"){
     const set=stack[stack.length-1];if(!(set instanceof Set))throw Error("key");
     const key=JSON.parse(raw.slice(i,end+1));if(set.has(key))throw Error("duplicate key");set.add(key);
    }
    i=end+1;
   }else if(c==="{"||c==="["){
    stack.push(c==="{"?new Set():null);if(stack.length>32)throw Error("depth");i++;
   }else if(c==="}"||c==="]"){if(!stack.length)throw Error("stack");stack.pop();i++;}
   else i++;
  }
  if(stack.length)throw Error("unbalanced");
  return val;
 }
 function admit(raw){
  const v=uniqueKeys(raw);
  if(!exact(v,["schema","mode","authority","verified_original_source","source_files_included","private_notes_included","steps"])||
   v.schema!==SCHEMA||v.mode!=="REVIEW_ONLY"||v.verified_original_source!==false||
   v.source_files_included!==false||v.private_notes_included!==false||
   !exact(v.authority,Object.keys(NO_AUTH))||Object.keys(NO_AUTH).some(k=>v.authority[k]!==false)||
   !Array.isArray(v.steps)||v.steps.length!==20)throw Error("schema");
  const out=Object.create(null);
  v.steps.forEach((row,i)=>{
   if(!exact(row,["action","self_reported_state"])||row.action!==ITEMS[i].id||!Object.hasOwn(STATE,row.self_reported_state))throw Error("row");
   out[row.action]=row.self_reported_state;
  });
  return out;
 }
 function signature(r){return ITEMS.map(i=>r[i.id]).join("|");}
 function changes(id){let n=0;for(let i=1;i<rounds.length;i++)if(rounds[i][id]!==rounds[i-1][id])n++;return n;}
 function visible(item){
  const term=$("search").value.trim().toLowerCase(),focus=$("focus").value,phase=$("phase").value;
  const state=rounds[rounds.length-1][item.id], count=changes(item.id);
  return (!term||item.label.toLowerCase().includes(term)||String(item.id).includes(term))&&
    (!phase||Number(phase)===item.phase)&&
    (!focus||(focus==="needs"&&state==="NEEDS_INPUT")||
      (focus==="pending"&&state!=="DISCUSSED")||
      (focus==="changed"&&count>0)||(focus==="repeat"&&count>1)||
      (focus==="unrouted"&&proposals[item.id].plan==="UNCLASSIFIED"));
 }
 function filtering(){
  if(!rounds)return;
  let shown=0;
  for(const row of $("rows").children){
   const item=ITEMS.find(i=>String(i.id)===row.dataset.id);
   row.hidden=!visible(item);if(!row.hidden)shown++;
  }
  $("shown").textContent=shown+" of 20 original HUMAN steps shown. All remain in exports.";
 }
 ["search","focus","phase"].forEach(k=>$(k).addEventListener("input",filtering));
 function summaries(){
  if(!rounds)return;
  const last=rounds[rounds.length-1];
  $("metrics").replaceChildren();
  PHASE.forEach((p,idx)=>{
   const items=ITEMS.filter(i=>i.phase===idx), card=el("div");
   card.className="metric";
   card.append(el("strong",p[0]),el("p",items.filter(i=>last[i.id]==="NEEDS_INPUT").length+
    " need original input · "+items.filter(i=>last[i.id]!=="DISCUSSED").length+
    " not marked discussed · "+items.filter(i=>changes(i.id)>0).length+" changed"));
   $("metrics").append(card);
  });
  $("summary").textContent=rounds.length+" untrusted manually ordered HUMAN rounds · "+
   ITEMS.filter(i=>proposals[i.id].plan!=="UNCLASSIFIED").length+
   "/20 explicitly triaged · No authenticated chronology or completed work.";
 }
 function options(select,values,choice){
  Object.entries(values).forEach(([key,label])=>{const op=el("option",label);op.value=key;select.append(op);});
  select.value=choice;
 }
 function render(){
  const last=rounds[rounds.length-1],body=$("rows");body.replaceChildren();
  ITEMS.forEach(item=>{
   const row=el("tr");row.dataset.id=String(item.id);
   [item.id+" · "+item.label,PHASE[item.phase][0],STATE[last[item.id]],String(changes(item.id))].
    forEach(x=>row.append(el("td",String(x))));
   const roles=el("select");roles.setAttribute("aria-label","Proposed role for action "+item.id);
   options(roles,ROLE,proposals[item.id].role);
   roles.addEventListener("change",()=>{proposals[item.id].role=roles.value;summaries();});
   const actions=el("select");actions.setAttribute("aria-label","HUMAN follow-up for action "+item.id);
   options(actions,PLAN,proposals[item.id].plan);
   actions.addEventListener("change",()=>{proposals[item.id].plan=actions.value;summaries();filtering();});
   const roleCell=el("td"),actionCell=el("td");
   roleCell.append(roles);actionCell.append(actions);row.append(roleCell,actionCell);body.append(row);
  });
  $("board").hidden=false;summaries();filtering();
 }
 $("imports").addEventListener("change",async e=>{
  const files=Array.from(e.target.files||[]);e.target.value="";
  if(!files.length)return;
  if(files.length>8){$("message").textContent="HOLD: select at most 8 HUMAN rounds.";return;}
  try{
   const imported=await Promise.all(files.map(async f=>{
    if(f.size<20||f.size>24576)throw Error("bytes");
    return admit(await f.text());
   }));
   if(new Set(imported.map(signature)).size!==imported.length)throw Error("same report");
   if(rounds&&!window.confirm("Discard previous LOCAL HUMAN proposal?"))return;
   rounds=imported;proposals=Object.create(null);
   ITEMS.forEach(i=>proposals[i.id]={role:"UNASSIGNED",plan:"UNCLASSIFIED"});
   $("search").value="";$("focus").value="";$("phase").value="";render();
   $("message").textContent="Loaded "+rounds.length+" bounded source-free HUMAN rounds, with no source or actor authentication.";
  }catch(_){$("message").textContent="HOLD: invalid, duplicated, oversized or authorizing HUMAN report. Existing board unchanged.";}
 });
 $("bulk").addEventListener("click",()=>{
  if(!rounds)return;
  const items=ITEMS.filter(i=>visible(i)&&rounds[rounds.length-1][i.id]==="NEEDS_INPUT");
  if(!items.length){$("message").textContent="No visible original-input steps.";return;}
  if(!window.confirm("Mark "+items.length+" VISIBLE self-reported NEEDS_INPUT steps as HUMAN proposed original-input requests? No dispatch."))return;
  items.forEach(i=>proposals[i.id].plan="NEEDS_ORIGINAL");render();
  $("message").textContent=items.length+" unsent HUMAN-only proposals recorded locally.";
 });
 $("clear").addEventListener("click",()=>{
  if(!rounds||!window.confirm("Discard all LOCAL HUMAN reports and proposals?"))return;
  rounds=null;proposals=Object.create(null);$("rows").replaceChildren();
  $("metrics").replaceChildren();$("board").hidden=true;
  $("message").textContent="Local memory cleared, no originals changed.";
 });
 function documentData(){
  const last=rounds[rounds.length-1];
  return {schema:"lightup.private.human-lab-attention.v2",mode:"REVIEW_ONLY",authority:{...NO_AUTH},
   original_source_verified:false,actual_work_verified:false,consent_or_release_inferred:false,
   source_files_included:false,notes_included:false,round_order:"MANUALLY_ASSUMED",round_count:rounds.length,
   source_profiles:rounds.map(signature),
   steps:ITEMS.map(i=>({action:i.id,self_reported_state:last[i.id],marker_transitions:changes(i.id),
    proposed_role:proposals[i.id].role,proposed_human_followup:proposals[i.id].plan}))};
 }
 // A saved HUMAN proposal can be reopened ONLY after the operator loads all
 // same source-free marker rounds in the same declared order. Byte identity,
 // actor identity, real source authenticity and chronology are NOT inferred.
 $("restore").addEventListener("change",async e=>{
  const file=e.target.files&&e.target.files[0];e.target.value="";
  if(!file)return;
  if(!rounds){$("message").textContent="HOLD: load original source-free HUMAN rounds before restoring a proposal.";return;}
  try{
   if(file.size<20||file.size>65536)throw Error("bytes");
   const saved=uniqueKeys(await file.text());
   const keys=["schema","mode","authority","original_source_verified","actual_work_verified",
    "consent_or_release_inferred","source_files_included","notes_included","round_order",
    "round_count","source_profiles","steps"];
   if(!exact(saved,keys)||saved.schema!=="lightup.private.human-lab-attention.v2"||
    saved.mode!=="REVIEW_ONLY"||!exact(saved.authority,Object.keys(NO_AUTH))||
    Object.keys(NO_AUTH).some(k=>saved.authority[k]!==false)||
    saved.original_source_verified!==false||saved.actual_work_verified!==false||
    saved.consent_or_release_inferred!==false||saved.source_files_included!==false||
    saved.notes_included!==false||saved.round_order!=="MANUALLY_ASSUMED"||
    saved.round_count!==rounds.length||!Array.isArray(saved.source_profiles)||
    saved.source_profiles.length!==rounds.length||
    saved.source_profiles.some((signatureValue,i)=>signatureValue!==signature(rounds[i]))||
    !Array.isArray(saved.steps)||saved.steps.length!==20)throw Error("source drift");
   const incoming=Object.create(null),last=rounds[rounds.length-1];
   saved.steps.forEach((entry,i)=>{
    const id=ITEMS[i].id;
    if(!exact(entry,["action","self_reported_state","marker_transitions",
      "proposed_role","proposed_human_followup"])||
      entry.action!==id||entry.self_reported_state!==last[id]||
      entry.marker_transitions!==changes(id)||
      !Object.hasOwn(ROLE,entry.proposed_role)||
      !Object.hasOwn(PLAN,entry.proposed_human_followup))throw Error("ambiguous proposal");
    incoming[id]={role:entry.proposed_role,plan:entry.proposed_human_followup};
   });
   if(!window.confirm("Restore ALL 20 HUMAN proposals against the identical currently loaded source-free discussion rounds? No original source, actor or consent was verified."))return;
   proposals=incoming;render();
   $("message").textContent="Restored exact source-marker-bound LOCAL HUMAN role/follow-up choices. Still REVIEW_ONLY / not authorized.";
  }catch(_){
   $("message").textContent="HOLD: saved HUMAN proposal refused (schema, duplicate key, source-marker drift or authority). Current proposals unchanged.";
  }
 });

 function download(filename,text,type){
  const url=URL.createObjectURL(new Blob([text],{type})),a=el("a");
  a.href=url;a.download=filename;document.body.append(a);a.click();a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
  $("message").textContent="A LOCAL file download was requested; check the private file before use.";
 }
 const escape=v=>String(v).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
 function brief(data){
  const rows=data.steps.map((row,idx)=>{
   const vals=[row.action+" · "+ITEMS[idx].label,STATE[row.self_reported_state],row.marker_transitions,
    ROLE[row.proposed_role],PLAN[row.proposed_human_followup]];
   return "<tr>"+vals.map(v=>"<td>"+escape(v)+"</td>").join("")+"</tr>";
  }).join("");
  return '<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; connect-src \'none\'"><meta name="referrer" content="no-referrer"><title>LightUp PRIVATE HUMAN attention</title>'+
   '<style>body{max-width:1200px;margin:auto;font:16px/1.5 system-ui;padding:20px}table{width:100%;border-collapse:collapse}td,th{border:1px solid #64748b;padding:8px;text-align:left}tr{break-inside:avoid}</style>'+
   '<h1>PRIVATE HUMAN attention brief · REVIEW_ONLY</h1><p>Not verified work, current authorization, source evidence, granted consent, chronology, approval or task dispatch. '+
   escape(data.round_count)+' manually ordered source-free HUMAN self-reports, all twenty original actions retained.</p><table><thead><tr><th>Action</th><th>Last self-report</th><th>Transitions*</th><th>Proposed role</th><th>Proposed HUMAN follow-up</th></tr></thead><tbody>'+
   rows+'</tbody></table><p>*Transitions use operator-selected file order, not verified time or source history. DRAFT/HOLD.</p></html>';
 }
 function exportAs(kind){
  if(!rounds)return;
  if(!window.confirm("Export all 20 UNSIGNED source-free HUMAN proposals? This is never execution, assignment, consent or approval."))return;
  const data=documentData();
  if(kind==="json")download("LightUp-PRIVATE-HUMAN-Attention.json",JSON.stringify(data,null,2)+"\n","application/json");
  if(kind==="csv"){
   const lines=["action,self_reported_state,marker_transitions,proposed_role,proposed_human_followup,authority"];
   data.steps.forEach(x=>lines.push([x.action,x.self_reported_state,x.marker_transitions,x.proposed_role,x.proposed_human_followup,"REVIEW_ONLY"].join(",")));
   download("LightUp-PRIVATE-HUMAN-Attention.csv",lines.join("\r\n")+"\r\n","text/csv");
  }
  if(kind==="html")download("LightUp-PRIVATE-HUMAN-Attention.html",brief(data),"text/html");
 }
 ["json","csv","html"].forEach(kind=>$(kind).addEventListener("click",()=>exportAs(kind)));
})();
