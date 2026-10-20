/* LightUp PRIVATE historical HUMAN inbox explorer. Local operator review only.
 * Uses only explicitly selected native-derived PRIVATE history JSON bytes.
 * Browser import is an unsigned preview, not authoritative native admission.
 */
(() => {
 "use strict";
 const $ = id => document.getElementById(id);
 const HISTORY="lightup.private.workspace-ledger-human-inbox-history.v1";
 const AUTH=["authorization","consent","verified_finding","release_approval"];
 const ROOT=["schema","authority","historical_only","sources_reopened","recipient_authenticated","consent_assumed","actions_dispatched","appointments_booked","verified_remediation","original_inbox_sha256","selected_original_proposed_human_owner_label","owner_scoped_private_export","original_human_discussion_rounds","private_human_history_slots"];
 const ROUNDS=["round","original_discussion_sha256","original_review_csv_sha256"];
 const SLOT=["local_case","historical_transition","original_kit","original_proposed_human_owner","original_human_stage","original_owner_reply_stage","first_human_triage_stage","latest_human_triage_stage","stage_changed_rounds","private_note_changed_rounds","round_stages"];
 const STAGES=["needs_discussion","proposed_followup","hold"];
 const MAX_BYTES=1048576;
 let history=null, rawDigest="", rows=[], rounds=0;
 let ownerScoped=false;
 function exact(o,keys){return !!o && typeof o==="object" && !Array.isArray(o) && Object.keys(o).length===keys.length && keys.every(k=>Object.prototype.hasOwnProperty.call(o,k));}
 function hex(s){return typeof s==="string" && /^[a-f0-9]{64}$/.test(s);}
 function stage(s){return STAGES.includes(s);}
 function label(s){return typeof s==="string" && s.length>0 && s.length<=80 && s.trim()===s && !/[\u0000-\u001f\u007f]/.test(s) && !/^\s*[=+@-]/.test(s);}
 function id(r){return r.local_case+"/"+r.historical_transition+"/"+r.original_kit;}
 function changes(a,seq){return a.filter((n,i)=>Number.isInteger(n)&&n>=2&&n<=seq&& (i===0||n>a[i-1]));}
 function verify(doc){
   if(!exact(doc,ROOT)||doc.schema!==HISTORY||!exact(doc.authority,AUTH)||!AUTH.every(k=>doc.authority[k]===false)||
     doc.historical_only!==true||!["sources_reopened","recipient_authenticated","consent_assumed","actions_dispatched","appointments_booked","verified_remediation"].every(k=>doc[k]===false)||
     !hex(doc.original_inbox_sha256) || typeof doc.owner_scoped_private_export!=="boolean" ||
     !Array.isArray(doc.original_human_discussion_rounds) || doc.original_human_discussion_rounds.length<2||doc.original_human_discussion_rounds.length>8 ||
     !Array.isArray(doc.private_human_history_slots) || doc.private_human_history_slots.length<1||doc.private_human_history_slots.length>2048) throw Error("Not the native PRIVATE HUMAN history schema");
   const scope=doc.selected_original_proposed_human_owner_label;
   if ((scope===null)!==!doc.owner_scoped_private_export || (scope!==null&&!label(scope))) throw Error("Owner-scoping boundary mismatch");
   const signatures=new Set();
   for(const [i,item] of doc.original_human_discussion_rounds.entries()){
      if(!exact(item,ROUNDS)||item.round!==i+1||!hex(item.original_discussion_sha256)||!hex(item.original_review_csv_sha256)||
        signatures.has(item.original_discussion_sha256)) throw Error("Original historical round identity or order invalid");
      signatures.add(item.original_discussion_sha256);
   }
   const size=doc.original_human_discussion_rounds.length, ids=new Set();
   for(const r of doc.private_human_history_slots){
     if(!exact(r,SLOT)||!label(r.original_proposed_human_owner)||
       (scope!==null&&r.original_proposed_human_owner!==scope)||
       !Number.isInteger(r.local_case)||r.local_case<1||r.local_case>8||
       !Number.isInteger(r.historical_transition)||r.historical_transition<1||r.historical_transition>11||
       !Number.isInteger(r.original_kit)||r.original_kit<1||r.original_kit>12||
       ids.has(id(r))||!stage(r.original_human_stage)||!stage(r.original_owner_reply_stage)||
       !stage(r.first_human_triage_stage)||!stage(r.latest_human_triage_stage)||
       !Array.isArray(r.round_stages)||r.round_stages.length!==size||!r.round_stages.every(stage)||
       r.round_stages[0]!==r.first_human_triage_stage||r.round_stages[size-1]!==r.latest_human_triage_stage||
       !Array.isArray(r.stage_changed_rounds)||!Array.isArray(r.private_note_changed_rounds)||
       changes(r.stage_changed_rounds,size).length!==r.stage_changed_rounds.length||
       changes(r.private_note_changed_rounds,size).length!==r.private_note_changed_rounds.length) throw Error("Original HUMAN case/round record invalid");
     const derived=[];
     for(let i=1;i<size;i++) if(r.round_stages[i]!==r.round_stages[i-1])derived.push(i+1);
     if(JSON.stringify(derived)!==JSON.stringify(r.stage_changed_rounds))throw Error("HUMAN stage transition does not match original rounds");
     ids.add(id(r));
   }
   return doc.private_human_history_slots.slice();
 }
 function element(tag,value,className){
   const e=document.createElement(tag);
   if(value!==undefined)e.textContent=String(value);
   if(className)e.className=className;
   return e;
 }
 function msg(s){$("status").textContent=s;}
 function clear(){
   history=null;rawDigest="";rows=[];rounds=0;ownerScoped=false;
   $("room").hidden=true;$("cards").replaceChildren();$("owner").replaceChildren();
   $("source").value="";$("ownerFilter").value="";$("search").value="";
   $("stage").value="";$("change").value="all";$("round").value="latest";
   msg("No PRIVATE source opened. Nothing stored by this page.");
 }
 function visibleRows(){
   const owner=$("ownerFilter").value;
   const stageValue=$("stage").value;
   const change=$("change").value;
   const term=$("search").value.trim().toLocaleLowerCase();
   const round=$("round").value==="latest"?rounds-1:Number($("round").value)-1;
   return rows.filter(r=>{
     const changed=!!(r.stage_changed_rounds.length||r.private_note_changed_rounds.length);
     if(owner && r.original_proposed_human_owner!==owner)return false;
     if(stageValue && r.round_stages[round]!==stageValue)return false;
     if(change==="changed"&&!changed)return false;
     if(change==="stable"&&changed)return false;
     if(change==="stage"&&!r.stage_changed_rounds.length)return false;
     if(change==="note"&&!r.private_note_changed_rounds.length)return false;
     if(term && !(r.original_proposed_human_owner+" "+id(r)+" "+r.round_stages.join(" ")).toLocaleLowerCase().includes(term))return false;
     return true;
   });
 }
 function render(){
   if(!history)return;
   const list=visibleRows(), box=$("cards"), byStage={};
   for(const s of STAGES)byStage[s]=0;
   const n=$("round").value==="latest"?rounds-1:Number($("round").value)-1;
   for(const r of list)byStage[r.round_stages[n]]++;
   $("total").textContent=rows.length+" original PRIVATE HUMAN slots · "+rounds+" explicitly ordered rounds · "+(ownerScoped?"original single-owner scope":"complete original owner set");
   $("shown").textContent=list.length+" visible of "+rows.length+" original private slots · "+STAGES.map(s=>s.replaceAll("_"," ")+": "+byStage[s]).join(" · ");
   box.replaceChildren();
   for(const r of list){
     const card=element("article",undefined,"card");
     card.append(element("h3","Original HUMAN slot "+id(r)));
     const facts=element("div",undefined,"facts");
     for(const [k,v] of [
       ["Proposed original HUMAN owner",r.original_proposed_human_owner],
       ["Original owner reply HUMAN proposal",r.original_owner_reply_stage],
       ["Selected HUMAN round proposal",r.round_stages[n]],
       ["Manual stages round 1–"+rounds,r.round_stages.join(" → ")],
       ["Proposed stage changed in rounds",r.stage_changed_rounds.join(", ")||"none"],
       ["PRIVATE note changed in rounds; text absent",r.private_note_changed_rounds.join(", ")||"none"]
     ]) {const fact=element("div",undefined,"fact");fact.append(element("strong",k),element("span",v));facts.append(fact);}
     card.append(facts);box.append(card);
   }
   if(!list.length)box.append(element("p","No original HUMAN proposal matches these filters; no remediation is implied."));
 }
 function csv(rows){
   // CSV is PRIVATE. Original source slot and owner are explicit; note contents excluded.
   const head=["original_history_sha256","selected_human_round","local_case","historical_transition","original_kit","original_proposed_human_owner","first_human_triage_stage","latest_human_triage_stage","stage_changed_rounds","private_note_changed_rounds"];
   const guarded=value=>{
      const s=String(value);
      if (/^\s*[=+@-]/.test(s))return "'"+s;
      return s;
   };
   const escape=value=>'"'+guarded(value).replaceAll('"','""')+'"';
   const selected=$("round").value==="latest"?rounds:Number($("round").value);
   return [head.join(","),...rows.map(r=>head.map(k=>escape(
       k==="original_history_sha256"?rawDigest:
       k==="selected_human_round"?selected:
       Array.isArray(r[k])?r[k].join(";"):r[k])).join(","))].join("\r\n")+"\r\n";
 }
 function download(name,type,data){
   const url=URL.createObjectURL(new Blob([data],{type}));const a=element("a");
   a.href=url;a.download=name;document.body.append(a);a.click();a.remove();
   setTimeout(()=>URL.revokeObjectURL(url),500);
 }
 function minimal(){
   // Never include names, case slots or SHA. Aggregate currently VISIBLE scope only.
   const list=visibleRows(), n=$("round").value==="latest"?rounds-1:Number($("round").value)-1;
   const byStage=Object.fromEntries(STAGES.map(s=>[s,list.filter(r=>r.round_stages[n]===s).length]));
   const record={schema:"lightup.private.human-history-visible-counts.v1",authority:{authorization:false,consent:false,verified_finding:false,release_approval:false},historical_only:true,original_round_count:rounds,filtered_visible_count:list.length,filtered_changed_human_slots:list.filter(r=>r.stage_changed_rounds.length||r.private_note_changed_rounds.length).length,selected_explicit_human_round:n+1,proposed_human_stages:byStage};
   download("LightUp-HUMAN-visible-counts.json","application/json",JSON.stringify(record,null,2)+"\n");
 }
 function privateCSV(){
   const list=visibleRows();
   const target=$("ownerFilter").value;
   if(!target || !window.confirm("PRIVATE handoff only for proposed HUMAN owner '"+target+"'. Original labels do not authenticate recipients. Confirm manual PRIVATE CSV creation?")) return;
   const mine=list.filter(r=>r.original_proposed_human_owner===target);
   if(!mine.length){msg("PRIVATE HOLD: no selected original HUMAN owner rows");return;}
   download("LightUp-PRIVATE-HUMAN-owner-visible.csv","text/csv;charset=utf-8",csv(mine));
   msg("PRIVATE owner-scoped CSV saved locally; verify recipient, original source and custody manually. Never authority.");
 }
 function safeSourceFile(file){
   return file && file.size>0 && file.size<=MAX_BYTES && file.name.toLowerCase().endsWith(".json");
 }
 async function load(evt){
   const file=evt.target.files?.[0];
   if(!safeSourceFile(file)){msg("PRIVATE HOLD: select one original native ≤1 MiB JSON history file");return;}
   try{
     const raw=await file.arrayBuffer();
     if(raw.byteLength!==file.size||!raw.byteLength||raw.byteLength>MAX_BYTES)throw Error("Source byte limit");
     const source=new TextDecoder("utf-8",{fatal:true}).decode(raw);
     const doc=JSON.parse(source), parsed=verify(doc);
     if(!crypto.subtle)throw Error("No local Web Crypto digest");
     const data=await crypto.subtle.digest("SHA-256",raw);
     const digest=Array.from(new Uint8Array(data),n=>n.toString(16).padStart(2,"0")).join("");
     history=doc;rawDigest=digest;rows=parsed;rounds=doc.original_human_discussion_rounds.length;
     ownerScoped=doc.owner_scoped_private_export;
     $("ownerFilter").replaceChildren(element("option","All ORIGINAL owners (operator-only)"));
     $("ownerFilter").firstChild.value="";
     const names=[...new Set(rows.map(r=>r.original_proposed_human_owner))].sort();
     for(const name of names){const option=element("option",name);option.value=name;$("ownerFilter").append(option);}
     if(ownerScoped){$("ownerFilter").value=names[0];$("ownerFilter").disabled=true;}
     else $("ownerFilter").disabled=false;
     $("round").replaceChildren(element("option","Latest HUMAN proposal"));
     $("round").firstChild.value="latest";
     for(let i=1;i<=rounds;i++){const o=element("option","Original HUMAN round "+i);o.value=String(i);$("round").append(o);}
     $("change").value="all";$("stage").value="";$("search").value="";
     $("room").hidden=false;
     render();
     msg("PRIVATE HUMAN-only original derived history opened: SHA-256 "+rawDigest+". Browser preview is unsigned, not native authority.");
   }catch(e){msg("PRIVATE HOLD: local original history not admitted ("+(e?.message||"invalid input")+"). Existing preview retained.");}
 }
 ["ownerFilter","round","stage","change"].forEach(k=>$(k).addEventListener("change",render));
 $("search").addEventListener("input",render);
 $("source").addEventListener("change",load);
 $("clear").addEventListener("click",clear);
 $("counts").addEventListener("click",minimal);
 $("ownerCsv").addEventListener("click",privateCSV);
 window.addEventListener("beforeunload",()=>{rows=[];history=null;});
 window.addEventListener("pagehide",clear);
 msg("Select existing native PRIVATE-HUMAN-inbox-history.json; software has no embedded customer or HUMAN data.");
})();