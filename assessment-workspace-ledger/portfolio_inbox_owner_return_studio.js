/* LightUp standalone PRIVATE HUMAN owner reply editor. Unsigned offline preview.
 * Native portfolio_inbox_owner_return.py remains the ONLY source admission.
 * No persistence, remote calls, grants, authenticated recipient or tasks.
 */
(() => {
"use strict";
const $=id=>document.getElementById(id);
const MAX=1048576;
const SCHEMA="lightup.private.workspace-ledger-history-human-selected-handoff.v1";
const FIELDS=["schema","authority","historical_only","sources_reopened","recipient_authenticated","consent_assumed","actions_dispatched","appointments_booked","verified_remediation","original_history_sha256","original_human_browser_selection_csv_sha256","selected_original_proposed_human_owner_label","selected_original_human_round","selected_original_human_rows_only"];
const ROW=["local_case","historical_transition","original_kit","original_proposed_human_owner","original_round_human_stage","human_stage_changes_at_rounds","private_note_changed_at_rounds"];
const AUTH=["authorization","consent","verified_finding","release_approval"];
const STAGES=["needs_discussion","proposed_followup","hold"];
const HEAD=["original_selection_sha256","local_case","historical_transition","original_kit","original_round_human_stage","human_reply_stage","private_human_reply_note"];
let original=null,sha="",rows=[],owner="",changed=false;
const exact=(obj,keys)=>obj&&typeof obj==="object"&&!Array.isArray(obj)&&Object.keys(obj).length===keys.length&&keys.every(k=>Object.hasOwn(obj,k));
const hex=s=>typeof s==="string"&&/^[0-9a-f]{64}$/.test(s);
function note(s){return typeof s==="string"&&s.length<=240&&!/[\u0000-\u001f\u007f]/.test(s)&&!/^\s*[=+@-]/.test(s);}
function safeOwner(s){return typeof s==="string"&&s&&s.length<=80&&s.trim()===s&&!/[\u0000-\u001f\u007f]/.test(s)&&!/^\s*[=+@-]/.test(s);}
function identity(r){return r.local_case+":"+r.historical_transition+":"+r.original_kit;}
 function parseUniqueJSON(source) {
   // Mirror the original native duplicate-key refusal in the offline preview.
   // This is only parse hygiene; the native PRIVATE admission is authoritative.
   let pos=0;
   const number=/-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
   const literal=/(?:true|false|null)/y;
   function space(){while(pos<source.length&&/[ \t\n\r]/.test(source[pos]))pos++;}
   function quoted(){
     if(source[pos]!=='"')throw Error("Malformed source JSON key");
     const start=pos++;
     while(pos<source.length){
       const ch=source[pos++];
       if(ch==='"')return JSON.parse(source.slice(start,pos));
       if(ch==="\\"){if(pos===source.length)throw Error("Malformed JSON escape");pos++;}
     }
     throw Error("Unterminated original source JSON string");
   }
   function value(depth){
     if(depth>60)throw Error("Original HUMAN history JSON too deeply nested");
     space();
     if(source[pos]==='{'){
       pos++;space();const seen=new Set();
       if(source[pos]==='}'){pos++;return;}
       while(true){
         space();const key=quoted();
         if(seen.has(key))throw Error("Duplicate original PRIVATE JSON key");
         seen.add(key);space();
         if(source[pos++]!==':')throw Error("Malformed JSON object");
         value(depth+1);space();
         const end=source[pos++];
         if(end==='}')return;
         if(end!==',')throw Error("Malformed original JSON object delimiter");
       }
     }
     if(source[pos]==='['){
       pos++;space();
       if(source[pos]===']'){pos++;return;}
       while(true){
         value(depth+1);space();const end=source[pos++];
         if(end===']')return;
         if(end!==',')throw Error("Malformed original JSON array delimiter");
       }
     }
     if(source[pos]==='"'){quoted();return;}
     number.lastIndex=pos;
     const n=number.exec(source);
     if(n){pos=number.lastIndex;return;}
     literal.lastIndex=pos;
     const l=literal.exec(source);
     if(l){pos=literal.lastIndex;return;}
     throw Error("Malformed PRIVATE HUMAN history JSON token");
   }
   value(0);space();
   if(pos!==source.length)throw Error("Trailing original PRIVATE history JSON data");
   return JSON.parse(source);
 }

function valid(doc){
 if(!exact(doc,FIELDS)||doc.schema!==SCHEMA||!exact(doc.authority,AUTH)||!AUTH.every(x=>doc.authority[x]===false)||
    doc.historical_only!==true||!["sources_reopened","recipient_authenticated","consent_assumed","actions_dispatched","appointments_booked","verified_remediation"].every(x=>doc[x]===false)||
    !hex(doc.original_history_sha256)||!hex(doc.original_human_browser_selection_csv_sha256)||
    !safeOwner(doc.selected_original_proposed_human_owner_label)||
    !Number.isInteger(doc.selected_original_human_round)||doc.selected_original_human_round<1||doc.selected_original_human_round>8||
    !Array.isArray(doc.selected_original_human_rows_only)||!doc.selected_original_human_rows_only.length||doc.selected_original_human_rows_only.length>2048)
       throw Error("Not original source-bound native owner selection");
 const ids=new Set();
 for(const r of doc.selected_original_human_rows_only){
   if(!exact(r,ROW)||r.original_proposed_human_owner!==doc.selected_original_proposed_human_owner_label||
      !Number.isInteger(r.local_case)||r.local_case<1||r.local_case>8||
      !Number.isInteger(r.historical_transition)||r.historical_transition<1||r.historical_transition>11||
      !Number.isInteger(r.original_kit)||r.original_kit<1||r.original_kit>12||
      ids.has(identity(r))||!STAGES.includes(r.original_round_human_stage)||
      !Array.isArray(r.human_stage_changes_at_rounds)||!Array.isArray(r.private_note_changed_at_rounds)||
      r.human_stage_changes_at_rounds.some(v=>!Number.isInteger(v)||v<2||v>8)||
      r.private_note_changed_at_rounds.some(v=>!Number.isInteger(v)||v<2||v>8))
      throw Error("Original HUMAN row or owner invalid");
   ids.add(identity(r));
 }
 return doc.selected_original_human_rows_only.map(r=>({...r,reply:"needs_discussion",free:""}));
}
function el(tag,value,className){
 const obj=document.createElement(tag);
 if(value!==undefined)obj.textContent=String(value);
 if(className)obj.className=className;
 return obj;
}
function message(s){$("status").textContent=s;}
function clear(){
 original=null;rows=[];sha="";owner="";changed=false;
 $("source").value="";$("restore").value="";
 $("room").hidden=true;$("cards").replaceChildren();
 $("owner").textContent="No original HUMAN owner selected";
 message("Private memory cleared. No file deleted or external action performed.");
}
function visible(row){
 const phrase=$("search").value.trim().toLocaleLowerCase();
 const stage=$("stage").value;
 if(stage&&row.reply!==stage)return false;
 if(!phrase)return true;
 return (identity(row)+" "+row.original_round_human_stage+" "+row.reply+" "+row.free).toLocaleLowerCase().includes(phrase);
}
function redraw(){
 if(!original)return;
 let shown=0;
 const cards=$("cards");cards.replaceChildren();
 for(const row of rows){
   if(!visible(row))continue;
   shown++;
   const card=el("article",undefined,"card");
   card.append(el("h3","Original HUMAN case "+row.local_case+" / "+row.historical_transition+" / "+row.original_kit));
   const facts=el("div",undefined,"facts");
   const labels=[["Original selected HUMAN round",original.selected_original_human_round],["Original HUMAN proposal",row.original_round_human_stage],["Historical HUMAN stage change slots",row.human_stage_changes_at_rounds.join(", ")||"none"],["PRIVATE HUMAN note changed at rounds",row.private_note_changed_at_rounds.join(", ")||"none (contents absent)"]];
   for(const [key,value] of labels){const f=el("div",undefined,"fact");f.append(el("strong",key),el("span",value));facts.append(f);}
   card.append(facts);
   const edit=el("div",undefined,"edit");
   const sLabel=el("label","New HUMAN-only proposed reply stage");
   const sel=el("select");
   for(const name of STAGES){const option=el("option",name.replaceAll("_"," "));option.value=name;option.selected=row.reply===name;sel.append(option);}
   sel.addEventListener("change",()=>{row.reply=sel.value;changed=true;renderCounts();});
   sLabel.append(sel);
   const noteLabel=el("label","PRIVATE HUMAN reply note (max 240 chars, no formulas)");
   const field=el("textarea");field.maxLength=240;field.rows=3;field.value=row.free;
   field.addEventListener("input",()=>{
       const val=field.value;
       if(!note(val)){
          field.value=row.free;
          message("PRIVATE HOLD: invalid HUMAN text or formula-like content; last valid local note retained.");
          return;
       }
       row.free=val;changed=true;renderCounts();
   });
   noteLabel.append(field);edit.append(sLabel,noteLabel);card.append(edit);
   cards.append(card);
 }
 $("visible").textContent="Visible "+shown+" of "+rows.length+" ORIGINAL source rows. Filters never drop rows from exported CSV.";
}
function renderCounts(){
 $("totals").textContent=rows.length+" original HUMAN slots • "+
   STAGES.map(s=>s.replaceAll("_"," ")+": "+rows.filter(r=>r.reply===s).length).join(" · ")+
   " • "+rows.filter(r=>r.free).length+" private HUMAN notes"+(changed?" • unsaved draft":"");
 redraw();
}
function csv(){
 const out=[HEAD.join(",")];
 const quote=s=>'"'+String(s).replaceAll('"','""')+'"';
 for(const r of rows){
   if(!note(r.free)||!STAGES.includes(r.reply))throw Error("Invalid HUMAN response");
   out.push([
      sha,r.local_case,r.historical_transition,r.original_kit,
      r.original_round_human_stage,r.reply,r.free
   ].map(quote).join(","));
 }
 return out.join("\r\n")+"\r\n";
}
function parseCSV(text){
 // Strict RFC4180 fields; quotes escaped as doubled double quotes.
 let i=0,field="",record=[],result=[],inQuote=false,closedQuote=false;
 while(i<text.length){
   const c=text[i++];
   if(inQuote){
     if(c==='"'){
       if(text[i]==='"'){field+='"';i++;}
       else{inQuote=false;closedQuote=true;}
     }else field+=c;
   }else if(c==='"'){
     if(field!==""||closedQuote)throw Error("Malformed quoted CSV");
     inQuote=true;
   }else if(c===','){
     record.push(field);field="";closedQuote=false;
   }else if(c==='\r'||c==='\n'){
     if(c==='\r'){if(text[i]!=='\n')throw Error("Noncanonical CSV newline");i++;}
     record.push(field);result.push(record);record=[];field="";closedQuote=false;
   }else{
     if(closedQuote)throw Error("CSV text after closing quote");
     field+=c;
   }
 }
 if(inQuote||field||record.length)throw Error("CSV truncated");
 return result;
}
async function importSource(evt){
 const file=evt.target.files?.[0];
 if(!file||file.size<=0||file.size>MAX||!file.name.toLowerCase().endsWith(".json")){
   message("PRIVATE HOLD: choose source-exact owner-only JSON ≤1 MiB");return;
 }
 try{
   const bytes=await file.arrayBuffer();
   if(bytes.byteLength!==file.size||!crypto.subtle)throw Error("Source byte mismatch or unavailable local SHA");
   const parsed=parseUniqueJSON(new TextDecoder("utf-8",{fatal:true}).decode(bytes));
   const rowsNext=valid(parsed);
   const shaNext=Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",bytes)),n=>n.toString(16).padStart(2,"0")).join("");
   if(original&&changed&&!window.confirm("Discard unsaved previous HUMAN proposals and load another ORIGINAL owner packet?"))return;
   original=parsed;rows=rowsNext;sha=shaNext;owner=parsed.selected_original_proposed_human_owner_label;changed=false;
   $("owner").textContent="Original proposed HUMAN owner: "+owner+" (NOT authenticated)";
   $("room").hidden=false;$("search").value="";$("stage").value="";
   renderCounts();
   message("Original local owner packet imported in memory. Unsigned byte SHA: "+sha+". Native original-source re-admission is still required.");
 }catch(e){message("PRIVATE HOLD: invalid original HUMAN source ("+(e?.message||"unreadable")+"). Existing local work retained.");}
}
async function restore(e){
 const f=e.target.files?.[0];
 if(!original||!f||f.size<=0||f.size>MAX){message("PRIVATE HOLD: load original owner packet, then a bounded complete HUMAN CSV");return;}
 try{
    const text=new TextDecoder("utf-8",{fatal:true}).decode(await f.arrayBuffer());
    const items=parseCSV(text);
    if(!items.length||JSON.stringify(items[0])!==JSON.stringify(HEAD)||items.length!==rows.length+1)
      throw Error("Original reply CSV missing exact complete row schema");
    const newChoices=[];
    for(let i=0;i<rows.length;i++){
      const source=rows[i],r=items[i+1];
      if(r.length!==HEAD.length||r[0]!==sha||r[1]!==String(source.local_case)||
         r[2]!==String(source.historical_transition)||r[3]!==String(source.original_kit)||
         r[4]!==source.original_round_human_stage||!STAGES.includes(r[5])||!note(r[6]))
        throw Error("Draft source, row, HUMAN stage or private note mismatch");
      newChoices.push([r[5],r[6]]);
    }
    if(!window.confirm("Restore complete HUMAN draft for this exact original owner packet? No real authorization follows."))return;
    for(let i=0;i<rows.length;i++){rows[i].reply=newChoices[i][0];rows[i].free=newChoices[i][1];}
    changed=true;renderCounts();message("Original source-bound HUMAN reply draft restored locally. Native receive remains required.");
 }catch(err){message("PRIVATE HOLD: original HUMAN draft rejected; existing local choices untouched ("+(err?.message||"invalid")+").");}
 finally{e.target.value="";}
}
function exportCSV(){
 if(!original){message("PRIVATE HOLD: original owner source not open");return;}
 if(!window.confirm("Export COMPLETE owner-only HUMAN reply CSV to local Downloads? Verify PRIVATE custody and native source admission."))return;
 try{
   const content=csv(),url=URL.createObjectURL(new Blob([content],{type:"text/csv;charset=utf-8"}));
   const a=el("a");a.download="HUMAN-owner-history-reply-template.csv";a.href=url;
   document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),500);
   changed=false;renderCounts();message("PRIVATE HUMAN owner reply exported locally. Native receive still required; no action assigned.");
 }catch(e){message("PRIVATE HOLD: HUMAN reply cannot be exported ("+(e?.message||"invalid")+").");}
}
$("source").addEventListener("change",importSource);
$("restore").addEventListener("change",restore);
$("search").addEventListener("input",redraw);
$("stage").addEventListener("change",redraw);
$("clear").addEventListener("click",clear);
$("export").addEventListener("click",exportCSV);
window.addEventListener("beforeunload",e=>{if(changed){e.preventDefault();e.returnValue="";}});
window.addEventListener("pagehide",clear);
message("Choose native ORIGINAL PRIVATE-HUMAN-history-selection.json. No data embedded or stored.");
})();