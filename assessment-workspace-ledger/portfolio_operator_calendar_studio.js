/* LightUp PRIVATE source-free HUMAN proposed review calendar editor.
 * Browser is a local editor only. All source provenance is rechecked in
 * the native original-bound receive/reopen commands. No actual scheduling.
 */
(() => {
"use strict";
const $ = id => document.getElementById(id);
const HEAD = [
 "original_operator_followup_sha256","original_proposed_human_owner_label",
 "local_case","historical_transition","original_kit",
 "original_owner_human_reply_stage","original_operator_human_stage",
 "proposed_human_review_day","human_attention_priority",
 "private_human_discussion_question"
];
const PRIORITY=["unset","human_urgent","near_term","routine"];
const STAGES=["needs_discussion","proposed_followup","hold"];
const hex=v=>typeof v==="string"&&/^[a-f0-9]{64}$/.test(v);
const clean=v=>typeof v==="string"&&v.length<=240&&!/[\u0000-\u001f\u007f]/.test(v)&&!/^\s*[=+@-]/.test(v);
const safeOwner=v=>clean(v)&&v.length>0&&v.length<=80&&v.trim()===v;
function day(value) {
 if(value==="")return true;
 if(!/^20\d\d-[01]\d-[0-3]\d$/.test(value))return false;
 const parsed=new Date(value+"T00:00:00Z");
 return !Number.isNaN(parsed.valueOf())&&parsed.toISOString().slice(0,10)===value;
}
const elem=(tag,value)=>{const node=document.createElement(tag);if(value!==undefined)node.textContent=String(value);return node;};
function status(msg){$("status").textContent=msg;}
function parseCSV(text) {
 let pos=0,field="",row=[],rows=[],quoted=false,closed=false;
 while(pos<text.length) {
   const ch=text[pos++];
   if(quoted) {
     if(ch==='"') {
       if(text[pos]==='"'){field+='"';pos++;}
       else{quoted=false;closed=true;}
     } else field+=ch;
   } else if(ch==='"') {
     if(field!==""||closed)throw Error("Invalid CSV quote");
     quoted=true;
   } else if(ch===',') {
     row.push(field);field="";closed=false;
   } else if(ch==='\n'||ch==='\r') {
     if(ch==='\r'){if(text[pos]!=='\n')throw Error("Invalid CSV newline");pos++;}
     row.push(field);rows.push(row);row=[];field="";closed=false;
   } else {
     if(closed)throw Error("Trailing CSV quoted cell content");
     field+=ch;
   }
 }
 if(quoted||field!==""||row.length!==0)throw Error("Truncated CSV record");
 return rows;
}
function parseOriginal(text) {
 const records=parseCSV(text);
 if(records.length<2||records.length>2049||JSON.stringify(records[0])!==JSON.stringify(HEAD))
   throw Error("Expected exact 10-column native HUMAN proposed calendar template");
 const rows=[],unique=new Set();
 let originalSha="";
 for(const cells of records.slice(1)) {
   if(cells.length!==HEAD.length||!hex(cells[0])||!safeOwner(cells[1])||
     !STAGES.includes(cells[5])||!STAGES.includes(cells[6])||
     !PRIORITY.includes(cells[8])||!day(cells[7])||!clean(cells[9]))
     throw Error("Invalid original HUMAN template row");
   const expected=[8,11,12];
   for(let k=2;k<=4;k++){
     const n=Number(cells[k]);
     if(!/^[1-9]\d*$/.test(cells[k])||!Number.isSafeInteger(n)||n>expected[k-2])
       throw Error("Invalid original source ordinal");
   }
   if(originalSha!==""&&cells[0]!==originalSha)
     throw Error("Multiple incompatible original HUMAN follow-up sources");
   originalSha=cells[0];
   const key=cells.slice(2,5).join(":");
   if(unique.has(key))throw Error("Duplicate original case/round/kit slot");
   unique.add(key);
   rows.push({source:cells.slice(0,7),date:cells[7],priority:cells[8],note:cells[9]});
 }
 return {sha:originalSha,rows};
}
function quote(v){return '"'+String(v).replaceAll('"','""')+'"';}
function exportCSV(rows) {
 const records=[HEAD.map(quote).join(",")];
 for(const row of rows) {
   if(!day(row.date)||!PRIORITY.includes(row.priority)||!clean(row.note))
      throw Error("Invalid local HUMAN proposal");
   records.push([...row.source,row.date,row.priority,row.note].map(quote).join(","));
 }
 return records.join("\r\n")+"\r\n";
}
let original=[],dirty=false,originalSha="";
function visible() {
 const owner=$("owner").value,priority=$("priority").value;
 const proposal=$("proposal").value,query=$("query").value.trim().toLowerCase();
 return original.filter(r=>{
   if(owner&&r.source[1]!==owner)return false;
   if(priority&&r.priority!==priority)return false;
   if(proposal==="set"&&!r.date)return false;
   if(proposal==="empty"&&r.date)return false;
   const hay=[...r.source,r.date,r.priority,r.note].join(" ").toLowerCase();
   return !query||hay.includes(query);
 });
}
function updateCounts(){
 const dates=original.filter(r=>r.date).length;
 $("summary").textContent=original.length+" original HUMAN source slots | "+
   dates+" proposed dates | "+original.filter(r=>r.priority==="human_urgent").length+
   " HUMAN urgent proposals"+(dirty?" | UNSAVED local edits":"");
 $("visible").textContent=visible().length+" source slots visible; filters never remove rows from full export.";
}
function render() {
 const cards=$("cards");cards.replaceChildren();
 updateCounts();
 for(const row of visible()) {
   const section=elem("article");section.className="card";
   section.append(elem("h3","Original slot "+row.source[2]+" / "+row.source[3]+" / "+row.source[4]));
   const facts=elem("p");
   facts.textContent="Original proposed HUMAN owner (NOT authenticated): "+row.source[1]+
    " | owner reply: "+row.source[5]+" | operator proposal: "+row.source[6];
   section.append(facts);
   const controls=elem("div");controls.className="controls";
   const dateLabel=elem("label","HUMAN proposed review day (not an appointment)");
   const proposed=elem("input");
   proposed.type="date";proposed.min="2000-01-01";proposed.max="2099-12-31";
   proposed.value=row.date;
   proposed.addEventListener("change",()=>{
     if(!day(proposed.value)){proposed.value=row.date;status("PRIVATE HOLD: invalid HUMAN proposed day");return;}
     row.date=proposed.value;dirty=true;updateCounts();
   });
   dateLabel.append(proposed);
   const prioLabel=elem("label","HUMAN-only attention priority");
   const select=elem("select");
   for(const name of PRIORITY) {
     const opt=elem("option",name.replaceAll("_"," "));opt.value=name;
     opt.selected=row.priority===name;select.append(opt);
   }
   select.addEventListener("change",()=>{row.priority=select.value;dirty=true;updateCounts();});
   prioLabel.append(select);
   const noteLabel=elem("label","PRIVATE HUMAN discussion question (max 240, no formulas)");
   const note=elem("textarea");note.maxLength=240;note.rows=2;note.value=row.note;
   note.addEventListener("input",()=>{
     if(!clean(note.value)){note.value=row.note;status("PRIVATE HOLD: HUMAN question rejected");return;}
     row.note=note.value;dirty=true;updateCounts();
   });
   noteLabel.append(note);
   controls.append(dateLabel,prioLabel,noteLabel);section.append(controls);cards.append(section);
 }
 if(!cards.childNodes.length)cards.append(elem("p","No matching HUMAN proposals. No change to the complete original CSV."));
}
async function readFile(event) {
 const file=event.target.files?.[0];
 if(!file||file.size===0||file.size>1048576||!file.name.toLowerCase().endsWith(".csv")) {
   status("PRIVATE HOLD: select bounded original HUMAN calendar CSV");return;
 }
 try {
   const source=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
   const proposed=parseOriginal(source);
   if(dirty&&!window.confirm("Discard unsaved local PRIVATE HUMAN edits?"))return;
   original=proposed.rows;originalSha=proposed.sha;dirty=false;
   const owners=new Set(original.map(r=>r.source[1]));
   $("owner").replaceChildren(elem("option","All proposed HUMAN owners"));
   $("owner").firstChild.value="";
   for(const owner of owners){const opt=elem("option",owner);opt.value=owner;$("owner").append(opt);}
   $("priority").value="";$("proposal").value="all";$("query").value="";
   $("room").hidden=false;render();
   status("Original template opened in browser memory. Native original-source receipt verification is STILL REQUIRED.");
 }catch(error){
   status("PRIVATE HOLD: input rejected ("+(error?.message||"invalid CSV")+"). Previous draft retained.");
 }
}
async function restoreFile(event) {
 const file=event.target.files?.[0];
 if(!original.length||!file||file.size===0||file.size>1048576){
   status("PRIVATE HOLD: open original HUMAN template and complete bounded draft");return;
 }
 try {
   const text=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
   const incoming=parseOriginal(text);
   if(incoming.sha!==originalSha||incoming.rows.length!==original.length||
      incoming.rows.some((r,i)=>JSON.stringify(r.source)!==JSON.stringify(original[i].source)))
     throw Error("Changed original source, owner or row order");
   if(!window.confirm("Restore ALL original-source-bound HUMAN edits? Current local draft will be replaced."))return;
   incoming.rows.forEach((r,i)=>{original[i].date=r.date;original[i].priority=r.priority;original[i].note=r.note;});
   dirty=false;render();status("Complete source-matching HUMAN draft restored. No native source admission yet.");
 }catch(error){
   status("PRIVATE HOLD: full HUMAN draft rejected ("+(error?.message||"invalid")+"). Existing edits retained.");
 }
}
function download() {
 if(!original.length)return;
 if(!window.confirm("Export COMPLETE original-bound PRIVATE HUMAN proposed calendar? This is not a real booking, permission, task or security result."))return;
 try {
   const csv=exportCSV(original),url=URL.createObjectURL(new Blob([csv],{type:"text/csv;charset=utf-8"}));
   const a=elem("a");a.href=url;a.download="HUMAN-proposed-calendar-template.csv";
   document.body.append(a);a.click();a.remove();
   setTimeout(()=>URL.revokeObjectURL(url),800);
   dirty=false;updateCounts();
   status("Full HUMAN proposal CSV downloaded. Native receive + exact original source validation required.");
 }catch(error){status("PRIVATE HOLD: proposed CSV not exported ("+(error?.message||"invalid")+").");}
}
function clear(){
 if(dirty&&!window.confirm("Discard unsaved PRIVATE HUMAN calendar edits?"))return;
 original=[];originalSha="";dirty=false;
 $("file").value="";$("restore").value="";$("room").hidden=true;
 $("cards").replaceChildren();status("PRIVATE HUMAN calendar cleared from browser memory.");
}
$("file").addEventListener("change",readFile);
$("restore").addEventListener("change",restoreFile);
for(const id of ["owner","priority","proposal","query"])$(id).addEventListener(id==="query"?"input":"change",render);
$("export").addEventListener("click",download);
$("clear").addEventListener("click",clear);
})();
