/* Source-free offline LightUp HUMAN calendar decision editor.
 * No native original file reads in the browser. No release/booking/authority.
 */
(() => {
"use strict";
const $=id=>document.getElementById(id);
const HEAD=[
"original_human_calendar_set_sha256","original_human_source_ordinal",
"original_proposed_human_owner_label","local_case","historical_transition","original_kit",
"human_day_proposals_differ","human_priority_proposals_differ",
"private_human_question_proposals_differ","human_selected_proposed_review_day",
"human_selected_priority","private_human_alignment_question","human_alignment_stage"];
const STAGES=["needs_discussion","hold","human_alignment_proposed"];
const PRIORITIES=["unset","human_urgent","near_term","routine"];
let records=[],sourceSha="",dirty=false;
const hex=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x);
const safe=x=>typeof x==="string"&&x.length<=240&&!/[\u0000-\u001f\u007f]/.test(x)&&!/^\s*[=+@-]/.test(x);
function validDate(x) {
 if(!x)return true;
 if(!/^20\d{2}-[01]\d-[0-3]\d$/.test(x))return false;
 const date=new Date(x+"T00:00:00Z");
 return !Number.isNaN(date.valueOf())&&date.toISOString().slice(0,10)===x;
}
function parseCSV(src) {
 const rows=[];let row=[],field="",at=0,quoted=false,ended=false;
 while(at<src.length){
  const c=src[at++];
  if(quoted){
   if(c==='"'){if(src[at]==='"'){field+='"';at++;}else{quoted=false;ended=true;}}
   else field+=c;
  }else if(c==='"'){
   if(field!==""||ended)throw Error("Malformed original CSV quoting");
   quoted=true;
  }else if(c===','){
   row.push(field);field="";ended=false;
  }else if(c==='\n'||c==='\r'){
   if(c==='\r'){if(src[at]!=='\n')throw Error("Noncanonical CSV newline");at++;}
   row.push(field);rows.push(row);row=[];field="";ended=false;
  }else{
   if(ended)throw Error("Trailing text after CSV close quote");
   field+=c;
  }
 }
 if(quoted||field||row.length)throw Error("Truncated HUMAN calendar decision CSV");
 return rows;
}
function admit(source) {
 const arr=parseCSV(source);
 if(arr.length<2||arr.length>2049||JSON.stringify(arr[0])!==JSON.stringify(HEAD))
   throw Error("Expected native complete original decision template");
 let sha="";const output=[],ids=new Set(),seenOwners=new Set();
 for(const cells of arr.slice(1)){
  if(cells.length!==HEAD.length||!hex(cells[0])||!safe(cells[2])||!cells[2]||
    cells[2]!==cells[2].trim()||cells[2].length>80||!validDate(cells[9])||
    !PRIORITIES.includes(cells[10])||!safe(cells[11])||!STAGES.includes(cells[12])||
    ![6,7,8].every(i=>["yes","no"].includes(cells[i])))
    throw Error("Malformed original HUMAN decision record");
  const limits=[2048,8,11,12];
  for(let j=0;j<4;j++){
   const n=cells[[1,3,4,5][j]];
   if(!/^[1-9]\d*$/.test(n)||Number(n)>limits[j])throw Error("Invalid original source number");
  }
  if(sha&&sha!==cells[0])throw Error("Mixed original calendar source sets");
  sha=cells[0];
  const id=cells.slice(3,6).join(":");
  if(ids.has(id))throw Error("Repeated original case slot");
  ids.add(id);
  if(cells[1]!==String(output.length+1))throw Error("Original source ordinal/order mismatch");
  output.push({
    fixed:cells.slice(0,9),
    owner:cells[2],day:cells[9],priority:cells[10],question:cells[11],
    stage:cells[12],conflict:cells.slice(6,9).includes("yes")
  });
  seenOwners.add(cells[2]);
 }
 return {sha,rows:output,owners:[...seenOwners]};
}
const create=(tag,value)=>{const element=document.createElement(tag);if(value!==undefined)element.textContent=String(value);return element;};
const status=message=>$("status").textContent=message;
function matching(){
 const owner=$("owner").value,stage=$("stage").value,conflict=$("conflict").value;
 const query=$("search").value.toLowerCase().trim();
 return records.filter(x=>{
  if(owner&&x.owner!==owner)return false;
  if(stage&&x.stage!==stage)return false;
  if(conflict==="diff"&&!x.conflict)return false;
  if(conflict==="stable"&&x.conflict)return false;
  const text=[...x.fixed,x.day,x.priority,x.question,x.stage].join(" ").toLowerCase();
  return !query||text.includes(query);
 });
}
function updateCounts(){
 $("summary").textContent=records.length+" ORIGINAL HUMAN source positions | "+
   records.filter(r=>r.conflict).length+" with differing proposals | "+
   STAGES.map(stage=>stage+": "+records.filter(r=>r.stage===stage).length).join(" | ")+
   (dirty?" | unsaved local HUMAN choices":"");
 $("visible").textContent=matching().length+" visible; complete source slot set stays intact.";
}
function render(){
 const cards=$("cards");cards.replaceChildren();
 updateCounts();
 for(const entry of matching()){
  const article=create("article");article.className="card";
  article.append(create("h3","Original HUMAN slot "+entry.fixed[3]+" / "+
    entry.fixed[4]+" / "+entry.fixed[5]));
  const info=create("p");
  info.textContent="Proposed HUMAN owner (not authenticated): "+entry.owner+
    " | conflicts: day "+entry.fixed[6]+", priority "+entry.fixed[7]+
    ", private question "+entry.fixed[8];
  article.append(info);
  const container=create("div");container.className="controls";
  const stageLabel=create("label","HUMAN alignment proposal only");
  const select=create("select");
  for(const value of STAGES){
   const opt=create("option",value.replaceAll("_"," "));opt.value=value;
   opt.selected=value===entry.stage;select.append(opt);
  }
  select.addEventListener("change",()=>{entry.stage=select.value;dirty=true;updateCounts();});
  stageLabel.append(select);
  const dayLabel=create("label","Human-proposed review day (NOT booked)");
  const day=create("input");
  day.type="date";day.min="2000-01-01";day.max="2099-12-31";day.value=entry.day;
  day.addEventListener("change",()=>{
   if(!validDate(day.value)){day.value=entry.day;status("PRIVATE HOLD: HUMAN date rejected");return;}
   entry.day=day.value;dirty=true;updateCounts();
  });
  dayLabel.append(day);
  const priorityLabel=create("label","Proposed HUMAN discussion priority");
  const priority=create("select");
  for(const value of PRIORITIES){
   const option=create("option",value.replaceAll("_"," "));option.value=value;
   option.selected=value===entry.priority;priority.append(option);
  }
  priority.addEventListener("change",()=>{entry.priority=priority.value;dirty=true;updateCounts();});
  priorityLabel.append(priority);
  const noteLabel=create("label","PRIVATE HUMAN discussion question (max 240)");
  const note=create("textarea");note.maxLength=240;note.rows=2;note.value=entry.question;
  note.addEventListener("input",()=>{
   if(!safe(note.value)){note.value=entry.question;status("PRIVATE HOLD: unsafe HUMAN question rejected");return;}
   entry.question=note.value;dirty=true;updateCounts();
  });
  noteLabel.append(note);
  container.append(stageLabel,dayLabel,priorityLabel,noteLabel);
  article.append(container);cards.append(article);
 }
 if(!cards.childNodes.length)cards.append(create("p","No matching HUMAN proposals; no original rows dropped."));
}
async function readCSV(file){
 if(!file||file.size<=0||file.size>1048576||!file.name.toLowerCase().endsWith(".csv"))
  throw Error("Select one original complete PRIVATE CSV <= 1 MiB");
 return new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
}
async function open(event){
 try{
  const parsed=admit(await readCSV(event.target.files?.[0]));
  if(dirty&&!window.confirm("Discard unsaved local HUMAN decisions?"))return;
  sourceSha=parsed.sha;records=parsed.rows;dirty=false;
  $("owner").replaceChildren(create("option","All proposed HUMAN owners"));
  $("owner").firstChild.value="";
  for(const owner of parsed.owners){
   const opt=create("option",owner);opt.value=owner;$("owner").append(opt);
  }
  $("search").value="";$("stage").value="";$("conflict").value="all";
  $("room").hidden=false;render();
  status("Original HUMAN decisions opened LOCALLY. Native original-source admission is mandatory.");
 }catch(error){status("PRIVATE HOLD: "+(error?.message||"invalid complete CSV")+". Existing draft unchanged.");}
}
async function restore(event){
 try{
  if(!records.length)throw Error("Open original HUMAN template first");
  const parsed=admit(await readCSV(event.target.files?.[0]));
  if(parsed.sha!==sourceSha||parsed.rows.length!==records.length||
      parsed.rows.some((r,i)=>JSON.stringify(r.fixed)!==JSON.stringify(records[i].fixed)))
    throw Error("Original HUMAN source/owner/order mismatch");
  if(!window.confirm("Restore COMPLETE source-bound local HUMAN draft? Existing choices replaced."))return;
  parsed.rows.forEach((r,i)=>{
   records[i].stage=r.stage;records[i].day=r.day;
   records[i].priority=r.priority;records[i].question=r.question;
  });
  dirty=false;render();status("Complete original-source HUMAN draft restored; still not native-verified.");
 }catch(error){status("PRIVATE HOLD: "+(error?.message||"draft refused")+". Earlier choices retained.");}
}
function download(){
 if(!records.length)return;
 if(!window.confirm("Export complete PRIVATE HUMAN decision proposal CSV? No real scheduling, grant or authorization."))return;
 try{
  const quote=x=>'"'+String(x).replaceAll('"','""')+'"';
  const lines=[HEAD.map(quote).join(",")];
  for(const r of records){
   if(!validDate(r.day)||!PRIORITIES.includes(r.priority)||!safe(r.question)||!STAGES.includes(r.stage))
    throw Error("Invalid HUMAN decision");
   lines.push([...r.fixed,r.day,r.priority,r.question,r.stage].map(quote).join(","));
  }
  const url=URL.createObjectURL(new Blob([lines.join("\r\n")+"\r\n"],{type:"text/csv;charset=utf-8"}));
  const a=create("a");a.href=url;a.download="HUMAN-calendar-decision-template.csv";
  document.body.append(a);a.click();a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),750);
  dirty=false;updateCounts();
  status("Complete original HUMAN CSV downloaded. Native original-bound RECEIVE still required.");
 }catch(error){status("PRIVATE HOLD: "+(error?.message||"export refused"));}
}
function forget(){
 if(dirty&&!window.confirm("Discard unsaved local PRIVATE HUMAN choices?"))return;
 records=[];sourceSha="";dirty=false;
 $("file").value="";$("restore").value="";$("room").hidden=true;
 $("cards").replaceChildren();status("Private HUMAN discussion cleared from browser memory.");
}
$("file").addEventListener("change",open);
$("restore").addEventListener("change",restore);
for(const id of ["owner","stage","conflict","search"])
 $(id).addEventListener(id==="search"?"input":"change",render);
$("export").addEventListener("click",download);
$("clear").addEventListener("click",forget);
})();