/* HUMAN-only offline original source-identical memo sequence desk. Order is human selected, not authenticated chronology. */
(() => {
"use strict";
const $=id=>document.getElementById(id);
const source=window.LightUpCasebookReceiptLibrary;
const comparison=window.LightUpCasebookRevisionLibrary;
const encoder=new TextEncoder();
const deny=m=>{throw Error(m);};
let steps=[],busy=false;
function status(msg,error=false){
 $("timeline-status").textContent=(error?"HOLD: ":"")+msg;
 $("timeline-status").classList.toggle("error",error);
}
function lock(v){
 busy=v;$("timeline-add").disabled=v;
 $("timeline-export").disabled=v||steps.length<2;
 $("timeline-clear").disabled=v;
}
const element=(tag,text)=>{const e=document.createElement(tag);e.textContent=text;return e;};
function count(record){return {
 changed_cases:record.changed_cases,
 changed_choice_fields:record.changed_choice_fields,
 changed_human_notes:record.changed_human_notes,
 changed_human_reasons:record.changed_human_reasons,
 unchanged_cases:record.unchanged_cases,
 human_csv_bytes_differ:record.human_csv_bytes_differ
};}
function render(){
 const root=$("timeline-view");root.replaceChildren();
 if(!steps.length){
  $("timeline-export").disabled=true;
  root.append(element("p","Open eerst PRIVATE memo A in het memo-paneel en voeg hier aparte vervolgmemobestanden toe."));
  return;
 }
 root.append(element("p",steps.length+" zelfgekozen HUMAN-reviewmomenten; de volgorde is een operatorinvoer, GEEN geverifieerde tijdlijn."));
 const table=element("table",""),tr=element("tr","");
 ["Handmatige volgorde","Wijzigingen t.o.v. vorige memo","Afwijking t.o.v. beginmemo","Uitvoer HUMAN CSV"]
 .forEach(t=>tr.append(element("th",t)));
 const head=element("thead","");head.append(tr);table.append(head);
 const body=element("tbody","");
 steps.forEach((s,i)=>{
  const row=element("tr","");
  const previous=i===0?"Start (zelfgekozen)":s.delta.changed_cases+" dossiers; "+
   s.delta.changed_choice_fields+" HUMAN-velden; "+
   s.delta.changed_human_notes+" notities gewijzigd; "+
   s.delta.changed_human_reasons+" redenen gewijzigd";
  const baseline=i===0?"Start":s.baseline.changed_cases+" dossiers sinds beginselectie";
  [String(i+1),previous,baseline,
   i===0?"Zelfverklaarde uitgang":s.delta.human_csv_bytes_differ?"Afwijkende CSV-bytehash":"Identieke CSV-bytehash"]
   .forEach(t=>row.append(element("td",t)));
  body.append(row);
 });
 table.append(body);root.append(table);
 $("timeline-export").disabled=busy||steps.length<2;
}
async function add(){
 if(steps.length>=12)deny("Maximaal twaalf menselijke memomomenten in deze lokale reeks.");
 const first=source.current();
 if(!first)deny("Open eerst een PRIVATE memo A hierboven.");
 const file=$("timeline-file").files[0],pw=$("timeline-pass").value;
 if(!file||!pw)deny("Kies een vervolgmemobestand en zelfstandig wachtwoord.");
 const incoming=await source.decodeMemo(file,pw);
 const anchor=steps[0]?.memo||first;
 // Strict original source/history and original HUMAN A/B input must be byte-identical.
 comparison.compare(anchor,incoming);
 const previous=steps.at(-1)?.memo||anchor;
 const delta=comparison.compare(previous,incoming).counts;
 const baseline=comparison.compare(anchor,incoming).counts;
 if(steps.length===0){
  steps.push({memo:anchor,delta:null,baseline:null});
 }
 steps.push({memo:incoming,delta:count(delta),baseline:count(baseline)});
 render();
 status("Zelfgekozen PRIVATE memo nr. "+steps.length+" bron-identiek toegelaten. Dit is géén geauthenticeerde kalender of bewijs van remediation.");
}
$("timeline-add").addEventListener("click",async()=>{
 if(!crypto?.subtle||!window.isSecureContext){status("Veilige WebCrypto-context ontbreekt.",true);return;}
 if(busy)return;lock(true);
 try{
  if(!$("ack").checked)deny("PRIVATE HUMAN-only erkenning ontbreekt.");
  await add();
 }catch(e){status(e instanceof Error?e.message:"Vervolgmemobestand geweigerd.",true);}
 finally{$("timeline-pass").value="";$("timeline-file").value="";lock(false);}
});
function clear(){
 steps=[];render();
 status("Zelfgekozen PRIVATE memo-reeks uit het lokale weergavegeheugen verwijderd.");
}
$("timeline-clear").addEventListener("click",()=>{
 if(busy||!steps.length)return;
 if(!window.confirm("Verwijder de lokale zelfgekozen PRIVATE memo-reeks uit dit tabblad? Reeds opgeslagen bestanden blijven intact."))return;
 clear();
});
window.LightUpCasebookTimelineClear=clear;
$("timeline-export").addEventListener("click",()=>{
 try{
  if(steps.length<2)deny("Minstens twee bron-identieke HUMAN-memo's nodig.");
  if(!window.confirm("Exporteer uitsluitend bronvrije aantallen van een zelfgekozen HUMAN-reeks? De volgorde is NIET geauthenticeerd en kleine groepen kunnen gevoelig zijn."))return;
  const out={
   schema:"lightup.casebook.human_review_selected_series_aggregate.v1",
   status:"REVIEW_ONLY",authority:"NONE",human_selected_order_only:true,
   source_order_authenticated:false,source_identity_authenticated:false,
   cases:steps[0].memo.cases.length,
   moments:steps.map((s,i)=>({
    human_selected_ordinal:i+1,
    changed_from_previous:i===0?null:s.delta,
    changed_from_first:i===0?null:s.baseline
   })),
   source_authenticated:false,client_consent_verified:false,
   operator_consent_verified:false,authorization_granted:false,
   execution_allowed:false,release_approved:false
  };
  const bytes=encoder.encode(JSON.stringify(out)+"\n");
  if(bytes.length>65536)deny("Bronvrij memo-aggregaat te groot.");
  const url=URL.createObjectURL(new Blob([bytes],{type:"application/octet-stream"}));
  const link=document.createElement("a");link.href=url;
  link.download="lightup-HUMAN-selected-memo-series-aggregate.json";
  document.body.append(link);link.click();link.remove();
  setTimeout(()=>URL.revokeObjectURL(url),2000);
  status("Bronvrije zelfgekozen HUMAN-reekstelling aangeboden; geen tijd-, bron- of toestemming-authenticatie.");
 }catch(e){status(e instanceof Error?e.message:"Aggregaat geweigerd.",true);}
});
render();
})();