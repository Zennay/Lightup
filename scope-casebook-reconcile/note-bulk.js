/* Offline PRIVATE HUMAN follow-up reason batch queue, source-bound, no authority. */
(() => {
"use strict";
const $=id=>document.getElementById(id),bridge=window.LightUpBulkBridge,
 notes=window.LightUpCasebookNotes;
const MAX_HISTORY=25;
const node=(tag,body)=>{const n=document.createElement(tag);n.textContent=body;return n;};
let proposed=null,undo=[],redo=[],busy=false;
const deny=m=>{throw Error(m);};
function status(text,error=false){
 $("note-bulk-status").textContent=(error?"HOLD: ":"")+text;
 $("note-bulk-status").classList.toggle("error",error);
}
function controls(){
 $("note-bulk-preview-btn").disabled=busy;
 $("note-bulk-apply").disabled=busy||!proposed;
 $("note-bulk-undo").disabled=busy||!undo.length;
 $("note-bulk-redo").disabled=busy||!redo.length;
 $("note-bulk-reason").disabled=busy;
 $("note-bulk-scope").disabled=busy;
 $("note-bulk-history").textContent=undo.length+" ongedaan-stappen · "+
  redo.length+" herstelstappen (alleen deze PRIVATE browsersessie).";
}
function invalidate(){
 proposed=null;
 $("note-bulk-plan").replaceChildren();
 $("note-bulk-plan").append(node("p","Nog geen actuele brongebonden HUMAN-redenenvoorvertoning."));
 controls();
}
function reset(){undo=[];redo=[];invalidate();}
function setBusy(v){busy=v;controls();}
function plan(){
 const original=bridge.read();if(!original)deny("Open eerst twee identieke PRIVATE Casebook-bronnen.");
 const reason=$("note-bulk-reason").value;
 if(!notes.reasons.includes(reason)||reason==="not-recorded")
  deny("Kies een originele HUMAN-opvolgreden (geen toestemming of grant).");
 const all=$("note-bulk-scope").value==="all",visible=new Set(original.visible),
  memo=notes.read(),changes=[],ids=[];
 if(memo.length!==original.cases.length)deny("PRIVATE HUMAN-notities niet aan huidige bronaantallen gekoppeld.");
 for(let i=0;i<original.cases.length;i++){
  if(!all&&!visible.has(i))continue;
  const c=original.cases[i];
  if(!c.a.some((x,j)=>x!==c.b[j]))continue;
  if(memo[i].reason!=="not-recorded")continue;
  changes.push({i,from:memo[i].reason,to:reason});ids.push(c.id);
 }
 if(!changes.length)deny("Geen PRIVATE HUMAN-conflictdossiers zonder bestaande opvolgreden in dit bereik.");
 if(changes.length>200)deny("Teveel PRIVATE menselijke notitieregels.");
 return {reason,all,changes,ids};
}
function renderPlan(p){
 const div=$("note-bulk-plan");div.replaceChildren();
 div.append(node("p",p.changes.length+" PRIVATE HUMAN-conflictdossiers zonder bestaande reden"+
  " → '"+notes.labels[p.reason]+"'. Reeds ingevulde redenen en alle oorspronkelijke privénotitieteksten blijven exact behouden."));
 div.append(node("p","Lokale voorbeelden: "+p.ids.slice(0,7).join(" · ")+
  (p.ids.length>7?" · plus "+(p.ids.length-7)+" andere PRIVATE broncases":"")));
 div.append(node("p","Dit is een menselijke opvolgredencategorie, GEEN verificatie, grant, scanmachtiging of automatische actie."));
}
$("note-bulk-preview-btn").addEventListener("click",()=>{
 try{proposed=plan();renderPlan(proposed);controls();status("PRIVATE opvolgredenen klaar voor expliciete menselijke bevestiging.");}
 catch(e){invalidate();status(e.message||"Redenenvoorvertoning ongeldig.",true);}
});
$("note-bulk-apply").addEventListener("click",()=>{
 try{
  if(busy||!proposed)deny("Nieuwe brongebonden voorvertoning vereist.");
  const now=plan();
  if(now.reason!==proposed.reason||now.all!==proposed.all||
    JSON.stringify(now.changes)!==JSON.stringify(proposed.changes))
    deny("PRIVATE oorspronkelijke dossiers of selectie gewijzigd. Maak een nieuwe voorvertoning.");
  if(!window.confirm("Zet uitsluitend "+proposed.changes.length+
    " nog lege PRIVATE HUMAN-opvolgredenen op '"+notes.labels[proposed.reason]+
    "'? Geen oorspronkelijke bron, notitietekst, grant of toestemming verandert."))return;
  const tx=proposed.changes.map(x=>({...x}));
  notes.applyReasons(tx);bridge.refresh();
  undo.push(tx);if(undo.length>MAX_HISTORY)undo.shift();redo=[];
  invalidate();
  status(tx.length+" PRIVATE menselijke opvolgredenen toegekend zonder bestaande redenen te overschrijven.");
 }catch(e){invalidate();status(e.message||"Redenenbulkactie geweigerd.",true);}
});
const reverse=changes=>changes.map(({i,from,to})=>({i,from:to,to:from}));
$("note-bulk-undo").addEventListener("click",()=>{
 if(busy||!undo.length)return;
 try{const tx=undo.at(-1);notes.applyReasons(reverse(tx));
  bridge.refresh();undo.pop();redo.push(tx);invalidate();
  status("Laatste menselijke PRIVATE redenenbatch ongedaan gemaakt.");}
 catch(e){invalidate();status(e.message||"Ongedaan maken geweigerd.",true);}
});
$("note-bulk-redo").addEventListener("click",()=>{
 if(busy||!redo.length)return;
 try{const tx=redo.at(-1);notes.applyReasons(tx);
  bridge.refresh();redo.pop();undo.push(tx);if(undo.length>MAX_HISTORY)undo.shift();
  invalidate();status("Eerder teruggedraaide PRIVATE menselijke redenenbatch hersteld.");}
 catch(e){invalidate();status(e.message||"Opnieuw toepassen geweigerd.",true);}
});
for(const id of ["note-bulk-reason","note-bulk-scope"])
 $(id).addEventListener("change",invalidate);
window.LightUpCasebookNoteBulk=Object.freeze({reset,setBusy,
 invalidateHistory:()=>{undo=[];redo=[];invalidate();}});
reset();
})();