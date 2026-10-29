/* LightUp offline source-bound PRIVATE HUMAN bulk triage and reversible decision history.
 * No risk approval, consent verification, grant, original source or network access. */
(() => {
"use strict";
const $=id=>document.getElementById(id);
const bridge=window.LightUpBulkBridge;
const options=[
 ["unreviewed","investigating","awaiting-owner","documented"],
 ["unassigned","original-scope-owner","client-clarification","independent-security-review","operator-followup"],
 ["none","missing-source","missing-owner","needs-independent-consent",
  "requires-revocation-review","unresolved-tenant-lineage"]
];
const humanFields=["HUMAN-fase","HUMAN-route","HUMAN-blokkade"];
const MAX_HISTORY=30;
let preview=null,undo=[],redo=[],busy=false;
const deny=m=>{throw Error(m);};
const setStatus=(m,error=false)=>{
 $("bulk-status").textContent=(error?"HOLD: ":"")+m;
 $("bulk-status").classList.toggle("error",error);
};
const make=(tag,text)=>{const n=document.createElement(tag);n.textContent=text;return n;};
const bulkChoice=()=>{
 const type=$("bulk-value").value;
 if(type!=="custom")return type;
 const choice=$("bulk-custom").value;
 return options[Number($("bulk-field").value)].includes(choice)?"custom:"+choice:"";
};
function showOptions(){
 const field=Number($("bulk-field").value);
 const list=$("bulk-custom");list.replaceChildren();
 const blank=make("option","Kies een expliciete HUMAN-waarde");blank.value="";
 list.append(blank);
 for(const value of options[field]){
  const node=make("option",value);node.value=value;list.append(node);
 }
 list.hidden=$("bulk-value").value!=="custom";
 invalidate();
}
function invalidate(){
 preview=null;
 $("bulk-apply").disabled=true;
 $("bulk-preview").replaceChildren();
 $("bulk-preview").append(make("p","Nog geen actuele HUMAN-bulkvoorvertoning."));
 updateButtons();
}
function updateButtons(){
 $("bulk-undo").disabled=busy||undo.length===0;
 $("bulk-redo").disabled=busy||redo.length===0;
 $("bulk-plan").disabled=busy;
 $("bulk-apply").disabled=busy||!preview;
 $("bulk-history").textContent=undo.length+" beschikbare ongedaan-stappen · "+
  redo.length+" beschikbare herstelstappen (alleen huidig PRIVATE tabblad).";
}
function setBusy(v){
 busy=v;
 for(const el of [$("bulk-field"),$("bulk-value"),$("bulk-custom"),$("bulk-scope")])el.disabled=v;
 updateButtons();
}
function reset(){
 undo=[];redo=[];invalidate();
 setStatus("PRIVATE brongebonden bulkgeschiedenis gewist; nog geen bulkkeuze toegepast.");
}
function recordManual(i,j,from,to){
 if(busy)return;
 if(from!==to){
  undo.push([{i,j,from,to}]);
  if(undo.length>MAX_HISTORY)undo.shift();
  redo=[];invalidate();
 }
}
function plan(){
 const data=bridge.read();
 if(!data)deny("Open eerst twee exact dezelfde oorspronkelijke PRIVATE bronnen.");
 const field=Number($("bulk-field").value),value=bulkChoice();
 if(!Number.isInteger(field)||field<0||field>2||
    !["A","B","reset"].includes(value)&&!(
       value.startsWith("custom:")&&options[field].includes(value.slice(7))))
  deny("Kies eerst één canonieke HUMAN-veldwaarde.");
 const all=$("bulk-scope").value==="all-unresolved";
 const visible=new Set(data.visible);
 const proposed=[];
 for(let i=0;i<data.cases.length;i++){
  const c=data.cases[i];
  if(!all&&!visible.has(i))continue;
  if(c.a[field]===c.b[field])continue;
  const old=c.choices[field];
  // Bulk decisions apply only to *unresolved* disagreements. Existing
  // deliberately selected HUMAN fields may never be silently overwritten.
  if(old!==""&&old!=="custom:")continue;
  if(old!==value)proposed.push({i,j:field,from:old,to:value});
 }
 if(!proposed.length)deny("Geen nog onbesliste oorspronkelijke HUMAN-veldconflicten binnen het gekozen bereik.");
 if(proposed.length>200)deny("Teveel wijzigingen in één expliciete HUMAN-bulkactie.");
 return {changes:proposed,field,value,scope:$("bulk-scope").value,
  affected:proposed.map(ch=>data.cases[ch.i].id)};
}
function renderPreview(result){
 const root=$("bulk-preview");root.replaceChildren();
 root.append(make("p","PRIVATE bulkvoorvertoning: "+result.changes.length+
  " nog onbesliste "+humanFields[result.field]+"-velden → "+
  (result.value.startsWith("custom:")?result.value.slice(7):result.value)+
  ". Reeds beoordeelde velden en originele bronbestanden blijven onaangeroerd."));
 const shown=result.affected.slice(0,8);
 const details=make("p","Getroffen PRIVATE brondossiers: "+shown.join(" · ")+
  (result.affected.length>8?" · plus "+(result.affected.length-8)+" andere PRIVATE dossiers.":""));
 root.append(details);
 root.append(make("p","Voorvertoning is GEEN goedkeuring: expliciete bevestiging vereist. "+
  "Bronacties, grants, cliënt-/operatortoestemming, werkelijk scanbeleid en originele CSV-bronrijen worden hierdoor niet geverifieerd."));
}
$("bulk-plan").addEventListener("click",()=>{
 try{preview=plan();renderPreview(preview);updateButtons();
  setStatus(preview.changes.length+" HUMAN-veldkeuzes klaar voor expliciete bulkbeoordeling.");}
 catch(e){invalidate();setStatus(e.message||"Ongeldige bulkvoorvertoning.",true);}
});
$("bulk-apply").addEventListener("click",()=>{
 try{
  if(!preview||!bridge.read())deny("Ververs eerst de HUMAN-bulkvoorvertoning.");
  const expected=plan();
  if(expected.field!==preview.field||expected.value!==preview.value||
    expected.scope!==preview.scope||
    JSON.stringify(expected.changes)!==JSON.stringify(preview.changes))
   deny("HOLD: oorspronkelijke keuzestand/filters zijn gewijzigd. Maak een nieuwe voorvertoning.");
  if(!window.confirm("Pas uitsluitend "+preview.changes.length+
      " PRIVATE HUMAN-keuzes toe in dit tabblad? Dit verleent GEEN grant, scanmachtiging of consent. Iedere stap kan via Ongedaan worden teruggezet."))
    return;
  const tx=preview.changes.map(c=>({...c}));
  bridge.apply(tx);
  undo.push(tx);if(undo.length>MAX_HISTORY)undo.shift();redo=[];
  invalidate();
  setStatus(tx.length+" oorspronkelijke HUMAN-conflicten expliciet gekozen; alle bronbestanden blijven intact.");
 }catch(e){invalidate();setStatus(e.message||"Bulk-actie geweigerd.",true);}
});
function reverse(tx){
 return tx.map(({i,j,from,to})=>({i,j,from:to,to:from}));
}
$("bulk-undo").addEventListener("click",()=>{
 if(busy||!undo.length)return;
 try{
  const tx=undo.at(-1);
  bridge.apply(reverse(tx));
  undo.pop();redo.push(tx);invalidate();
  setStatus("Laatste PRIVATE HUMAN-keuzestap ongedaan gemaakt zonder wijziging van bronbestanden.");
 }catch(e){invalidate();setStatus("HOLD: "+e.message,true);}
});
$("bulk-redo").addEventListener("click",()=>{
 if(busy||!redo.length)return;
 try{
  const tx=redo.at(-1);
  bridge.apply(tx);redo.pop();undo.push(tx);
  if(undo.length>MAX_HISTORY)undo.shift();invalidate();
  setStatus("Laatste teruggedraaide PRIVATE HUMAN-keuzestap opnieuw toegepast.");
 }catch(e){invalidate();setStatus("HOLD: "+e.message,true);}
});
for(const id of ["bulk-field","bulk-value"])$(id).addEventListener("change",showOptions);
for(const id of ["bulk-custom","bulk-scope"])$(id).addEventListener("change",invalidate);
window.LightUpCasebookBulk=Object.freeze({reset,recordManual,setBusy});
showOptions();
})();