/* Offline human-only exact reconciled Casebook CSV pre-publication preview, not authority. */
(() => {
"use strict";
const $=id=>document.getElementById(id);
const bridge=window.LightUpBulkBridge,original=window.LightUpCasebookHandoff;
const enc=new TextEncoder();
const allowed=[
 ["unreviewed","investigating","awaiting-owner","documented"],
 ["unassigned","original-scope-owner","client-clarification","independent-security-review","operator-followup"],
 ["none","missing-source","missing-owner","needs-independent-consent",
  "requires-revocation-review","unresolved-tenant-lineage"]
];
let generation=0,active=false,expectedSha=null;
const deny=x=>{throw Error(x);};
const el=(tag,s)=>{const e=document.createElement(tag);e.textContent=s;return e;};
function setStatus(message,error=false){
 $("preview-status").textContent=(error?"HOLD: ":"")+message;
 $("preview-status").classList.toggle("error",error);
}
function outcome(a,b,choice,j){
 if(a===b)return {value:a,method:"Oorspronkelijk gelijk"};
 if(choice==="A")return {value:a,method:"Menselijk A"};
 if(choice==="B")return {value:b,method:"Menselijk B"};
 if(choice==="reset")return {value:allowed[j][0],method:"Menselijk heropend"};
 if(typeof choice==="string"&&choice.startsWith("custom:")&&
    allowed[j].includes(choice.slice(7)))
  return {value:choice.slice(7),method:"Nieuwe toegestane HUMAN-waarde"};
 return {value:null,method:"HOLD — nog geen menselijk besluit"};
}
function evaluate(data){
 if(!data)deny("Laad eerst twee oorspronkelijke, exacte PRIVATE bronsets.");
 const rows=[],cases=[];
 let unresolved=0,differing=0,kept=0,deliberate=0;
 for(const c of data.cases){
  const row=[c.id,c.action,c.attention],fields=[];
  let caseChanged=false;
  for(let j=0;j<3;j++){
   const a=c.a[j],b=c.b[j],chosen=outcome(a,b,c.choices[j],j);
   if(!allowed[j].includes(a)||!allowed[j].includes(b))
    deny("Niet-canoniek oorspronkelijke HUMAN-veld.");
   if(a!==b){caseChanged=true;deliberate+=Number(chosen.value!==null);}
   else kept++;
   if(chosen.value===null)unresolved++;
   row.push(chosen.value);
   fields.push({a,b,...chosen,field:["Fase","Route","Blokkade"][j]});
  }
  if(caseChanged)differing++;
  rows.push(row);cases.push({id:c.id,action:c.action,attention:c.attention,fields,caseChanged});
 }
 return {rows,cases,total:cases.length,differing,unresolved,kept,deliberate};
}
function render(result){
 const panel=$("preview-result");panel.replaceChildren();
 const term=$("preview-search").value.trim().toLocaleLowerCase("nl-NL"),
  differentOnly=$("preview-different").checked;
 let shown=0;
 for(const c of result.cases){
  if(differentOnly&&!c.caseChanged)continue;
  if(term&&![c.id,c.action,c.attention].some(x=>x.toLocaleLowerCase("nl-NL").includes(term)))continue;
  const details=el("details","");details.className="result-case";
  const summary=el("summary",c.id+" · "+(c.caseChanged?"HUMAN-verschil":"Oorspronkelijk HUMAN gelijk")+
   " · "+c.attention);
  details.append(summary,el("p","Originele bronactie (niet onafhankelijk geverifieerd): "+c.action));
  const table=el("table",""),head=el("tr","");
  ["Menselijk veld","Bron A","Bron B","Voorgenomen HUMAN-uitkomst","Keuzebasis"].forEach(t=>head.append(el("th",t)));
  const thead=el("thead","");thead.append(head);table.append(thead);
  const tbody=el("tbody","");
  c.fields.forEach(f=>{
   const row=el("tr","");
   [f.field,f.a,f.b,f.value===null?"HOLD — GEEN UITKOMST":f.value,f.method].forEach(x=>row.append(el("td",x)));
   if(f.value===null)row.className="pending";
   tbody.append(row);
  });
  table.append(tbody);details.append(table);
  panel.append(details);
  shown++;
 }
 $("preview-visible").textContent=shown+" van "+result.total+" PRIVATE dossiers in de huidige voorvertoning.";
}
function invalidate(){
 generation++;active=false;expectedSha=null;
 $("preview-sha").textContent="Geen actuele SHA-256 van een volledig menselijk besloten resultaat.";
 $("preview-result").replaceChildren();
 $("preview-visible").textContent="";
 $("preview-export-state").textContent="Geen actueel prospectief CSV-resultaat.";
}
async function calculate(){
 const thisGeneration=++generation;
 active=false;
 const data=bridge.read();
 const review=evaluate(data);
 render(review);
 $("preview-different").disabled=false;$("preview-search").disabled=false;
 $("preview-export-state").textContent=review.total+" oorspronkelijke PRIVATE dossiers · "+
  review.differing+" met HUMAN-verschillen · "+
  review.deliberate+" expliciet besloten conflictvelden · "+
  review.unresolved+" nog onbehandeld.";
 if(review.unresolved){
  $("preview-sha").textContent="HOLD: geen volledig brongebonden HUMAN-CSV SHA-256 zolang besluiten ontbreken.";
  setStatus("Alleen een lokaal gedeeltelijk HUMAN-voorstel getoond. Export van definitieve Casebook blijft in bestaande flow geweigerd.");
  return;
 }
 if(!crypto?.subtle||!window.isSecureContext)deny("SHA-256 preview vereist een veilige lokale WebCrypto-context.");
 // Match exactly the original source-owner's canonical current HUMAN CSV serializer.
 const humanBytes=enc.encode(original.serialize(review.rows));
 if(humanBytes.length>131072)deny("Voorlopige huidige HUMAN-CSV groter dan oorspronkelijke grens.");
 let digest;
 try{
  digest=Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",humanBytes)),
   b=>b.toString(16).padStart(2,"0")).join("");
 }finally{humanBytes.fill(0);}
 if(thisGeneration!==generation)return;
 const current=bridge.read();
 if(!current||JSON.stringify(data.cases)!==JSON.stringify(current.cases)){
  invalidate();deny("Bron-/HUMAN-keuzes wijzigden tijdens de lokale preview. Kies opnieuw.");
 }
 active=true;expectedSha=digest;
 render(review);
 $("preview-sha").textContent="Zelfberekende prospective HUMAN CSV SHA-256 (geen bronverificatie): "+digest;
 setStatus("Volledig besloten HUMAN-uitvoer lokaal vooraf bekeken. Het SHA-verwijzingsgetal authenticeert geen producent of toestemming; daadwerkelijke export blijft afzonderlijk expliciet.");
}
$("preview-build").addEventListener("click",async()=>{
 try{await calculate();}catch(e){invalidate();setStatus(e.message||"Ongeldige HUMAN-resultaatvoorvertoning.",true);}
});
for(const [id,event] of [["preview-search","input"],["preview-different","change"]]){
 $(id).addEventListener(event,()=>{
  if(!active)return;
  const data=bridge.read();if(!data){invalidate();return;}
  try{render(evaluate(data));}catch(e){invalidate();setStatus(e.message,true);}
 });
}
window.LightUpCasebookOutputPreview=Object.freeze({invalidate,
 comparePublished:actual=>{
  if(!expectedSha){setStatus("PRIVATE .lupt aangeboden zonder eerdere optionele CSV-preview; geen hashvergelijking geclaimd.");return;}
  if(typeof actual!=="string"||!/^[a-f0-9]{64}$/.test(actual)||actual!==expectedSha){
   setStatus("HOLD: de actuele .lupt HUMAN CSV-hash is NIET identiek aan de voorgaande lokale preview; controleer de nieuwe overdracht opnieuw bij oorspronkelijke validator.",true);
   return;
  }
  setStatus("LOKALE BYTEGELIJKHEID: nieuwe versleutelde HUMAN-CSV-hash en eerder bekeken voorlopige CSV-hash zijn gelijk. Dit authenticeert geen oorspronkelijke bronproducent, toestemming of grant.");
 }
});
invalidate();
})();