/* LightUp PRIVATE source-declared Casebook operator portfolio; browser-only, no grant. */
(() => {
"use strict";
const $=id=>document.getElementById(id),bridge=window.LightUpBulkBridge,
 enc=new TextEncoder();
const buckets=[
 ["source-hold","Bronlabel HOLD (niet geverifieerd)"],
 ["risk-pending","Risicobesluit wacht volgens bron"],
 ["window-review","Verlopen/toekomstig grantvenster volgens bron"],
 ["other","Overige oorspronkelijke bronlabels"]
];
const stages=[
 ["unresolved","Onbeslist"],["partial","Gedeeltelijk besloten"],
 ["resolved","Alle HUMAN-verschillen besloten"],["identical","Geen HUMAN-verschil"]
];
const six={
 source_authenticated:false,client_consent_verified:false,
 operator_consent_verified:false,authorization_granted:false,
 execution_allowed:false,release_approved:false
};
let frozen=false;
const element=(tag,body)=>{const e=document.createElement(tag);e.textContent=body;return e;};
const deny=msg=>{throw Error(msg);};
function attentionClass(s){
 return s.startsWith("HOLD_")?"source-hold":
  s==="RISK_DECISION_PENDING_SOURCE_REVIEW"?"risk-pending":
  ["EXPIRED_GRANT_SOURCE_REVIEW","FUTURE_GRANT_SOURCE_REVIEW"].includes(s)?"window-review":"other";
}
function stage(c){
 let diff=0,done=0;
 for(let j=0;j<3;j++){
  if(c.a[j]===c.b[j])continue;
  diff++;
  const x=c.choices[j];
  if(["A","B","reset"].includes(x)||
    typeof x==="string"&&x.startsWith("custom:")&&x.length>7)done++;
 }
 return {diff,done,status:diff===0?"identical":
  done===0?"unresolved":done===diff?"resolved":"partial"};
}
function stats(data){
 const groups=Object.fromEntries(buckets.map(([id])=>[id,{
  cases:0,differences:0,pending:0,decided:0,complete:0
 }]));
 const cases=data.cases.map((c,i)=>{
  const s=stage(c),bucket=attentionClass(c.attention);
  const g=groups[bucket];g.cases++;g.differences+=s.diff;
  g.decided+=s.done;g.pending+=s.diff-s.done;
  g.complete+=Number(s.status==="resolved"||s.status==="identical");
  return {i,...c,...s,bucket};
 });
 const total={cases:cases.length,differences:0,pending:0,decided:0,
  complete:0,source_hold:0};
 for(const g of Object.values(groups)){
  total.differences+=g.differences;total.pending+=g.pending;
  total.decided+=g.decided;total.complete+=g.complete;
 }
 total.source_hold=groups["source-hold"].cases;
 return {cases,groups,total};
}
function showMessage(s,error=false){
 $("portfolio-status").textContent=(error?"HOLD: ":"")+s;
 $("portfolio-status").classList.toggle("error",error);
}
function addCell(row,text){
 const td=element("td",text);row.append(td);
}
function render(){
 const pane=$("portfolio-table"),root=$("portfolio-groups");
 const current=bridge.read();
 if(!current){
  if(frozen)return;
  pane.replaceChildren();root.replaceChildren();
  $("portfolio-progress").value=0;$("portfolio-progress").max=1;
  $("portfolio-numbers").textContent="Geen oorspronkelijke PRIVATE bron geopend.";
  $("portfolio-export").disabled=true;
  $("portfolio-jump").disabled=true;
  return;
 }
 const derived=stats(current);
 const t=derived.total;
 $("portfolio-numbers").textContent=t.cases+" PRIVATE cases · "+
  t.differences+" oorspronkelijke HUMAN-conflictvelden · "+
  t.decided+" menselijk beslist · "+t.pending+" onbeslist · "+
  t.source_hold+" volgens ongeverifieerde HOLD-bronlabels.";
 $("portfolio-progress").max=Math.max(1,t.differences);
 $("portfolio-progress").value=t.decided;
 root.replaceChildren();
 const gtable=element("table",""),head=element("tr","");
 ["Originele broncategorie","Privé-dossiers","Onbeslist","Menselijk besloten"].forEach(x=>head.append(element("th",x)));
 const thead=element("thead","");thead.append(head);gtable.append(thead);
 const tbody=element("tbody","");
 for(const [id,label] of buckets){
  const g=derived.groups[id],row=element("tr","");
  [label,String(g.cases),String(g.pending),String(g.decided)].forEach(v=>addCell(row,v));
  tbody.append(row);
 }
 gtable.append(tbody);root.append(gtable);
 const q=$("portfolio-search").value.trim().toLocaleLowerCase("nl-NL");
 const category=$("portfolio-group").value,review=$("portfolio-stage").value;
 let rows=derived.cases.filter(c=>
  (category==="all"||c.bucket===category)&&
  (review==="all"||c.status===review)&&
  (!q||[c.id,c.action,c.attention].some(x=>x.toLocaleLowerCase("nl-NL").includes(q))));
 rows=rows.sort((a,b)=>{
  const pa=buckets.findIndex(x=>x[0]===a.bucket),pb=buckets.findIndex(x=>x[0]===b.bucket);
  return pa-pb||(b.diff-b.done)-(a.diff-a.done)||(a.id<b.id?-1:1);
 });
 pane.replaceChildren();
 $("portfolio-visible").textContent=rows.length+" van "+derived.cases.length+" PRIVATE dossiers zichtbaar.";
 if(!rows.length){
  pane.append(element("p","Geen PRIVATE dossiers voldoen aan deze lokale bron- en HUMAN-filters."));
  $("portfolio-jump").disabled=true;
 }else{
  const table=element("table",""),header=element("tr","");
  ["Origineel dossier","Bronlabel","HUMAN-velden","Status","Open dossier"].forEach(x=>header.append(element("th",x)));
  const h=element("thead","");h.append(header);table.append(h);
  const body=element("tbody","");
  for(const c of rows){
   const tr=element("tr","");
   [c.id,c.attention,c.done+"/"+c.diff,c.status].forEach(v=>addCell(tr,v));
   const cell=element("td","");
   const button=element("button","Open in HUMAN-workruimte");
   button.type="button";button.className="secondary";
   button.disabled=frozen;button.addEventListener("click",()=>bridge.focus(c.i));
   cell.append(button);tr.append(cell);body.append(tr);
  }
  table.append(body);pane.append(table);
  $("portfolio-jump").disabled=frozen;
 }
 $("portfolio-export").disabled=frozen;
}
function setBusy(state){
 frozen=state;
 $("portfolio-jump").disabled=state;
 $("portfolio-export").disabled=state;
 for(const b of $("portfolio-table").querySelectorAll("button"))b.disabled=state;
 if(!state)render();
}
$("portfolio-jump").addEventListener("click",()=>{
 try{
  const data=bridge.read();if(!data)deny("Geen actuele originele PRIVATE Cases.");
  const s=stats(data);
  const group=$("portfolio-group").value,status=$("portfolio-stage").value;
  const q=$("portfolio-search").value.trim().toLocaleLowerCase("nl-NL");
  const list=s.cases.filter(c=>
   (group==="all"||c.bucket===group)&&
   (status==="all"||c.status===status)&&
   (!q||[c.id,c.action,c.attention].some(v=>v.toLocaleLowerCase("nl-NL").includes(q))));
  if(!list.length)deny("Geen lokaal zichtbaar dossier in deze categorie.");
  list.sort((a,b)=>(b.diff-b.done)-(a.diff-a.done));
  bridge.focus(list[0].i);
  showMessage("Naar gekozen PRIVATE HUMAN-broncase genavigeerd; geen bevoegdheid toegekend.");
 }catch(e){showMessage(e.message,true);}
});
$("portfolio-export").addEventListener("click",()=>{
 try{
  const data=bridge.read();if(!data)deny("Originele PRIVATE bron niet geopend.");
  if(!window.confirm("Exporteer uitsluitend HUMAN-voortgangsaantallen per zelfverklaarde brongroep (geen dossier-ID/bronhash/actietekst)? Kleine cohorten kunnen alsnog gevoelig zijn."))return;
  const {groups,total}=stats(data);
  const out={schema:"lightup.casebook.private_human_portfolio_aggregate.v1",
   status:"REVIEW_ONLY",authority:"NONE",source_labels_unverified:true,
   ...total,groups:Object.entries(groups).map(([category,n])=>({category,...n})),...six};
  const encoded=enc.encode(JSON.stringify(out)+"\n");
  const url=URL.createObjectURL(new Blob([encoded],{type:"application/octet-stream"}));
  const a=document.createElement("a");a.href=url;
  a.download="lightup-PRIVATE-human-portfolio-aggregate.json";
  document.body.append(a);a.click();a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),2500);
  showMessage("Bronvrij HUMAN-triageportfolio lokaal aangeboden; geen bronvalidatie of toestemming.");
 }catch(e){showMessage(e.message,true);}
});
for(const id of ["portfolio-search","portfolio-group","portfolio-stage"]){
 $(id).addEventListener(id==="portfolio-search"?"input":"change",render);
}
window.LightUpCasebookPortfolio=Object.freeze({render,setBusy});
render();
})();