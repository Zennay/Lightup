/* Independent private HUMAN review memo revision reader; never authorizes activity. */
(() => {
"use strict";
const $=id=>document.getElementById(id);
const library=window.LightUpCasebookReceiptLibrary;
const enc=new TextEncoder();
const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const deny=s=>{throw Error(s);};
let summary=null,busy=false;
const status=(s,error=false)=>{
 $("revision-status").textContent=(error?"HOLD: ":"")+s;
 $("revision-status").classList.toggle("error",error);
};
const make=(tag,text)=>{const n=document.createElement(tag);n.textContent=text;return n;};
function setBusy(v){
 busy=v;$("revision-compare").disabled=v;$("revision-export").disabled=v||!summary;
}
function admission(a,b){
 if(!a||!b)deny("Open eerst memo A en kies een tweede memo B.");
 if(!eq(a.sources,b.sources)||!eq(a.human,b.human))
  deny("Verschillende originele Casebook-bronnen of A/B HUMAN-input: geen historische conclusie.");
 if(a.cases.length!==b.cases.length)deny("Ongelijk aantal broncases; afgebroken vergelijking.");
 for(let i=0;i<a.cases.length;i++){
  const prev=a.cases[i],next=b.cases[i];
  if(!eq([prev.id,prev.source_action,prev.source_attention,prev.original_a,prev.original_b],
         [next.id,next.source_action,next.source_attention,next.original_a,next.original_b]))
   deny("Casebook-bron of oorspronkelijke HUMAN-ingang gewijzigd op bronrij "+(i+1)+".");
 }
}
function compare(a,b){
 admission(a,b);
 const changes=[],counts={cases:a.cases.length,changed_cases:0,
  changed_choice_fields:0,changed_human_notes:0,changed_human_reasons:0,
  unchanged_cases:0,source_bound:true,
  human_csv_bytes_differ:a.result.human_csv_sha256!==b.result.human_csv_sha256};
 for(let i=0;i<a.cases.length;i++){
  const x=a.cases[i],y=b.cases[i];
  const decisions=[0,1,2].filter(j=>x.decision[j]!==y.decision[j]);
  const noteChanged=x.note.note!==y.note.note;
  const reasonChanged=x.note.reason!==y.note.reason;
  const changed=decisions.length>0||noteChanged||reasonChanged;
  if(changed){
   counts.changed_cases++;
   counts.changed_choice_fields+=decisions.length;
   counts.changed_human_notes+=Number(noteChanged);
   counts.changed_human_reasons+=Number(reasonChanged);
   changes.push({id:x.id,decision_fields:decisions,
      before:x.decision,after:y.decision,
      previous_reason:x.note.reason,next_reason:y.note.reason,
      note_changed:noteChanged});
  }else counts.unchanged_cases++;
 }
 return {counts,changes};
}
function render(comparison,a,b){
 const box=$("revision-view");box.replaceChildren();
 box.append(make("h3","PRIVATE menselijk revisieverschil — uitsluitend zelfverklaarde bronbytes"));
 const c=comparison.counts;
 box.append(make("p",c.changed_cases+" dossiers gewijzigd · "+
 c.changed_choice_fields+" keuzes gewijzigd · "+c.changed_human_reasons+
 " redenwijzigingen · "+c.changed_human_notes+" notities gewijzigd (inhoud verborgen)."));
 box.append(make("p","Oorspronkelijke inputs identiek aan bronreferenties in beide versleutelde memo's. "+
 (c.human_csv_bytes_differ?"Uitvoer-HUMAN CSV bytes verschillen.":"Uitvoer-HUMAN CSV bytes zijn gelijk.")+
 " Geen datum-, volgorde-, toestemming- of producentauthenticatie."));
 box.append(make("p","Memo A ongetekende .lupt SHA-256: "+a.result.bundle_sha256+
 " · memo B ongetekende .lupt SHA-256: "+b.result.bundle_sha256));
 if(!comparison.changes.length){box.append(make("p","Geen verschillen in bewaarde HUMAN-beslissingen, reden of notitietekst."));return;}
 const table=make("table",""),head=make("tr","");
 ["PRIVATE broncase","HUMAN-keuzeverandering","HUMAN-redencategorie",
  "Privénotitie veranderd?"].forEach(s=>head.append(make("th",s)));
 const thead=make("thead","");thead.append(head);table.append(thead);
 const tbody=make("tbody","");
 const names=["fase","route","blokkade"];
 for(const row of comparison.changes){
  const tr=make("tr","");
  const d=row.decision_fields.length ? row.decision_fields.map(i=>
    names[i]+": "+row.before[i]+" → "+row.after[i]).join(" · "):"Geen HUMAN-keuzewijziging";
  const vals=[row.id,d,row.previous_reason+" → "+row.next_reason,
    row.note_changed?"JA (inhoud niet gekopieerd)":"NEE"];
  vals.forEach(v=>tr.append(make("td",v)));tbody.append(tr);
 }
 table.append(tbody);box.append(table);
}
$("revision-compare").addEventListener("click",async()=>{
 if(!crypto?.subtle||!window.isSecureContext){status("Veilige WebCrypto-context ontbreekt.",true);return;}
 if(busy)return;setBusy(true);
 try{
  if(!$("ack").checked)deny("Bevestig PRIVATE, niet-autoriserende bronreview.");
  const old=library.current();
  if(!old)deny("Open eerst memo A in het bovenstaande PRIVATE memo-leesdeel.");
  const candidate=await library.decodeMemo(
    $("revision-file").files[0],$("revision-password").value);
  const next=compare(old,candidate);
  render(next,old,candidate);
  summary=next.counts;
  status("Brongebonden HUMAN-memo-verschillen lokaal berekend; geen originele producer-/clientauthenticatie.");
 }catch(e){status(e instanceof Error?e.message:"Niet-compatibele memo's",true);}
 finally{$("revision-password").value="";$("revision-file").value="";setBusy(false);}
});
$("revision-export").addEventListener("click",()=>{
 try{
  if(!summary)deny("Vergelijk eerst twee volledig geaccepteerde PRIVATE memos.");
  if(!window.confirm("Exporteer slechts menselijke revisie-aantallen zonder Casebook IDs, bron-SHAs of notities? Kleine cohorten kunnen gevoelig blijven."))return;
  const body={schema:"lightup.casebook.human_review_revision_aggregate.v1",
    status:"REVIEW_ONLY",authority:"NONE",
    cases:summary.cases,changed_cases:summary.changed_cases,
    changed_choice_fields:summary.changed_choice_fields,
    changed_human_notes:summary.changed_human_notes,
    changed_human_reasons:summary.changed_human_reasons,
    unchanged_cases:summary.unchanged_cases,
    human_csv_bytes_differ:summary.human_csv_bytes_differ,
    source_authenticated:false,client_consent_verified:false,
    operator_consent_verified:false,authorization_granted:false,
    execution_allowed:false,release_approved:false};
  const url=URL.createObjectURL(new Blob([enc.encode(JSON.stringify(body)+"\n")],
    {type:"application/octet-stream"}));
  const a=document.createElement("a");a.href=url;
  a.download="lightup-HUMAN-revision-aggregate.json";
  document.body.append(a);a.click();a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),2000);
  status("Bronvrije HUMAN-revisietelling lokaal aangeboden; geen bron of toestemming geverifieerd.");
 }catch(e){status(e instanceof Error?e.message:"Revisietelling geweigerd.",true);}
});
window.LightUpCasebookRevisionLibrary=Object.freeze({compare});
window.LightUpCasebookRevisionClear=()=>{
 summary=null;$("revision-view").replaceChildren();
 $("revision-export").disabled=true;
 status("PRIVATE revisievergelijking gewist.");
};
})();