/* Offline private HUMAN reconciliation reasons; no grant, client authorization or source mutation. */
(() => {
"use strict";
const REASONS=Object.freeze([
 "not-recorded","source-clarification","client-question","independent-review",
 "consent-to-verify","revocation-followup","conflicting-human-interpretation",
 "manual-followup"
]);
const LABELS=Object.freeze({
 "not-recorded":"Geen reden ingevuld",
 "source-clarification":"Oorspronkelijke bron moet worden verduidelijkt",
 "client-question":"Vraag aan oorspronkelijke cliënt",
 "independent-review":"Onafhankelijke menselijke review nodig",
 "consent-to-verify":"Actuele toestemming moet onafhankelijk worden nagegaan",
 "revocation-followup":"Oorspronkelijke intrekking vereist menselijke opvolging",
 "conflicting-human-interpretation":"Twee verschillende HUMAN-interpretaties",
 "manual-followup":"Overig HUMAN-vervolg"
});
const MAX_BYTES=1200,MAX_ENTRIES=200;
const enc=new TextEncoder();
let notes=[];
const deny=x=>{throw Error(x);};
function canonical(entry){
 if(!entry||typeof entry!=="object"||Array.isArray(entry)||
  JSON.stringify(Object.keys(entry))!==JSON.stringify(["reason","note"]))
  deny("HOLD: PRIVATE HUMAN-aantekening heeft onbekende velden.");
 const {reason,note}=entry;
 if(!REASONS.includes(reason)||typeof note!=="string"||
   note.length>800||enc.encode(note).length>MAX_BYTES||
   /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(note))
  deny("HOLD: HUMAN-aantekening is te groot of onveilig.");
 return {reason,note};
}
function reset(length){
 if(!Number.isInteger(length)||length<0||length>MAX_ENTRIES)deny("Teveel HUMAN-aantekeningen.");
 notes=Array.from({length},()=>({reason:"not-recorded",note:""}));
 window.LightUpCasebookNoteBulk?.reset();
}
function read(){
 return notes.map(x=>({...x}));
}
function restore(rows){
 if(!Array.isArray(rows)||rows.length!==notes.length||rows.length>MAX_ENTRIES)
  deny("HOLD: HUMAN-notities komen niet overeen met de huidige oorspronkelijke dossiers.");
 const candidate=rows.map(canonical);
 notes=candidate;
 window.LightUpCasebookNoteBulk?.reset();
}
function render(parent,index,caseInfo){
 const entry=notes[index];
 if(!entry||!caseInfo)deny("HOLD: brongebonden notitie ontbreekt.");
 const section=document.createElement("section");
 section.className="human-notes";
 const title=document.createElement("h4");
 title.textContent="Optionele PRIVATE HUMAN-motivering — geen bronbewijs of toestemming";
 section.append(title);
 const label=document.createElement("label");
 label.textContent="Menselijke reden voor opvolging";
 const select=document.createElement("select");
 select.setAttribute("aria-label","PRIVATE reden voor "+caseInfo.id);
 for(const value of REASONS){
  const option=document.createElement("option");
  option.value=value;option.textContent=LABELS[value];
  select.append(option);
 }
 select.value=entry.reason;
 select.addEventListener("change",()=>{
  notes[index]=canonical({reason:select.value,note:notes[index].note});
  window.LightUpCasebookNoteBulk?.invalidateHistory();
 });
 label.append(select);section.append(label);
 const noteLabel=document.createElement("label");
 noteLabel.textContent="Privécontext (maximaal 800 tekens en 1.200 UTF-8 bytes; niet in Casebook CSV)";
 const textarea=document.createElement("textarea");
 textarea.rows=3;textarea.maxLength=800;textarea.value=entry.note;
 textarea.setAttribute("aria-label","PRIVATE motivering voor "+caseInfo.id);
 const feedback=document.createElement("small");
 feedback.className="muted";feedback.textContent="Uitsluitend privé, niet in oorspronkelijke bron of telling.";
 textarea.addEventListener("input",()=>{
  const next={reason:notes[index].reason,note:textarea.value};
  try {
   notes[index]=canonical(next);
   feedback.textContent=enc.encode(next.note).length+" van 1.200 privé UTF-8 bytes";
   feedback.classList.remove("error");
  }catch{
   textarea.value=notes[index].note;
   feedback.textContent="HOLD: motivering overschrijdt privélengte of bevat controlecodes.";
   feedback.classList.add("error");
  }
 });
 noteLabel.append(textarea,feedback);section.append(noteLabel);
 parent.append(section);
}
function applyReasons(changes){
 if(!Array.isArray(changes)||changes.length<1||changes.length>MAX_ENTRIES)
  deny("HOLD: te groot of ontbrekend PRIVATE HUMAN-redenenpakket.");
 const seen=new Set();
 for(const change of changes){
  if(!change||typeof change!=="object"||
    JSON.stringify(Object.keys(change))!==JSON.stringify(["i","from","to"])||
    !Number.isInteger(change.i)||change.i<0||change.i>=notes.length||
    seen.has(change.i)||!REASONS.includes(change.from)||
    !REASONS.includes(change.to)||change.from===change.to||
    notes[change.i].reason!==change.from)
   deny("HOLD: ongeldige of intussen gewijzigde PRIVATE HUMAN-opvolgreden.");
  seen.add(change.i);
 }
 for(const change of changes)notes[change.i]={
  reason:change.to,note:notes[change.i].note};
 return changes.length;
}
window.LightUpCasebookNotes=Object.freeze({reset,read,restore,render,canonical,applyReasons,
 reasons:REASONS,labels:LABELS});
})();
