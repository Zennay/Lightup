/* Offline scope Casebook HUMAN two-recipient field reconciliation. Never authorizes a scan. */
(() => {
"use strict";
const $=id=>document.getElementById(id), enc=new TextEncoder(),
  dec=new TextDecoder("utf-8",{fatal:true}), h=window.LightUpCasebookHandoff;
const SCHEMA="lightup-private-casebook-transfer",ITER=310000,
  MAX_VAULT=26*1024*1024,MAX_SOURCE=4*1024*1024,MAX_SUM=12*1024*1024;
let work=null,busy=false;
const deny=message=>{throw Error(message);};
const keys=(obj,names)=>obj&&typeof obj==="object"&&!Array.isArray(obj)&&
  JSON.stringify(Object.keys(obj))===JSON.stringify(names);
const sha=async bytes=>Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",bytes)),
  n=>n.toString(16).padStart(2,"0")).join("");
const originalNames=name=>/^casebook-(?:0[1-9]|1[0-2])\.json$/.test(name);
const defaultHuman=["unreviewed","unassigned","none"];
const humanOptions=[
 ["unreviewed","investigating","awaiting-owner","documented"],
 ["unassigned","original-scope-owner","client-clarification", "independent-security-review","operator-followup"],
 ["none","missing-source","missing-owner","needs-independent-consent", "requires-revocation-review","unresolved-tenant-lineage"]
];
const customChoice=(v,j)=>typeof v==="string"&&v.startsWith("custom:")&&
 humanOptions[j].includes(v.slice(7));
const resolved=(v,j)=>["A","B","reset"].includes(v)||customChoice(v,j);

const flags=["source_authenticated","client_consent_verified","operator_consent_verified",
 "authorization_granted","execution_allowed","release_approved"];
function b64(bytes) {
 let s="";for(let i=0;i<bytes.length;i+=8192)s+=String.fromCharCode(...bytes.subarray(i,i+8192));
 return btoa(s);
}
function from64(text,max) {
 if(typeof text!=="string"||text.length>Math.ceil(max/3)*4+8||
   !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text))
   deny("Ongeldige of te grote base64-data.");
 let raw;try{raw=atob(text);}catch{deny("Ongeldige base64-data.");}
 if(raw.length>max)deny("Brondata overschrijdt vaste limiet.");
 const bytes=Uint8Array.from(raw,c=>c.charCodeAt(0));
 if(b64(bytes)!==text)deny("Niet-canonieke base64-data.");
 return bytes;
}
function canonical(text,label) {
 let o;try{o=JSON.parse(text);}catch{deny("Ongeldige "+label+"-JSON.");}
 if(JSON.stringify(o)!==text)deny("Niet-canonieke "+label+"-JSON.");
 return o;
}
function rejectDuplicateKeys(text) {
 let p=0;const skip=()=>{while(p<text.length&&/[ \t\r\n]/.test(text[p]))p++;};
 const str=()=>{
  if(text[p]!=='"')deny("Ongeldige JSON sleutel/tekst.");
  const start=p++;
  while(p<text.length){const c=text[p++];if(c==="\\"){p++;continue;}
    if(c==='"')return JSON.parse(text.slice(start,p));}
  deny("Afgebroken JSON-tekst.");
 };
 const val=depth=>{
  if(depth>40)deny("JSON bron te diep.");skip();
  if(text[p]==="{"){
   p++;const found=new Set();skip();if(text[p]==="}"){p++;return;}
   for(;;){skip();const k=str();if(found.has(k))deny("Dubbele JSON bron-sleutel.");
    found.add(k);skip();if(text[p++]!==":")deny("Onjuiste JSON bron.");
    val(depth+1);skip();if(text[p]==="}"){p++;return;}
    if(text[p++]!==",")deny("Onjuiste JSON bron.");}
  }
  if(text[p]==="["){
   p++;skip();if(text[p]==="]"){p++;return;}
   for(;;){val(depth+1);skip();if(text[p]==="]"){p++;return;}
    if(text[p++]!==",")deny("Onjuiste JSON bronlijst.");}
  }
  if(text[p]==='"'){str();return;}
  const m=/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(p));
  if(!m)deny("Onjuiste JSON bronwaarde.");p+=m[0].length;
 };
 val(0);skip();if(p!==text.length)deny("Overtollige JSON broninhoud.");
}
function sourceClient(bytes) {
 const text=dec.decode(bytes);rejectDuplicateKeys(text);
 let o;try{o=JSON.parse(text);}catch{deny("Ongeldige Casebook JSON.");}
 const fields=["schema","status","source","as_of","client_id",
  "requests","engagements","grants","risk_approvals","case_overview","declared_counts",...flags];
 if(!o||typeof o!=="object"||Array.isArray(o)||
  Object.keys(o).length!==fields.length||fields.some(k=>!Object.hasOwn(o,k))||
  o.schema!=="lightup.auth_casebook.v1"||o.status!=="REVIEW_ONLY"||
  o.source!=="original_persisted_domain_unverified"||
  typeof o.client_id!=="string"||!/^[\x21-\x7e]{1,180}$/.test(o.client_id)||
  ["requests","engagements","grants","risk_approvals","case_overview"].some(k=>!Array.isArray(o[k]))||
  !o.declared_counts||typeof o.declared_counts!=="object"||Array.isArray(o.declared_counts)||
  flags.some(k=>o[k]!==false))deny("Bronvorm of NON-AUTHORITY-vlaggen ongeldig.");
 return o.client_id;
}
function checkNames(files) {
 if(!Array.isArray(files)||files.length<2||files.length>13)
  deny("Vereist 1–12 originele Casebooks met opgeslagen HUMAN CSV.");
 const names=files.map(f=>f.name);
 if(names.at(-1)!=="workroom-current-template.csv"||
  JSON.stringify(names)!==JSON.stringify([...names].sort()))
  deny("Oorspronkelijke bestandslijst niet compleet/canoniek.");
 names.slice(0,-1).forEach((n,i)=>{
  if(n!=="casebook-"+String(i+1).padStart(2,"0")+".json")
   deny("Ontbrekende, dubbele of niet-opeenvolgende bronmomenten.");
 });
}
async function keyFor(password,salt,usage){
 const material=await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveKey"]);
 return crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:ITER,hash:"SHA-256"},
   material,{name:"AES-GCM",length:256},false,[usage]);
}
async function admit(file,password){
 if(!file||typeof file.name!=="string"||!/\.lupt$/i.test(file.name)||
  file.name.length>160||file.size<100||file.size>MAX_VAULT)
  deny("Kies een begrensde oorspronkelijke .lupt overdracht.");
 const envelope=canonical(await file.text(),"originele envelope");
 if(!keys(envelope,["schema","version","kdf","iterations","cipher","salt_b64",
  "iv_b64","ciphertext_b64"])||
  envelope.schema!==SCHEMA||envelope.version!==1||envelope.kdf!=="PBKDF2-SHA256"||
  envelope.iterations!==ITER||envelope.cipher!=="AES-256-GCM")
  deny("Geen oorspronkelijke canonieke PRIVATE Casebook v1 envelope.");
 const salt=from64(envelope.salt_b64,16),iv=from64(envelope.iv_b64,12),
  cipher=from64(envelope.ciphertext_b64,MAX_VAULT);
 if(salt.length!==16||iv.length!==12||cipher.length<16)deny("Ongeldige cryptografische envelope.");
 let plaintext;
 try {plaintext=new Uint8Array(await crypto.subtle.decrypt(
  {name:"AES-GCM",iv},await keyFor(password,salt,"decrypt"),cipher));}
 catch{deny("Ontsleutelen geweigerd; wachtwoord of bytes gewijzigd.");}
 let body;
 try{
  if(plaintext.length>20*1024*1024)deny("Ontsleutelde inhoud te groot.");
  body=canonical(dec.decode(plaintext),"PRIVATE inhoud");
 }finally{plaintext.fill(0);}
 if(!keys(body,["schema","version","files"])||body.schema!==SCHEMA||
  body.version!==1)deny("PRIVATE body heeft onbekend formaat.");
 checkNames(body.files);
 const records=[];let total=0,client=null;
 for(const item of body.files) {
  if(!keys(item,["name","size","sha256","content_b64"])||
    !Number.isSafeInteger(item.size)||item.size<1||item.size>MAX_SOURCE||
    typeof item.sha256!=="string"||!/^[a-f0-9]{64}$/.test(item.sha256))
   deny("Onjuiste PRIVATE bestandsmanifest.");
  const bytes=from64(item.content_b64,MAX_SOURCE);
  if(bytes.length!==item.size||await sha(bytes)!==item.sha256)
   deny("Bronbyte-lengte of SHA-256 niet gelijk.");
  total+=bytes.length;if(total>MAX_SUM)deny("Bronbundel te groot.");
  if(originalNames(item.name)){
   const c=sourceClient(bytes);
   if(client!==null&&client!==c)deny("Verschillende zelfverklaarde client-ID in bronset.");
   client=c;
  }
  records.push({name:item.name,size:item.size,sha256:item.sha256,bytes});
 }
 const admitted=h.admit(records);
 if(!admitted.hasCSV)deny("Beide pakketten moeten opgeslagen brongebonden HUMAN-keuzes bevatten.");
 return {records,client,cases:admitted.cases,rows:admitted.rows};
}
function zero(bundle){if(bundle)for(const r of bundle.records)r.bytes.fill(0);}
function sameSource(a,b){
 if(a.client!==b.client||a.records.length!==b.records.length||
   JSON.stringify(a.cases)!==JSON.stringify(b.cases))
  deny("HOLD: niet dezelfde originele historische Casebook-bronset.");
 for(let i=0;i<a.records.length-1;i++)if(
   a.records[i].name!==b.records[i].name||
   a.records[i].size!==b.records[i].size||
   a.records[i].sha256!==b.records[i].sha256)
  deny("HOLD: andere originele Casebook-bronbytes (geen automatische samenvoeging).");
}
function status(message,error=false) {
 $("status").textContent=message;$("status").classList.toggle("error",error);
}
function node(tag,text){const n=document.createElement(tag);n.textContent=text;return n;}
function tally(){
 if(!work)return;
 let unresolved=0,changed=0;
 work.a.rows.forEach((r,i)=>{
  if(r.slice(3).some((v,j)=>v!==work.b.rows[i][j+3]))changed++;
  r.slice(3).forEach((v,j)=>{if(v!==work.b.rows[i][j+3]&&!resolved(work.choices[i][j],j))unresolved++;});
 });
 $("summary").textContent=work.cases.length+" brondossiers · "+changed+
  " met HUMAN-verschil · "+unresolved+" onbesliste velden. De bron blijft ongeverifieerd.";
 $("publish").disabled=busy||unresolved!==0;
 $("aggregate").disabled=busy||unresolved!==0;
 window.LightUpCasebookPortfolio?.render();
}
function show(){
 $("cases").replaceChildren();
 if(!work)return;
 const search=$("search").value.trim().toLowerCase(),only=$("conflicts").checked,
  unresolvedOnly=$("unresolved-only").checked;
 let shown=0;
 work.cases.forEach((c,i)=>{
  const ra=work.a.rows[i],rb=work.b.rows[i];
  const diff=ra.slice(3).some((v,j)=>v!==rb[j+3]);
  const pending=ra.slice(3).some((v,j)=>v!==rb[j+3]&&!resolved(work.choices[i][j],j));
  if(only&&!diff||unresolvedOnly&&!pending)return;
  if(search&&![c.id,c.action,c.attention].some(s=>s.toLowerCase().includes(search)))return;
  shown++;
  const card=node("article","");card.className="case"+(diff?" differing":"");
  card.dataset.caseIndex=String(i);
  card.tabIndex=-1;
  card.append(node("h3",c.id),
   node("p","Originele bronactie: "+c.action+" · aandacht: "+c.attention+" (niet actueel geverifieerd)"));
  const table=node("table",""),header=node("tr","");
  ["HUMAN-veld","Ontvanger A","Ontvanger B","Expliciete keuze"].forEach(s=>header.append(node("th",s)));
  const head=node("thead","");head.append(header);table.append(head);
  const body=node("tbody","");
  ["Fase","Route","Blokkade"].forEach((label,j)=>{
   const row=node("tr","");row.append(node("th",label),
    node("td",ra[j+3]),node("td",rb[j+3]));
   const td=node("td","");
   if(ra[j+3]===rb[j+3])td.append(node("strong","Identiek — behouden"));
   else{
    const select=document.createElement("select");select.setAttribute("aria-label",label+" voor "+c.id);
    [["","HOLD — beslis"],["A","Kies A: "+ra[j+3]],["B","Kies B: "+rb[j+3]],
     ["reset","Heropen HUMAN: "+defaultHuman[j]],
     ["custom","Andere toegestane HUMAN-waarde…"]].forEach(([v,s])=>{
      const option=node("option",s);option.value=v;select.append(option);
     });
    const saved=work.choices[i][j];
    select.value=saved.startsWith("custom:")?"custom":saved;
    const extra=document.createElement("select");
    extra.setAttribute("aria-label","Nieuwe canonieke HUMAN-waarde "+label+" voor "+c.id);
    const prompt=node("option","Kies nieuwe HUMAN-waarde");prompt.value="";extra.append(prompt);
    humanOptions[j].forEach(v=>{const o=node("option",v);o.value=v;extra.append(o);});
    extra.value=customChoice(saved,j)?saved.slice(7):"";
    extra.hidden=select.value!=="custom";
    extra.addEventListener("change",()=>{
      const before=work.choices[i][j];
      window.LightUpCasebookOutputPreview?.invalidate();
      work.finalReceipt=null;
      work.choices[i][j]="custom:"+extra.value;
      window.LightUpCasebookBulk?.recordManual(i,j,before,work.choices[i][j]);
      tally();
      if(unresolvedOnly&&resolved(work.choices[i][j],j))show();
    });
    select.addEventListener("change",()=>{
      extra.hidden=select.value!=="custom";
      extra.value="";
      const before=work.choices[i][j];
      window.LightUpCasebookOutputPreview?.invalidate();
      work.finalReceipt=null;
      work.choices[i][j]=select.value==="custom"?"custom:":select.value;
      window.LightUpCasebookBulk?.recordManual(i,j,before,work.choices[i][j]);
      tally();if(unresolvedOnly&&resolved(work.choices[i][j],j))show();
    });
    td.append(select,extra);
   }
   row.append(td);body.append(row);
  });
  table.append(body);card.append(table);
  if(diff)window.LightUpCasebookNotes?.render(card,i,c);
  $("cases").append(card);
 });
 $("shown").textContent="Zichtbaar: "+shown+" van "+work.cases.length;
 for(const element of $("cases").querySelectorAll("select,textarea"))element.disabled=busy;
 tally();
}
async function publish(){
 if(!work)deny("Geen huidige PRIVATE werkruimte.");
 const combined=work.a.rows.map((ra,i)=>{
  const rb=work.b.rows[i];const row=ra.slice(0,3);
  for(let j=0;j<3;j++){
   const choice=work.choices[i][j];
   if(ra[j+3]===rb[j+3])row.push(ra[j+3]);
   else if(choice==="A")row.push(ra[j+3]);
   else if(choice==="B")row.push(rb[j+3]);
   else if(choice==="reset")row.push(defaultHuman[j]);
   else if(customChoice(choice,j))row.push(choice.slice(7));
   else deny("HOLD: nog onbesliste HUMAN-keuzes.");
  }
  return row;
 });
 const password=$("new-password").value;
 if([...password].length<12||enc.encode(password).length>1024)
  deny("Nieuw wachtwoord moet 12–1024 UTF-8-tekens/bytes bevatten.");
 if(!$("ack").checked)deny("PRIVATE HUMAN-only bevestiging ontbreekt.");
 if(!window.confirm("Maak uitsluitend NIEUW lokaal AES-256-GCM bron+HUMAN pakket? Niets autoriseert een scan."))
  return;
 const csv=enc.encode(h.serialize(combined));
 try{
  if(csv.length>131072)deny("Nieuwe HUMAN-CSV te groot.");
  const orig=work.a.records.slice(0,-1);
  const newHuman={name:"workroom-current-template.csv",size:csv.length,
   sha256:await sha(csv),bytes:csv};
  // Read the exact outgoing current HUMAN CSV with the original source-owner
  // admission code before producing a protected transfer. This is the existing
  // source contract, not a new authorization or release gate.
  const native=h.admit([...orig,newHuman]);
  if(!native.hasCSV||JSON.stringify(native.rows)!==JSON.stringify(combined))
   deny("HOLD: oorspronkelijke brongebonden HUMAN-validator weigert de beoogde uitgang.");
  const items=[...orig,newHuman].map(x=>({
   name:x.name,size:x.size,sha256:x.sha256,content_b64:b64(x.bytes)}));
  const plaintext=enc.encode(JSON.stringify({schema:SCHEMA,version:1,files:items}));
  let ciphertext,salt,iv;
  try{
   if(plaintext.length>20*1024*1024)deny("Nieuwe PRIVATE bundel te groot.");
   salt=crypto.getRandomValues(new Uint8Array(16));
   iv=crypto.getRandomValues(new Uint8Array(12));
   ciphertext=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv},
    await keyFor(password,salt,"encrypt"),plaintext));
  }finally{plaintext.fill(0);}
  const envelope={schema:SCHEMA,version:1,kdf:"PBKDF2-SHA256",iterations:ITER,
   cipher:"AES-256-GCM",salt_b64:b64(salt),iv_b64:b64(iv),ciphertext_b64:b64(ciphertext)};
  const bytes=enc.encode(JSON.stringify(envelope));
  if(bytes.length>MAX_VAULT)deny("Nieuwe versleutelde bundel te groot.");
  const offeredSha256=await sha(bytes);
  const url=URL.createObjectURL(new Blob([bytes],{type:"application/octet-stream"}));
  const link=document.createElement("a");link.href=url;
  link.download="lightup-casebook-private-reconciled.lupt";
  document.body.append(link);link.click();link.remove();
  work.finalReceipt={bundle_sha256:offeredSha256,human_csv_sha256:newHuman.sha256};
  window.LightUpCasebookOutputPreview?.comparePublished(newHuman.sha256);
  setTimeout(()=>URL.revokeObjectURL(url),2000);
  status("Nieuwe AES-256-GCM PRIVATE brongebonden overdracht aangeboden. Oorspronkelijke HUMAN-validator accepteert exacte uitvoerbytes; dit verleent geen consent, grant of bronproducent-authenticatie.");
 }finally{csv.fill(0);}
}
function setBusy(v){
 busy=v;$("open").disabled=v;$("publish").disabled=v||!work;
 $("aggregate").disabled=v||!work;
 $("clear-session").disabled=v;
 for(const element of $("cases").querySelectorAll("select,textarea"))element.disabled=v;
 window.LightUpCasebookBulk?.setBusy(v);
 window.LightUpCasebookPortfolio?.setBusy(v);
 window.LightUpCasebookNoteBulk?.setBusy(v);
}
$("open").addEventListener("click",async()=>{
 if(!window.crypto?.subtle||!window.isSecureContext){status("HOLD: WebCrypto secure context vereist.",true);return;}
 setBusy(true);let a=null,b=null;
 try{
  if(!$("ack").checked)deny("Bevestig PRIVATE HUMAN-only reikwijdte.");
  if(!$("file-a").files[0]||!$("file-b").files[0])deny("Twee originele .lupt-pakketten vereist.");
  a=await admit($("file-a").files[0],$("password-a").value);
  b=await admit($("file-b").files[0],$("password-b").value);
  sameSource(a,b);
  if(work&&!window.confirm("Vorige lokale nog niet-gepubliceerde HUMAN-beslissingen vervangen?"))
   deny("Bestaande werkruimte behouden.");
  const old=work;
  window.LightUpCasebookOutputPreview?.invalidate();
  work={a,b,cases:a.cases,choices:a.rows.map((r,i)=>[0,1,2].map(j=>
   r[j+3]===b.rows[i][j+3]?"same":"")),finalReceipt:null};
  a=null;b=null;
  window.LightUpCasebookNotes?.reset(work.cases.length);
  window.LightUpCasebookBulk?.reset();
  zero(old?.a);zero(old?.b);
  show();status("Beide exacte originele bronsets en opgeslagen HUMAN-keuzes lokaal geaccepteerd. Verschillen vereisen expliciete menselijke beslissingen.");
 }catch(e){status("HOLD: "+(e instanceof Error?e.message:"Ongeldige overdracht"),true);}
 finally{zero(a);zero(b);
  $("password-a").value="";$("password-b").value="";
  $("file-a").value="";$("file-b").value="";
  setBusy(false);tally();}
});
$("publish").addEventListener("click",async()=>{
 setBusy(true);
 try{await publish();}catch(e){status("HOLD: "+(e instanceof Error?e.message:"Overdracht geweigerd"),true);}
 finally{$("new-password").value="";setBusy(false);tally();}
});
$("search").addEventListener("input",show);
$("conflicts").addEventListener("change",show);
$("unresolved-only").addEventListener("change",show);
$("next-unresolved").addEventListener("click",()=>{
 if(!work)return;
 const pending=[];
 work.a.rows.forEach((r,i)=>{
  if(r.slice(3).some((v,j)=>v!==work.b.rows[i][j+3]&&!resolved(work.choices[i][j],j)))
   pending.push(i);
 });
 if(!pending.length){status("Alle HUMAN-conflicten zijn expliciet beslist.");return;}
 $("search").value="";$("unresolved-only").checked=true;
 $("conflicts").checked=false;
 const visible=Array.from($("cases").querySelectorAll("[data-case-index]"))
  .map(n=>Number(n.dataset.caseIndex));
 const selected=visible.filter(i=>pending.includes(i));
 const target=selected.length ? selected[0] : pending[0];
 show();
 const node=$("cases").querySelector('[data-case-index="'+target+'"]');
 node?.scrollIntoView({behavior:"smooth",block:"start"});
 node?.focus({preventScroll:true});
});
function anonymousReport(){
 if(!work||$("publish").disabled)deny("HOLD: los eerst alle HUMAN-verschillen op.");
 const c={cases:work.cases.length,conflicting_cases:0,changed_fields:0,
   selected_a:0,selected_b:0,reopened:0,custom_human:0,identical:0};
 work.a.rows.forEach((row,i)=>{
  let different=false;
  for(let j=0;j<3;j++){
   if(row[j+3]===work.b.rows[i][j+3]){c.identical++;continue;}
   different=true;c.changed_fields++;
   const selected=work.choices[i][j];
   if(selected==="A")c.selected_a++;
   else if(selected==="B")c.selected_b++;
   else if(selected==="reset")c.reopened++;
   else if(customChoice(selected,j))c.custom_human++;
   else deny("HOLD: onbesliste HUMAN-keuze in rapport.");
  }
  if(different)c.conflicting_cases++;
 });
 if(!window.confirm("Exporteer uitsluitend PRIVATE-geaggregeerde HUMAN-aantallen zonder bron-IDs of hashes? Kleine groepen kunnen toch gevoelige informatie verraden."))return;
 const out={schema:"lightup.casebook.human_reconciliation_aggregate.v1",
  status:"REVIEW_ONLY",authority:"NONE",...c,
  source_authenticated:false,client_consent_verified:false,
  operator_consent_verified:false,authorization_granted:false,
  execution_allowed:false,release_approved:false};
 const bytes=enc.encode(JSON.stringify(out)+"\n");
 const url=URL.createObjectURL(new Blob([bytes],{type:"application/octet-stream"}));
 const link=document.createElement("a");link.href=url;
 link.download="lightup-casebook-HUMAN-aggregate.json";
 document.body.append(link);link.click();link.remove();
 setTimeout(()=>URL.revokeObjectURL(url),2000);
 status("Bronvrije HUMAN-aggregaatontvangst aangeboden; geen controle, consent of autorisatie.");
}
$("aggregate").addEventListener("click",()=>{
 try{anonymousReport();}catch(e){status("HOLD: "+e.message,true);}
});
window.LightUpBulkBridge=Object.freeze({
 refresh:()=>{if(!work||busy)deny("HOLD: PRIVATE HUMAN-werkruimte niet geopend.");show();},
 focus:index=>{
  if(!work||busy||!Number.isInteger(index)||index<0||index>=work.cases.length)
   deny("HOLD: ongeldig privébroncase voor lokale navigatie.");
  $("search").value="";$("conflicts").checked=false;
  $("unresolved-only").checked=false;
  show();
  const card=$("cases").querySelector('[data-case-index="'+index+'"]');
  card?.scrollIntoView({behavior:"smooth",block:"start"});
  card?.focus({preventScroll:true});
 },
 read:()=>{
  if(!work||busy)return null;
  const visible=Array.from($("cases").querySelectorAll("[data-case-index]"))
   .map(e=>Number(e.dataset.caseIndex));
  return {cases:work.cases.map((c,i)=>({
   id:c.id,attention:c.attention,action:c.action,
   a:work.a.rows[i].slice(3),b:work.b.rows[i].slice(3),
   choices:[...work.choices[i]]})),visible};
 },
 apply:changes=>{
  if(!work||busy||!Array.isArray(changes)||!changes.length||changes.length>600)
   deny("HOLD: geen geldige PRIVATE HUMAN-keuzewerkset.");
  const touched=new Set();
  for(const {i,j,from,to} of changes){
   if(!Number.isInteger(i)||i<0||i>=work.cases.length||
    !Number.isInteger(j)||j<0||j>2||
    ![from,to].every(v=>typeof v==="string")||touched.has(i+":"+j))
    deny("HOLD: ongeldige of dubbele bulk-aanpassing.");
   touched.add(i+":"+j);
   const same=work.a.rows[i][j+3]===work.b.rows[i][j+3];
   if(work.choices[i][j]!==from||from===to||
    (same&&(to!=="same"||from!=="same"))||
    (!same&&!["","custom:","A","B","reset"].includes(to)&&!customChoice(to,j)))
    deny("HOLD: verlopen of niet-canonieke HUMAN-keuzewijziging; bron opnieuw bekijken.");
  }
  window.LightUpCasebookOutputPreview?.invalidate();
  for(const {i,j,to} of changes)work.choices[i][j]=to;
  work.finalReceipt=null;
  show();
  return changes.length;
 }
});
window.LightUpCasebookDraftAPI=Object.freeze({
 snapshot:()=>work?{
  sources:work.a.records.slice(0,-1).map(r=>({name:r.name,size:r.size,sha256:r.sha256})),
  human:[work.a.records.at(-1).sha256,work.b.records.at(-1).sha256],
  choices:work.choices.map(r=>[...r]),
  notes:window.LightUpCasebookNotes?.read()||[]}:null,
 restore:body=>{
  if(!work)deny("HOLD: oorspronkelijke PRIVATE bronnen ontbreken.");
  const actual=window.LightUpCasebookDraftAPI.snapshot();
  if(JSON.stringify(body.sources)!==JSON.stringify(actual.sources)||
    JSON.stringify(body.human)!==JSON.stringify(actual.human))
   deny("HOLD: checkpoint hoort bij andere originele bron of andere A/B HUMAN-revisie.");
  if(!Array.isArray(body.choices)||body.choices.length!==work.cases.length)
   deny("HOLD: checkpoint heeft een afwijkend aantal HUMAN-cases.");
  const candidate=body.choices.map((r,i)=>{
   if(!Array.isArray(r)||r.length!==3)deny("HOLD: incomplete HUMAN-beslissingen.");
   return r.map((v,j)=>{
    const same=work.a.rows[i][j+3]===work.b.rows[i][j+3];
    if(same&&v!=="same")deny("HOLD: bronidentiek HUMAN-veld mag niet worden herzien.");
    if(!same&&!["","custom:","A","B","reset"].includes(v)&&!customChoice(v,j))
     deny("HOLD: niet-canonieke HUMAN-conflictbeslissing.");
    return v;
   });
  });
  const existing=window.LightUpCasebookNotes?.read()||[];
  const incoming=body.version===2?body.notes:existing;
  if(!Array.isArray(incoming)||incoming.length!==work.cases.length)
   deny("HOLD: PRIVATE HUMAN-motivering heeft onjuist bronaantal.");
  const bound=incoming.map(window.LightUpCasebookNotes.canonical);
  if(!window.confirm("Herstel alleen HUMAN-keuzes en optionele PRIVATE notities op exact dezelfde oorspronkelijke bronnen? Originele Casebook bytes blijven onveranderd."))
   return false;
  window.LightUpCasebookNotes.restore(bound);
  work.finalReceipt=null;
  window.LightUpCasebookOutputPreview?.invalidate();
  work.choices=candidate;
  window.LightUpCasebookBulk?.reset();
  show();return true;
 }
});
window.LightUpCasebookReceiptAPI=Object.freeze({
 snapshot:()=>{
  if(!work||busy||!work.finalReceipt)return null;
  let pending=false;
  work.a.rows.forEach((r,i)=>r.slice(3).forEach((v,j)=>{
   if(v!==work.b.rows[i][j+3]&&!resolved(work.choices[i][j],j))pending=true;
  }));
  if(pending)return null;
  const draft=window.LightUpCasebookDraftAPI.snapshot();
  return {sources:draft.sources,human:draft.human,
   result:{...work.finalReceipt},
   cases:work.cases.map((c,i)=>({
    id:c.id,source_action:c.action,source_attention:c.attention,
    original_a:work.a.rows[i].slice(3),original_b:work.b.rows[i].slice(3),
    decision:[...work.choices[i]],note:window.LightUpCasebookNotes.read()[i]
   }))};
 }
});
$("clear-session").addEventListener("click",()=>{
 if(busy)return;
 if(!work&&!window.LightUpCasebookReceiptClear)return;
 if(!window.confirm("Wis alle lokale PRIVATE Casebook-werksetbytes, HUMAN-keuzes, notities, ingelezen reviewmemo en formulierselecties uit dit browsertabblad? Opgeslagen originele bestanden op schijf blijven onaangeroerd."))return;
 if(work){zero(work.a);zero(work.b);}
 work=null;
 window.LightUpCasebookOutputPreview?.invalidate();
 window.LightUpCasebookBulk?.reset();
 window.LightUpCasebookPortfolio?.render();
 window.LightUpCasebookNotes?.reset(0);
 window.LightUpCasebookReceiptClear?.();
 $("cases").replaceChildren();$("shown").textContent="";
 $("summary").textContent="Lokale PRIVATE werkset gewist; geen originele bronnen geladen.";
 for(const el of document.querySelectorAll('input[type="password"],input[type="file"]'))el.value="";
 $("search").value="";$("conflicts").checked=false;
 $("unresolved-only").checked=false;
 $("publish").disabled=true;$("aggregate").disabled=true;
 status("Lokale PRIVATE werkset, reviewmemo en keuzecontext uit appstatus verwijderd; browsergeheugen kan door de runtime nog tijdelijk kopieën bevatten.");
});
window.addEventListener("pagehide",()=>{if(work){zero(work.a);zero(work.b);}
 window.LightUpCasebookReceiptClear?.();});
$("publish").disabled=true;$("aggregate").disabled=true;
})();