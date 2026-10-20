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
 if(plaintext.length>20*1024*1024)deny("Ontsleutelde inhoud te groot.");
 const body=canonical(dec.decode(plaintext),"PRIVATE inhoud");
 plaintext.fill(0);
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
  r.slice(3).forEach((v,j)=>{if(v!==work.b.rows[i][j+3]&&!work.choices[i][j])unresolved++;});
 });
 $("summary").textContent=work.cases.length+" brondossiers · "+changed+
  " met HUMAN-verschil · "+unresolved+" onbesliste velden. De bron blijft ongeverifieerd.";
 $("publish").disabled=busy||unresolved!==0;
 $("aggregate").disabled=busy||unresolved!==0;
}
function show(){
 $("cases").replaceChildren();
 if(!work)return;
 const search=$("search").value.trim().toLowerCase(),only=$("conflicts").checked;
 let shown=0;
 work.cases.forEach((c,i)=>{
  const ra=work.a.rows[i],rb=work.b.rows[i];
  const diff=ra.slice(3).some((v,j)=>v!==rb[j+3]);
  if(only&&!diff)return;
  if(search&&![c.id,c.action,c.attention].some(s=>s.toLowerCase().includes(search)))return;
  shown++;
  const card=node("article","");card.className="case"+(diff?" differing":"");
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
     ["reset","Heropen HUMAN: "+defaultHuman[j]]].forEach(([v,s])=>{
      const option=node("option",s);option.value=v;select.append(option);
     });
    select.value=work.choices[i][j];
    select.addEventListener("change",()=>{work.choices[i][j]=select.value;tally();});
    td.append(select);
   }
   row.append(td);body.append(row);
  });
  table.append(body);card.append(table);$("cases").append(card);
 });
 $("shown").textContent="Zichtbaar: "+shown+" van "+work.cases.length;
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
   else deny("HOLD: nog onbesliste HUMAN-keuzes.");
  }
  return row;
 });
 const csv=enc.encode(h.serialize(combined));
 if(csv.length>131072)deny("Nieuwe HUMAN-CSV te groot.");
 const password=$("new-password").value;
 if([...password].length<12||enc.encode(password).length>1024)
  deny("Nieuw wachtwoord moet 12–1024 UTF-8-tekens/bytes bevatten.");
 if(!$("ack").checked)deny("PRIVATE HUMAN-only bevestiging ontbreekt.");
 if(!window.confirm("Maak uitsluitend NIEUW lokaal AES-256-GCM bron+HUMAN pakket? Niets autoriseert een scan."))
  return;
 const orig=work.a.records.slice(0,-1);
 const newHuman={name:"workroom-current-template.csv",size:csv.length,
  sha256:await sha(csv),bytes:csv};
 const items=[...orig,newHuman].map(x=>({
  name:x.name,size:x.size,sha256:x.sha256,content_b64:b64(x.bytes)}));
 const content=enc.encode(JSON.stringify({schema:SCHEMA,version:1,files:items}));
 if(content.length>20*1024*1024)deny("Nieuwe PRIVATE bundel te groot.");
 const salt=crypto.getRandomValues(new Uint8Array(16)),
  iv=crypto.getRandomValues(new Uint8Array(12));
 const ciphertext=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv},
  await keyFor(password,salt,"encrypt"),content));
 content.fill(0);csv.fill(0);
 const envelope={schema:SCHEMA,version:1,kdf:"PBKDF2-SHA256",iterations:ITER,
  cipher:"AES-256-GCM",salt_b64:b64(salt),iv_b64:b64(iv),ciphertext_b64:b64(ciphertext)};
 const bytes=enc.encode(JSON.stringify(envelope));
 if(bytes.length>MAX_VAULT)deny("Nieuwe versleutelde bundel te groot.");
 const url=URL.createObjectURL(new Blob([bytes],{type:"application/octet-stream"}));
 const link=document.createElement("a");link.href=url;
 link.download="lightup-casebook-private-reconciled.lupt";
 document.body.append(link);link.click();link.remove();
 setTimeout(()=>URL.revokeObjectURL(url),2000);
 status("Nieuwe AES-256-GCM PRIVATE overdracht aangeboden: dezelfde originele bronbytes, expliciet gekozen HUMAN-velden; geen bronverificatie, grant of consent.");
}
function setBusy(v){
 busy=v;$("open").disabled=v;$("publish").disabled=v||!work;
 $("aggregate").disabled=v||!work;
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
  work={a,b,cases:a.cases,choices:a.rows.map((r,i)=>[0,1,2].map(j=>
   r[j+3]===b.rows[i][j+3]?"same":""))};
  a=null;b=null;
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
function anonymousReport(){
 if(!work||$("publish").disabled)deny("HOLD: los eerst alle HUMAN-verschillen op.");
 const c={cases:work.cases.length,conflicting_cases:0,changed_fields:0,
   selected_a:0,selected_b:0,reopened:0,identical:0};
 work.a.rows.forEach((row,i)=>{
  let different=false;
  for(let j=0;j<3;j++){
   if(row[j+3]===work.b.rows[i][j+3]){c.identical++;continue;}
   different=true;c.changed_fields++;
   const selected=work.choices[i][j];
   if(selected==="A")c.selected_a++;
   else if(selected==="B")c.selected_b++;
   else if(selected==="reset")c.reopened++;
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
window.addEventListener("pagehide",()=>{if(work){zero(work.a);zero(work.b);}});
$("publish").disabled=true;$("aggregate").disabled=true;
})();