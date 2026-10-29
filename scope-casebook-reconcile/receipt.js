/* PRIVATE encrypted HUMAN reviewer memorandum linked to offered original .lupt byte digest.
 * Does not authenticate original producer, human identity, client consent or grant. */
(() => {
"use strict";
const $=id=>document.getElementById(id);
const API=window.LightUpCasebookReceiptAPI,notes=window.LightUpCasebookNotes;
const enc=new TextEncoder(),dec=new TextDecoder("utf-8",{fatal:true});
const SCHEMA="lightup.casebook.private_human_review_memo.v1",ITER=310000,
 MAX_FILE=1024*1024,MAX_BODY=512*1024,FLAGS=[
 "source_authenticated","client_consent_verified","operator_consent_verified",
 "authorization_granted","execution_allowed","release_approved"
];
const REASON_FIELDS=["schema","version","status","sources","human","result","cases",...FLAGS];
const fail=msg=>{throw Error(msg);};
const exact=(o,keys)=>o!==null&&typeof o==="object"&&!Array.isArray(o)&&
 JSON.stringify(Object.keys(o))===JSON.stringify(keys);
const hex=x=>typeof x==="string"&&/^[0-9a-f]{64}$/.test(x);
const safeText=(s,max=1200)=>typeof s==="string"&&s.length<=max&&
 !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(s);
const stages=["unreviewed","investigating","awaiting-owner","documented"];
const routes=["unassigned","original-scope-owner","client-clarification",
 "independent-security-review","operator-followup"];
const blockers=["none","missing-source","missing-owner","needs-independent-consent",
 "requires-revocation-review","unresolved-tenant-lineage"];
const enums=[stages,routes,blockers];
let opened=null,working=false;
window.LightUpCasebookReceiptClear=()=>{
 opened=null;$("receipt-view").replaceChildren();
 window.LightUpCasebookRevisionClear?.();
 window.LightUpCasebookTimelineClear?.();
 status("PRIVATE lokaal ontvangen memo uit weergave verwijderd.");
};
function status(message,error=false){
 $("receipt-status").textContent=(error?"HOLD: ":"")+message;
 $("receipt-status").classList.toggle("error",error);
}
function base64(bytes){
 let s="";for(let i=0;i<bytes.length;i+=8192)
  s+=String.fromCharCode(...bytes.subarray(i,i+8192));
 return btoa(s);
}
function from64(text,limit){
 if(typeof text!=="string"||text.length>Math.ceil(limit/3)*4+8||
  !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text))
  fail("Ongeldige memo base64.");
 let raw;try{raw=atob(text);}catch{fail("Ongeldige memo base64.");}
 if(raw.length>limit)fail("Memo overschrijdt harde grens.");
 const bytes=Uint8Array.from(raw,c=>c.charCodeAt(0));
 if(base64(bytes)!==text)fail("Niet-canonieke memo base64.");
 return bytes;
}
function parse(text){
 let body;try{body=JSON.parse(text);}catch{fail("Memo is geen geldige JSON.");}
 if(JSON.stringify(body)!==text)fail("Memo-JSON niet canoniek.");
 return body;
}
function checkPassword(password){
 if([...password].length<12||enc.encode(password).length>1024)
  fail("Memo-wachtwoord: minimaal 12 tekens, maximaal 1024 UTF-8 bytes.");
}
async function keyFor(password,salt,usage){
 const raw=await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveKey"]);
 return crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:ITER,hash:"SHA-256"},
   raw,{name:"AES-GCM",length:256},false,[usage]);
}
function admit(body){
 if(!exact(body,REASON_FIELDS)||body.schema!==SCHEMA||body.version!==1||
  body.status!=="REVIEW_ONLY"||FLAGS.some(k=>body[k]!==false))
  fail("Memo bronformaat of authority-vlaggen onjuist.");
 if(!Array.isArray(body.sources)||body.sources.length<1||body.sources.length>12||
  !Array.isArray(body.human)||body.human.length!==2||
  !body.human.every(hex)||!exact(body.result,["bundle_sha256","human_csv_sha256"])||
  !hex(body.result.bundle_sha256)||!hex(body.result.human_csv_sha256)||
  !Array.isArray(body.cases)||body.cases.length>200)
  fail("Memo heeft onjuist bron-/resultaatmanifest.");
 body.sources.forEach((source,i)=>{
  if(!exact(source,["name","size","sha256"])||
   source.name!=="casebook-"+String(i+1).padStart(2,"0")+".json"||
   !Number.isSafeInteger(source.size)||source.size<1||source.size>4*1024*1024||
   !hex(source.sha256))
   fail("Memo noemt een onjuist oorspronkelijk bronbestand.");
 });
 const seen=new Set();
 body.cases.forEach(row=>{
  if(!exact(row,["id","source_action","source_attention","original_a",
    "original_b","decision","note"])||
   !safeText(row.id,400)||!row.id||seen.has(row.id)||
   !safeText(row.source_action,2000)||!safeText(row.source_attention,500)||
   !Array.isArray(row.original_a)||!Array.isArray(row.original_b)||
   !Array.isArray(row.decision)||row.original_a.length!==3||
   row.original_b.length!==3||row.decision.length!==3)
   fail("Memo-case ongeldig, dubbel of incompleet.");
  seen.add(row.id);
  notes.canonical(row.note);
  for(let j=0;j<3;j++){
   const a=row.original_a[j],b=row.original_b[j],chosen=row.decision[j];
   if(!enums[j].includes(a)||!enums[j].includes(b)||
    (a===b&&chosen!=="same")||
    (a!==b&&!["A","B","reset"].includes(chosen)&&
     !(typeof chosen==="string"&&chosen.startsWith("custom:")&&
       enums[j].includes(chosen.slice(7)))))
    fail("Memo heeft niet-originele HUMAN-waarden.");
  }
 });
 return body;
}
function produce(snapshot){
 if(!snapshot)fail("Maak eerst een versleutelde PRIVATE bron+HUMAN overdracht.");
 if(!Array.isArray(snapshot.cases)||snapshot.cases.length<1)
  fail("Geen echte originele HUMAN-cases om te documenteren.");
 return admit({schema:SCHEMA,version:1,status:"REVIEW_ONLY",
  sources:snapshot.sources,human:snapshot.human,result:snapshot.result,
  cases:snapshot.cases,source_authenticated:false,client_consent_verified:false,
  operator_consent_verified:false,authorization_granted:false,
  execution_allowed:false,release_approved:false});
}
function download(name,bytes){
 const url=URL.createObjectURL(new Blob([bytes],{type:"application/octet-stream"}));
 const a=document.createElement("a");a.href=url;a.download=name;
 document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),2000);
}
function setWorking(v){
 working=v;$("receipt-save").disabled=v;$("receipt-open").disabled=v;
 $("receipt-verify").disabled=v;$("receipt-rekey").disabled=v;
}
const el=(tag,t)=>{const e=document.createElement(tag);e.textContent=t;return e;};
function render(body){
 const panel=$("receipt-view");panel.replaceChildren();
 const h=el("h3","Ontvangen PRIVATE HUMAN-memo · bron is NIET geauthenticeerd");
 panel.append(h,el("p","Resultaat (ongetekende lokale versleutelde byte-SHA256): "+
  body.result.bundle_sha256),
  el("p","HUMAN CSV SHA256: "+body.result.human_csv_sha256),
  el("p","Oorspronkelijke bronnen: "+body.sources.length+
   " · PRIVÉ-dossiers: "+body.cases.length+
   " · memo is uitsluitend door de bezitters van het wachtwoord ontsleuteld."));
 const table=el("table",""),thead=el("thead",""),top=el("tr","");
 ["Privé broncase","Oorspronkelijke bronactie","HUMAN-beslissingen","Privé reviewreden en motivering"]
  .forEach(s=>top.append(el("th",s)));thead.append(top);table.append(thead);
 const tbody=el("tbody","");
 for(const row of body.cases){
  const tr=el("tr","");
  const decisions=row.decision.map((d,i)=>{
   const resolved=d==="same"?row.original_a[i]:
    d==="A"?row.original_a[i]:
    d==="B"?row.original_b[i]:
    d==="reset"?enums[i][0]:d.slice(7);
   return ["fase","route","blokkade"][i]+": "+resolved+" ("+d+")";
  }).join("\n");
  [row.id,row.source_action+" / "+row.source_attention,decisions,
    row.note.reason+" — "+row.note.note].forEach(v=>tr.append(el("td",v)));
  tbody.append(tr);
 }
 table.append(tbody);panel.append(table);
}
async function decodeMemo(file,pw){
  if(!file||typeof file.name!=="string"||file.name.length>160||
    !/\.lurm$/i.test(file.name)||file.size<80||file.size>MAX_FILE||!pw)
    fail("Selecteer een geldig beperkt PRIVATE memo en wachtwoord.");
  const env=parse(await file.text());
  if(!exact(env,["schema","version","kdf","iterations","cipher","salt_b64","iv_b64","ciphertext_b64"])||
    env.schema!==SCHEMA||env.version!==1||env.kdf!=="PBKDF2-SHA256"||
    env.iterations!==ITER||env.cipher!=="AES-256-GCM")
    fail("Memo-envelope onbekend.");
  const salt=from64(env.salt_b64,16),iv=from64(env.iv_b64,12),
    cipher=from64(env.ciphertext_b64,MAX_FILE);
  if(salt.length!==16||iv.length!==12||cipher.length<16)fail("Memo cryptografische parameters ongeldig.");
  let clear;
  try{clear=new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv},
    await keyFor(pw,salt,"decrypt"),cipher));}
  catch{fail("Wachtwoord of memo-body onjuist.");}
  if(clear.length>MAX_BODY)fail("PRIVATE memo te groot.");
  let candidate;
  try{candidate=admit(parse(dec.decode(clear)));}
  finally{clear.fill(0);}
  return candidate;
 }
window.LightUpCasebookReceiptLibrary=Object.freeze({
 decodeMemo,current:()=>opened
});
async function encryptMemo(memo,pw,filename){
 checkPassword(pw);
  const plaintext=enc.encode(JSON.stringify(memo));
  let encrypted,salt,iv;
  try{
   if(plaintext.length>MAX_BODY)fail("PRIVATE memo te groot.");
   salt=crypto.getRandomValues(new Uint8Array(16));
   iv=crypto.getRandomValues(new Uint8Array(12));
   encrypted=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv},
     await keyFor(pw,salt,"encrypt"),plaintext));
  }finally{plaintext.fill(0);}
  const envelope={schema:SCHEMA,version:1,kdf:"PBKDF2-SHA256",
    iterations:ITER,cipher:"AES-256-GCM",salt_b64:base64(salt),
    iv_b64:base64(iv),ciphertext_b64:base64(encrypted)};
  const bytes=enc.encode(JSON.stringify(envelope));
  if(bytes.length>MAX_FILE)fail("Versleuteld PRIVATE memo te groot.");
  download(filename,bytes);
}
$("receipt-save").addEventListener("click",async()=>{
 if(!window.isSecureContext||!crypto?.subtle){status("WebCrypto secure context vereist.",true);return;}
 if(working)return;setWorking(true);
 try{
  if(!$("ack").checked)fail("Bevestig eerst PRIVATE HUMAN-only gebruik.");
  const snapshot=produce(API.snapshot()),pw=$("receipt-save-pass").value;
  checkPassword(pw);
  if(!window.confirm("Maak afzonderlijk NIEUW versleuteld PRIVATE memo met oorspronkelijke dossier-IDs, HUMAN-opvolgnotities en ongetekende SHA-256-resultaatbinding? Dit is GEEN autorisatie."))return;
  await encryptMemo(snapshot,pw,"lightup-PRIVATE-human-review-memo.lurm");
  status("Nieuw afzonderlijk PRIVATE HUMAN-memo aangeboden; niet in oorspronkelijke Casebook/HUMAN CSV opgenomen.");
 }catch(e){status(e instanceof Error?e.message:"Versleuteld memo geweigerd.",true);}
 finally{$("receipt-save-pass").value="";setWorking(false);}
});
$("receipt-open").addEventListener("click",async()=>{
 if(!window.isSecureContext||!crypto?.subtle){status("WebCrypto secure context vereist.",true);return;}
 if(working)return;setWorking(true);
 try{
  if(!$("ack").checked)fail("PRIVATE HUMAN-only erkenning vereist.");
  const candidate=await decodeMemo($("receipt-file").files[0],$("receipt-open-pass").value);
  if(opened&&!window.confirm("Vorige gelezen PRIVATE memo vervangen?"))return;
  opened=candidate;window.LightUpCasebookRevisionClear?.();
  window.LightUpCasebookTimelineClear?.();render(opened);
  status("PRIVATE HUMAN-memo lokaal heropend, intern consistent maar zonder echte oorspronkelijke producent-, consent- of grant-verificatie.");
 }catch(e){status(e instanceof Error?e.message:"Ongeldig memo.",true);}
 finally{$("receipt-open-pass").value="";$("receipt-file").value="";setWorking(false);}
});
$("receipt-rekey").addEventListener("click",async()=>{
 if(!window.isSecureContext||!crypto?.subtle){status("Veilige WebCrypto-context vereist.",true);return;}
 if(working)return;setWorking(true);
 try{
  if(!opened)fail("Open eerst een bestaande PRIVATE reviewmemo.");
  if(!$("ack").checked)fail("PRIVATE HUMAN-only erkenning ontbreekt.");
  const pw=$("receipt-rekey-pass").value;checkPassword(pw);
  if(!window.confirm("Versleutel exact dezelfde intern geaccepteerde PRIVATE HUMAN-reviewmemo opnieuw onder een nieuw onafhankelijk wachtwoord, verse salt en nonce? Geen bron of consent is geverifieerd."))return;
  await encryptMemo(opened,pw,"lightup-PRIVATE-human-review-memo-rekey.lurm");
  status("Bestaand PRIVATE HUMAN-reviewmemo met nieuwe AES-GCM salt/nonce opnieuw versleuteld, zonder oorspronkelijke plaintext bronbestanden te downloaden.");
 }catch(e){status(e instanceof Error?e.message:"Dooroverdracht geweigerd.",true);}
 finally{$("receipt-rekey-pass").value="";setWorking(false);}
});
$("receipt-verify").addEventListener("click",async()=>{
 if(working)return;setWorking(true);
 try{
  if(!opened)fail("Open eerst een privé versleuteld memo.");
  const file=$("receipt-check-file").files[0];
  if(!file||file.size<100||file.size>26*1024*1024||
    !/\.lupt$/i.test(file.name))fail("Kies een begrensd origineel versleuteld .lupt-resultaat.");
  const hash=Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",await file.arrayBuffer())),
   b=>b.toString(16).padStart(2,"0")).join("");
  if(hash!==opened.result.bundle_sha256)
    fail("Geselecteerd versleuteld resultaat heeft NIET de memo-bytehash; geen bronbinding bewezen.");
  status("EXACTE ENCRYPTED BYTE MATCH: .lupt-bestand hoort bij het ongetekende PRIVATE memo. Dit bewijst geen oorspronkelijke bronproducent, geldigheid, consent of scanmachtiging.");
 }catch(e){status(e instanceof Error?e.message:"Bytevergelijking geweigerd.",true);}
 finally{$("receipt-check-file").value="";setWorking(false);}
});
})();