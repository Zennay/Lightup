/* Offline, source-bound encrypted HUMAN decision checkpoint. No original bytes in checkpoint. */
(() => {
"use strict";
const $=id=>document.getElementById(id),api=window.LightUpCasebookDraftAPI;
const enc=new TextEncoder(),dec=new TextDecoder("utf-8",{fatal:true});
const LEGACY_SCHEMA="lightup.casebook.private_human_reconciliation_draft.v1";
const SCHEMA="lightup.casebook.private_human_reconciliation_draft.v2";
const ITER=310000,MAX_FILE=256*1024,MAX_BODY=128*1024;
const fail=msg=>{throw Error(msg);};
const exact=(o,k)=>o!==null&&typeof o==="object"&&!Array.isArray(o)&&
 JSON.stringify(Object.keys(o))===JSON.stringify(k);
function from64(s,max){
 if(typeof s!=="string"||s.length>Math.ceil(max/3)*4+8||
  !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s))
   fail("Onveilige HUMAN checkpoint-base64.");
 let raw;try{raw=atob(s);}catch{fail("Ongeldige checkpoint-base64.");}
 if(raw.length>max)fail("Checkpoint te groot.");
 const arr=Uint8Array.from(raw,c=>c.charCodeAt(0));
 if(to64(arr)!==s)fail("Niet-canonieke checkpoint-base64.");
 return arr;
}
function to64(bytes){
 let str="";for(let i=0;i<bytes.length;i+=8192)
  str+=String.fromCharCode(...bytes.subarray(i,i+8192));
 return btoa(str);
}
function parse(text){
 let obj;try{obj=JSON.parse(text);}catch{fail("Checkpoint-JSON ongeldig.");}
 if(JSON.stringify(obj)!==text)fail("Niet-canonieke checkpoint-inhoud.");
 return obj;
}
function passwordOk(password){
 if([...password].length<12||enc.encode(password).length>1024)
  fail("Checkpoint-wachtwoord moet minimaal 12 tekens en maximaal 1024 UTF-8 bytes bevatten.");
}
async function keyFor(password,salt,usage){
 const key=await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveKey"]);
 return crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:ITER,hash:"SHA-256"},
  key,{name:"AES-GCM",length:256},false,[usage]);
}
function status(msg,error=false){
 $("draft-status").textContent=(error?"HOLD: ":"")+msg;
 $("draft-status").classList.toggle("error",error);
}
function download(name,bytes){
 const url=URL.createObjectURL(new Blob([bytes],{type:"application/octet-stream"}));
 const link=document.createElement("a");link.href=url;link.download=name;
 document.body.append(link);link.click();link.remove();
 setTimeout(()=>URL.revokeObjectURL(url),2000);
}
function authBody(snapshot){
 if(!snapshot)fail("Open eerst beide oorspronkelijke PRIVATE Casebook-bronnen.");
 if(!snapshot.sources||!snapshot.human||!snapshot.choices)
  fail("Originele bron en HUMAN binding ontbreken.");
 return {schema:SCHEMA,version:2,sources:snapshot.sources,human:snapshot.human,
  choices:snapshot.choices,notes:snapshot.notes,
  source_authenticated:false,client_consent_verified:false,
  operator_consent_verified:false,authorization_granted:false,
  execution_allowed:false,release_approved:false};
}
let busy=false;
function setBusy(b){
 busy=b;for(const id of ["draft-save","draft-open"])$(id).disabled=b;
}
$("draft-save").addEventListener("click",async()=>{
 if(!crypto?.subtle||!isSecureContext){status("WebCrypto secure context ontbreekt.",true);return;}
 if(busy)return;setBusy(true);
 try{
  if(!$("ack").checked)fail("HUMAN-only bevestiging ontbreekt.");
  const snapshot=api.snapshot(),pass=$("draft-new-pass").value;passwordOk(pass);
  if(!window.confirm("Maak een NIEUW versleuteld PRIVATE HUMAN-beslisconcept? Originele bronnen worden NIET bijgevoegd."))return;
  const body=enc.encode(JSON.stringify(authBody(snapshot)));
  if(body.length>MAX_BODY)fail("Checkpoint-overzicht te groot.");
  const salt=crypto.getRandomValues(new Uint8Array(16)),
   iv=crypto.getRandomValues(new Uint8Array(12));
  const cipher=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv},
   await keyFor(pass,salt,"encrypt"),body));
  body.fill(0);
  const envelope={schema:SCHEMA,version:2,kdf:"PBKDF2-SHA256",
   iterations:ITER,cipher:"AES-256-GCM",salt_b64:to64(salt),
   iv_b64:to64(iv),ciphertext_b64:to64(cipher)};
  const bytes=enc.encode(JSON.stringify(envelope));
  if(bytes.length>MAX_FILE)fail("Versleuteld checkpoint groter dan limiet.");
  download("lightup-casebook-PRIVATE-human-draft.lurd",bytes);
  status("Alleen bronhash-gebonden HUMAN-keuzes versleuteld opgeslagen. Voor herstel moeten beide oorspronkelijke PRIVATE overdrachten opnieuw worden geopend.");
 }catch(e){status(e instanceof Error?e.message:"Checkpoint geweigerd.",true);}
 finally{$("draft-new-pass").value="";setBusy(false);}
});
$("draft-open").addEventListener("click",async()=>{
 if(!crypto?.subtle||!isSecureContext){status("WebCrypto secure context ontbreekt.",true);return;}
 if(busy)return;setBusy(true);
 try{
  if(!$("ack").checked)fail("HUMAN-only bevestiging ontbreekt.");
  const file=$("draft-file").files[0],password=$("draft-open-pass").value;
  if(!file||typeof file.name!=="string"||file.name.length>160||
    !/\.lurd$/i.test(file.name)||file.size<80||file.size>MAX_FILE)
   fail("Kies een geldige beperkte PRIVATE HUMAN-checkpoint .lurd.");
  if(!password)fail("Wachtwoord ontbreekt.");
  if(!api.snapshot())fail("Open eerst de twee oorspronkelijke PRIVATE bronsets.");
  const env=parse(await file.text());
  if(!exact(env,["schema","version","kdf","iterations","cipher","salt_b64",
   "iv_b64","ciphertext_b64"])||!((env.schema===SCHEMA&&env.version===2)||
    (env.schema===LEGACY_SCHEMA&&env.version===1))||
   env.kdf!=="PBKDF2-SHA256"||env.iterations!==ITER||env.cipher!=="AES-256-GCM")
   fail("Checkpoint-envelope niet oorspronkelijk canoniek.");
  const salt=from64(env.salt_b64,16),iv=from64(env.iv_b64,12),
   cipher=from64(env.ciphertext_b64,MAX_FILE);
  if(salt.length!==16||iv.length!==12||cipher.length<16)
   fail("Ongeldige cryptografische parameters.");
  let bytes;
  try{bytes=new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv},
    await keyFor(password,salt,"decrypt"),cipher));}
  catch{fail("Wachtwoord of checkpoint-ciphertext onjuist.");}
  if(bytes.length>MAX_BODY)fail("Checkpoint-plaintext te groot.");
  let body;
  try{body=parse(dec.decode(bytes));}
  finally{bytes.fill(0);}
  const mandatory=["schema","version","sources","human","choices"];
  const authority=["source_authenticated","client_consent_verified","operator_consent_verified",
    "authorization_granted","execution_allowed","release_approved"];
  const isV2=env.schema===SCHEMA;
  if(!exact(body,[...mandatory,...(isV2?["notes"]:[]),...authority])||
    body.schema!==env.schema||body.version!==env.version||
    ["source_authenticated","client_consent_verified","operator_consent_verified",
     "authorization_granted","execution_allowed","release_approved"].some(k=>body[k]!==false))
   fail("Onjuiste checkpoint-bron of autoriteitsflags.");
  // api.restore performs a second, exact *currently open* original-source,
  // both original HUMAN CSV fingerprints and every HUMAN option check.
  if(!api.restore(body)){status("HUMAN-restore geannuleerd; bestaande keuzes behouden.");return;}
  status("Oorspronkelijk bron+beide HUMAN-CSV-bound beslisconcept in huidig browsergeheugen hersteld. Geen grant/toestemming.");
 }catch(e){status(e instanceof Error?e.message:"Checkpoint geweigerd.",true);}
 finally{$("draft-open-pass").value="";$("draft-file").value="";setBusy(false);}
});
})();