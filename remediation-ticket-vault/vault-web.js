/* LightUp HUMAN Ticket Vault: offline WebCrypto interoperable with vault.py v1. */
(()=>{'use strict';
const $=id=>document.getElementById(id);
const e=['operation','source','old-password','new-password','confirmation','plaintext-ack','run','forget','status','result','preview','viewer','viewer-content'];
const ui=Object.fromEntries(e.map(id=>[id,$(id)]));
const enc=new TextEncoder(),dec=new TextDecoder('utf-8',{fatal:true});
const MAGIC=new Uint8Array([76,85,84,75,86,49,0,10]); // LUTKV1\0\n
const ITERATIONS=600000, LIMIT=4*1024*1024, VAULT_LIMIT=LIMIT+4096;
const HEADER_KEYS=['kind','schema_version','cipher','kdf','iterations','salt','nonce'];
const FLAGS=['authenticated','tenant_verified','source_authorized','grant','client_consent','operator_consent','execution','scan','retest_verified','release'];
const META_KEYS=['kind','schema_version','content_type','content_size','content_sha256',...FLAGS];
let url=null;
function clearLink(){if(url)URL.revokeObjectURL(url);url=null;ui.result.replaceChildren();}
function clearViewer(){ui['viewer-content'].textContent='';ui.viewer.hidden=true;}
function status(message,bad=false){ui.status.textContent=message;ui.status.classList.toggle('error',bad);}
function concat(...arrays){const result=new Uint8Array(arrays.reduce((x,b)=>x+b.length,0));let i=0;for(const x of arrays){result.set(x,i);i+=x.length;}return result;}
function be(n,width){const out=new Uint8Array(width);for(let k=width-1;k>=0;k--){out[k]=n&255;n=Math.floor(n/256);}return out;}
function fromBe(arr){let v=0;for(const b of arr)v=v*256+b;return v;}
function binaryEncode(bytes){let v='';for(const x of bytes)v+=String.fromCharCode(x);return btoa(v);}
function binaryDecode(s){if(typeof s!=='string'||!s||!/^[A-Za-z0-9+/]+={0,2}$/.test(s))throw Error('Invalid authenticated vault base64.');let bin;try{bin=atob(s);}catch(e){throw Error('Invalid authenticated vault base64.');}const arr=Uint8Array.from(bin,ch=>ch.charCodeAt(0));if(binaryEncode(arr)!==s)throw Error('Noncanonical vault base64.');return arr;}
function canonical(obj){return JSON.stringify(Object.fromEntries(Object.keys(obj).sort().map(key=>[key,obj[key]])));}
function fieldSet(obj,allowed){return obj&&typeof obj==='object'&&!Array.isArray(obj)&&Object.keys(obj).length===allowed.length&&allowed.every(key=>Object.prototype.hasOwnProperty.call(obj,key));}
function canonicalParse(bytes,fields){let obj;try{obj=JSON.parse(dec.decode(bytes));}catch(err){throw Error('Invalid or ambiguous vault JSON.');}if(!fieldSet(obj,fields)||canonical(obj)!==dec.decode(bytes))throw Error('Noncanonical or duplicated vault metadata.');return obj;}
function textUtf8(bytes){try{return dec.decode(bytes);}catch(e){throw Error('Vault contains invalid UTF-8 HUMAN text.');}}
function hex(bytes){return Array.from(bytes,x=>x.toString(16).padStart(2,'0')).join('');}
async function sha256(bytes){return hex(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)));}
async function key(pass,salt){
 if(!pass||pass.length>4096||/[\uD800-\uDFFF]/u.test(pass))throw Error('Unsupported or missing passphrase.');
 let secret=enc.encode(pass);
 try{
  const material=await crypto.subtle.importKey('raw',secret,{name:'PBKDF2'},false,['deriveKey']);
  return await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations:ITERATIONS},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
 }finally{secret.fill(0);}
}
function newPass(){
 const value=ui['new-password'].value;
 if(value.length<14||value.length>4096||value!==ui.confirmation.value||/[\uD800-\uDFFF]/u.test(value))throw Error('New passphrase must be at least 14 characters and exactly match confirmation.');
 return value;
}
function headerRead(file){
 if(file.length>VAULT_LIMIT||file.length<MAGIC.length+2+16||!MAGIC.every((b,i)=>file[i]===b))throw Error('Unsupported or oversized PRIVATE ticket vault.');
 const size=fromBe(file.slice(8,10)),end=10+size;
 if(size<=0||size>1024||file.length<end+16)throw Error('Invalid bounded vault header.');
 const headerBytes=file.slice(10,end),header=canonicalParse(headerBytes,HEADER_KEYS);
 if(header.kind!=='lightup.private_human_ticket_vault'||header.schema_version!==1||header.kdf!=='PBKDF2-HMAC-SHA256'||header.cipher!=='AES-256-GCM'||header.iterations!==ITERATIONS)throw Error('Unsupported crypto parameters.');
 const salt=binaryDecode(header.salt),nonce=binaryDecode(header.nonce);
 if(salt.length!==16||nonce.length!==12)throw Error('Invalid salt/nonce size.');
 return {header,nonce,salt,prefix:file.slice(0,end),cipher:file.slice(end)};
}
async function seal(inner,pass){
 const salt=crypto.getRandomValues(new Uint8Array(16)),nonce=crypto.getRandomValues(new Uint8Array(12));
 const header={kind:'lightup.private_human_ticket_vault',schema_version:1,cipher:'AES-256-GCM',kdf:'PBKDF2-HMAC-SHA256',iterations:ITERATIONS,salt:binaryEncode(salt),nonce:binaryEncode(nonce)};
 const h=enc.encode(canonical(header)),prefix=concat(MAGIC,be(h.length,2),h);
 const auth=await key(pass,salt);
 const ciphertext=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:prefix,tagLength:128},auth,inner));
 const out=concat(prefix,ciphertext);if(out.length>VAULT_LIMIT)throw Error('Encrypted file exceeds size limit.');
 return out;
}
async function unpack(file,pass){
 const v=headerRead(file);const auth=await key(pass,v.salt);let inner;
 try{inner=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:v.nonce,additionalData:v.prefix,tagLength:128},auth,v.cipher));}
 catch(err){throw Error('Vault authentication HOLD: wrong passphrase or tampered ciphertext. No plaintext exported.');}
 if(inner.length<4)throw Error('Decrypted metadata missing.');
 const mlen=fromBe(inner.slice(0,4));if(mlen<1||mlen>1024||4+mlen>inner.length)throw Error('Invalid decrypted metadata length.');
 const meta=canonicalParse(inner.slice(4,4+mlen),META_KEYS),plain=inner.slice(4+mlen);
 if(meta.kind!=='lightup.private_human_ticket_contents'||meta.schema_version!==1||
   !['text/markdown','application/json'].includes(meta.content_type)||
   !Number.isSafeInteger(meta.content_size)||meta.content_size!==plain.length||
   meta.content_sha256!==await sha256(plain)||FLAGS.some(k=>meta[k]!==false)||
   plain.length===0||plain.length>LIMIT)throw Error('Private HUMAN envelope integrity HOLD.');
 textUtf8(plain);return {inner,plain,meta};
}
function output(data,name,mime){
 clearLink();
 url=URL.createObjectURL(new Blob([data],{type:mime}));
 const a=document.createElement('a');a.href=url;a.download=name;a.textContent='Save new PRIVATE local file';a.className='download';
 ui.result.appendChild(a);ui.result.append(' · The filename and storage location are your responsibility.');
}
function update(){
 const op=ui.operation.value;
 for(const id of ['old-password','new-password','confirmation'])ui[id].closest('.field').hidden=(op==='inspect'||(op==='seal'&&id==='old-password')||((op==='open'||op==='view')&&id!=='old-password'));
 ui['plaintext-ack'].closest('label').hidden=!(op==='open'||op==='view');
 ui.preview.textContent=op==='seal'?'Encrypt original PRIVATE Markdown/JSON without reading original client authority.':
 op==='open'?'Decrypt to an explicitly saved PRIVATE plaintext file only.':
 op==='view'?'Review source HUMAN plaintext in tab memory only, without a new disk file; clear it with Forget.':
 op==='rotate'?'Re-encrypt into a new vault; old encrypted file stays untouched.':
 'Read visible anonymous vault parameters only; authenticity is not verified without passphrase.';
 clearLink();clearViewer();
}
async function run(){
 const op=ui.operation.value,file=ui.source.files[0];
 if(!file)throw Error('Select a local file.');
 if(!crypto?.subtle||!crypto.getRandomValues)throw Error('Secure browser WebCrypto unavailable for this local page.');
 if(!Number.isSafeInteger(file.size)||file.size<1||file.size>(op==='seal'?LIMIT:VAULT_LIMIT))throw Error('Private file exceeds bounded size.');
 const raw=new Uint8Array(await file.arrayBuffer());
 if(op==='inspect'){
  const h=headerRead(raw);
  status('Structurally valid anonymous v1 vault header, AES-256-GCM / PBKDF2-SHA256, '+ITERATIONS+' iterations, '+raw.length+' encrypted bytes. Authenticity NOT checked; no identity, authority or retest inferred.');
  return;
 }
 if(op==='seal'){
  const low=file.name.toLowerCase(),type=low.endsWith('.md')?'text/markdown':low.endsWith('.json')?'application/json':null;
  if(!type)throw Error('Only original PRIVATE HUMAN Markdown or JSON exports are supported.');
  textUtf8(raw);const meta={kind:'lightup.private_human_ticket_contents',schema_version:1,
    content_type:type,content_size:raw.length,content_sha256:await sha256(raw),
    ...Object.fromEntries(FLAGS.map(k=>[k,false]))};
  const m=enc.encode(canonical(meta));if(m.length>1024)throw Error('Metadata size exceeded.');
  const inner=concat(be(m.length,4),m,raw);
  output(await seal(inner,newPass()),'lightup-PRIVATE-human-handoff.ltv','application/octet-stream');
  inner.fill(0);status('New authenticated encrypted PRIVATE HUMAN vault ready for local download. Original plaintext was NOT deleted; use approved private storage.');
  return;
 }
 if(!file.name.toLowerCase().endsWith('.ltv'))throw Error('Select a PRIVATE .ltv vault.');
 const source=await unpack(raw,ui['old-password'].value);
 if(op==='rotate'){
  if(ui['old-password'].value===newPass())throw Error('Replacement passphrase must differ from old one.');
  const encrypted=await seal(source.inner,newPass());
  output(encrypted,'lightup-PRIVATE-human-rotated.ltv','application/octet-stream');
  source.inner.fill(0);source.plain.fill(0);
  status('Separate fresh encrypted vault ready. Old encrypted vault was not modified and no plaintext file was written.');
  return;
 }
 if(op==='view'){
  if(!ui['plaintext-ack'].checked||!confirm('Display PRIVATE decrypted HUMAN notes on this trusted local screen without writing any plaintext file? Screenshots/screen sharing are your responsibility.'))throw Error('Local private viewing not approved.');
  if(source.plain.length>262144)throw Error('Private text exceeds safe 256 KiB in-memory viewer limit; use approved private plaintext export instead.');
  ui['viewer-content'].textContent=textUtf8(source.plain);
  ui.viewer.hidden=false;
  source.inner.fill(0);source.plain.fill(0);
  status('PRIVATE HUMAN content decrypted for this local read-only viewer. No new plaintext file was written. Choose Forget to clear the visible content.');
  return;
 }
 if(!ui['plaintext-ack'].checked||!confirm('Deliberately prepare sensitive PRIVATE plaintext for approved local storage? No authentication, consent, verified fix or authorization is conferred.'))throw Error('Plaintext disclosure not approved.');
 const suffix=source.meta.content_type==='text/markdown'?'.md':'.json';
 output(source.plain,'lightup-PRIVATE-human-restored'+suffix,source.meta.content_type+';charset=utf-8');
 source.inner.fill(0);status('PRIVATE plaintext download ready. Store securely and delete all unneeded copies separately.');
}
ui.run.addEventListener('click',async()=>{
 ui.run.disabled=true;clearLink();clearViewer();status('Local cryptography in progress; no network call is made.');
 try{await run();}catch(err){status('HOLD: '+err.message,true);}
 finally{for(const id of ['old-password','new-password','confirmation'])ui[id].value='';ui.run.disabled=false;}
});
ui.operation.addEventListener('change',update);
ui.source.addEventListener('change',()=>{clearLink();clearViewer();});
ui.forget.addEventListener('click',()=>{clearLink();clearViewer();ui.source.value='';for(const id of ['old-password','new-password','confirmation'])ui[id].value='';ui['plaintext-ack'].checked=false;status('File reference and temporary download forgotten from this page. Previously downloaded copies need separate handling.');});
update();
})();