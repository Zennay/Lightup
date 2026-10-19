/* Optional local private HUMAN workspace AES-GCM vault.
 * A derived encryption key binds the ciphertext to exact imported original CSV source bytes.
 * Neither a password nor a ciphertext establishes authenticated sender/client authorization.
 */
(function(global) {
'use strict';
const KIND='lightup.private_human_ticket_vault';
const ROUNDS=600000, MAX_VAULT_BYTES=8*1024*1024, MAX_CLEAR_BYTES=4*1024*1024;
const te=new TextEncoder();
const td=new TextDecoder('utf-8',{fatal:true});
function sourceAAD(state){
 if(!state||typeof state.canonical!=='string'||typeof state.bytesHash!=='string'||
 !/^[a-f0-9]{64}$/.test(state.canonical)||!/^[a-f0-9]{64}$/.test(state.bytesHash))
 throw Error('First load exact original LightUp source CSV.');
 return te.encode(KIND+'|v1|'+state.canonical+'|'+state.bytesHash);
}
function secret(passphrase){
 if(typeof passphrase!=='string'||passphrase.length<12||passphrase.length>256||
 /[\u0000-\u001f\u007f\u202a-\u202e\u2060-\u206f\ufeff]/u.test(passphrase))
 throw Error('Choose a private passphrase of 12–256 characters without control/hidden Unicode characters.');
 return passphrase;
}
function b64(data){
 let parts=[];
 for(let i=0;i<data.length;i+=0x4000)
  parts.push(String.fromCharCode(...data.slice(i,i+0x4000)));
 return btoa(parts.join(''));
}
function bytes(s,max,name){
 if(typeof s!=='string'||s.length>max*2||s.length%4||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s))
  throw Error('Invalid '+name+' encoding.');
 let raw;
 try{raw=atob(s);}catch{throw Error('Invalid '+name+' base64.');}
 if(raw.length>max)throw Error('Encrypted '+name+' exceeds capacity.');
 const dst=new Uint8Array(raw.length);for(let i=0;i<raw.length;i++)dst[i]=raw.charCodeAt(i);
 if(b64(dst)!==s)throw Error('Noncanonical '+name+' base64.');
 return dst;
}
async function key(passphrase,salt){
 if(!global.crypto?.subtle||!global.crypto?.getRandomValues)throw Error('Web Crypto unavailable: cannot save encrypted vault.');
 const base=await crypto.subtle.importKey('raw',te.encode(secret(passphrase)),'PBKDF2',false,['deriveKey']);
 return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:ROUNDS,hash:'SHA-256'},
 base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
async function seal(plaintext,passphrase,state){
 const aad=sourceAAD(state);secret(passphrase);
 if(typeof plaintext!=='string')throw Error('Expected PRIVATE HUMAN checkpoint text.');
 const clear=te.encode(plaintext);
 if(clear.byteLength>MAX_CLEAR_BYTES)throw Error('PRIVATE plaintext workspace exceeds 4 MiB.');
 const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));
 const secretKey=await key(passphrase,salt);
 const sealed=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad,tagLength:128},secretKey,clear);
 const output={kind:KIND,schema_version:1,disposition:'ENCRYPTED_PRIVATE_HUMAN_ONLY',
 kdf:'PBKDF2-SHA256',iterations:ROUNDS,cipher:'AES-256-GCM',tag_bits:128,
 salt_b64:b64(salt),iv_b64:b64(iv),ciphertext_b64:b64(new Uint8Array(sealed)),
 warning:'Locally encrypted HUMAN-only draft, no authenticated identity, authorization, verified fix, retest or release.'};
 const text=JSON.stringify(output,null,2)+'\n';
 if(te.encode(text).byteLength>MAX_VAULT_BYTES)throw Error('PRIVATE encrypted vault exceeds 8 MiB.');
 return text;
}
async function open(vaultText,passphrase,state){
 const aad=sourceAAD(state);secret(passphrase);
 if(typeof vaultText!=='string'||te.encode(vaultText).byteLength>MAX_VAULT_BYTES)throw Error('PRIVATE vault exceeds 8 MiB.');
 if(!global.LightUpTicketIntake?.parsePrivateJSON)throw Error('Source-bound duplicate-safe intake unavailable.');
 // The outer envelope is not trusted. Exact keys, algorithm version and bounds precede costly KDF.
 const p=global.LightUpTicketIntake.parsePrivateJSON(vaultText,MAX_VAULT_BYTES);
 const expected=['kind','schema_version','disposition','kdf','iterations','cipher','tag_bits','salt_b64','iv_b64','ciphertext_b64','warning'];
 if(!p||typeof p!=='object'||Array.isArray(p)||Object.keys(p).length!==expected.length||
 !expected.every(k=>Object.prototype.hasOwnProperty.call(p,k))||
 p.kind!==KIND||p.schema_version!==1||p.disposition!=='ENCRYPTED_PRIVATE_HUMAN_ONLY'||
 p.kdf!=='PBKDF2-SHA256'||p.iterations!==ROUNDS||p.cipher!=='AES-256-GCM'||p.tag_bits!==128||
 typeof p.warning!=='string'||p.warning.length>500)throw Error('Unsupported or malformed PRIVATE HUMAN vault header.');
 const salt=bytes(p.salt_b64,16,'salt'),iv=bytes(p.iv_b64,12,'IV');
 const ciphertext=bytes(p.ciphertext_b64,MAX_CLEAR_BYTES+16,'ciphertext');
 if(salt.length!==16||iv.length!==12||ciphertext.length<16)throw Error('Malformed vault encryption metadata.');
 const derived=await key(passphrase,salt);
 let clear;
 try{clear=await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData:aad,tagLength:128},derived,ciphertext);}
 catch{throw Error('Encrypted HUMAN vault cannot be opened for this passphrase AND exact original source CSV. HOLD.');}
 if(clear.byteLength>MAX_CLEAR_BYTES)throw Error('Decrypted PRIVATE workspace exceeds 4 MiB.');
 try{return td.decode(clear);}catch{throw Error('Decrypted PRIVATE workspace is not UTF-8.');}
}
global.LightUpTicketVault=Object.freeze({seal,open});
})(window);
