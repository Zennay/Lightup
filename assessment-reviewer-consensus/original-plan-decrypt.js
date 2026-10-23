"use strict";
/* READ-ONLY compatibility with original PR #1667 encrypted PRIVATE HUMAN v1 plans.
 * This is not source authentication, client permission or an execution capability.
 * All decryption occurs locally; no plan or passphrase is transmitted/stored. */
const LIGHTUP_ORIGINAL_ENCRYPTED_PLAN_KIND = "lightup.private_human_matrix_aesgcm";
async function decryptOriginalHumanPlan(envelope, passphrase) {
  const keys=["kind","version","kdf","iterations","cipher","salt_b64","iv_b64","payload_b64"];
  const fail=(ok)=>{if(!ok)throw Error("HOLD: incompatible encrypted PRIVATE HUMAN plan");};
  fail(envelope!==null&&typeof envelope==="object"&&!Array.isArray(envelope)&&
    Object.keys(envelope).length===keys.length&&keys.every(k=>Object.hasOwn(envelope,k)));
  fail(envelope.kind===LIGHTUP_ORIGINAL_ENCRYPTED_PLAN_KIND&&
    envelope.version===1&&envelope.kdf==="PBKDF2-SHA256"&&
    envelope.iterations===310000&&envelope.cipher==="AES-256-GCM");
  fail(globalThis.crypto&&crypto.subtle&&crypto.getRandomValues&&
    globalThis.TextEncoder&&globalThis.TextDecoder);
  fail(typeof passphrase==="string"&&passphrase.length>=12&&passphrase.length<=256&&
    !/[\u0000-\u001f\u007f]/.test(passphrase));
  const maxText=3*1024*1024;
  const base64ToBytes=(value, limit)=>{
    fail(typeof value==="string"&&value.length>=4&&
      value.length<=Math.ceil(limit/3)*4+4&&
      /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value));
    const raw=atob(value);
    fail(raw.length<=limit);
    const bytes=new Uint8Array(raw.length);
    for(let i=0;i<raw.length;i++)bytes[i]=raw.charCodeAt(i);
    let canonical="";
    for(let i=0;i<bytes.length;i+=16384)canonical+=String.fromCharCode(...bytes.subarray(i,i+16384));
    fail(btoa(canonical)===value);
    return bytes;
  };
  const salt=base64ToBytes(envelope.salt_b64,16);
  const iv=base64ToBytes(envelope.iv_b64,12);
  const ciphertext=base64ToBytes(envelope.payload_b64,maxText+16);
  fail(salt.length===16&&iv.length===12&&ciphertext.length>=17);
  try {
    const material=await crypto.subtle.importKey("raw",new TextEncoder().encode(passphrase),
      "PBKDF2",false,["deriveKey"]);
    const key=await crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:310000,hash:"SHA-256"},
      material,{name:"AES-GCM",length:256},false,["decrypt"]);
    const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv},key,ciphertext);
    fail(plain.byteLength>0&&plain.byteLength<=maxText);
    return new TextDecoder("utf-8",{fatal:true}).decode(plain);
  } catch {
    throw Error("HOLD: wrong PRIVATE plan passphrase, changed bytes or unsupported source");
  }
}
