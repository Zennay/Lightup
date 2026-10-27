"use strict";
/* Original LightUp PRIVATE HUMAN v1 plan envelope writer (local only).
 * Compatible with unmodified original #1667 private-plan-crypto.js.
 * Encryption provides confidentiality/integrity relative to a local password,
 * NOT original-source authentication, independent review or permission. */
async function encryptOriginalHumanPlan(plain, passphrase) {
  const fail=ok=>{if(!ok)throw Error("HOLD: invalid PRIVATE encrypted HUMAN plan export");};
  fail(globalThis.crypto&&crypto.subtle&&crypto.getRandomValues);
  fail(typeof plain==="string");
  fail(typeof passphrase==="string"&&passphrase.length>=12&&passphrase.length<=256&&
    !/[\u0000-\u001f\u007f]/.test(passphrase));
  const bytes=new TextEncoder().encode(plain);
  fail(bytes.length>0&&bytes.length<=3*1024*1024);
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const material=await crypto.subtle.importKey("raw",new TextEncoder().encode(passphrase),
    "PBKDF2",false,["deriveKey"]);
  const key=await crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:310000,hash:"SHA-256"},
    material,{name:"AES-GCM",length:256},false,["encrypt"]);
  const ciphertext=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv},key,bytes));
  const base64 = arr => {
    let raw="";
    for(let i=0;i<arr.length;i+=16384)
      raw+=String.fromCharCode(...arr.subarray(i,i+16384));
    return btoa(raw);
  };
  return {
    kind:"lightup.private_human_matrix_aesgcm",
    version:1,kdf:"PBKDF2-SHA256",iterations:310000,cipher:"AES-256-GCM",
    salt_b64:base64(salt),iv_b64:base64(iv),payload_b64:base64(ciphertext)
  };
}
