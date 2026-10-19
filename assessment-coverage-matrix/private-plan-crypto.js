"use strict";
/* Optional PRIVATE browser-only AES-GCM encrypted HUMAN planning envelopes.
   No network, no password persistence, no authentication, no scan authority. */
function createPrivatePlanCrypto() {
  const MAGIC="lightup.private_human_matrix_aesgcm";
  const MAX_TEXT=3*1024*1024;
  const WORKSPACE_MAGIC="lightup.private_lab_complete_workspace_aesgcm";
  const MAX_WORKSPACE_TEXT=48*1024*1024;
  const ITERATIONS=310000;
  const FIELDS=["kind","version","kdf","iterations","cipher",
    "salt_b64","iv_b64","payload_b64"];
  function assert(ok) {if(!ok)throw Error("Incompatible PRIVATE encrypted plan envelope");}
  function supported() {
    return !!(globalThis.crypto&&crypto.subtle&&crypto.getRandomValues&&
      globalThis.TextEncoder&&globalThis.TextDecoder);
  }
  function passphrase(value) {
    if(typeof value!=="string"||value.length<12||value.length>256||
      /[\u0000-\u001f\u007f]/.test(value))throw Error("Choose a PRIVATE passphrase of 12–256 characters without control characters");
    return value;
  }
  function toBase64(bytes) {
    let encoded="";
    for(let i=0;i<bytes.length;i+=16384) {
      encoded+=String.fromCharCode(...bytes.subarray(i,i+16384));
    }
    return btoa(encoded);
  }
  function fromBase64(value,maxBytes) {
    assert(typeof value==="string"&&value.length>=4&&value.length<=Math.ceil(maxBytes/3)*4+4&&
      /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value));
    const raw=atob(value);assert(raw.length<=maxBytes);
    const bytes=new Uint8Array(raw.length);
    for(let i=0;i<raw.length;i++)bytes[i]=raw.charCodeAt(i);
    assert(toBase64(bytes)===value); // reject noncanonical base64 aliases
    return bytes;
  }
  async function key(password,salt) {
    const enc=new TextEncoder();
    const material=await crypto.subtle.importKey("raw",enc.encode(passphrase(password)),
      "PBKDF2",false,["deriveKey"]);
    return crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:ITERATIONS,hash:"SHA-256"},
      material,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
  }
  async function encryptBounded(plaintext,password,kind,maxBytes) {
    if(!supported())throw Error("Browser WebCrypto is unavailable for PRIVATE encryption");
    if(typeof plaintext!=="string")throw Error("Only local HUMAN JSON text may be encrypted");
    const bytes=new TextEncoder().encode(plaintext);
    if(bytes.length===0||bytes.length>maxBytes)throw Error("PRIVATE content exceeds encryption size bound");
    const salt=crypto.getRandomValues(new Uint8Array(16));
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const derived=await key(password,salt);
    const ciphertext=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv},
      derived,bytes));
    return {kind,version:1,kdf:"PBKDF2-SHA256",iterations:ITERATIONS,
      cipher:"AES-256-GCM",salt_b64:toBase64(salt),
      iv_b64:toBase64(iv),payload_b64:toBase64(ciphertext)};
  }
  function isEncrypted(source) {
    return source!==null&&typeof source==="object"&&!Array.isArray(source)&&
      source.kind===MAGIC;
  }
  async function decryptBounded(envelope,password,kind,maxBytes) {
    if(!supported())throw Error("Browser WebCrypto unavailable for PRIVATE decryption");
    assert(envelope!==null&&typeof envelope==="object"&&!Array.isArray(envelope)&&
      Object.keys(envelope).length===FIELDS.length&&FIELDS.every(k=>Object.hasOwn(envelope,k)));
    assert(envelope.kind===kind&&envelope.version===1&&
      envelope.kdf==="PBKDF2-SHA256"&&envelope.cipher==="AES-256-GCM"&&
      envelope.iterations===ITERATIONS);
    const salt=fromBase64(envelope.salt_b64,16),iv=fromBase64(envelope.iv_b64,12);
    assert(salt.length===16&&iv.length===12);
    const cipher=fromBase64(envelope.payload_b64,maxBytes+16);
    assert(cipher.length>=17);
    try {
      const derived=await key(password,salt);
      const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv},derived,cipher);
      assert(plain.byteLength>0&&plain.byteLength<=maxBytes);
      return new TextDecoder("utf-8",{fatal:true}).decode(plain);
    } catch {
      throw Error("Cannot open PRIVATE encrypted plan: wrong passphrase, changed bytes or incompatible envelope");
    }
  }
  const encrypt=(plain,password)=>encryptBounded(plain,password,MAGIC,MAX_TEXT);
  const decrypt=(envelope,password)=>decryptBounded(envelope,password,MAGIC,MAX_TEXT);
  const encryptWorkspace=(plain,password)=>
    encryptBounded(plain,password,WORKSPACE_MAGIC,MAX_WORKSPACE_TEXT);
  const decryptWorkspace=(envelope,password)=>
    decryptBounded(envelope,password,WORKSPACE_MAGIC,MAX_WORKSPACE_TEXT);
  const isWorkspace=source=>source!==null&&typeof source==="object"&&
    !Array.isArray(source)&&source.kind===WORKSPACE_MAGIC;
  return Object.freeze({encrypt,decrypt,isEncrypted,supported,
    encryptWorkspace,decryptWorkspace,isWorkspace});
}
