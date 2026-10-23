"use strict";
/* Offline PRIVATE reviewer workspace transport. Not original producer evidence or authority.
 * Own domain-separation AAD prevents reinterpretation as an original HUMAN plan envelope.
 * Payloads can contain original PRIVATE source SHA256 and all reviewer HUMAN choices.
 */
const LIGHTUP_REVIEWER_WORKSPACE_KIND="lightup.private_reviewer_consensus_workspace_aesgcm";
const LIGHTUP_REVIEWER_WORKSPACE_AAD="lightup.private_reviewer_consensus_workspace_aesgcm|v1";
const LIGHTUP_REVIEWER_WORKSPACE_TEXT_LIMIT=28*1024*1024;
const LIGHTUP_REVIEWER_WORKSPACE_CIPHER_LIMIT=LIGHTUP_REVIEWER_WORKSPACE_TEXT_LIMIT+16;
function reviewerWorkspaceEnvelopeFields(obj){
  const keys=["kind","version","kdf","iterations","cipher","salt_b64","iv_b64","payload_b64"];
  return obj!==null&&typeof obj==="object"&&!Array.isArray(obj)&&
    Object.keys(obj).length===keys.length&&keys.every(k=>Object.hasOwn(obj,k));
}
function reviewerWorkspacePassword(password){
  if(typeof password!=="string"||password.length<12||password.length>256||
    /[\u0000-\u001f\u007f]/.test(password))
    throw Error("Choose a local passphrase 12–256 characters without control characters");
  return password;
}
function reviewerBytesToBase64(bytes){
  let text="";
  for(let i=0;i<bytes.length;i+=16384)
    text+=String.fromCharCode(...bytes.subarray(i,i+16384));
  return btoa(text);
}
function reviewerBase64ToBytes(text,max){
  if(typeof text!=="string"||text.length<4||
    text.length>Math.ceil(max/3)*4+4||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text))
    throw Error("Invalid bounded PRIVATE reviewer workspace encoding");
  const decoded=atob(text);
  if(decoded.length>max)throw Error("PRIVATE reviewer workspace exceeds bounded input");
  const bytes=Uint8Array.from(decoded,char=>char.charCodeAt(0));
  if(reviewerBytesToBase64(bytes)!==text)
    throw Error("Noncanonical PRIVATE reviewer workspace encoding");
  return bytes;
}
async function reviewerWorkspaceKey(password,salt){
  if(!globalThis.crypto||!crypto.subtle||!crypto.getRandomValues)
    throw Error("Local WebCrypto is unavailable");
  const encoded=new TextEncoder().encode(reviewerWorkspacePassword(password));
  const material=await crypto.subtle.importKey("raw",encoded,"PBKDF2",false,["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:310000,
    hash:"SHA-256"},material,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
}
async function sealReviewerWorkspace(text,password) {
  if(typeof text!=="string")throw Error("Invalid PRIVATE workspace body");
  const payload=new TextEncoder().encode(text);
  if(!payload.length||payload.length>LIGHTUP_REVIEWER_WORKSPACE_TEXT_LIMIT)
    throw Error("PRIVATE review bundle exceeds 28 MiB");
  reviewerWorkspacePassword(password);
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const key=await reviewerWorkspaceKey(password,salt);
  const aad=new TextEncoder().encode(LIGHTUP_REVIEWER_WORKSPACE_AAD);
  const encrypted=new Uint8Array(await crypto.subtle.encrypt({
    name:"AES-GCM",iv,additionalData:aad},key,payload));
  return {kind:LIGHTUP_REVIEWER_WORKSPACE_KIND,version:1,kdf:"PBKDF2-SHA256",
    iterations:310000,cipher:"AES-256-GCM",salt_b64:reviewerBytesToBase64(salt),
    iv_b64:reviewerBytesToBase64(iv),payload_b64:reviewerBytesToBase64(encrypted)};
}
async function unsealReviewerWorkspace(envelope,password) {
  if(!reviewerWorkspaceEnvelopeFields(envelope)||
    envelope.kind!==LIGHTUP_REVIEWER_WORKSPACE_KIND||envelope.version!==1||
    envelope.kdf!=="PBKDF2-SHA256"||envelope.iterations!==310000||
    envelope.cipher!=="AES-256-GCM")
    throw Error("Unsupported PRIVATE reviewer workspace envelope; cannot admit");
  const salt=reviewerBase64ToBytes(envelope.salt_b64,16);
  const iv=reviewerBase64ToBytes(envelope.iv_b64,12);
  const ct=reviewerBase64ToBytes(envelope.payload_b64,LIGHTUP_REVIEWER_WORKSPACE_CIPHER_LIMIT);
  if(salt.length!==16||iv.length!==12||ct.length<17)
    throw Error("Invalid bounded PRIVATE reviewer workspace nonce/salt/payload");
  const key=await reviewerWorkspaceKey(password,salt);
  const aad=new TextEncoder().encode(LIGHTUP_REVIEWER_WORKSPACE_AAD);
  try{
    const payload=await crypto.subtle.decrypt({name:"AES-GCM",iv,additionalData:aad},key,ct);
    if(!payload.byteLength||payload.byteLength>LIGHTUP_REVIEWER_WORKSPACE_TEXT_LIMIT)
      throw Error("Workspace size HOLD");
    return new TextDecoder("utf-8",{fatal:true}).decode(payload);
  }catch{
    throw Error("Cannot open PRIVATE reviewer workspace: wrong passphrase, changed ciphertext or incompatible content");
  }
}
