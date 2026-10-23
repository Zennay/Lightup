"use strict";
/* LightUp offline HUMAN CSV envelope v1.
 * This protects confidentiality/integrity of the HUMAN CSV with a passphrase;
 * it does not authenticate the original lab source, a sender, consent or grant.
 */
(() => {
  const MAGIC = new Uint8Array([76,85,72,85,77,48,48,49]); // LUHUM001
  const HEADER = 68; // 8-byte purpose/version + 16-byte salt + 12-byte IV + 32-byte receipt SHA256
  const MAX_CSV = 256 * 1024;
  const MAX_VAULT = HEADER + MAX_CSV + 16;
  const ROUNDS = 600000;
  function requireValid(ok) { if (!ok) throw new Error("PRIVATE HUMAN vault HOLD"); }
  function digestBytes(hex) {
    requireValid(typeof hex === "string" && /^[a-f0-9]{64}$/u.test(hex));
    return new Uint8Array(hex.match(/.{2}/gu).map(x => parseInt(x, 16)));
  }
  function passphraseValid(value) {
    return typeof value === "string" && value.length >= 14 && value.length <= 256 &&
           !/[\u0000-\u001f\u007f]/u.test(value);
  }
  async function derive(password, salt, usages) {
    requireValid(passphraseValid(password));
    requireValid(globalThis.isSecureContext && crypto && crypto.subtle);
    const pw = new TextEncoder().encode(password);
    try {
      const imported = await crypto.subtle.importKey("raw", pw, "PBKDF2", false, ["deriveKey"]);
      return await crypto.subtle.deriveKey(
        {name:"PBKDF2", salt, iterations:ROUNDS, hash:"SHA-256"},
        imported, {name:"AES-GCM",length:256}, false, usages);
    } finally { pw.fill(0); }
  }
  async function seal(csv, password, receiptSha) {
    requireValid(typeof csv === "string");
    const plain = new TextEncoder().encode(csv);
    try {
      requireValid(plain.length > 0 && plain.length <= MAX_CSV);
      const header = new Uint8Array(HEADER);
      header.set(MAGIC);
      header.set(crypto.getRandomValues(new Uint8Array(16)), 8);
      header.set(crypto.getRandomValues(new Uint8Array(12)), 24);
      header.set(digestBytes(receiptSha), 36);
      const key = await derive(password, header.subarray(8,24), ["encrypt"]);
      const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
        {name:"AES-GCM",iv:header.subarray(24,36),
         additionalData:header,tagLength:128},key,plain));
      requireValid(ciphertext.length === plain.length + 16);
      const vault = new Uint8Array(HEADER + ciphertext.length);
      vault.set(header);
      vault.set(ciphertext, HEADER);
      return vault;
    } finally { plain.fill(0); }
  }
  async function open(bytes, password, expectedSha) {
    requireValid(bytes instanceof ArrayBuffer && bytes.byteLength > HEADER + 16 &&
                 bytes.byteLength <= MAX_VAULT);
    const packed = new Uint8Array(bytes);
    const header = packed.subarray(0,HEADER);
    requireValid(MAGIC.every((b,i) => header[i] === b));
    const digest = digestBytes(expectedSha);
    let difference = 0;
    for (let i = 0; i < 32; ++i) difference |= digest[i] ^ header[36+i];
    requireValid(difference === 0);
    const key = await derive(password, header.subarray(8,24), ["decrypt"]);
    const clear = new Uint8Array(await crypto.subtle.decrypt(
      {name:"AES-GCM",iv:header.subarray(24,36),
       additionalData:header,tagLength:128},key,packed.subarray(HEADER)));
    try {
      requireValid(clear.length > 0 && clear.length <= MAX_CSV);
      return new TextDecoder("utf-8",{fatal:true}).decode(clear);
    } finally { clear.fill(0); }
  }
  const BUNDLE_MAGIC = new Uint8Array([76,85,72,66,80,48,48,49]); // LUHBP001
  const BUNDLE_HEADER = 36; // magic8 | salt16 | nonce12
  const CONTENT_HEADER = 16; // LUHBP001 | receipt length u32be | csv length u32be
  const MAX_RECEIPT = 256 * 1024;
  const MAX_BUNDLE = BUNDLE_HEADER + CONTENT_HEADER + MAX_RECEIPT + MAX_CSV + 16;

  function u32(target, at, value) {
    requireValid(Number.isInteger(value) && value >= 0 && value <= 0xffffffff);
    new DataView(target.buffer).setUint32(at, value, false);
  }
  async function sealBundle(receiptArrayBuffer, csv, password) {
    requireValid(receiptArrayBuffer instanceof ArrayBuffer && typeof csv === "string");
    const receipt = new Uint8Array(receiptArrayBuffer);
    const notes = new TextEncoder().encode(csv);
    let clear;
    try {
      requireValid(receipt.byteLength > 0 && receipt.byteLength <= MAX_RECEIPT);
      requireValid(notes.byteLength > 0 && notes.byteLength <= MAX_CSV);
      clear = new Uint8Array(CONTENT_HEADER + receipt.byteLength + notes.byteLength);
      clear.set(BUNDLE_MAGIC);
      u32(clear, 8, receipt.byteLength);
      u32(clear, 12, notes.byteLength);
      clear.set(receipt, CONTENT_HEADER);
      clear.set(notes, CONTENT_HEADER + receipt.byteLength);
      const header = new Uint8Array(BUNDLE_HEADER);
      header.set(BUNDLE_MAGIC);
      header.set(crypto.getRandomValues(new Uint8Array(16)), 8);
      header.set(crypto.getRandomValues(new Uint8Array(12)), 24);
      const key = await derive(password, header.subarray(8, 24), ["encrypt"]);
      const encrypted = new Uint8Array(await crypto.subtle.encrypt({
        name:"AES-GCM",iv:header.subarray(24, 36),additionalData:header,tagLength:128
      }, key, clear));
      requireValid(encrypted.byteLength === clear.byteLength + 16);
      const packet = new Uint8Array(BUNDLE_HEADER + encrypted.byteLength);
      packet.set(header);
      packet.set(encrypted, BUNDLE_HEADER);
      return packet;
    } finally {
      notes.fill(0);
      if (clear) clear.fill(0);
    }
  }
  async function openBundle(data, password) {
    requireValid(data instanceof ArrayBuffer &&
      data.byteLength > BUNDLE_HEADER + CONTENT_HEADER + 16 &&
      data.byteLength <= MAX_BUNDLE);
    const packet = new Uint8Array(data);
    const header = packet.subarray(0, BUNDLE_HEADER);
    requireValid(BUNDLE_MAGIC.every((b,i) => header[i] === b));
    const key = await derive(password, header.subarray(8,24), ["decrypt"]);
    const plain = new Uint8Array(await crypto.subtle.decrypt({
      name:"AES-GCM", iv:header.subarray(24,36),additionalData:header,tagLength:128
    }, key, packet.subarray(BUNDLE_HEADER)));
    try {
      requireValid(plain.byteLength >= CONTENT_HEADER + 2);
      requireValid(BUNDLE_MAGIC.every((b,i) => plain[i] === b));
      const view = new DataView(plain.buffer, plain.byteOffset, plain.byteLength);
      const receiptLen = view.getUint32(8, false), notesLen = view.getUint32(12, false);
      requireValid(receiptLen > 0 && receiptLen <= MAX_RECEIPT &&
                   notesLen > 0 && notesLen <= MAX_CSV &&
                   plain.byteLength === CONTENT_HEADER + receiptLen + notesLen);
      const receipt = plain.slice(CONTENT_HEADER, CONTENT_HEADER + receiptLen).buffer;
      const csv = new TextDecoder("utf-8", {fatal:true}).decode(
        plain.subarray(CONTENT_HEADER + receiptLen));
      return {receipt, csv};
    } finally { plain.fill(0); }
  }
  Object.defineProperty(globalThis,"LightUpHumanVault",{
    value:Object.freeze({seal,open,sealBundle,openBundle,maxVaultBytes:MAX_VAULT,maxBundleBytes:MAX_BUNDLE}),
    enumerable:false,configurable:false,writable:false
  });
})();
