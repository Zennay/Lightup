"use strict";
/* PRIVATE encrypted HUMAN journal transport, memory-only decrypted source.
 * A passphrase authenticates ciphertext, NOT original source/client/consent.
 * Standalone companion; no target, network, persistence or grant.
 */
(function () {
  const SCHEMA = "lightup.offline_human_csv_encrypted_journal.v1";
  const TYPE = "PRIVATE_HUMAN_ONLY";
  const KDF = "PBKDF2-SHA256";
  const CIPHER = "AES-256-GCM";
  const ITERATIONS = 600000;
  const MAX_PLAIN = 512 * 1024;
  const MAX_FILE = 1024 * 1024;
  const enc = new TextEncoder();
  const dec = new TextDecoder("utf-8", {fatal: true});

  function reject() { throw new Error("Encrypted PRIVATE journal could not be admitted or opened"); }
  function exact(value, fields) {
    return value !== null && typeof value === "object" &&
      !Array.isArray(value) &&
      Object.keys(value).length === fields.length &&
      fields.every(field => Object.prototype.hasOwnProperty.call(value, field));
  }
  function to64(data) {
    let chars = "";
    for (const byte of data) chars += String.fromCharCode(byte);
    return btoa(chars);
  }
  function from64(input, len) {
    if (typeof input !== "string" || input.length > MAX_FILE * 2 ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(input)) reject();
    let bytes;
    try {
      bytes = Uint8Array.from(atob(input), character => character.charCodeAt(0));
    } catch (_) { reject(); }
    if ((len !== null && bytes.length !== len) ||
        bytes.length > MAX_FILE || to64(bytes) !== input) reject();
    return bytes;
  }
  async function derive(passphrase, salt, operations) {
    if (typeof passphrase !== "string" || passphrase.length < 12 ||
        enc.encode(passphrase).length > 1024) {
      throw new Error("Private passphrase must contain 12–1024 UTF-8 bytes");
    }
    if (!globalThis.crypto?.subtle || !globalThis.crypto.getRandomValues) {
      throw new Error("This local browser cannot provide required WebCrypto");
    }
    const raw = enc.encode(passphrase);
    try {
      const material = await crypto.subtle.importKey("raw", raw, "PBKDF2", false, ["deriveKey"]);
      return await crypto.subtle.deriveKey(
        {name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256"}, material,
        {name: "AES-GCM", length: 256}, false, operations);
    } finally {
      raw.fill(0);
    }
  }
  function admittedPlain(value) {
    const bytes = enc.encode(JSON.stringify(value, null, 2) + "\n");
    if (!bytes.length || bytes.length > MAX_PLAIN) {
      throw new Error("PRIVATE journal exceeds supported size");
    }
    return bytes;
  }
  async function seal(document, passphrase) {
    const data = admittedPlain(document);
    try {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const key = await derive(passphrase, salt, ["encrypt"]);
      const cipher = await crypto.subtle.encrypt({name: "AES-GCM", iv: nonce}, key, data);
      const obj = {
        schema: SCHEMA, classification: TYPE,
        kdf: KDF, iterations: ITERATIONS, cipher: CIPHER,
        salt: to64(salt), nonce: to64(nonce), ciphertext: to64(new Uint8Array(cipher))
      };
      return JSON.stringify(obj, null, 2) + "\n";
    } finally {
      data.fill(0);
    }
  }
  async function unseal(text, passphrase) {
    if (typeof text !== "string" || enc.encode(text).length > MAX_FILE) reject();
    let obj;
    try { obj = JSON.parse(text); } catch (_) { reject(); }
    if (!exact(obj, ["schema", "classification", "kdf", "iterations",
                     "cipher", "salt", "nonce", "ciphertext"]) ||
        obj.schema !== SCHEMA || obj.classification !== TYPE ||
        obj.kdf !== KDF || obj.iterations !== ITERATIONS ||
        obj.cipher !== CIPHER || text !== JSON.stringify(obj, null, 2) + "\n") reject();
    const salt = from64(obj.salt, 16);
    const nonce = from64(obj.nonce, 12);
    const ciphertext = from64(obj.ciphertext, null);
    if (ciphertext.length < 17 || ciphertext.length > MAX_PLAIN + 16) reject();
    let plain;
    try {
      const key = await derive(passphrase, salt, ["decrypt"]);
      plain = new Uint8Array(await crypto.subtle.decrypt({name: "AES-GCM", iv: nonce}, key, ciphertext));
      if (plain.length > MAX_PLAIN) reject();
      const raw = dec.decode(plain);
      const result = JSON.parse(raw);
      if (raw !== JSON.stringify(result, null, 2) + "\n") reject();
      return result;
    } catch (_) {
      reject();
    } finally {
      if (plain) plain.fill(0);
    }
  }
  globalThis.LightUpEncryptedJournal = Object.freeze({seal, unseal});
})();
