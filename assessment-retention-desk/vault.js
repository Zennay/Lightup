"use strict";
/* Local-only, optional encrypted HUMAN plan continuity. Never authenticates the producer
   or authorizes scanning, retention, deletion, remediation or client operations. */
(() => {
  const bridge = window.LightUpPrivateVaultBridge;
  if (!bridge) throw Error("Original private assessment workroom must load before vault.");
  const $ = id => document.getElementById(id);
  const KIND = "lightup.private.assessment.retention.encrypted";
  const ITERATIONS = 310000;
  const PURPOSE = new TextEncoder().encode("lightup.private.assessment.retention.encrypted.v1");
  const MAX_ORIGINAL_BYTES = 131072, MAX_ENVELOPE_BYTES = 262144;
  const AUTHORITY = Object.freeze({
    authorizes_scan:false, authorizes_delete:false, verifies_finding:false,
    verifies_remediation:false, proves_consent:false, authenticates_source:false
  });
  const fields = (obj, expected) => obj && typeof obj === "object" && !Array.isArray(obj) &&
    Object.keys(obj).sort().join("|") === expected.slice().sort().join("|");
  const hex = bytes => Array.from(bytes, x => x.toString(16).padStart(2,"0")).join("");
  function unhex(value, length) {
    if (typeof value !== "string" || value.length !== length*2 ||
        !/^[a-f0-9]+$/.test(value)) throw Error("Ongeldige cryptografische parameters.");
    const bytes = new Uint8Array(length);
    for (let i=0;i<length;i++) bytes[i] = parseInt(value.slice(i*2,i*2+2),16);
    return bytes;
  }
  function base64(bytes) {
    let b = "";
    for (let i=0;i<bytes.length;i+=4096)
      b += String.fromCharCode(...bytes.subarray(i,i+4096));
    return btoa(b);
  }
  function unbase64(value) {
    if (typeof value !== "string" || value.length > 200000 || value.length < 24 ||
        value.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value))
      throw Error("Ongeldige ciphertext.");
    const str = atob(value);
    if (btoa(str) !== value) throw Error("Niet-canonieke ciphertext.");
    const bytes = new Uint8Array(str.length);
    for (let i=0;i<str.length;i++) bytes[i] = str.charCodeAt(i);
    if (bytes.length < 17 || bytes.length > MAX_ORIGINAL_BYTES + 16)
      throw Error("Onveilige grootte van versleuteld plan.");
    return bytes;
  }
  function takePassword() {
    const input = $("vault-password");
    const password = input.value;
    input.value = "";
    const encoded = new TextEncoder().encode(password);
    if (password.length < 12 || password.length > 128 || encoded.length > 256 ||
        /[\u0000-\u001f\u007f-\u009f]/u.test(password))
      throw Error("Privéwachtwoord vereist 12–128 tekens, maximaal 256 UTF-8 bytes, zonder stuurtekens.");
    if (!globalThis.crypto || !crypto.subtle || !crypto.getRandomValues)
      throw Error("WebCrypto niet beschikbaar op deze vertrouwde browsercontext.");
    return encoded;
  }
  async function derive(pass, salt) {
    const imported = await crypto.subtle.importKey("raw", pass, "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      {name:"PBKDF2", hash:"SHA-256", salt, iterations:ITERATIONS},
      imported, {name:"AES-GCM", length:256}, false, ["encrypt","decrypt"]);
  }
  function download(name, json) {
    const url = URL.createObjectURL(new Blob([json],{type:"application/json"}));
    const anchor = document.createElement("a");
    anchor.href = url; anchor.download = name; anchor.hidden = true;
    document.body.append(anchor); anchor.click(); anchor.remove();
    setTimeout(()=>URL.revokeObjectURL(url),30000);
  }
  function enter() {
    if (bridge.busy()) throw Error("Een andere bestandsbewerking loopt nog.");
    bridge.setBusy(true);
  }
  function leave() {
    $("vault-password").value = "";
    $("vault-import").value = "";
    $("vault-compare").value = "";
    bridge.setBusy(false);
  }
  async function exportVault() {
    let payload;
    let acquired = false;
    try {
      // Verify source and HUMAN records before setting busy.
      const original = bridge.snapshot();
      const pass = takePassword();
      enter(); acquired = true;
      const plain = new TextEncoder().encode(JSON.stringify(original));
      if (!plain.length || plain.length > MAX_ORIGINAL_BYTES) throw Error("HUMAN-plan te groot.");
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const key = await derive(pass, salt);
      payload = new Uint8Array(await crypto.subtle.encrypt(
        {name:"AES-GCM",iv:nonce,additionalData:PURPOSE,tagLength:128},key,plain));
      const envelope = {
        kind:KIND, version:1, algorithm:"PBKDF2-SHA256/AES-256-GCM",
        iterations:ITERATIONS, salt:hex(salt), nonce:hex(nonce),
        ciphertext:base64(payload), authority:AUTHORITY
      };
      download("lightup-private-human-retention.lurt",JSON.stringify(envelope));
      bridge.notify("Volledige PRIVATE HUMAN-planning AES-256-GCM versleuteld opgeslagen. Geen bron- of consentauthenticatie.");
    } catch(e) {
      bridge.notify("HOLD: PRIVATE versleuteling geweigerd: " + e.message, true);
    } finally {
      if (acquired) leave(); else $("vault-password").value = "";
    }
  }
  async function decryptEnvelope(file, pass) {
    if (file.size < 1 || file.size > MAX_ENVELOPE_BYTES)
      throw Error("Versleuteld bestand is leeg of groter dan 256 KiB.");
    const json = await file.text();
    let receipt;
    try { receipt = JSON.parse(json); } catch { throw Error("Ongeldig versleuteld JSON."); }
    if (JSON.stringify(receipt) !== json.trim() ||
        !fields(receipt,["kind","version","algorithm","iterations","salt","nonce","ciphertext","authority"]) ||
        receipt.kind !== KIND || receipt.version !== 1 ||
        receipt.algorithm !== "PBKDF2-SHA256/AES-256-GCM" ||
        receipt.iterations !== ITERATIONS ||
        !fields(receipt.authority,Object.keys(AUTHORITY)) ||
        Object.keys(AUTHORITY).some(k=>receipt.authority[k] !== false))
      throw Error("Niet-canoniek PRIVATE vaultcontract of ongeoorloofde bevoegdheidsclaim.");
    const salt = unhex(receipt.salt,16);
    const nonce = unhex(receipt.nonce,12);
    const ciphertext = unbase64(receipt.ciphertext);
    let decrypted;
    try {
      const key = await derive(pass,salt);
      decrypted = await crypto.subtle.decrypt(
        {name:"AES-GCM",iv:nonce,additionalData:PURPOSE,tagLength:128},key,ciphertext);
    } catch {
      throw Error("Verkeerd wachtwoord of gewijzigde cryptografische inhoud.");
    }
    return new TextDecoder("utf-8",{fatal:true}).decode(decrypted);
  }
  async function importVault(event) {
    let acquired = false;
    try {
      const file = event.target.files?.[0];
      if (!file) return;
      const pass = takePassword();
      enter(); acquired = true;
      const original = await decryptEnvelope(file, pass);
      // Exact original source SHA/size admission and separate HUMAN confirmation
      // remain exclusively in the original offline workroom bridge.
      bridge.restore(original,"versleutelde PRIVATE HUMAN-ontvangst");
    } catch(e) {
      bridge.notify("HOLD: versleutelde HUMAN-heropening geweigerd: " + e.message +
        " Bestaande PRIVATE keuzes blijven intact.",true);
    } finally {
      if (acquired) leave(); else { $("vault-password").value = ""; $("vault-import").value = ""; }
    }
  }
  $("export-vault").addEventListener("click",exportVault);
  $("vault-import").addEventListener("change",importVault);
  async function compareVault(event) {
    let acquired = false;
    try {
      const file = event.target.files?.[0];
      if (!file) return;
      // Current genuine original source files must already be selected.
      bridge.snapshot();
      const pass = takePassword();
      enter(); acquired = true;
      const original = await decryptEnvelope(file, pass);
      bridge.compare(original);  // validates exact entire current original source set, no change.
    } catch(e) {
      bridge.notify("HOLD: versleutelde PRIVATE vergelijking geweigerd: " + e.message +
        " Geen HUMAN-velden gewijzigd.",true);
    } finally {
      if (acquired) leave(); else { $("vault-password").value = ""; $("vault-compare").value = ""; }
    }
  }
  $("vault-compare").addEventListener("change",compareVault);
})();