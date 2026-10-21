"use strict";
/*
 * LightUp PRIVATE offline courier, non-authorizing transport only.
 * AES-256-GCM with fresh per-envelope nonce and salt; PBKDF2-SHA-256 310k.
 * No network, cookies, storage, auto-execution, tenant/auth/grant/scan logic.
 * A passphrase is NOT proof of actual reviewer or source-producer identity.
 */
(() => {
  const MAX_BYTES = 2 * 1024 * 1024;
  const MAX_ENVELOPE = MAX_BYTES + 4096;
  const MAGIC = new Uint8Array([76, 85, 72, 82, 0, 1, 0, 0]); // LUHR v1
  const HEADER = 40;
  const sealInput = document.getElementById("plainInput");
  const openInput = document.getElementById("vaultInput");
  const pwBox = document.getElementById("entryA");
  const confirmBox = document.getElementById("entryB");
  const digestExpected = document.getElementById("expectedDigest");
  const message = document.getElementById("message");
  const lockBtn = document.getElementById("seal");
  const unlockBtn = document.getElementById("open");
  let busy = false;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", {fatal: true});
  const validName = name => typeof name === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9_.-]{0,119}$/.test(name) &&
    !name.includes("..") && /\.(?:html|csv|json|zip)$/i.test(name);
  function say(value) { message.textContent = value; }
  async function sha256(bytes) {
    const raw = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
    return Array.from(raw, x => x.toString(16).padStart(2, "0")).join("");
  }
  function exclusive(f) {
    return async () => {
      if (busy) return;
      busy = true; lockBtn.disabled = true; unlockBtn.disabled = true;
      try { await f(); }
      catch (_) {
        say("HOLD: invalid or untrusted private file, wrong password or unsupported browser. Existing files and source data were not changed.");
      } finally {
        busy = false; lockBtn.disabled = false; unlockBtn.disabled = false;
      }
    };
  }
  function acceptPass(pass) {
    const size = encoder.encode(pass).byteLength;
    if (size < 12 || size > 1024) throw Error("weak or oversized passphrase");
    return pass;
  }
  async function derive(pass, salt) {
    const base = await crypto.subtle.importKey("raw", encoder.encode(acceptPass(pass)),
      "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({
      name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256"
    }, base, {name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"]);
  }
  function choose(file, sizeLimit) {
    if (!file || !Number.isSafeInteger(file.size) || file.size < 1 ||
      file.size > sizeLimit) throw Error("missing, empty or oversized private file");
    return file;
  }
  function save(filename, bytes, mime) {
    if (!validName(filename) && !filename.endsWith(".luhr")) {
      throw Error("invalid PRIVATE output filename");
    }
    const url = URL.createObjectURL(new Blob([bytes], {type: mime}));
    const link = document.createElement("a");
    link.href = url; link.download = filename;
    link.rel = "noopener";
    document.body.appendChild(link);
    link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }
  function bytesForFile(file) {
    if (!validName(file.name)) throw Error("unsafe original private filename");
    return file.arrayBuffer().then(data => new Uint8Array(data));
  }
  async function seal() {
    if (!crypto?.subtle || !crypto.getRandomValues) throw Error("WebCrypto unavailable");
    const file = choose(sealInput.files?.[0], MAX_BYTES);
    const pass = acceptPass(pwBox.value);
    if (pass !== confirmBox.value) throw Error("password confirmation mismatch");
    const name = encoder.encode(file.name);
    if (!validName(file.name) || name.length > 120) throw Error("unsafe private filename");
    const sourceBytes = await bytesForFile(file);
    const plain = new Uint8Array(2 + name.length + sourceBytes.length);
    new DataView(plain.buffer).setUint16(0, name.length, false);
    plain.set(name, 2); plain.set(sourceBytes, 2 + name.length);
    const header = new Uint8Array(HEADER);
    header.set(MAGIC);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    header.set(salt, 8); header.set(nonce, 24);
    new DataView(header.buffer).setUint32(36, plain.length, false);
    const key = await derive(pass, salt);
    const encrypted = new Uint8Array(await crypto.subtle.encrypt({
      name: "AES-GCM", iv: nonce, additionalData: header, tagLength: 128
    }, key, plain));
    const out = new Uint8Array(HEADER + encrypted.length);
    out.set(header); out.set(encrypted, HEADER);
    plain.fill(0); sourceBytes.fill(0);
    const fingerprint = await sha256(out);
    // No customer source, grants, consent or reviewer role is authenticated here.
    if (!confirm("Save an encrypted PRIVATE handoff? Share the passphrase through a different authenticated channel. Encryption alone is NOT client/operator authorization.")) return;
    save("LightUp-PRIVATE-HUMAN-handoff.luhr", out, "application/octet-stream");
    say("Encrypted PRIVATE courier file prepared. Envelope SHA-256: " + fingerprint + "\nShare this digest separately through an independently authenticated channel, if desired. This is not sender verification or authorization.");
    pwBox.value = ""; confirmBox.value = "";
    sealInput.value = "";
  }
  async function open() {
    if (!crypto?.subtle) throw Error("WebCrypto unavailable");
    const file = choose(openInput.files?.[0], MAX_ENVELOPE);
    if (!file.name.toLowerCase().endsWith(".luhr")) throw Error("not a courier envelope");
    const pass = acceptPass(pwBox.value);
    const blob = new Uint8Array(await file.arrayBuffer());
    const actualDigest = await sha256(blob);
    const expected = digestExpected.value.trim().toLowerCase();
    if (expected && (!/^[0-9a-f]{64}$/.test(expected) || expected !== actualDigest)) {
      throw Error("unauthenticated envelope fingerprint mismatch");
    }
    if (blob.length < HEADER + 16) throw Error("short envelope");
    if (!MAGIC.every((v, i) => v === blob[i])) throw Error("wrong envelope version");
    const header = blob.subarray(0, HEADER);
    const declared = new DataView(blob.buffer, blob.byteOffset, blob.byteLength).getUint32(36, false);
    if (declared < 4 || declared > MAX_BYTES + 122 || blob.length !== HEADER + declared + 16) {
      throw Error("invalid authenticated plaintext length");
    }
    const key = await derive(pass, header.subarray(8, 24));
    const plain = new Uint8Array(await crypto.subtle.decrypt({
      name: "AES-GCM", iv: header.subarray(24, 36), additionalData: header,
      tagLength: 128
    }, key, blob.subarray(HEADER)));
    if (plain.length !== declared) throw Error("plaintext length drift");
    const nameLen = new DataView(plain.buffer, plain.byteOffset, plain.byteLength).getUint16(0, false);
    if (nameLen < 1 || nameLen > 120 || 2 + nameLen >= plain.length) {
      throw Error("invalid encrypted filename");
    }
    const originalName = decoder.decode(plain.subarray(2, 2 + nameLen));
    if (!validName(originalName)) throw Error("unsafe decrypted filename");
    const data = plain.subarray(2 + nameLen);
    if (data.length > MAX_BYTES) throw Error("oversized decrypted file");
    if (!confirm("Decrypt this locally authenticated AES-GCM payload? The content and sender are NOT independently trusted. Save privately; do not open HTML from unknown people.")) { plain.fill(0); return; }
    save(originalName, data, "application/octet-stream");
    say("PRIVATE original file downloaded without automatic execution. Envelope SHA-256: " + actualDigest + "\nAn independently supplied matching digest is only a byte-comparison, not an authenticated sender or scope grant.");
    pwBox.value = ""; confirmBox.value = ""; openInput.value = "";
    plain.fill(0);
  }
  lockBtn.addEventListener("click", exclusive(seal));
  unlockBtn.addEventListener("click", exclusive(open));
  if (!globalThis.isSecureContext || !globalThis.crypto?.subtle) {
    say("HOLD: WebCrypto secure context unavailable in this browser. Open the file locally in a supported browser; no remote hosting is required.");
    lockBtn.disabled = true; unlockBtn.disabled = true;
  }
})();