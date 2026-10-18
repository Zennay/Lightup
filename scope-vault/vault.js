"use strict";

/*
 * LightUp Private Scope Packet Vault — offline HUMAN REVIEW MATERIAL ONLY.
 * Cryptography protects confidentiality in transit. It grants no scope,
 * consent, actor identity, permission, scan, merge or release authority.
 * No fetch/XHR, persistent storage, service workers, or outbound links.
 */
(() => {
  const MAX_FILES = 12;
  const MAX_FILE_BYTES = 512 * 1024;
  const MAX_TOTAL_BYTES = 2 * 1024 * 1024;
  const MAX_ENVELOPE_BYTES = 3 * 1024 * 1024;
  const ROUNDS = 600000;
  const IDLE_MS = 5 * 60 * 1000;
  const ENC = new TextEncoder();
  const DEC = new TextDecoder("utf-8", {fatal: true});
  const allowed = /\.(json|md|txt|ics|csv)$/i;
  const roles = ["Unclassified", "Client proposal — unverified", "Operator review — unverified", "Scope revision — unverified", "Schedule handoff — unverified"];
  function validRole(role) { return typeof role === "string" && roles.includes(role); }
  const $ = (id) => document.getElementById(id);
  const els = {
    files: $("files"), list: $("file-list"), summary: $("file-summary"),
    seal: $("seal"), selectAll: $("select-all"), selectNone: $("select-none"),
    password: $("seal-password"), confirm: $("seal-confirm"),
    clear: $("clear"), openFile: $("open-file"), openPassword: $("open-password"),
    unlock: $("unlock"), lock: $("lock"), recovered: $("recovered"),
    mergeMode: $("merge-mode"),
    message: $("message")
  };
  let entries = [];
  let busy = false;
  let lastAction = Date.now();

  function touch() { lastAction = Date.now(); }
  function notice(message, error = false) {
    els.message.textContent = message;
    els.message.classList.toggle("error", error);
  }
  function invariant(cond) {
    if (!cond) throw new Error("Malformed, incompatible, or unsafe packet. No files were restored.");
  }
  function parseCanonicalJson(raw) {
    const parsed = JSON.parse(raw);
    // Exports are canonical JSON.stringify bytes: this also refuses duplicate keys,
    // whitespace rewrites and alternate escape spellings before any state mutation.
    invariant(JSON.stringify(parsed) === raw);
    return parsed;
  }
  function strictKeys(obj, keys) {
    invariant(obj !== null && typeof obj === "object" && !Array.isArray(obj));
    const present = Object.keys(obj);
    invariant(present.length === keys.length && keys.every((key) => Object.prototype.hasOwnProperty.call(obj, key)));
  }
  function nameOf(value) {
    invariant(typeof value === "string" && value.length > 0 && value.length <= 120);
    invariant(value === value.normalize("NFC") && !/[\\/\u0000-\u001f\u007f]/.test(value));
    invariant(value !== "." && value !== ".." && allowed.test(value));
    return value;
  }
  function validHex(value) { return typeof value === "string" && /^[a-f0-9]{64}$/.test(value); }
  function hex(bytes) { return Array.from(bytes, (v) => v.toString(16).padStart(2, "0")).join(""); }
  function digest(bytes) { return crypto.subtle.digest("SHA-256", bytes).then((buffer) => hex(new Uint8Array(buffer))); }
  function b64(bytes) {
    let output = "";
    for (let i = 0; i < bytes.length; i += 8192) {
      output += String.fromCharCode(...bytes.subarray(i, i + 8192));
    }
    return btoa(output);
  }
  function unb64(str, maxBytes) {
    invariant(typeof str === "string" && str.length > 0 && str.length <= Math.ceil(maxBytes / 3) * 4 + 4);
    invariant(str.length % 4 === 0 && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(str));
    const decoded = atob(str);
    invariant(decoded.length <= maxBytes);
    const arr = new Uint8Array(decoded.length);
    for (let i = 0; i < decoded.length; i++) arr[i] = decoded.charCodeAt(i);
    invariant(b64(arr) === str);
    return arr;
  }
  function scrub() {
    for (const entry of entries) entry.bytes.fill(0);
    entries = [];
    els.files.value = "";
    els.openFile.value = "";
    els.password.value = "";
    els.confirm.value = "";
    els.openPassword.value = "";
    paint();
  }
  function paint() {
    els.list.replaceChildren();
    els.recovered.replaceChildren();
    const total = entries.reduce((n, e) => n + e.bytes.length, 0);
    const selectedCount = entries.filter((item) => item.selected).length;
    els.summary.textContent = entries.length + " local file(s), " + total.toLocaleString() + " bytes in tab memory; " + selectedCount + " selected for encrypted export. All contents remain unapproved.";
    entries.forEach((entry, index) => {
      const box = document.createElement("div");
      box.className = "item";
      const text = document.createElement("div");
      const bold = document.createElement("strong");
      bold.textContent = entry.name;
      const details = document.createElement("small");
      details.textContent = entry.bytes.length.toLocaleString() + " bytes · SHA-256 " + entry.hash.slice(0, 12) + "… (local integrity hint only)";
      text.append(bold, details);
      const remove = document.createElement("button");
      remove.type = "button"; remove.className = "secondary"; remove.textContent = "Remove";
      remove.addEventListener("click", () => {
        if (busy) return;
        entry.bytes.fill(0);
        entries.splice(index, 1);
        touch(); paint();
        notice("File forgotten from tab memory. Existing downloaded vault files were not changed.");
      });
      const role = document.createElement("select");
      role.setAttribute("aria-label", "Self-reported, unverified review role for " + entry.name);
      role.title = "Offline sorting label only. Never client or operator approval.";
      for (const name of roles) {
        const option = document.createElement("option"); option.value = name; option.textContent = name;
        role.append(option);
      }
      role.value = entry.role;
      role.addEventListener("change", () => {
        if (busy) return;
        entry.role = role.value;
        touch(); notice("Self-reported role updated in tab memory; this is not independent identity or authorization.");
      });
      text.append(role);
      const select = document.createElement("label"); select.className = "checkline";
      const checkbox = document.createElement("input"); checkbox.type = "checkbox";
      checkbox.checked = entry.selected;
      checkbox.setAttribute("aria-label", "Include " + entry.name + " in encrypted handoff");
      checkbox.addEventListener("change", () => {
        if (busy) return;
        entry.selected = checkbox.checked;
        touch(); paint();
      });
      const caption = document.createElement("span"); caption.textContent = "Include in next encrypted handoff";
      select.append(checkbox, caption);
      text.append(select);
      box.append(text, remove);
      els.list.append(box);
      const recovered = document.createElement("div");
      recovered.className = "item";
      const info = document.createElement("span");
      info.textContent = entry.name + " · local draft, never an authorization record";
      const download = document.createElement("button");
      download.type = "button"; download.className = "secondary";
      download.textContent = "Download original";
      download.addEventListener("click", () => {
        if (busy) return;
        touch();
        if (!window.confirm("Download unencrypted local copy of " + entry.name + "? It is review material only, not permission.")) return;
        // Blob takes a copy so zeroizing in-memory bytes cannot revoke a past download.
        save(new Blob([entry.bytes.slice()], {type: "application/octet-stream"}), entry.name);
        notice("Unencrypted file downloaded locally. Protect or delete it yourself; this app cannot revoke saved files.");
      });
      recovered.append(info, download);
      els.recovered.append(recovered);
    });
    els.seal.disabled = busy || selectedCount === 0 || !window.isSecureContext || !window.crypto || !window.crypto.subtle;
    els.unlock.disabled = busy || !window.isSecureContext || !window.crypto || !window.crypto.subtle;
    els.files.disabled = busy;
    els.openFile.disabled = busy;
  }
  function save(blob, filename) {
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.rel = "noopener";
    anchor.hidden = true;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60 * 1000);
  }
  function supportsCrypto() {
    invariant(window.isSecureContext && window.crypto && window.crypto.subtle && window.crypto.getRandomValues);
  }
  async function derive(password, salt) {
    const raw = ENC.encode(password);
    try {
      const material = await crypto.subtle.importKey("raw", raw, {name: "PBKDF2"}, false, ["deriveKey"]);
      return await crypto.subtle.deriveKey(
        {name: "PBKDF2", hash: "SHA-256", salt, iterations: ROUNDS},
        material, {name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"]
      );
    } finally { raw.fill(0); }
  }
  async function inProgress(work) {
    if (busy) return;
    busy = true; touch(); paint();
    try { await work(); }
    catch (error) {
      console.error("Local scope vault operation rejected; details are deliberately withheld.");
      notice("Operation held: " + ((error instanceof DOMException && error.name === "OperationError") ? "incorrect passphrase or damaged encrypted packet." : "unsupported environment, invalid input or exceeded limits. No authority was created."), true);
    }
    finally {
      busy = false; touch();
      if (document.hidden) {
        scrub(); notice("Workspace locked after the operation finished in a hidden tab.");
      } else paint();
    }
  }
  async function addFiles() {
    const selected = Array.from(els.files.files || []);
    els.files.value = "";
    if (!selected.length) return;
    await inProgress(async () => {
      supportsCrypto();
      invariant(entries.length + selected.length <= MAX_FILES);
      const existing = new Set(entries.map((e) => e.name));
      const staged = [];
      let total = entries.reduce((n, e) => n + e.bytes.length, 0);
      try {
        for (const file of selected) {
          const name = nameOf(file.name);
          invariant(!existing.has(name));
          existing.add(name);
          invariant(file.size > 0 && file.size <= MAX_FILE_BYTES);
          total += file.size;
          invariant(total <= MAX_TOTAL_BYTES);
          const bytes = new Uint8Array(await file.arrayBuffer());
          invariant(bytes.length === file.size);
          DEC.decode(bytes); // Only canonical UTF-8 text drafts, not arbitrary binary payloads.
          staged.push({name, bytes, hash: await digest(bytes), role: roles[0], selected: true});
        }
        entries.push(...staged);
        notice("New local draft files loaded. They are not persisted until you explicitly export an encrypted vault.");
      } catch (err) {
        for (const item of staged) item.bytes.fill(0);
        throw err;
      }
    });
  }
  async function seal() {
    await inProgress(async () => {
      supportsCrypto();
      const outgoing = entries.filter((entry) => entry.selected);
      invariant(outgoing.length > 0 && outgoing.length <= MAX_FILES);
      const passphrase = els.password.value;
      const confirm = els.confirm.value;
      els.password.value = ""; els.confirm.value = "";
      if (passphrase.length < 14 || passphrase.length > 256 || passphrase !== confirm) {
        notice("Use a matching 14–256 character passphrase. There is no account reset or recovery.", true);
        return;
      }
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const payload = {
        schema: "lightup.offline.scope-packet.payload.v1",
        createdUtc: new Date().toISOString(),
        authority: {may_authorize: false, may_consent: false, may_grant: false, may_scan: false, may_dispatch: false, may_deploy: false, may_release: false},
        files: outgoing.map((entry) => ({name: entry.name, length: entry.bytes.length, sha256: entry.hash, role: entry.role, base64: b64(entry.bytes)}))
      };
      const cleartext = ENC.encode(JSON.stringify(payload));
      try {
        const key = await derive(passphrase, salt);
        const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
          {name: "AES-GCM", iv, additionalData: ENC.encode("LIGHTUP-SCOPE-PACKET-V1"), tagLength: 128},
          key, cleartext
        ));
        const envelope = {
          format: "lightup.offline.encrypted-scope-packet.v1",
          kdf: "PBKDF2-SHA256", iterations: ROUNDS, encryption: "AES-256-GCM",
          salt: b64(salt), iv: b64(iv), ciphertext: b64(ciphertext)
        };
        const blob = new Blob([JSON.stringify(envelope)], {type: "application/json"});
        invariant(blob.size <= MAX_ENVELOPE_BYTES);
        save(blob, "lightup-private-scope-packet.lightup-vault.json");
        notice("Selected " + outgoing.length + " file(s) encrypted into a new packet. Unselected local files stay in memory, but were excluded from this download. No permissions created.");
      } finally { cleartext.fill(0); }
    });
  }
  function validatePayload(body) {
    strictKeys(body, ["schema", "createdUtc", "authority", "files"]);
    invariant(body.schema === "lightup.offline.scope-packet.payload.v1");
    invariant(typeof body.createdUtc === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(body.createdUtc));
    strictKeys(body.authority, ["may_authorize", "may_consent", "may_grant", "may_scan", "may_dispatch", "may_deploy", "may_release"]);
    invariant(Object.values(body.authority).every((x) => x === false));
    invariant(Array.isArray(body.files) && body.files.length > 0 && body.files.length <= MAX_FILES);
  }
  async function unlock() {
    await inProgress(async () => {
      supportsCrypto();
      const file = els.openFile.files && els.openFile.files[0];
      const passphrase = els.openPassword.value;
      els.openPassword.value = ""; els.openFile.value = "";
      invariant(file && file.size > 0 && file.size <= MAX_ENVELOPE_BYTES && passphrase.length >= 14 && passphrase.length <= 256);
      const envelope = parseCanonicalJson(DEC.decode(new Uint8Array(await file.arrayBuffer())));
      strictKeys(envelope, ["format", "kdf", "iterations", "encryption", "salt", "iv", "ciphertext"]);
      invariant(envelope.format === "lightup.offline.encrypted-scope-packet.v1");
      invariant(envelope.kdf === "PBKDF2-SHA256" && envelope.iterations === ROUNDS && envelope.encryption === "AES-256-GCM");
      const salt = unb64(envelope.salt, 16), iv = unb64(envelope.iv, 12);
      invariant(salt.length === 16 && iv.length === 12);
      const ciphertext = unb64(envelope.ciphertext, MAX_ENVELOPE_BYTES);
      invariant(ciphertext.length >= 16);
      const key = await derive(passphrase, salt);
      const cleartext = new Uint8Array(await crypto.subtle.decrypt(
        {name: "AES-GCM", iv, additionalData: ENC.encode("LIGHTUP-SCOPE-PACKET-V1"), tagLength: 128},
        key, ciphertext
      ));
      const staged = [];
      try {
        const payload = parseCanonicalJson(DEC.decode(cleartext));
        validatePayload(payload);
        const names = new Set();
        let total = 0;
        for (const record of payload.files) {
          const hasRole = Object.prototype.hasOwnProperty.call(record, "role");
          strictKeys(record, hasRole ? ["name", "length", "sha256", "role", "base64"] : ["name", "length", "sha256", "base64"]);
          if (hasRole) invariant(validRole(record.role));
          const name = nameOf(record.name);
          invariant(!names.has(name));
          names.add(name);
          invariant(Number.isSafeInteger(record.length) && record.length > 0 && record.length <= MAX_FILE_BYTES);
          invariant(validHex(record.sha256));
          total += record.length;
          invariant(total <= MAX_TOTAL_BYTES);
          const bytes = unb64(record.base64, MAX_FILE_BYTES);
          staged.push({name, bytes, hash: record.sha256, role: hasRole ? record.role : roles[0], selected: true});
          invariant(bytes.length === record.length && (await digest(bytes)) === record.sha256);
          DEC.decode(bytes);
        }
        if (els.mergeMode.checked) {
          // Never accept filename collisions with different bytes or review roles.
          // An atomic failure leaves the entire previous workspace intact.
          const merged = [...entries];
          const byName = new Map(entries.map((item) => [item.name, item]));
          let newCount = 0;
          let priorTotal = entries.reduce((n, item) => n + item.bytes.length, 0);
          for (const item of staged) {
            const current = byName.get(item.name);
            if (current) {
              invariant(current.hash === item.hash && current.role === item.role && current.bytes.length === item.bytes.length);
              item.bytes.fill(0);
            } else {
              invariant(merged.length < MAX_FILES && priorTotal + item.bytes.length <= MAX_TOTAL_BYTES);
              merged.push(item);
              byName.set(item.name, item);
              priorTotal += item.bytes.length;
              newCount++;
            }
          }
          entries = merged;
          notice(newCount + " new local file(s) merged atomically. Existing matching files kept; source identities/roles remain unverified.");
        } else {
          // Atomic replacement: previous plaintext is forgotten only after authenticated validation.
          for (const item of entries) item.bytes.fill(0);
          entries = staged;
          notice("Encrypted packet restored locally. Verify drafts with real client/operator; the vault grants no authorization.");
        }
      } catch (err) {
        for (const item of staged) item.bytes.fill(0);
        throw err;
      } finally { cleartext.fill(0); }
    });
  }

  els.files.addEventListener("change", addFiles);
  els.selectAll.addEventListener("click", () => {
    if (busy) return; entries.forEach((entry) => {entry.selected = true;}); touch(); paint();
  });
  els.selectNone.addEventListener("click", () => {
    if (busy) return; entries.forEach((entry) => {entry.selected = false;}); touch(); paint();
  });
  els.seal.addEventListener("click", seal);
  els.unlock.addEventListener("click", unlock);
  els.clear.addEventListener("click", () => {
    if (busy) return;
    scrub(); touch(); notice("All accessible plaintext forgotten from tab memory. Previously downloaded files remain on disk.");
  });
  els.lock.addEventListener("click", () => {
    if (busy) return;
    scrub(); touch(); notice("Locked. Load the encrypted file again to restore it.");
  });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden && !busy) {
      scrub(); notice("Workspace automatically locked when the tab became hidden.");
    }
  });
  window.addEventListener("pagehide", () => { if (!busy) scrub(); });
  ["pointerdown", "keydown"].forEach((eventName) => window.addEventListener(eventName, touch, {passive: true}));
  setInterval(() => {
    if (!busy && entries.length && Date.now() - lastAction >= IDLE_MS) {
      scrub(); notice("Workspace automatically locked after five minutes of inactivity.");
    }
  }, 15000);
  if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
    notice("Crypto unavailable in this browser/context. The vault is disabled; open this local file in a modern secure-context browser.", true);
    els.seal.disabled = true; els.unlock.disabled = true;
  }
  paint();
})();
