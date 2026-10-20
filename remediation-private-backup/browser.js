/* LightUp PRIVATE HUMAN backup recovery — local-only WebCrypto, no transport or storage. */
"use strict";
(() => {
  const VERSION = "lightup-private-human-backup/v1";
  const AAD = new TextEncoder().encode("LightUp PRIVATE HUMAN archive v1 - DRAFT HOLD no authority");
  const ROUNDS = 600000, MAX_ARCHIVE = 38 * 1024 * 1024;
  const MAX_FILES = 32, MAX_FILE = 2 * 1024 * 1024, MAX_TOTAL = 16 * 1024 * 1024;
  const FLAGS = Object.freeze({ consent_verified: false, authorized: false,
    remediation_verified: false, release_approved: false });
  const slots = [null, null];
  const generations = [0, 0];
  const temporaryDownloads = new Set();
  const el = id => document.getElementById(id);
  function expireDownloads() {
    for (const url of temporaryDownloads) URL.revokeObjectURL(url);
    temporaryDownloads.clear();
  }
  function localDownload(blob, filename) {
    const url = URL.createObjectURL(blob);
    temporaryDownloads.add(url);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.rel = "noopener";
    anchor.hidden = true;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => {
      URL.revokeObjectURL(url);
      temporaryDownloads.delete(url);
    }, 60000);
  }
  function release(index) {
    const prior = slots[index];
    slots[index] = null;
    if (prior?.files) for (const file of prior.files) file.bytes.fill(0);
  }
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const expectedKeys = (value, keys) =>
    value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
  function demand(ok, message) { if (!ok) throw new Error(message); }
  function asJsonAscii(value) {
    if (Array.isArray(value)) return "[" + value.map(asJsonAscii).join(",") + "]";
    if (value && typeof value === "object") {
      return "{" + Object.keys(value).sort().map(key =>
        asJsonAscii(key) + ":" + asJsonAscii(value[key])).join(",") + "}";
    }
    if (typeof value === "string") return JSON.stringify(value).replace(
      /[\u007f-\uffff]/g, letter => "\\u" + letter.charCodeAt(0).toString(16).padStart(4, "0"));
    return JSON.stringify(value);
  }
  function strictJson(content, newline = false) {
    const parsed = JSON.parse(content);
    const canonical = asJsonAscii(parsed) + (newline ? "\n" : "");
    demand(content === canonical, "Noncanonical JSON or duplicate keys; HOLD");
    return parsed;
  }
  function fromBase64(value, max) {
    demand(typeof value === "string" && value.length <= Math.ceil(max / 3) * 4 + 8,
      "Encoded field outside budget");
    demand(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value),
      "Noncanonical or invalid base64");
    const binary = atob(value);
    demand(binary.length <= max && btoa(binary) === value, "Decoded size or encoding rejected");
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }
  function eqFlags(value) {
    return expectedKeys(value, Object.keys(FLAGS)) &&
      Object.keys(FLAGS).every(key => value[key] === false);
  }
  function safeName(value) {
    if (typeof value !== "string" || value === "." || value === ".." ||
        value.toLowerCase() === "review-only.txt" || /[/\\\x00-\x1f\x7f-\x9f]/.test(value)) return false;
    const size = encoder.encode(value).byteLength;
    return size >= 1 && size <= 160;
  }
  function hex(array) {
    return [...new Uint8Array(array)].map(byte => byte.toString(16).padStart(2, "0")).join("");
  }
  async function admit(source, password) {
    demand(globalThis.isSecureContext && globalThis.crypto?.subtle,
      "WebCrypto unavailable for this local page. Open this file directly in a modern secure-context browser.");
    demand(source && source.size > 0 && source.size <= MAX_ARCHIVE, "Archive outside local size limit");
    demand(typeof password === "string" && encoder.encode(password).length >= 12 &&
      encoder.encode(password).length <= 1024, "Password length invalid");
    const envelope = strictJson(decoder.decode(await source.arrayBuffer()), true);
    demand(expectedKeys(envelope, ["version", "kdf", "iterations", "salt", "nonce",
      "ciphertext", "authority"]), "Unsupported outer archive structure");
    demand(envelope.version === VERSION && envelope.kdf === "PBKDF2-HMAC-SHA256" &&
      envelope.iterations === ROUNDS && eqFlags(envelope.authority),
      "Unexpected version, PBKDF2 settings or authority assertion");
    const salt = fromBase64(envelope.salt, 16), nonce = fromBase64(envelope.nonce, 12),
      ciphertext = fromBase64(envelope.ciphertext, MAX_ARCHIVE);
    demand(salt.length === 16 && nonce.length === 12 && ciphertext.length >= 16,
      "Invalid encryption parameter lengths");
    const passwordBytes = encoder.encode(password);
    const imported = await crypto.subtle.importKey("raw", passwordBytes, "PBKDF2", false, ["deriveKey"]);
    passwordBytes.fill(0);
    const key = await crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256",
      iterations: ROUNDS, salt }, imported, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    let decoded;
    try {
      decoded = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce,
        additionalData: AAD, tagLength: 128 }, key, ciphertext);
    } catch (_) { throw new Error("Password or encrypted content invalid. Nothing was opened."); }
    const inner = strictJson(decoder.decode(decoded));
    demand(expectedKeys(inner, ["version", "authority", "files"]) &&
      inner.version === VERSION && eqFlags(inner.authority),
      "Unexpected authenticated source or release claims");
    demand(Array.isArray(inner.files) && inner.files.length >= 1 &&
      inner.files.length <= MAX_FILES, "Invalid file count");
    let total = 0;
    const names = new Set(), files = [];
    for (const record of inner.files) {
      demand(expectedKeys(record, ["name", "size", "sha256", "bytes"]), "Unexpected source file schema");
      demand(safeName(record.name), "Unsafe or reserved original filename");
      const folded = record.name.normalize("NFC").toLowerCase();
      demand(!names.has(folded), "Duplicate source filename");
      names.add(folded);
      demand(Number.isSafeInteger(record.size) && record.size >= 0 &&
        record.size <= MAX_FILE, "Invalid file size");
      const bytes = fromBase64(record.bytes, MAX_FILE);
      total += bytes.length;
      demand(bytes.length === record.size && total <= MAX_TOTAL, "Source size or total budget violated");
      const digest = await crypto.subtle.digest("SHA-256", bytes);
      demand(typeof record.sha256 === "string" && record.sha256 === hex(digest),
        "Source byte digest mismatch");
      files.push({ name: record.name, size: bytes.length, sha256: record.sha256, bytes });
    }
    return { filename: source.name, files, byName: new Map(files.map(file => [file.name, file])) };
  }
  function status(id, message) { el(id).textContent = message; }
  function clear(index, resetInput = true) {
    // Every explicit clear or changed file invalidates pending async decrypts.
    generations[index]++;
    release(index);
    expireDownloads(); // Explicit clear cancels any still-live private Blob URLs.
    const label = index === 0 ? "a" : "b";
    if (resetInput) el(label + "-file").value = "";
    el(label + "-pass").value = "";
    el(label + "-open").disabled = false;
    status(label + "-status", "No decrypted source retained.");
    render();
  }
  async function open(index) {
    const label = index === 0 ? "a" : "b";
    const input = el(label + "-file"), pass = el(label + "-pass");
    // Failure never leaves old state or a partially authenticated replacement.
    const source = input.files && input.files[0];
    const secret = pass.value;
    const ticket = ++generations[index];
    pass.value = "";
    el(label + "-open").disabled = true;
    status(label + "-status", "Authenticating selected encrypted bytes locally…");
    try {
      const item = await admit(source, secret);
      if (generations[index] !== ticket || input.files?.[0] !== source) {
        for (const file of item.files) file.bytes.fill(0);
        return; // User selected another file or cleared while PBKDF2 was running.
      }
      release(index);
      slots[index] = item;
      status(label + "-status", "PRIVATE DRAFT/HOLD: " + item.files.length +
        " authenticated local files; original selected archive untouched.");
    } catch (error) {
      if (generations[index] === ticket) {
        release(index);
        status(label + "-status", "HOLD: " + (error?.message || "Unable to admit archive") +
          " · previous decrypted state cleared.");
      }
    } finally {
      if (generations[index] === ticket) el(label + "-open").disabled = false;
      render();
    }
  }
  function node(tag, value) {
    const element = document.createElement(tag);
    element.textContent = value;
    return element;
  }
  function cell(row, value) { row.append(node("td", String(value))); }
  function button(label, handler) {
    const element = document.createElement("button");
    element.type = "button";
    element.textContent = label;
    element.addEventListener("click", handler);
    return element;
  }
  function asBase64(bytes) {
    const chunks = [];
    for (let i = 0; i < bytes.length; i += 8192) {
      chunks.push(String.fromCharCode(...bytes.subarray(i, i + 8192)));
    }
    return btoa(chunks.join(""));
  }
  async function sealedArchive(rows, secret) {
    demand(globalThis.isSecureContext && crypto?.subtle, "WebCrypto unavailable");
    const passBytes = encoder.encode(secret);
    demand(passBytes.length >= 12 && passBytes.length <= 1024, "New password must be 12–1024 UTF-8 bytes");
    demand(Array.isArray(rows) && rows.length >= 1 && rows.length <= MAX_FILES,
      "Encrypted archive requires 1–32 explicitly chosen files");
    const inner = { version: VERSION, authority: FLAGS, files: rows };
    const plaintext = encoder.encode(asJsonAscii(inner));
    demand(plaintext.byteLength <= MAX_ARCHIVE, "PRIVATE payload outside bounded archive budget");
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    try {
      const imported = await crypto.subtle.importKey("raw", passBytes, "PBKDF2", false, ["deriveKey"]);
      const key = await crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256",
        salt, iterations: ROUNDS }, imported, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
      const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce,
        additionalData: AAD, tagLength: 128 }, key, plaintext));
      const envelope = { version: VERSION, kdf: "PBKDF2-HMAC-SHA256", iterations: ROUNDS,
        salt: asBase64(salt), nonce: asBase64(nonce),
        ciphertext: asBase64(cipher), authority: FLAGS };
      const output = encoder.encode(asJsonAscii(envelope) + "\n");
      demand(output.byteLength <= MAX_ARCHIVE, "Encrypted backup exceeds browser budget");
      return output;
    } finally {
      passBytes.fill(0);
      plaintext.fill(0);
    }
  }

  let captureGeneration = 0;
  function clearCapture(resetFiles = true) {
    captureGeneration++;
    if (resetFiles) el("capture-files").value = "";
    el("capture-pass").value = "";
    el("capture-confirm").value = "";
    el("capture-create").disabled = false;
    status("capture-status", "Selection cleared. No original file data retained by the workroom.");
  }
  async function createCapture() {
    const input = el("capture-files");
    const selected = Array.from(input.files || []);
    const generation = ++captureGeneration;
    const secret = el("capture-pass").value;
    const confirmation = el("capture-confirm").value;
    el("capture-pass").value = ""; el("capture-confirm").value = "";
    el("capture-create").disabled = true;
    const admitted = [];
    try {
      demand(selected.length > 0 && selected.length <= MAX_FILES, "Select 1–32 local files explicitly");
      demand(secret === confirmation, "New passwords do not match");
      const names = new Set();
      let total = 0;
      for (const file of selected) {
        demand(safeName(file.name) && !file.webkitRelativePath, "Unsafe or directory-derived filename");
        demand(!file.name.toLowerCase().endsWith(".lupb"), "Archive nesting is not accepted");
        const folded = file.name.normalize("NFC").toLowerCase();
        demand(!names.has(folded), "Duplicate original filename");
        names.add(folded);
        demand(file.size <= MAX_FILE, "Original file exceeds 2 MiB");
        total += file.size;
        demand(total <= MAX_TOTAL, "Selected original files exceed 16 MiB");
      }
      demand(confirm("Encrypt exactly " + selected.length + " PRIVATE local file(s), " + total +
        " bytes? No files are uploaded. A download may land in unprotected storage."),
        "Local encryption cancelled");
      status("capture-status", "Reading only the chosen original files; preparing encrypted archive…");
      const rows = [];
      for (const file of selected) {
        const bytes = new Uint8Array(await file.arrayBuffer());
        admitted.push(bytes);
        demand(bytes.byteLength === file.size, "Original selected file changed during reading");
        const digest = hex(await crypto.subtle.digest("SHA-256", bytes));
        rows.push({ name: file.name, size: bytes.byteLength, sha256: digest, bytes: asBase64(bytes) });
        demand(captureGeneration === generation && selected.every((f, i) => input.files?.[i] === f),
          "Source file selection changed; refusing stale capture");
      }
      const output = await sealedArchive(rows, secret);
      demand(captureGeneration === generation && selected.every((f, i) => input.files?.[i] === f),
        "Selection changed during encryption; no archive published");
      localDownload(new Blob([output], { type: "application/octet-stream" }),
        "LightUp-PRIVATE-HUMAN-new-DRAFT-HOLD.lupb");
      output.fill(0);
      input.value = "";
      status("capture-status", "PRIVATE DRAFT/HOLD: created new encrypted local archive of " +
        selected.length + " original file(s). Move browser download into owner-private storage. " +
        "Not source authenticated, approved for disclosure, or permission to remediate.");
    } catch (error) {
      if (captureGeneration === generation)
        status("capture-status", "HOLD: " + (error?.message || "Local archive creation failed"));
    } finally {
      for (const bytes of admitted) bytes.fill(0);
      if (captureGeneration === generation) el("capture-create").disabled = false;
    }
  }

  async function encryptSubset() {
    const activeIndex = Number(el("source-select").value);
    const active = slots[activeIndex];
    const originalGeneration = generations[activeIndex];
    const pass = el("subset-pass"), verify = el("subset-confirm");
    const secret = pass.value, confirmed = verify.value;
    pass.value = ""; verify.value = "";
    el("subset-export").disabled = true;
    try {
      demand(active, "Unlock and select a PRIVATE archive");
      const checkboxes = [...el("file-rows").querySelectorAll("input[type=checkbox]:checked")];
      demand(checkboxes.length > 0 && checkboxes.length <= MAX_FILES, "Select one or more original files");
      const selected = checkboxes.map(input => active.files[Number(input.value)]);
      demand(selected.every(Boolean), "Invalid source selection");
      demand(secret === confirmed, "New passwords do not match");
      demand(confirm("Create a NEW encrypted PRIVATE archive with " + selected.length +
        " chosen original files? This is NOT an approved disclosure."),
        "Operator declined");
      const rows = selected.map(file => ({ name: file.name, size: file.size,
        sha256: file.sha256, bytes: asBase64(file.bytes) }));
      const output = await sealedArchive(rows, secret);
      demand(generations[activeIndex] === originalGeneration && slots[activeIndex] === active,
        "Original source was cleared or changed during encryption; no export");
      localDownload(new Blob([output], { type: "application/octet-stream" }),
        "LightUp-PRIVATE-HUMAN-selected-DRAFT-HOLD.lupb");
      output.fill(0);
      status("subset-status", "PRIVATE DRAFT/HOLD: encrypted " + selected.length +
        " exact original files into a newly downloaded .lupb. Browser downloads may be unsafe; " +
        "move to owner-private storage. No disclosure approval.");
    } catch (error) {
      status("subset-status", "HOLD: " + (error?.message || "Subset encryption failed"));
    } finally { el("subset-export").disabled = false; }
  }
  function download(file) {
    if (!confirm("Export this original PRIVATE file as unencrypted plaintext? No authorization or sanitization is implied.")) return;
    const blob = new Blob([file.bytes], { type: "application/octet-stream" });
    localDownload(blob, file.name);
  }
  function preview(file) {
    const area = el("preview");
    area.textContent = "";
    area.classList.add("hide");
    if (!/\.(txt|csv|json|md|log)$/i.test(file.name)) {
      status("file-meta", "PRIVATE original " + file.name + " is not a text preview type.");
      return;
    }
    try {
      const text = decoder.decode(file.bytes.subarray(0, Math.min(file.size, 8192)));
      area.textContent = text + (file.size > 8192 ? "\n… [PRIVATE preview truncated]" : "");
      area.classList.remove("hide");
      status("file-meta", "PRIVATE original " + file.name + " · content shown locally (not sanitized).");
    } catch (_) { status("file-meta", "Non-UTF-8 source bytes: preview withheld."); }
  }
  function renderInventory() {
    const selected = Number(el("source-select").value), archive = slots[selected];
    const root = el("file-rows");
    root.replaceChildren();
    el("preview").textContent = "";
    el("preview").classList.add("hide");
    status("file-meta", "");
    if (!archive) {
      status("inventory-status", "Unlock archive " + (selected === 0 ? "A" : "B") + " to inspect.");
      return;
    }
    status("inventory-status", archive.files.length + " private files · " +
      archive.files.reduce((sum, f) => sum + f.size, 0) +
      " bytes · password-authenticated local source. NO grant, release or verified fix.");
    for (const f of archive.files) {
      const row = document.createElement("tr");
      cell(row, f.name); cell(row, f.size); cell(row, f.sha256);
      const controls = document.createElement("td");
      controls.append(button("Preview", () => preview(f)));
      controls.append(button("Download plaintext", () => download(f)));
      row.append(controls);
      const selection = document.createElement("td");
      const input = document.createElement("input");
      input.type = "checkbox"; input.value = String(archive.files.indexOf(f));
      input.setAttribute("aria-label", "Include original " + f.name + " in a new encrypted PRIVATE archive");
      selection.append(input);
      row.append(selection);
      root.append(row);
    }
  }
  function renderComparison() {
    const root = el("compare-rows");
    root.replaceChildren();
    if (!slots[0] || !slots[1]) {
      status("compare-status", "Unlock both independent encrypted archives to compare.");
      return;
    }
    const left = slots[0].byName, right = slots[1].byName;
    const names = [...new Set([...left.keys(), ...right.keys()])].sort();
    const totals = { ADDED: 0, REMOVED: 0, CHANGED: 0, UNCHANGED: 0 };
    for (const name of names) {
      const a = left.get(name), b = right.get(name);
      const kind = !a ? "ADDED" : !b ? "REMOVED" :
        a.sha256 !== b.sha256 || a.size !== b.size ? "CHANGED" : "UNCHANGED";
      totals[kind]++;
      const tr = document.createElement("tr");
      cell(tr, kind); cell(tr, name); cell(tr, a?.size ?? "—"); cell(tr, b?.size ?? "—");
      root.append(tr);
    }
    status("compare-status", Object.entries(totals).map(([key, value]) => key + ": " + value).join(" · ") +
      ". Source byte differences are NOT remediation proof or chronology.");
  }
  function render() { renderInventory(); renderComparison(); }
  el("a-file").addEventListener("change", () => clear(0, false));
  el("b-file").addEventListener("change", () => clear(1, false));
  el("a-open").addEventListener("click", () => open(0));
  el("b-open").addEventListener("click", () => open(1));
  el("a-clear").addEventListener("click", () => clear(0));
  el("b-clear").addEventListener("click", () => clear(1));
  el("source-select").addEventListener("change", renderInventory);
  el("capture-files").addEventListener("change", () => clearCapture(false));
  el("capture-create").addEventListener("click", createCapture);
  el("capture-clear").addEventListener("click", () => clearCapture(true));
  el("subset-export").addEventListener("click", encryptSubset);
  el("clear-all").addEventListener("click", () => { clear(0); clear(1); });
  window.addEventListener("pagehide", () => {
    generations[0]++; generations[1]++;
    release(0); release(1);
    expireDownloads();
    el("a-pass").value = ""; el("b-pass").value = "";
    el("subset-pass").value = ""; el("subset-confirm").value = "";
    el("a-file").value = ""; el("b-file").value = "";
    clearCapture(true);
    render(); // Do not leave filenames, digests or preview in bfcache DOM.
  });
  window.addEventListener("pageshow", event => {
    if (event.persisted) render();
  });
  render();
})();
