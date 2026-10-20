"use strict";
/* Independent LightUp human PREPARATION ONLY. No calls, storage, scans or authorizations. */
(function () {
  const SCHEMA = "lightup.scope_intake.preparation.v1";
  const FENCE = Object.freeze({
    consent_validated: false,
    grant_issued: false,
    target_authorized: false,
    scanning_enabled: false,
    release_approved: false
  });
  const CAPABILITIES = Object.freeze({
    none: "None — excluded",
    inventory: "Passive inventory proposal",
    http_baseline: "Passive HTTP baseline proposal",
    tls_baseline: "Passive TLS baseline proposal",
    lab_review: "Isolated LAB review proposal",
    "inventory+http_baseline": "Passive inventory + HTTP baseline proposal",
    "inventory+tls_baseline": "Passive inventory + TLS baseline proposal",
    "http_baseline+tls_baseline": "Passive HTTP + TLS baseline proposal",
    "inventory+http_baseline+tls_baseline": "Passive inventory + HTTP + TLS baseline proposal"
  });
  const OWNERSHIP = Object.freeze({
    unverified: "Unverified",
    claimed: "Human claims ownership (unverified)",
    docs_requested: "Ownership documents requested"
  });
  const STATUS = Object.freeze({
    draft: "Draft",
    "needs-client-review": "Needs client review",
    blocked: "Blocked"
  });
  const RISK = Object.freeze(["informational", "low", "medium", "high"]);
  const FORM_FIELDS = ["project", "client", "contact", "start", "end", "risk", "purpose", "evidence"];
  const DOC_KEYS = ["schema", "posture", "authority", ...FORM_FIELDS, "rows"];
  const ROW_KEYS = ["id", "asset", "excluded", "capability", "ownership", "status", "question"];
  const MAX_BYTES = 65536;
  const textBytes = value => new TextEncoder().encode(value).length;
  const $ = id => document.getElementById(id);
  let rowNumber = 0;
  let state = blankDocument();

  function blankDocument() {
    return {
      project: "", client: "", contact: "", start: "", end: "",
      risk: "informational", purpose: "", evidence: "", rows: []
    };
  }

  function exactKeys(value, keys) {
    return value && typeof value === "object" && !Array.isArray(value) &&
      Object.keys(value).length === keys.length &&
      Object.keys(value).every((key, i) => key === keys[i]);
  }

  function safeString(value, limit, required) {
    return typeof value === "string" && value.length <= limit &&
      textBytes(value) <= limit * 4 && value === value.trim() &&
      (!required || value.length > 0) &&
      !/[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/u.test(value) &&
      !/\p{Cf}|\p{Cs}|\p{Co}|\p{Cn}/u.test(value);
  }

  function validAsset(value) {
    if (!safeString(value, 253, true)) return false;
    if (value !== value.toLowerCase()) return false;
    if (value === "localhost") return true;
    const match = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\/(\d{1,2}))?$/.exec(value);
    if (match) {
      const parts = match[1].split(".").map(Number);
      if (parts.some((part, i) => part > 255 || String(part) !== match[1].split(".")[i])) return false;
      if (match[2] !== undefined && (+match[2] < 24 || +match[2] > 32 || String(+match[2]) !== match[2])) return false;
      if (match[2] !== undefined) {
        const mask = +match[2];
        const num = parts.reduce((acc, x) => ((acc << 8) | x) >>> 0, 0);
        const hostMask = (2 ** (32 - mask)) - 1;
        if ((num & hostMask) !== 0) return false;
      }
      return true;
    }
    if (value.includes("/") || value.length > 253 || !value.includes(".")) return false;
    // A dotted numeric address that failed canonical IPv4 admission cannot be
    // reclassified as a hostname and silently remain in the proposed scope.
    if (/^[0-9.]+$/.test(value)) return false;
    if (!/^[a-z0-9.-]+$/.test(value) || value.endsWith(".") || value.startsWith(".")) return false;
    return value.split(".").every(part => part.length > 0 && part.length <= 63 &&
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(part));
  }

  function timeValid(value) {
    if (typeof value !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d$/.test(value)) return false;
    const [day, time] = value.split("T");
    const [year, month, date] = day.split("-").map(Number);
    const [hour, minute] = time.split(":").map(Number);
    const d = new Date(Date.UTC(year, month - 1, date, hour, minute));
    return year >= 2000 && year <= 2100 &&
      d.getUTCFullYear() === year && d.getUTCMonth() === month - 1 &&
      d.getUTCDate() === date && d.getUTCHours() === hour && d.getUTCMinutes() === minute;
  }

  function validate(doc) {
    const problems = [];
    if (!safeString(doc.project, 80, true)) problems.push("Name the draft (1–80 safe characters).");
    if (!safeString(doc.client, 100, true)) problems.push("Enter a declared client label (unverified).");
    if (!safeString(doc.contact, 80, false)) problems.push("Review contact must be a short safe alias.");
    if (!safeString(doc.purpose, 1800, true)) problems.push("Describe the purpose and human review questions.");
    if (!safeString(doc.evidence, 120, false)) problems.push("Evidence label contains unsupported characters.");
    if (!RISK.includes(doc.risk)) problems.push("Choose a supported descriptive risk ceiling.");
    if (!timeValid(doc.start) || !timeValid(doc.end) || doc.start >= doc.end) {
      problems.push("Provide a real local requested start and later end time (2000–2100).");
    }
    if (!Array.isArray(doc.rows) || doc.rows.length < 1 || doc.rows.length > 32) {
      problems.push("Add 1–32 proposed boundaries.");
      return problems;
    }
    const seenIds = new Set(), seenAssets = new Set();
    doc.rows.forEach((row, i) => {
      const n = i + 1;
      if (!exactKeys(row, ROW_KEYS)) { problems.push("Row " + n + ": unsupported row shape."); return; }
      if (!/^r[1-9]\d{0,5}$/.test(row.id) || seenIds.has(row.id)) problems.push("Row " + n + ": ambiguous row identity.");
      seenIds.add(row.id);
      if (!validAsset(row.asset)) problems.push("Row " + n + ": use an exact lowercase DNS hostname, canonical IPv4, or /24–/32 network.");
      else if (seenAssets.has(row.asset)) problems.push("Row " + n + ": duplicate literal asset.");
      seenAssets.add(row.asset);
      if (typeof row.excluded !== "boolean") problems.push("Row " + n + ": boundary flag must be exact boolean.");
      if (!Object.hasOwn(CAPABILITIES, row.capability) ||
          (row.excluded && row.capability !== "none") ||
          (!row.excluded && row.capability === "none")) {
        problems.push("Row " + n + ": capability conflicts with exclusion.");
      }
      if (!Object.hasOwn(OWNERSHIP, row.ownership)) problems.push("Row " + n + ": unsupported ownership label.");
      if (!Object.hasOwn(STATUS, row.status)) problems.push("Row " + n + ": unsupported human state.");
      if (!safeString(row.question, 450, false)) problems.push("Row " + n + ": question is too long or contains unsafe control text.");
    });
    return problems;
  }

  function snapshot() {
    return {
      schema: SCHEMA, posture: "PREPARATION_ONLY", authority: { ...FENCE },
      project: state.project, client: state.client, contact: state.contact,
      start: state.start, end: state.end, risk: state.risk,
      purpose: state.purpose, evidence: state.evidence,
      rows: state.rows.map(row => ({...row}))
    };
  }

  function decodeOwnExport(raw) {
    if (typeof raw !== "string" || textBytes(raw) > MAX_BYTES) throw Error("Input exceeds the 64 KiB limit.");
    let doc;
    try { doc = JSON.parse(raw); } catch (_) { throw Error("Not a valid canonical LightUp PRIVATE draft JSON."); }
    // Our own exporter writes one exact representation. Noncanonical JSON, duplicate keys,
    // re-ordered or hidden keys are refused atomically before touching the live document.
    if (raw !== JSON.stringify(doc, null, 2) + "\n") throw Error("Not canonical: altered formatting, duplicate keys or unknown serialization.");
    if (!exactKeys(doc, DOC_KEYS) || doc.schema !== SCHEMA || doc.posture !== "PREPARATION_ONLY" ||
        !exactKeys(doc.authority, Object.keys(FENCE)) ||
        Object.keys(FENCE).some(k => doc.authority[k] !== false)) {
      throw Error("Unsupported PRIVATE draft version or non-false authority claim.");
    }
    const fields = {...doc}; delete fields.schema; delete fields.posture; delete fields.authority;
    const problems = validate(fields);
    if (problems.length) throw Error(problems[0] + (problems.length > 1 ? " (" + problems.length + " issues)" : ""));
    return fields;
  }

  function optionSelect(values, selected, change, aria) {
    const select = document.createElement("select");
    select.setAttribute("aria-label", aria);
    for (const [value, label] of Object.entries(values)) {
      const option = document.createElement("option");
      option.value = value; option.textContent = label; select.append(option);
    }
    select.value = selected;
    select.addEventListener("change", event => change(event.target.value));
    return select;
  }
  function cell(row) { const td = document.createElement("td"); row.append(td); return td; }
  function editText(value, max, label, change, multi = false) {
    const input = document.createElement(multi ? "textarea" : "input");
    if (!multi) input.type = "text";
    input.value = value; input.maxLength = max; input.autocomplete = "off";
    input.setAttribute("aria-label", label);
    input.addEventListener("input", event => { change(event.target.value); refresh(); });
    return input;
  }
  function rowButton(title, action, danger = false) {
    const button = document.createElement("button");
    button.type = "button"; button.textContent = title; button.setAttribute("aria-label", title);
    if (danger) button.classList.add("danger");
    button.addEventListener("click", action);
    return button;
  }
  function renderRows() {
    const tbody = $("rows"); tbody.replaceChildren();
    const filter = $("filter").value.toLowerCase();
    const statusFilter = $("status-filter").value;
    let shown = 0;
    for (const row of state.rows) {
      if (statusFilter !== "all" && row.status !== statusFilter) continue;
      if (filter && !(row.asset + " " + row.question).toLowerCase().includes(filter)) continue;
      shown++;
      const tr = document.createElement("tr");
      const identity = cell(tr);
      identity.append(editText(row.asset, 253, "Proposed literal asset for " + row.id, value => row.asset = value));
      identity.append(editText(row.question, 450, "Human question for " + row.id, value => row.question = value, true));
      const boundary = cell(tr);
      boundary.append(optionSelect({included:"Proposed inclusion",excluded:"Explicit exclusion"},
        row.excluded ? "excluded" : "included", value => {
          row.excluded = value === "excluded";
          row.capability = row.excluded ? "none" : "inventory";
          renderRows(); refresh();
        }, "Boundary for " + row.id));
      const capability = cell(tr);
      capability.append(optionSelect(CAPABILITIES, row.capability, value => {
        row.capability = value; refresh();
      }, "Proposed capability for " + row.id));
      const ownership = cell(tr);
      ownership.append(optionSelect(OWNERSHIP, row.ownership, value => {
        row.ownership = value; refresh();
      }, "Declared ownership evidence for " + row.id));
      const status = cell(tr);
      status.append(optionSelect(STATUS, row.status, value => {
        row.status = value; refresh();
      }, "Human preparation status for " + row.id));
      const tools = cell(tr); tools.className = "row-tools";
      tools.append(rowButton("Copy " + row.id, () => duplicateRow(row.id)));
      tools.append(rowButton("Remove " + row.id, () => removeRow(row.id), true));
      tbody.append(tr);
    }
    $("empty-rows").hidden = shown > 0;
    $("empty-rows").textContent = state.rows.length ?
      "No rows match the local filter." : "No proposed assets yet.";
  }

  function bulkAdd() {
    const raw = $("bulk-lines").value;
    if (raw.length > 4096 || !raw.trim()) {
      announce("HOLD: paste 1–32 bounded literal proposal lines.", true); return;
    }
    const lines = raw.trim().split(/\r?\n/);
    const distinct = new Set(state.rows.map(row => row.asset));
    const staging = [];
    for (let i = 0; i < lines.length; i++) {
      const value = lines[i].trim();
      if (!value) {
        announce("HOLD: blank bulk line " + (i + 1) + " — no rows added.", true); return;
      }
      const excluded = value.startsWith("!");
      const asset = excluded ? value.slice(1).trim() : value;
      if (!validAsset(asset) || distinct.has(asset)) {
        announce("HOLD: invalid or duplicate literal on line " + (i + 1) + " — no rows added.", true); return;
      }
      distinct.add(asset);
      staging.push({asset, excluded});
    }
    if (staging.length > 32 || staging.length + state.rows.length > 32) {
      announce("HOLD: the draft cannot exceed 32 total proposed assets. No rows added.", true); return;
    }
    const exclusions = staging.filter(row => row.excluded).length;
    if (!confirm("Add " + staging.length + " unverified proposed DRAFT assets (" + exclusions +
      " explicit exclusions)? No approval, permission, grant or scan is issued.")) return;
    for (const proposed of staging) {
      rowNumber++;
      state.rows.push({
        id: "r" + rowNumber, asset: proposed.asset, excluded: proposed.excluded,
        capability: proposed.excluded ? "none" : "inventory",
        ownership: "unverified", status: "draft", question: ""
      });
    }
    $("bulk-lines").value = "";
    $("filter").value = ""; $("status-filter").value = "all";
    renderRows(); refresh();
    announce("Atomic local bulk draft: " + staging.length +
      " literals added for HUMAN review, not authorized.");
  }

  function addRow() {
    if (state.rows.length >= 32) { announce("Maximum 32 proposed assets.", true); return; }
    rowNumber++;
    state.rows.push({
      id: "r" + rowNumber, asset: "", excluded: false, capability: "inventory",
      ownership: "unverified", status: "draft", question: ""
    });
    $("filter").value = ""; $("status-filter").value = "all";
    renderRows(); refresh();
  }
  function duplicateRow(id) {
    if (state.rows.length >= 32) { announce("Maximum 32 proposed assets.", true); return; }
    const source = state.rows.find(row => row.id === id);
    if (!source) return;
    rowNumber++;
    state.rows.push({...source, id: "r" + rowNumber, asset: ""});
    $("filter").value = ""; $("status-filter").value = "all";
    renderRows(); refresh();
  }
  function removeRow(id) {
    const index = state.rows.findIndex(row => row.id === id);
    if (index >= 0) state.rows.splice(index, 1);
    renderRows(); refresh();
  }
  function announce(message, isError = false) {
    $("notice").textContent = message;
    $("notice").classList.toggle("danger-text", isError);
  }
  function refresh() {
    // Any actual proposal mutation makes the previously rendered comparison stale.
    $("compare-section").hidden = true;
    $("total-count").textContent = state.rows.length;
    $("excluded-count").textContent = state.rows.filter(row => row.excluded).length;
    $("review-count").textContent = state.rows.filter(row => row.status === "needs-client-review").length;
    $("blocked-count").textContent = state.rows.filter(row => row.status === "blocked").length;
    const issues = validate(state);
    renderAgenda();
    announce(issues.length ? "DRAFT INCOMPLETE (" + issues.length + "): " +
      issues.slice(0, 5).join(" ") + (issues.length > 5 ? " …" : "") :
      "Locally complete PREPARATION ONLY. No consent, grant, authority, scanning right, verified finding or release has been established.",
      issues.length > 0);
  }
  function syncForm() {
    for (const field of FORM_FIELDS) $(field).value = state[field];
  }
  function download(name, text, type = "application/json") {
    const blob = new Blob([text], { type: type + ";charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = name;
    document.body.append(a);
    a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }
  function exportDraft() {
    const errors = validate(state);
    if (errors.length) { announce("Cannot export incomplete draft: " + errors.join(" "), true); return; }
    if (!confirm("PRIVATE unencrypted asset/client details. Save only to a trusted local location? This does NOT authorize anything.")) return;
    const serialized = JSON.stringify(snapshot(), null, 2) + "\n";
    if (textBytes(serialized) > MAX_BYTES) { announce("Draft exceeds 64 KiB export cap.", true); return; }
    download("lightup-scope-intake-PRIVATE.json", serialized);
    announce("PRIVATE draft prepared for local download. Still PREPARATION ONLY / DRAFT.");
  }

  const ENCRYPTED_SCHEMA = "lightup.scope_intake.encrypted_private.v1";
  const PURPOSE = "lightup.scope_intake.encrypted_private.v1;PREPARATION_ONLY";
  const KDF_ROUNDS = 600000;
  const MAX_ENCRYPTED = 100000;
  const ENCRYPTED_KEYS = [
    "schema", "posture", "cipher", "kdf", "iterations", "salt_b64", "nonce_b64", "sealed_b64"
  ];

  function requireCrypto() {
    if (!globalThis.isSecureContext || !globalThis.crypto?.subtle ||
        typeof globalThis.crypto.getRandomValues !== "function") {
      throw Error("Secure offline WebCrypto unavailable. Use a browser that supports secure local file contexts. Plaintext fallback is never automatic.");
    }
  }

  function strictBase64(bytes) {
    let encoded = "";
    for (let at = 0; at < bytes.length; at += 4096) {
      encoded += String.fromCharCode(...bytes.subarray(at, at + 4096));
    }
    return btoa(encoded);
  }

  function readCanonicalBase64(value, expectedSize = null) {
    if (typeof value !== "string" || value.length > MAX_ENCRYPTED ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
      throw Error("Invalid canonical encrypted package.");
    }
    let bytes;
    try { bytes = Uint8Array.from(atob(value), c => c.charCodeAt(0)); }
    catch (_) { throw Error("Invalid canonical encrypted package."); }
    if (strictBase64(bytes) !== value || (expectedSize !== null && bytes.length !== expectedSize)) {
      bytes.fill(0); throw Error("Invalid canonical encrypted package.");
    }
    return bytes;
  }

  function passphraseInput(confirmNew) {
    const first = prompt(confirmNew ?
      "New PRIVATE encryption password (14–256 characters). Keep it safe: it cannot be recovered." :
      "Password for this PRIVATE encrypted workroom:");
    if (first === null) return null;
    const length = textBytes(first);
    if (length < 14 || length > 256 || !first.trim() ||
        /[\u0000-\u001f\u007f]/u.test(first)) {
      throw Error("Password must contain 14–256 safe UTF-8 bytes.");
    }
    if (confirmNew) {
      const second = prompt("Confirm new PRIVATE encryption password:");
      if (second === null) return null;
      if (first !== second) throw Error("Password confirmation does not match.");
    }
    return first;
  }

  async function derivePrivateKey(password, salt) {
    const material = new TextEncoder().encode(password);
    try {
      const parent = await globalThis.crypto.subtle.importKey("raw", material, "PBKDF2", false, ["deriveKey"]);
      return await globalThis.crypto.subtle.deriveKey(
        {name: "PBKDF2", salt, iterations: KDF_ROUNDS, hash: "SHA-256"},
        parent,
        {name: "AES-GCM", length: 256},
        false,
        ["encrypt", "decrypt"]
      );
    } finally {
      material.fill(0); // Strings and browser internals cannot be reliably zeroized.
    }
  }

  async function encryptWorkroom() {
    try {
      const problems = validate(state);
      if (problems.length) throw Error("Complete the PRIVATE draft first: " + problems[0]);
      requireCrypto();
      const pwd = passphraseInput(true);
      if (pwd === null) { announce("Encryption canceled; existing draft unchanged."); return; }
      if (!confirm("Encrypt this PRIVATE draft locally? This is NOT client/operator authentication, consent, a grant or permission. Keep the password separately.")) return;
      const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
      const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
      const aad = new TextEncoder().encode(PURPOSE);
      const key = await derivePrivateKey(pwd, salt);
      const plain = new TextEncoder().encode(JSON.stringify(snapshot(), null, 2) + "\n");
      try {
        if (plain.length > MAX_BYTES) throw Error("Draft exceeds original 64 KiB source limit.");
        const bytes = new Uint8Array(await globalThis.crypto.subtle.encrypt(
          {name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128}, key, plain
        ));
        try {
          const envelope = {
            schema: ENCRYPTED_SCHEMA, posture: "PREPARATION_ONLY", cipher: "AES-256-GCM",
            kdf: "PBKDF2-SHA256", iterations: KDF_ROUNDS,
            salt_b64: strictBase64(salt), nonce_b64: strictBase64(nonce), sealed_b64: strictBase64(bytes)
          };
          const raw = JSON.stringify(envelope, null, 2) + "\n";
          if (textBytes(raw) > MAX_ENCRYPTED) throw Error("Encrypted envelope exceeds size cap.");
          download("lightup-scope-PRIVATE-encrypted.luie", raw);
          announce("AES-256-GCM PRIVATE workroom downloaded. Preserve the password; this file is not an authorization.");
        } finally { bytes.fill(0); }
      } finally {
        plain.fill(0); salt.fill(0); nonce.fill(0); aad.fill(0);
      }
    } catch (error) {
      announce("ENCRYPTED SAVE FAILED: " + error.message + " Existing draft was retained.", true);
    }
  }

  async function decryptWorkroom(file) {
    requireCrypto();
    if (!file || file.size > MAX_ENCRYPTED) throw Error("Encrypted PRIVATE file is over 100 KiB.");
    const original = new Uint8Array(await file.arrayBuffer());
    let raw;
    try { raw = new TextDecoder("utf-8", {fatal: true, ignoreBOM: true}).decode(original); }
    catch (_) { throw Error("Encrypted file is not UTF-8."); }
    if (textBytes(raw) !== original.length || raw.length > MAX_ENCRYPTED) {
      throw Error("Encrypted file is not canonical UTF-8.");
    }
    let obj;
    try { obj = JSON.parse(raw); } catch (_) { throw Error("Invalid encrypted envelope."); }
    if (raw !== JSON.stringify(obj, null, 2) + "\n" ||
        !exactKeys(obj, ENCRYPTED_KEYS) || obj.schema !== ENCRYPTED_SCHEMA ||
        obj.posture !== "PREPARATION_ONLY" || obj.cipher !== "AES-256-GCM" ||
        obj.kdf !== "PBKDF2-SHA256" || obj.iterations !== KDF_ROUNDS) {
      throw Error("Unsupported, ambiguous or noncanonical encrypted envelope.");
    }
    const salt = readCanonicalBase64(obj.salt_b64, 16);
    const nonce = readCanonicalBase64(obj.nonce_b64, 12);
    const sealed = readCanonicalBase64(obj.sealed_b64);
    if (sealed.length < 18 || sealed.length > MAX_BYTES + 16) {
      salt.fill(0); nonce.fill(0); sealed.fill(0);
      throw Error("Encrypted payload size is invalid.");
    }
    try {
      const pwd = passphraseInput(false);
      if (pwd === null) throw Error("Password entry canceled.");
      const key = await derivePrivateKey(pwd, salt);
      let opened;
      try {
        opened = new Uint8Array(await globalThis.crypto.subtle.decrypt(
          {name: "AES-GCM", iv: nonce, additionalData: new TextEncoder().encode(PURPOSE), tagLength: 128},
          key, sealed
        ));
      } catch (_) { throw Error("Password incorrect, content altered or envelope authentication failed."); }
      try {
        if (opened.length > MAX_BYTES) throw Error("Decrypted draft exceeds 64 KiB.");
        let plaintext;
        try { plaintext = new TextDecoder("utf-8", {fatal: true, ignoreBOM: true}).decode(opened); }
        catch (_) { throw Error("Decrypted draft is not valid UTF-8."); }
        if (textBytes(plaintext) !== opened.length) throw Error("Decrypted UTF-8 is not canonical.");
        // Original source validator enforces all false authority claims, strict fields
        // and correct original canonical bytes before the current draft can be replaced.
        return decodeOwnExport(plaintext);
      } finally { opened.fill(0); }
    } finally { salt.fill(0); nonce.fill(0); sealed.fill(0); original.fill(0); }
  }

  function exportCounts() {
    const problems = validate(state);
    if (problems.length) { announce("Complete the draft before generating aggregate counts.", true); return; }
    if (!confirm("Export only aggregate numbers? Small groups may still be sensitive. No authorization claims.")) return;
    const counts = Object.fromEntries(Object.keys(STATUS).map(k => [k, state.rows.filter(r => r.status === k).length]));
    const categories = Object.fromEntries(Object.keys(CAPABILITIES).map(k => [k, state.rows.filter(r => r.capability === k).length]));
    const receipt = {
      schema: "lightup.scope_intake.anonymous_counts.v1",
      posture: "PREPARATION_ONLY",
      authority: {...FENCE},
      proposed_count: state.rows.length,
      excluded_count: state.rows.filter(r => r.excluded).length,
      ownership_claimed_unverified_count: state.rows.filter(r => r.ownership === "claimed").length,
      human_status_counts: counts, proposed_capability_counts: categories
    };
    download("lightup-scope-intake-COUNTS.json", JSON.stringify(receipt, null, 2) + "\n");
    announce("Counts-only receipt prepared. No target, client, identity or scope evidence included; still not an authorization.");
  }
  function humanAgenda() {
    const items = [];
    items.push("Confirm the authentic current client and independently authenticated operator outside this offline draft.");
    items.push("Obtain original request/grant/risk decisions and check current action-time revocation through the source-owned LightUp process.");
    items.push("Confirm the requested LOCAL planning window with a trusted reference clock; local input is not a signed validity interval.");
    if (state.risk === "high") items.push("HIGH proposed ceiling: independent human risk decision needed; do not infer permission.");
    for (const row of state.rows) {
      const name = row.asset || "(missing proposed asset)";
      if (row.excluded) {
        items.push("EXCLUDED " + name + ": keep excluded from any future reviewed authorization; no revocation is proven.");
      } else {
        items.push("PROPOSED " + name + ": request independent ownership, exact scope and " +
          (CAPABILITIES[row.capability] || "unknown capability") + " decisions.");
      }
      if (row.ownership === "claimed") {
        items.push(name + ": human ownership CLAIM is not independently authenticated.");
      } else if (row.ownership === "docs_requested") {
        items.push(name + ": gather the requested independent ownership documents.");
      } else {
        items.push(name + ": no ownership evidence was declared.");
      }
      if (row.status === "blocked") items.push(name + ": BLOCKED — clear only through external independent human review.");
      if (row.status === "needs-client-review") items.push(name + ": explicitly pending client review.");
      if (row.question) items.push(name + ": PRIVATE human question — " + row.question);
    }
    items.push("Before any real work: original owner/security/privacy approvals, #177/#182/#829, exact-head hosted and named VPS CI, authentic consent plus action-time revocation and explicit HUMAN GO remain mandatory.");
    return items;
  }

  function renderAgenda() {
    const items = humanAgenda();
    const list = $("agenda-items"); list.replaceChildren();
    for (const item of items) {
      const li = document.createElement("li"); li.textContent = item; list.append(li);
    }
    $("agenda-count").textContent = items.length + " self-declared HUMAN follow-up items — zero verified approvals";
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  }

  function exportAgenda() {
    const problems = validate(state);
    if (problems.length) {
      announce("Complete all draft fields before exporting a PRIVATE agenda: " + problems[0], true);
      return;
    }
    if (!confirm("This PRIVATE agenda includes original client labels, proposed targets and human questions. It is UNENCRYPTED and NOT authorization. Download to a trusted private location?")) return;
    const lines = humanAgenda().map(x => "<li>" + escapeHtml(x) + "</li>").join("\n");
    const html = '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width, initial-scale=1">' +
      '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">' +
      '<title>LightUp PRIVATE human preparation agenda</title>' +
      '<style>body{font:16px/1.55 system-ui,sans-serif;max-width:850px;margin:40px auto;padding:0 20px;color:#1d2734}li{padding:7px 0}header{border-bottom:2px solid #3e665d;padding-bottom:16px}strong{color:#9b2020}aside{border-left:4px solid #9b2020;padding:12px;background:#fff3f3}footer{margin-top:35px;color:#555;font-size:12px}</style>' +
      '</head><body><header><h1>PRIVATE human scope follow-up</h1><p><strong>PREPARATION ONLY · NO VERIFIED CONSENT / GRANT / PERMISSION</strong></p>' +
      '<p>Internal draft: ' + escapeHtml(state.project) + ' · Client-declared label: ' + escapeHtml(state.client) + '</p>' +
      '<p>Requested local window: ' + escapeHtml(state.start) + ' → ' + escapeHtml(state.end) +
      ' · Proposed ceiling: ' + escapeHtml(state.risk) + '</p></header>' +
      '<aside>This is untrusted human-entered preparation. No real-world execution, activation, scanning, revocation or release is authorized.</aside>' +
      '<ol>' + lines + '</ol><footer>LightUp Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · This unsigned PRIVATE paper does not prove any named person, client, source, risk decision or consent.</footer>' +
      '</body></html>';
    if (textBytes(html) > MAX_BYTES) {
      announce("Agenda exceeds the 64 KiB PRIVATE export cap.", true);
      return;
    }
    download("lightup-scope-human-agenda-PRIVATE.html", html, "text/html");
    announce("Standalone scriptless PRIVATE human agenda prepared for local download — still not authorized.");
  }

  async function readFile(file) {
    if (!file || file.size > MAX_BYTES) throw Error("Select a JSON file no larger than 64 KiB.");
    // Decode original file bytes strictly: File.text() can silently replace invalid UTF-8.
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (bytes.byteLength > MAX_BYTES) throw Error("PRIVATE draft file exceeds 64 KiB.");
    let raw;
    try { raw = new TextDecoder("utf-8", {fatal: true, ignoreBOM: true}).decode(bytes); }
    catch (_) { throw Error("PRIVATE draft is not valid UTF-8."); }
    if (textBytes(raw) !== bytes.byteLength) throw Error("Noncanonical UTF-8 bytes refused.");
    return decodeOwnExport(raw);
  }
  async function importDraft(file, encrypted = false) {
    try {
      const next = encrypted ? await decryptWorkroom(file) : await readFile(file);
      if (!confirm("Replace all current unsaved PRIVATE draft data with the selected validated file?")) return;
      state = next;
      rowNumber = Math.max(0, ...state.rows.map(row => Number(row.id.slice(1))));
      $("filter").value = ""; $("status-filter").value = "all";
      $("compare-section").hidden = true;
      syncForm(); renderRows(); refresh();
      announce("PRIVATE draft opened locally after full strict admission. Still DRAFT/HOLD.");
    } catch (error) { announce("OPEN REJECTED: " + error.message + " Existing draft was retained.", true); }
  }
  async function compareDraft(file, encrypted = false) {
    try {
      const before = encrypted ? await decryptWorkroom(file) : await readFile(file);
      const problems = validate(state);
      if (problems.length) throw Error("Complete current draft before comparing: " + problems[0]);
      const oldAssets = new Map(before.rows.map(row => [row.asset, row]));
      const newAssets = new Map(state.rows.map(row => [row.asset, row]));
      const added = state.rows.filter(row => !oldAssets.has(row.asset)).map(row => row.asset);
      const removed = before.rows.filter(row => !newAssets.has(row.asset)).map(row => row.asset);
      const changed = state.rows.filter(row => {
        const old = oldAssets.get(row.asset);
        return old && ROW_KEYS.filter(key => key !== "id" && key !== "asset")
          .some(key => JSON.stringify(old[key]) !== JSON.stringify(row[key]));
      }).map(row => row.asset + " — proposed boundary/capability/review fields changed");
      const headerChanged = FORM_FIELDS.filter(key => before[key] !== state[key]);
      if (headerChanged.length) changed.unshift("Proposed engagement fields changed: " + headerChanged.join(", "));
      $("added").textContent = added.join("\n") || "(none)";
      $("removed").textContent = removed.join("\n") || "(none)";
      $("changed").textContent = changed.join("\n") || "(none)";
      $("compare-section").hidden = false;
      announce("Literal PRIVATE draft comparison only. Additions are NOT approved and removals are NOT verified revocations.");
    } catch (error) { announce("COMPARISON REJECTED: " + error.message + " No draft was modified.", true); }
  }

  function init() {
    for (const field of FORM_FIELDS) {
      $(field).addEventListener("input", event => {
        state[field] = field === "risk" ? event.target.value : event.target.value.trim();
        refresh();
      });
      // On blur the visible input and serialized draft must agree.
      $(field).addEventListener("blur", event => {
        event.target.value = state[field];
      });
    }
    $("add").addEventListener("click", addRow);
    $("add-bottom").addEventListener("click", addRow);
    $("bulk-add").addEventListener("click", bulkAdd);
    $("filter").addEventListener("input", renderRows);
    $("status-filter").addEventListener("change", renderRows);
    $("export-encrypted").addEventListener("click", encryptWorkroom);
    $("export").addEventListener("click", exportDraft);
    $("receipt").addEventListener("click", exportCounts);
    $("export-agenda").addEventListener("click", exportAgenda);
    $("print").addEventListener("click", () => {
      const problems = validate(state);
      if (problems.length) { announce("Complete draft before printing: " + problems[0], true); return; }
      if (confirm("Print PRIVATE unverified scope proposal? Only use an approved destination.")) window.print();
    });
    $("choose-import").addEventListener("click", () => $("file-import").click());
    $("choose-compare").addEventListener("click", () => $("file-compare").click());
    $("choose-import-encrypted").addEventListener("click", () => $("file-import-encrypted").click());
    $("choose-compare-encrypted").addEventListener("click", () => $("file-compare-encrypted").click());
    $("file-import").addEventListener("change", async event => {
      const file = event.target.files[0]; event.target.value = ""; if (file) await importDraft(file);
    });
    $("file-compare").addEventListener("change", async event => {
      const file = event.target.files[0]; event.target.value = ""; if (file) await compareDraft(file);
    });

    $("file-import-encrypted").addEventListener("change", async event => {
      const file = event.target.files[0]; event.target.value = ""; if (file) await importDraft(file, true);
    });
    $("file-compare-encrypted").addEventListener("change", async event => {
      const file = event.target.files[0]; event.target.value = ""; if (file) await compareDraft(file, true);
    });
    $("close-compare").addEventListener("click", () => $("compare-section").hidden = true);
    $("clear").addEventListener("click", () => {
      if (!confirm("Discard all current PRIVATE draft state in this page? This cannot be undone.")) return;
      state = blankDocument(); rowNumber = 0;
      $("filter").value = ""; $("status-filter").value = "all";
      $("compare-section").hidden = true;
      syncForm(); renderRows(); refresh();
    });
    syncForm(); renderRows(); refresh();
  }
  document.addEventListener("DOMContentLoaded", init, {once: true});
}());
