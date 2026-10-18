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
  const handoffRoutes = ["private-archive", "client-review", "operator-review"];
  const clientReviewRoles = ["Client proposal — unverified", "Scope revision — unverified", "Schedule handoff — unverified"];
  const prepStages = ["unsorted", "clarify", "drafting", "ready", "historical"];
  const stageLabels = {unsorted: "Unsorted", clarify: "Needs human clarification", drafting: "Preparation in progress", ready: "Prepared for human review — NOT approved", historical: "Historical draft — NOT current"};
  const MAX_NOTE_CHARS = 600;
  const roles = ["Unclassified", "Client proposal — unverified", "Operator review — unverified", "Scope revision — unverified", "Schedule handoff — unverified"];
  function validRole(role) { return typeof role === "string" && roles.includes(role); }
  const $ = (id) => document.getElementById(id);
  const els = {
    files: $("files"), list: $("file-list"), summary: $("file-summary"),
    seal: $("seal"), rekey: $("rekey"), selectAll: $("select-all"), selectNone: $("select-none"), selectRoute: $("select-route"), stageFilter: $("stage-filter"),
    password: $("seal-password"), confirm: $("seal-confirm"),
    clear: $("clear"), openFile: $("open-file"), openPassword: $("open-password"),
    unlock: $("unlock"), lock: $("lock"), recovered: $("recovered"),
    mergeMode: $("merge-mode"), handoffRoute: $("handoff-route"),
    before: $("compare-before"), after: $("compare-after"),
    previewFile: $("preview-file"), compareFiles: $("compare-files"),
    hidePreview: $("hide-preview"), comparisonOutput: $("comparison-output"),
    comparisonSummary: $("comparison-summary"),
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
    clearPreview();
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
    const beforeValue = els.before.value, afterValue = els.after.value;
    els.before.replaceChildren();
    els.after.replaceChildren();
    for (const dropdown of [els.before, els.after]) {
      const placeholder = document.createElement("option");
      placeholder.value = ""; placeholder.textContent = "Choose a local draft";
      dropdown.append(placeholder);
      entries.forEach((entry, index) => {
        const option = document.createElement("option");
        option.value = String(index); option.textContent = entry.name;
        dropdown.append(option);
      });
    }
    if (entries[Number(beforeValue)] && beforeValue !== "") els.before.value = beforeValue;
    if (entries[Number(afterValue)] && afterValue !== "") els.after.value = afterValue;
    const total = entries.reduce((n, e) => n + e.bytes.length, 0);
    const selectedCount = entries.filter((item) => item.selected).length;
    const clarifyCount = entries.filter((item) => item.stage === "clarify").length;
    const preparedCount = entries.filter((item) => item.stage === "ready").length;
    els.summary.textContent = entries.length + " local file(s), " + total.toLocaleString() + " bytes in tab memory; " + selectedCount + " selected for encrypted export; " + clarifyCount + " need clarification, " + preparedCount + " prepared for HUMAN REVIEW ONLY. No items approved.";
    entries.forEach((entry, index) => {
      if (els.stageFilter.value !== "all" && entry.stage !== els.stageFilter.value) return;
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
        clearPreview();
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
      const stageLabel = document.createElement("label");
      stageLabel.textContent = "Private preparation stage (never a grant)";
      const stage = document.createElement("select");
      stage.setAttribute("aria-label", "Unverified local preparation stage for " + entry.name);
      for (const key of prepStages) {
        const option = document.createElement("option");
        option.value = key; option.textContent = stageLabels[key]; stage.append(option);
      }
      stage.value = entry.stage;
      stage.addEventListener("change", () => {
        if (busy) return;
        entry.stage = stage.value; touch(); paint();
        notice("Preparation stage saved to temporary local memory only. Re-encrypt an archive to save it.");
      });
      stageLabel.append(stage);
      text.append(stageLabel);
      const noteLabel = document.createElement("label");
      noteLabel.textContent = "Internal review note (encrypted in archive; excluded from client handoff)";
      const memo = document.createElement("textarea");
      memo.setAttribute("aria-label", "Internal private note for " + entry.name);
      memo.maxLength = MAX_NOTE_CHARS; memo.rows = 2;
      memo.placeholder = "Human follow-up only; avoid secrets and personal data";
      memo.value = entry.note;
      memo.addEventListener("input", () => {
        if (busy) return;
        entry.note = memo.value.slice(0, MAX_NOTE_CHARS);
        touch();
      });
      noteLabel.append(memo);
      text.append(noteLabel);
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
          staged.push({name, bytes, hash: await digest(bytes), role: roles[0], selected: true, stage: "unsorted", note: ""});
        }
        entries.push(...staged);
        clearPreview();
        notice("New local draft files loaded. They are not persisted until you explicitly export an encrypted vault.");
      } catch (err) {
        for (const item of staged) item.bytes.fill(0);
        throw err;
      }
    });
  }
  async function seal(archive = false) {
    await inProgress(async () => {
      supportsCrypto();
      const outgoing = archive ? entries.slice() : entries.filter((entry) => entry.selected);
      invariant(outgoing.length > 0 && outgoing.length <= MAX_FILES);
      const passphrase = els.password.value;
      const confirm = els.confirm.value;
      const route = archive ? "private-archive" : els.handoffRoute.value;
      els.password.value = ""; els.confirm.value = "";
      if (passphrase.length < 14 || passphrase.length > 256 || passphrase !== confirm) {
        notice("Use a matching 14–256 character passphrase. There is no account reset or recovery.", true);
        return;
      }
      invariant(handoffRoutes.includes(route));
      if (route === "client-review") invariant(outgoing.every((entry) => clientReviewRoles.includes(entry.role)));
      // An archive rotation always includes the complete in-memory dossier regardless
      // of export selection, and never downgrades it into a recipient packet.
      const manifest = outgoing.map((entry) => entry.name + " [" + entry.role + "]").join("\n");
      if (!window.confirm((archive ? "Full private archive re-encryption (old files remain valid).\n" : "") + "Intended route: " + route
        + "\n\nInclude exactly these local files?\n" + manifest
        + "\n\nThis does not verify recipient identity or confer consent. Continue encrypting?")) {
        notice("Encryption cancelled before creating a packet; no files were sent or downloaded.");
        return;
      }
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const payload = {
        schema: "lightup.offline.scope-packet.payload.v1",
        createdUtc: new Date().toISOString(),
        handoffRoute: route,
        authority: {may_authorize: false, may_consent: false, may_grant: false, may_scan: false, may_dispatch: false, may_deploy: false, may_release: false},
        files: outgoing.map((entry) => {
          const record = {name: entry.name, length: entry.bytes.length, sha256: entry.hash,
            role: entry.role, base64: b64(entry.bytes)};
          if (route !== "client-review") {
            invariant(prepStages.includes(entry.stage) && typeof entry.note === "string" && entry.note.length <= MAX_NOTE_CHARS);
            record.stage = entry.stage;
            record.note = entry.note;
          }
          return record;
        })
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
        save(blob, archive ?
          "lightup-private-scope-packet-reencrypted.lightup-vault.json" :
          "lightup-private-scope-packet.lightup-vault.json");
        notice((archive ? "Entire in-memory private dossier re-encrypted with fresh salt/IV. Previous downloaded files and passphrases remain usable until you delete those copies. " :
          "Selected " + outgoing.length + " file(s) encrypted; unselected local files excluded. ") +
          (route === "client-review" ? "Internal notes and preparation stages excluded. " : "Internal notes and stages encrypted. ") +
          "No identities verified or permissions created.");
      } finally { cleartext.fill(0); }
    });
  }
  function validatePayload(body) {
    const hasRoute = Object.prototype.hasOwnProperty.call(body, "handoffRoute");
    strictKeys(body, hasRoute ?
      ["schema", "createdUtc", "handoffRoute", "authority", "files"] :
      ["schema", "createdUtc", "authority", "files"]);
    if (hasRoute) invariant(handoffRoutes.includes(body.handoffRoute));
    invariant(body.schema === "lightup.offline.scope-packet.payload.v1");
    invariant(typeof body.createdUtc === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(body.createdUtc));
    strictKeys(body.authority, ["may_authorize", "may_consent", "may_grant", "may_scan", "may_dispatch", "may_deploy", "may_release"]);
    invariant(Object.values(body.authority).every((x) => x === false));
    invariant(Array.isArray(body.files) && body.files.length > 0 && body.files.length <= MAX_FILES);
    return hasRoute ? body.handoffRoute : "private-archive";
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
        const importedRoute = validatePayload(payload);
        const names = new Set();
        let total = 0;
        for (const record of payload.files) {
          const hasRole = Object.prototype.hasOwnProperty.call(record, "role");
          const hasDossier = Object.prototype.hasOwnProperty.call(record, "stage") ||
            Object.prototype.hasOwnProperty.call(record, "note");
          const expected = ["name", "length", "sha256", "base64"];
          if (hasRole) expected.push("role");
          if (hasDossier) expected.push("stage", "note");
          strictKeys(record, expected);
          if (hasRole) invariant(validRole(record.role));
          if (hasDossier) invariant(prepStages.includes(record.stage) &&
            typeof record.note === "string" && record.note.length <= MAX_NOTE_CHARS &&
            !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(record.note));
          if (importedRoute === "client-review") {
            invariant(clientReviewRoles.includes(record.role));
            invariant(!hasDossier); // The client handoff must never carry internal annotations.
          }
          const name = nameOf(record.name);
          invariant(!names.has(name));
          names.add(name);
          invariant(Number.isSafeInteger(record.length) && record.length > 0 && record.length <= MAX_FILE_BYTES);
          invariant(validHex(record.sha256));
          total += record.length;
          invariant(total <= MAX_TOTAL_BYTES);
          const bytes = unb64(record.base64, MAX_FILE_BYTES);
          staged.push({name, bytes, hash: record.sha256, role: hasRole ? record.role : roles[0], selected: true, stage: hasDossier ? record.stage : "unsorted", note: hasDossier ? record.note : ""});
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
              invariant(current.hash === item.hash && current.role === item.role &&
                current.bytes.length === item.bytes.length &&
                current.stage === item.stage && current.note === item.note);
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
          clearPreview();
          notice(newCount + " new local file(s) merged atomically from " + importedRoute + " handoff. Roles/recipient identities remain unverified.");
        } else {
          // Atomic replacement: previous plaintext is forgotten only after authenticated validation.
          for (const item of entries) item.bytes.fill(0);
          entries = staged;
          clearPreview();
          notice("Encrypted " + importedRoute + " packet restored locally. Verify drafts with real client/operator; the vault grants no authorization.");
        }
      } catch (err) {
        for (const item of staged) item.bytes.fill(0);
        throw err;
      } finally { cleartext.fill(0); }
    });
  }


  // Review-only viewer: DOM text nodes, never HTML execution or browser navigation.
  // Bounded line-level diff avoids quadratic work beyond 400 lines per file.
  const MAX_REVIEW_LINES = 400;
  const MAX_REVIEW_COLUMNS = 2048;
  function clearPreview() {
    els.comparisonOutput.replaceChildren();
    els.comparisonOutput.hidden = true;
    els.comparisonSummary.textContent =
      "No private text visible. Viewing or comparing drafts cannot verify scope or grant permission.";
  }
  function reviewEntry(selector) {
    const value = selector.value;
    invariant(/^(?:0|[1-9][0-9]?)$/.test(value) && Number(value) < entries.length);
    const entry = entries[Number(value)];
    invariant(entry && entry.bytes.length <= MAX_FILE_BYTES);
    const raw = DEC.decode(entry.bytes).replace(/\r\n?/g, "\n");
    const lines = raw.split("\n");
    invariant(lines.length <= MAX_REVIEW_LINES && lines.every((line) => line.length <= MAX_REVIEW_COLUMNS));
    return {entry, lines};
  }
  function displayRows(rows) {
    els.comparisonOutput.replaceChildren();
    const fragment = document.createDocumentFragment();
    for (const row of rows) {
      const line = document.createElement("span");
      line.className = row.kind;
      // textContent, not innerHTML: imported script/markup can never execute.
      line.textContent = row.prefix + row.text + "\n";
      fragment.append(line);
    }
    els.comparisonOutput.append(fragment);
    els.comparisonOutput.hidden = false;
  }
  function preview() {
    if (busy) return;
    touch(); clearPreview();
    try {
      const {entry, lines} = reviewEntry(els.before);
      displayRows(lines.map((text) => ({kind: "same", prefix: "  ", text})));
      els.comparisonSummary.textContent = "Local read-only preview: " + entry.name + ". "
        + lines.length + " lines. No scope/identity/consent status has been established.";
    } catch {
      notice("Local preview held: select a valid bounded UTF-8 draft (400 lines max, 2048 characters per line).", true);
    }
  }
  function compare() {
    if (busy) return;
    touch(); clearPreview();
    try {
      invariant(els.before.value !== els.after.value);
      const old = reviewEntry(els.before), current = reviewEntry(els.after);
      const a = old.lines, b = current.lines;
      // Dynamic-programming LCS, 401 x 401 finite grid, avoids misleading positional diff.
      const dp = Array.from({length: a.length + 1}, () => new Uint16Array(b.length + 1));
      for (let i = a.length - 1; i >= 0; i--) {
        for (let j = b.length - 1; j >= 0; j--) {
          dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1
            : Math.max(dp[i + 1][j], dp[i][j + 1]);
        }
      }
      const rows = [];
      let i = 0, j = 0, removed = 0, added = 0;
      while (i < a.length || j < b.length) {
        if (i < a.length && j < b.length && a[i] === b[j]) {
          rows.push({kind: "same", prefix: "  ", text: a[i++]}); j++;
        } else if (i < a.length && (j >= b.length || dp[i + 1][j] >= dp[i][j + 1])) {
          rows.push({kind: "removed", prefix: "- ", text: a[i++]}); removed++;
        } else {
          rows.push({kind: "added", prefix: "+ ", text: b[j++]}); added++;
        }
      }
      displayRows(rows);
      els.comparisonSummary.textContent =
        "Read-only comparison: " + old.entry.name + " → " + current.entry.name
        + ". " + added + " added, " + removed + " removed lines. Source documents may still lack authenticated identity, consent or authorization.";
    } catch {
      notice("Comparison held: choose two distinct bounded local UTF-8 drafts (400 lines max, 2048 characters per line).", true);
    }
  }

  els.files.addEventListener("change", addFiles);
  els.previewFile.addEventListener("click", preview);
  els.compareFiles.addEventListener("click", compare);
  els.hidePreview.addEventListener("click", () => { touch(); clearPreview(); });
  els.selectAll.addEventListener("click", () => {
    if (busy) return; entries.forEach((entry) => {entry.selected = true;}); touch(); paint();
  });
  els.selectNone.addEventListener("click", () => {
    if (busy) return; entries.forEach((entry) => {entry.selected = false;}); touch(); paint();
  });
  els.seal.addEventListener("click", () => seal(false));
  els.rekey.addEventListener("click", () => seal(true));
  els.stageFilter.addEventListener("change", () => {touch(); paint();});
  els.selectRoute.addEventListener("click", () => {
    if (busy) return;
    const route = els.handoffRoute.value;
    invariant(handoffRoutes.includes(route));
    const choose = (entry) => route === "private-archive" ||
      (route === "client-review" && clientReviewRoles.includes(entry.role) && entry.stage !== "historical") ||
      (route === "operator-review" && entry.role === "Operator review — unverified" && entry.stage !== "historical");
    const proposed = entries.filter(choose);
    if (!proposed.length) {notice("No current files fit that self-reported route. Select eligible files manually.", true);return;}
    if (!window.confirm("Select " + proposed.length + " self-labelled file(s) for " + route +
      "? This is a convenience suggestion, NOT verification of the recipient or the contents.")) return;
    entries.forEach((entry) => {entry.selected = choose(entry);});
    touch(); paint(); notice("Suggested selection applied. Manually inspect every file before export.");
  });
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
