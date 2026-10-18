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
  function likelyCredentialContent(bytes) {
    // Intentional limited DLP warning for accidental client-handoff leaks only.
    // NOT a comprehensive secrets scanner or proof of a clean/authorized target.
    const source = DEC.decode(bytes);
    const hints = [
      /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/i,
      /\bAuthorization\s*:\s*Bearer\s+[^\s"'<>]{10,}/i,
      /\b(?:api[_ -]?key|secret[_ -]?(?:key|token)|access[_ -]?token|password)\s*[:=]\s*["']?[^\s"'<>]{12,}/i,
      /\bAKIA[0-9A-Z]{16}\b/,
      /\b(?:session[_ -]?cookie|set-cookie)\s*[:=]\s*[^\r\n]{24,}/i
    ];
    return hints.some((pattern) => pattern.test(source));
  }
  const $ = (id) => document.getElementById(id);
  const els = {
    files: $("files"), list: $("file-list"), summary: $("file-summary"),
    seal: $("seal"), lockAfterExport: $("lock-after-export"), rekey: $("rekey"), selectAll: $("select-all"), selectNone: $("select-none"), selectRoute: $("select-route"), stageFilter: $("stage-filter"),
    password: $("seal-password"), confirm: $("seal-confirm"),
    clear: $("clear"), openFile: $("open-file"), openPassword: $("open-password"),
    unlock: $("unlock"), lock: $("lock"), recovered: $("recovered"),
    mergeMode: $("merge-mode"), handoffRoute: $("handoff-route"),
    before: $("compare-before"), after: $("compare-after"),
    studioSource: $("studio-source"), studioInspect: $("studio-inspect"), studioBulk: $("studio-bulk"), studioBulkExport: $("studio-bulk-export"), studioBulkFlag: $("studio-bulk-flag"),
    studioFlag: $("studio-flag"), studioReport: $("studio-report"),
    studioClear: $("studio-clear"), studioStatus: $("studio-status"),
    studioSummary: $("studio-summary"), studioAssets: $("studio-assets"),
    redactSource: $("redact-source"), redactTerm: $("redact-term"),
    redactCredentials: $("redact-credentials"), redactCreate: $("redact-create"),
    redactClear: $("redact-clear"), redactSummary: $("redact-summary"),
    previewFile: $("preview-file"), compareFiles: $("compare-files"),
    hidePreview: $("hide-preview"), comparisonOutput: $("comparison-output"),
    comparisonSummary: $("comparison-summary"),
    message: $("message")
  };
  let entries = [];
  let busy = false;
  let lastAction = Date.now();
  let inspectedStudio = null;
  let inspectedPortfolio = null;

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
    inspectedStudio = null;
    inspectedPortfolio = null;
    els.studioStatus.textContent = "Locked. No proposal inspection retained.";
    els.studioSummary.replaceChildren(); els.studioAssets.textContent = "";
    els.stageFilter.value = "all";
    clearPreview();
    els.files.value = "";
    els.openFile.value = "";
    els.password.value = "";
    els.confirm.value = "";
    els.openPassword.value = "";
    els.redactTerm.value = "";
    els.redactSummary.textContent = "No local edited copy in this session; all authority flags remain false.";
    paint();
  }
  function paint() {
    els.list.replaceChildren();
    els.recovered.replaceChildren();
    const beforeValue = els.before.value, afterValue = els.after.value;
    const redactValue = els.redactSource.value;
    const studioValue = els.studioSource.value;
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
    els.studioSource.replaceChildren();
    const studioPlaceholder = document.createElement("option");
    studioPlaceholder.value = ""; studioPlaceholder.textContent = "Choose a Studio v1 JSON draft";
    els.studioSource.append(studioPlaceholder);
    entries.forEach((entry, index) => {
      if (!entry.name.toLowerCase().endsWith(".json")) return;
      const option = document.createElement("option");
      option.value = String(index); option.textContent = entry.name;
      els.studioSource.append(option);
    });
    if (studioValue !== "" && entries[Number(studioValue)] &&
        entries[Number(studioValue)].name.toLowerCase().endsWith(".json")) {
      els.studioSource.value = studioValue;
    }
    els.redactSource.replaceChildren();
    const redactPlaceholder = document.createElement("option");
    redactPlaceholder.value = ""; redactPlaceholder.textContent = "Choose local file";
    els.redactSource.append(redactPlaceholder);
    entries.forEach((entry, index) => {
      const option = document.createElement("option");
      option.value = String(index); option.textContent = entry.name;
      els.redactSource.append(option);
    });
    if (entries[Number(redactValue)] && redactValue !== "") els.redactSource.value = redactValue;
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
        inspectedStudio = null; els.studioAssets.textContent = "";
        els.studioSummary.replaceChildren();
        els.studioStatus.textContent = "Source selection changed; inspect a current exact file.";
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
        const cleaned = memo.value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "");
        if (cleaned !== memo.value) memo.value = cleaned;
        entry.note = cleaned.slice(0, MAX_NOTE_CHARS);
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
    els.redactCreate.disabled = busy || entries.length === 0 || entries.length >= MAX_FILES || !window.isSecureContext || !window.crypto || !window.crypto.subtle;
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
        inspectedStudio = null;
        els.studioSummary.replaceChildren(); els.studioAssets.textContent = "";
        clearPreview();
        notice("New local draft files loaded. They are not persisted until you explicitly export an encrypted vault.");
      } catch (err) {
        for (const item of staged) item.bytes.fill(0);
        throw err;
      }
    });
  }

  // Local review-copy preparation only. Never edit the source byte array,
  // generate authorizing metadata or make claims that redaction is complete.
  async function createPrivacyCopy() {
    await inProgress(async () => {
      supportsCrypto();
      const rawIndex = els.redactSource.value;
      const manualTerm = els.redactTerm.value;
      const auto = els.redactCredentials.checked;
      els.redactTerm.value = "";
      invariant(/^(0|[1-9]\d?)$/.test(rawIndex));
      const index = Number(rawIndex);
      invariant(index < entries.length && entries.length < MAX_FILES);
      invariant(manualTerm.length === 0 ||
        (manualTerm.length >= 6 && manualTerm.length <= 128 &&
        !/[\u0000-\u001f\u007f]/.test(manualTerm)));
      invariant(auto || manualTerm.length >= 6);
      const source = entries[index];
      const original = DEC.decode(source.bytes);
      let changed = original;
      let replacements = 0;
      const mask = (label) => () => { replacements++; return "[LIGHTUP-REDACTED-" + label + "]"; };
      if (auto) {
        // A complete bounded PEM block is required. Truncated/unpaired headers
        // still trigger the original client safety hold after substitution.
        changed = changed.replace(
          /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]{0,131072}?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/gi,
          mask("PRIVATE-KEY")
        );
        changed = changed.replace(
          /\bAuthorization\s*:\s*Bearer\s+[^\s"'<>]{10,}/gi,
          mask("BEARER")
        );
        changed = changed.replace(
          /\b(?:api[_ -]?key|secret[_ -]?(?:key|token)|access[_ -]?token|password)\s*[:=]\s*["']?[^\s"'<>]{12,}/gi,
          mask("CREDENTIAL")
        );
        changed = changed.replace(/\bAKIA[0-9A-Z]{16}\b/g, mask("ACCESS-KEY"));
        changed = changed.replace(
          /\b(?:session[_ -]?cookie|set-cookie)\s*[:=]\s*[^\r\n]{24,}/gi,
          mask("COOKIE")
        );
      }
      if (manualTerm.length) {
        const occurrences = changed.split(manualTerm).length - 1;
        if (occurrences) {
          replacements += occurrences;
          changed = changed.split(manualTerm).join("[LIGHTUP-REDACTED-PRIVATE-TERM]");
        }
      }
      invariant(replacements > 0);
      const edited = ENC.encode(changed);
      try {
        invariant(edited.length > 0 && edited.length <= MAX_FILE_BYTES);
        // Refuse residual recognized credentials; heuristic inability to find
        // others is never treated as evidence of safety.
        invariant(!likelyCredentialContent(edited));
        invariant(entries.reduce((sum, item) => sum + item.bytes.length, 0) +
          edited.length <= MAX_TOTAL_BYTES);
        const hash = await digest(edited);
        const stem = source.name.replace(/\.[^.]+$/, "").slice(0, 62);
        const proposed = stem + "-privacy-" + hash.slice(0, 12) + ".txt";
        const name = nameOf(proposed);
        invariant(!entries.some((item) => item.name === name));
        const approved = window.confirm("Create a distinct edited TEXT copy of " +
          source.name + " with " + replacements + " redaction(s)?\n\n" +
          "The source remains untouched; the new copy is NOT selected for export " +
          "and remains NEEDS HUMAN CLARIFICATION until you inspect its full contents. " +
          "Masking can alter document structure and is never a certificate that no secrets remain.");
        if (!approved) {
          edited.fill(0);
          els.redactSummary.textContent = "Local privacy edit cancelled; original unchanged.";
          return;
        }
        entries.push({
          name, bytes: edited, hash, role: source.role,
          selected: false, stage: "clarify",
          note: "Local privacy derivative from source SHA-256 " + source.hash +
            ". Masked " + replacements + " recognized/literal occurrence(s). " +
            "Review full text before any independent human handoff."
        });
        els.stageFilter.value = "all";
        touch(); paint();
        els.before.value = String(index);
        els.after.value = String(entries.length - 1);
        els.redactSummary.textContent = "Created local copy: " + name +
          ". " + replacements + " replacement(s), new SHA-256 " + hash.slice(0, 16) +
          "…; original unchanged. New copy is NOT selected and is not approved for sharing.";
        notice("Privacy edit added to offline inventory. Compare both versions and manually check for remaining confidential details.");
      } catch (error) {
        edited.fill(0);
        throw error;
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
      if (route === "client-review") {
        // No internal notes/stages are exported. Historical drafts are not
        // silently promoted to a current client handoff.
        invariant(outgoing.every((entry) =>
          clientReviewRoles.includes(entry.role) && entry.stage === "ready"));
        // Local bounded best-effort detection; reject on suspicious data,
        // disclose no matching raw content or credential fragments.
        const riskyCount = outgoing.filter((entry) => likelyCredentialContent(entry.bytes)).length;
        if (riskyCount) {
          notice("Client-facing export held: " + riskyCount +
            " selected draft(s) contain potential credential material. Remove/redact it in the SOURCE file and re-import; do not bypass using a role label. Heuristics are not a guarantee.", true);
          return;
        }
      }
      // An archive rotation always includes the complete in-memory dossier regardless
      // of export selection, and never downgrades it into a recipient packet.
      const manifest = outgoing.map((entry) => entry.name + " [" + entry.role + "]").join("\n");
      if (!window.confirm((archive ? "Full private archive re-encryption (old files remain valid).\n" : "") + "Intended route: " + route
        + "\n\nInclude exactly these local files?\n" + manifest
        + "\n\nThis does not verify recipient identity or confer consent. Continue encrypting?")) {
        notice("Encryption cancelled before creating a packet; no files were sent or downloaded.");
        return;
      }
      // A client/export-only packet deliberately omits internal annotations.
      // Auto-lock would irreversibly discard unsaved local work. Explicit
      // acknowledgement prevents silently destroying the only review copy.
      if (els.lockAfterExport.checked &&
          (route !== "private-archive" || outgoing.length !== entries.length)) {
        if (!window.confirm("DATA LOSS WARNING: this export does NOT preserve every document and private note in a full encrypted archive. Automatic lock will forget ALL current files and unsaved internal review notes from this tab after download.\n\nCreate a full private archive backup first, or uncheck automatic lock to continue editing. Explicitly discard the remaining workspace after export?")) {
          notice("Export cancelled without clearing local notes. Save a full private archive or disable automatic lock before limited handoff.");
          return;
        }
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
            invariant(prepStages.includes(entry.stage) && typeof entry.note === "string" &&
              entry.note.length <= MAX_NOTE_CHARS &&
              !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(entry.note));
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
        const shouldLock = els.lockAfterExport.checked;
        notice((archive ? "Entire in-memory private dossier re-encrypted with fresh salt/IV. Previous downloaded files and passphrases remain usable until you delete those copies. " :
          "Selected " + outgoing.length + " file(s) encrypted; unselected local files excluded. ") +
          (route === "client-review" ? "Internal notes and preparation stages excluded. " : "Internal notes and stages encrypted. ") +
          "No identities verified or permissions created.");
        if (shouldLock) {
          scrub();
          notice("Encrypted download created; readable workspace locked and in-memory file buffers cleared. Save your passphrase separately. Already downloaded copies remain on disk.");
        }
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
          staged.push({name, bytes, hash: record.sha256,
            role: hasRole ? record.role : roles[0], selected: true,
            stage: hasDossier ? record.stage : "unsorted",
            note: hasDossier ? record.note : "",
            hasPrivateMetadata: hasDossier});
          invariant(bytes.length === record.length && (await digest(bytes)) === record.sha256);
          DEC.decode(bytes);
        }
        if (els.mergeMode.checked) {
          // Never accept filename collisions with different bytes or review roles.
          // If a client handoff intentionally omitted PRIVATE metadata, preserve
          // the already-open operator memo/stage instead of treating the absent
          // values as a contradictory new declaration. Explicit private
          // metadata conflicts still hold atomically.
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
                (!item.hasPrivateMetadata ||
                  (current.stage === item.stage && current.note === item.note)));
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
          inspectedStudio = null;
          els.studioSummary.replaceChildren(); els.studioAssets.textContent = "";
          clearPreview();
          notice(newCount + " new local file(s) merged atomically from " + importedRoute + " handoff. Roles/recipient identities remain unverified.");
        } else {
          // Atomic replacement: previous plaintext is forgotten only after authenticated validation.
          for (const item of entries) item.bytes.fill(0);
          entries = staged;
          inspectedStudio = null;
          els.studioSummary.replaceChildren(); els.studioAssets.textContent = "";
          clearPreview();
          notice("Encrypted " + importedRoute + " packet restored locally. Verify drafts with real client/operator; the vault grants no authorization.");
        }
      } catch (err) {
        for (const item of staged) item.bytes.fill(0);
        throw err;
      } finally { cleartext.fill(0); }
    });
  }



  // Read-only offline adapter for exactly the *draft* Studio v1 producer format.
  // Not an authority policy, membership checker, operator decision or grant.
  function parseStudioStrict(source) {
    invariant(source.bytes.length > 0 && source.bytes.length <= 64 * 1024);
    const raw = DEC.decode(source.bytes);
    const stack = [];
    for (let i = 0; i < raw.length; i++) {
      const ch = raw[i];
      if (ch === '{' || ch === '[') stack.push({type: ch, keys: ch === '{' ? new Set() : null});
      else if (ch === '}' || ch === ']') {
        invariant(stack.length && stack[stack.length - 1].type === (ch === '}' ? '{' : '['));
        stack.pop();
      } else if (ch === '"') {
        const start = i;
        i++;
        while (i < raw.length) {
          if (raw[i] === '\\') { i += 2; continue; }
          if (raw[i] === '"') break;
          i++;
        }
        invariant(i < raw.length);
        const key = JSON.parse(raw.slice(start, i + 1));
        let next = i + 1;
        while (next < raw.length && /\s/.test(raw[next])) next++;
        if (raw[next] === ':') {
          invariant(stack.length && stack[stack.length - 1].type === '{');
          invariant(!['__proto__','prototype','constructor'].includes(key));
          const keys = stack[stack.length - 1].keys;
          invariant(!keys.has(key));
          keys.add(key);
        }
      }
    }
    invariant(stack.length === 0);
    const p = JSON.parse(raw);
    invariant(p !== null && typeof p === 'object' && !Array.isArray(p));
    const root = [
      'schema_version','kind','state','authorization','client_consent',
      'operator_consent','grant','execution','revocation_checked',
      'proposal_name','client_label','requested_assets','excluded_assets',
      'requested_mode','requested_risk','notes','proposed_activities',
      'proposed_window_local','proposed_window_utc','exported_at_utc'
    ];
    invariant(Object.keys(p).every(k => root.includes(k) || k === 'scope_fingerprint_sha256'));
    invariant(root.every(k => Object.prototype.hasOwnProperty.call(p,k)));
    invariant(p.schema_version === 1 && p.kind === 'lightup.scope_proposal_draft' && p.state === 'DRAFT_ONLY');
    for (const k of ['authorization','client_consent','operator_consent','grant','execution','revocation_checked']) {
      invariant(p[k] === false);
    }
    const str=(s,max)=>typeof s==='string' && s.length<=max && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(s);
    invariant(str(p.proposal_name,300) && str(p.client_label,300) && str(p.notes,3000));
    invariant(p.requested_mode === 'analysis_only' || p.requested_mode === 'authorized_assessment');
    invariant(Number.isInteger(p.requested_risk) && p.requested_risk >= 1 && p.requested_risk <= 4);
    for (const k of ['requested_assets','excluded_assets']) {
      invariant(Array.isArray(p[k]) && p[k].length<=80);
      invariant(p[k].every(v=>str(v,255) && v.length>0 && v === v.trim() && v === v.normalize('NFC')));
      invariant(new Set(p[k]).size === p[k].length);
    }
    invariant(p.proposed_activities !== null && typeof p.proposed_activities === 'object' &&
      !Array.isArray(p.proposed_activities));
    const activityKeys = ['passive_analysis','configuration_review','private_lab_network_checks'];
    strictKeys(p.proposed_activities,activityKeys);
    invariant(activityKeys.every(k=>typeof p.proposed_activities[k]==='boolean'));
    invariant(p.proposed_window_local !== null && typeof p.proposed_window_local === 'object' &&
      !Array.isArray(p.proposed_window_local));
    invariant(Object.keys(p.proposed_window_local).every(k=>['start','end'].includes(k)));
    for(const key of ['start','end']) invariant(
      p.proposed_window_local[key] === null || str(p.proposed_window_local[key],40));
    const utc = p.proposed_window_utc;
    invariant(utc && typeof utc==='object' && !Array.isArray(utc));
    invariant(Object.keys(utc).every(k=>[
      'status','timezone','start','end','start_offset_minutes','end_offset_minutes'
    ].includes(k)));
    invariant(str(utc.status,50) && str(utc.timezone,120));
    if (utc.status === 'resolved') {
      const iso=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
      invariant(typeof utc.start==='string' && iso.test(utc.start) &&
        typeof utc.end==='string' && iso.test(utc.end) &&
        !Number.isNaN(Date.parse(utc.start)) && !Number.isNaN(Date.parse(utc.end)) &&
        utc.start<utc.end &&
        Number.isInteger(utc.start_offset_minutes) && Math.abs(utc.start_offset_minutes)<=840 &&
        Number.isInteger(utc.end_offset_minutes) && Math.abs(utc.end_offset_minutes)<=840);
    } else {
      invariant(utc.start === null && utc.end === null);
    }
    invariant(str(p.exported_at_utc,40));
    if(Object.prototype.hasOwnProperty.call(p,'scope_fingerprint_sha256')) {
      invariant(typeof p.scope_fingerprint_sha256==='string' &&
        /^[a-f0-9]{64}$/.test(p.scope_fingerprint_sha256));
      // Studio's canonical digest needs the source-owner fingerprint algorithm.
      // It is NOT reproduced or treated as verified here.
    }
    return p;
  }

  function studioReview(p) {
    const concerns = [];
    const add=(code,message)=>concerns.push({code,message});
    if(!p.requested_assets.length) add('MISSING_PROPOSED_ASSETS','No proposed assets recorded for independent client/operator review.');
    if(!p.excluded_assets.length) add('EXCLUSIONS_NOT_DECLARED','No explicit exclusions recorded; operator must independently decide excluded assets.');
    if(p.requested_risk===4) add('RISK4_ESCALATION','Risk 4 requires distinct human escalation and an approved risk record.');
    if(p.proposed_activities.private_lab_network_checks)
      add('PRIVATE_LAB_PROVENANCE','Private lab network activity needs independent scope, isolation and approved lab-only handling.');
    if(p.requested_mode==='authorized_assessment')
      add('ACTIVE_MODE_NEEDS_REAL_GRANT','Requested active assessment mode is not an actual issued authorization.');
    if(!p.proposed_activities.passive_analysis && !p.proposed_activities.configuration_review &&
       !p.proposed_activities.private_lab_network_checks)
      add('NO_ACTIVITIES','No assessment activities explicitly proposed.');
    if(p.proposed_window_utc.status !== 'resolved')
      add('UTC_WINDOW_UNRESOLVED','Local requested time has no resolved UTC planning evidence.');
    else add('UTC_WINDOW_UNAPPROVED','Resolved UTC timestamps are tentative and not an operator-approved booking.');
    if(p.proposed_activities.private_lab_network_checks && p.requested_mode==='analysis_only')
      add('MODE_ACTIVITY_MISMATCH','Private-lab network checks are proposed alongside analysis-only mode. Clarify intended scope.');
    if(p.notes.trim().length<15) add('SAFETY_NOTES_INCOMPLETE','Safety / stop conditions should be independently clarified.');
    // Always include non-negotiable human checks, even if other fields look good.
    add('CLIENT_IDENTITY_AND_ASSET_CONTROL','Verify real client, tenant, ownership and exact allowed targets through authenticated systems.');
    add('OPERATOR_CONSENT_AND_REVOCATION','Require separate operator consent, permitted execution window and revocation check at action time.');
    add('CI_SECURITY_HUMAN_GO','The repository CI, independent security/privacy review and explicit human GO remain external gates.');
    return concerns;
  }

  function clearStudioInspection(message='Private proposal view hidden.') {
    inspectedStudio=null;
    inspectedPortfolio=null;
    els.studioSummary.replaceChildren();
    els.studioAssets.textContent='';
    els.studioStatus.textContent=message;
  }
  function inspectStudio() {
    if(busy)return;
    clearStudioInspection();
    touch();
    try {
      const id=els.studioSource.value;
      invariant(/^(0|[1-9]\d?)$/.test(id) && Number(id)<entries.length);
      const entry=entries[Number(id)];
      invariant(entry.name.toLowerCase().endsWith('.json'));
      const p=parseStudioStrict(entry);
      const concerns=studioReview(p);
      inspectedStudio={index:Number(id),hash:entry.hash,concerns,
        summary:{risk:p.requested_risk,mode:p.requested_mode,
          proposed:p.requested_assets.length,excluded:p.excluded_assets.length,
          utc:p.proposed_window_utc.status}};
      const head=document.createElement('div');
      head.className='item';
      head.textContent='Draft only · Risk '+p.requested_risk+' · Mode '+p.requested_mode+
        ' · '+p.requested_assets.length+' proposed assets · '+
        p.excluded_assets.length+' exclusions · UTC '+p.proposed_window_utc.status;
      els.studioSummary.append(head);
      for(const concern of concerns){
        const item=document.createElement('div');item.className='item';
        const span=document.createElement('span');
        span.textContent=concern.code+': '+concern.message;
        item.append(span);els.studioSummary.append(item);
      }
      // Raw proposed identities are shown ONLY in the private tab on deliberate disclosure.
      els.studioAssets.textContent=
        'PROPOSED (NOT AUTHORIZED):\n'+p.requested_assets.join('\n')+
        '\n\nEXCLUDED (NOT ENFORCED):\n'+p.excluded_assets.join('\n');
      els.studioStatus.textContent='Read-only offline source inspection: '+concerns.length+
        ' human review checks. Original SHA-256 '+entry.hash.slice(0,16)+
        '…; Studio embedded fingerprint, client identity, assets and UTC claims are NOT authenticated.';
      notice('Scope proposal inspected locally. Nothing was authorized, dispatched or submitted.');
    } catch {
      clearStudioInspection('HOLD: not an exact bounded Studio v1 proposal, ambiguous JSON keys, or unsupported values. Original remains unchanged.');
      notice('Scope proposal inspection refused; no trusted client/operator authority was created.',true);
    }
  }

  function inspectStudioPortfolio() {
    if (busy) return;
    touch(); clearStudioInspection();
    try {
      const candidates=entries.filter(item=>item.name.toLowerCase().endsWith('.json'));
      invariant(candidates.length>0 && candidates.length<=MAX_FILES);
      const records=[];
      let rejected=0;
      for (const entry of candidates) {
        try {
          const p=parseStudioStrict(entry);
          const warnings=studioReview(p);
          records.push({hash:entry.hash,risk:p.requested_risk,mode:p.requested_mode,
            assets:p.requested_assets.length,exclusions:p.excluded_assets.length,
            utc:p.proposed_window_utc.status,concerns:warnings});
        } catch {rejected++; }
      }
      invariant(records.length>0);
      inspectedPortfolio={
        snapshot:entries.map(entry=>entry.name+'\n'+entry.hash),
        records:records.map(({hash,risk,mode,assets,exclusions,utc,concerns})=>({
          source_sha256:hash,requested_risk:risk,requested_mode:mode,
          proposed_assets_count:assets,excluded_assets_count:exclusions,
          proposed_utc_status:utc,human_followup_codes:concerns.map(x=>x.code)
        })),
        excluded_count:rejected
      };
      const summary=document.createElement('div');summary.className='item';
      summary.textContent=records.length+' self-reported Studio v1 drafts inspected · '+
        rejected+' unknown/incompatible JSON document(s) excluded · '+
        records.filter(x=>x.risk===4).length+' high-risk draft(s) · '+
        records.filter(x=>x.utc!=='resolved').length+' unresolved UTC window(s). '+
        'This is human preparation, never evidence of consent or authority.';
      els.studioSummary.append(summary);
      const aggregate=new Map();
      for (const record of records) for(const x of record.concerns)
        aggregate.set(x.code,(aggregate.get(x.code)||0)+1);
      for (const [code,n] of [...aggregate.entries()].sort((a,b)=>b[1]-a[1])) {
        const line=document.createElement('div');line.className='item';
        line.textContent=n+' of '+records.length+' draft(s) need human follow-up: '+code;
        els.studioSummary.append(line);
      }
      for (const record of records) {
        const row=document.createElement('div');row.className='item';
        row.textContent='Local source SHA-256 '+record.hash.slice(0,16)+
          '… · risk '+record.risk+' · '+record.mode+
          ' · '+record.assets+' proposed / '+record.exclusions+' excluded'+
          ' · UTC '+record.utc+' · '+record.concerns.length+' review questions';
        els.studioSummary.append(row);
      }
      els.studioStatus.textContent='Private portfolio review only. For notes and anonymous file-bound export, inspect ONE exact source. '+rejected+' incompatible file(s) excluded.';
      els.studioAssets.textContent='';
      notice('Local portfolio overview prepared without raw asset or client labels. Nothing authorized.');
    } catch {
      clearStudioInspection('HOLD: import a well-formed bounded Studio v1 JSON source before making a local portfolio view.');
      notice('Portfolio review unavailable; no authority was established.',true);
    }
  }


  function exportStudioPortfolio() {
    if(busy)return;
    try {
      invariant(inspectedPortfolio && Array.isArray(inspectedPortfolio.records) &&
        inspectedPortfolio.records.length>0);
      const snapshot=entries.map(entry=>entry.name+'\n'+entry.hash);
      invariant(JSON.stringify(snapshot)===JSON.stringify(inspectedPortfolio.snapshot));
      if(!window.confirm(
        'Download an anonymous UNSIGNED portfolio preparation handoff? It includes source SHA-256 fingerprints, risk, proposed counts, UTC status and generic follow-up codes. No filenames or raw assets. Hashes are correlation hints, NOT identity or consent.'))return;
      const packet={
        kind:'lightup.offline.studio_scope_portfolio_human_preparation.v1',
        state:'REVIEW_ONLY_NOT_AUTHORIZED',
        authority:{authorized:false,client_consent_verified:false,
          operator_consent_verified:false,grant_issued:false,
          dispatch_allowed:false,scan_allowed:false,release_allowed:false},
        included_count:inspectedPortfolio.records.length,
        excluded_unsupported_json_count:inspectedPortfolio.excluded_count,
        sources:inspectedPortfolio.records
      };
      const output=JSON.stringify(packet,null,2)+'\n';
      invariant(ENC.encode(output).length<=32*1024);
      save(new Blob([output],{type:'application/json'}),
        'lightup-anonymous-portfolio-review.json');
      touch();notice('Anonymous multi-proposal human review handoff downloaded. No consent, grant or release rights created.');
    }catch{
      notice('HOLD: rebuild the local portfolio overview after import/removal changes. No review report exported.',true);
    }
  }


  function filePortfolioFollowUps() {
    if(busy)return;
    touch();
    try {
      invariant(inspectedPortfolio && inspectedPortfolio.records.length);
      const snapshot=entries.map(entry=>entry.name+'\n'+entry.hash);
      invariant(JSON.stringify(snapshot)===JSON.stringify(inspectedPortfolio.snapshot));
      const byHash=new Map(inspectedPortfolio.records.map(
        row=>[row.source_sha256,row.human_followup_codes]
      ));
      const candidates=[];
      let skipped=0;
      for(const entry of entries) {
        if(!entry.name.toLowerCase().endsWith('.json')||!byHash.has(entry.hash)) continue;
        // An explicitly historic or human-reviewed draft must never be
        // silently moved backward by a portfolio action.
        if(entry.stage==='ready'||entry.stage==='historical'){skipped++;continue;}
        const marker='Studio portfolio human follow-up ['+entry.hash.slice(0,12)+']';
        if(entry.note.includes(marker)){skipped++;continue;}
        const line=marker+': '+byHash.get(entry.hash).join(', ');
        const updated=entry.note ? entry.note+'\n'+line : line;
        invariant(updated.length <= MAX_NOTE_CHARS);
        candidates.push({entry,updated});
      }
      invariant(candidates.length>0);
      if(!window.confirm('File private human-follow-up codes for '+candidates.length+
        ' unapproved imported Studio drafts? '+skipped+
        ' previously prepared/historical/already-filed draft(s) remain unchanged. '+
        'Original files are untouched. All edits remain only in tab memory until you export a FULL encrypted private archive. No consent, grant or release rights are created.')) return;
      // Atomic casework update only AFTER every note is fully bounded.
      for(const {entry,updated} of candidates) {
        entry.note=updated;
        entry.stage='clarify';
      }
      paint();
      // Source checks remain available; no changes to source bytes.
      els.studioStatus.textContent=candidates.length+
        ' private follow-up note(s) filed. Save FULL encrypted private archive; changing review stages is NOT operator authorization.';
      notice('Human clarification follow-ups filed in temporary private dossier memory. No original Studio sources or permissions modified.');
    } catch {
      notice('HOLD: refresh the Studio portfolio view or resolve oversized/private notes; nothing was filed.',true);
    }
  }

  function currentStudio() {
    invariant(inspectedStudio && entries[inspectedStudio.index] &&
      entries[inspectedStudio.index].hash===inspectedStudio.hash &&
      els.studioSource.value===String(inspectedStudio.index));
    return inspectedStudio;
  }
  function flagStudio() {
    if(busy)return;
    try {
      const inspection=currentStudio();
      const entry=entries[inspection.index];
      const missing=inspection.concerns.map(x=>x.code).join(', ');
      const append='Studio v1 human follow-up ['+inspection.hash.slice(0,12)+']: '+missing;
      invariant(append.length + entry.note.length + 2 <= MAX_NOTE_CHARS);
      if(!window.confirm('Mark this local proposal Needs clarification and add anonymized human follow-up codes to its PRIVATE encrypted note? This is not an operator decision, signature or authorization.'))return;
      entry.note=(entry.note ? entry.note+'\n':'')+append;
      entry.stage='clarify';
      touch();paint();
      notice('Review checklist codes appended to private in-memory note. Save a full encrypted archive to retain them; no approval exists.');
    }catch {
      notice('HOLD: re-inspect current source or clear existing private note before adding follow-up. No changes made.',true);
    }
  }
  function exportStudioReport() {
    if(busy)return;
    try {
      const inspection=currentStudio();
      invariant(window.confirm('Download an anonymous UNSIGNED preparation checklist? It excludes source filenames, assets, notes, client labels and identity, and is NOT proof of consent or release approval.'));
      const packet={
        kind:'lightup.offline.studio_scope_human_preparation.v1',
        state:'REVIEW_ONLY_NOT_AUTHORIZED',
        authority:{authorized:false,client_consent_verified:false,
          operator_consent_verified:false,grant_issued:false,
          dispatch_allowed:false,scan_allowed:false,release_allowed:false},
        source_sha256:inspection.hash,
        proposed_counts:{assets:inspection.summary.proposed,exclusions:inspection.summary.excluded},
        requested_mode:inspection.summary.mode,
        requested_risk:inspection.summary.risk,
        proposed_utc_status:inspection.summary.utc,
        human_followup_codes:inspection.concerns.map(x=>x.code)
      };
      const contents=JSON.stringify(packet,null,2)+'\n';
      save(new Blob([contents],{type:'application/json'}),'lightup-anonymous-review-checklist.json');
      touch();notice('Unsigned anonymous preparation checklist downloaded. No identities verified or permissions granted.');
    }catch {
      notice('HOLD: inspect a current exact Studio v1 source before exporting the anonymous checklist.',true);
    }
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

  els.redactCreate.addEventListener("click", createPrivacyCopy);
  els.redactClear.addEventListener("click", () => {
    els.redactTerm.value = ""; touch();
    els.redactSummary.textContent = "Sensitive term input cleared from the form.";
  });
  els.studioInspect.addEventListener("click",inspectStudio);
  els.studioBulk.addEventListener("click",inspectStudioPortfolio);
  els.studioBulkExport.addEventListener("click",exportStudioPortfolio);
  els.studioBulkFlag.addEventListener("click",filePortfolioFollowUps);
  els.studioFlag.addEventListener("click",flagStudio);
  els.studioReport.addEventListener("click",exportStudioReport);
  els.studioClear.addEventListener("click",()=>{
    touch();clearStudioInspection();
    notice('Private proposal inspection hidden and no source changed.');
  });
  els.studioSource.addEventListener("change",()=>{clearStudioInspection();touch();});
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
      (route === "client-review" && clientReviewRoles.includes(entry.role) && entry.stage === "ready") ||
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
