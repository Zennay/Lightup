"use strict";
/* PRIVACY: strictly local, memory-only display and ORIGINAL-native decision CSV.
 * Never grant release, infer source identity, automatically choose a reviewer
 * or use network/storage/clipboard/shell. The Python finalizer re-admits inputs.
 */
(() => {
  const FIELDS = ["receipt_sha256", "ordinal", "source_kind", "stage", "question", "next_action"];
  const CHOICE_FIELDS = ["receipt_sha256", "review_a_sha256", "review_b_sha256",
                         "ordinal", "source_kind", "choice", "human_reason"];
  const KINDS = ["isolated_lab_input_preview", "offline_lab_benchmark_source", "isolated_lab_assessment"];
  const STAGES = ["unreviewed", "privacy_hold", "source_owner_hold", "consent_hold",
                  "follow_up_required", "human_reviewed_no_release"];
  const FLAGS = ["source_authenticated", "ground_truth_verified", "client_consent_verified",
                 "operator_consent_verified", "authorization_granted", "dispatch_allowed", "release_allowed"];
  const MAX = 256 * 1024;
  const byId = name => document.getElementById(name);
  let source = null, decisions = [], dirty = false, epoch = 0;
  let decisionRevision = 0, exportedRevision = -1;
  let undoStack = [], redoStack = [], noteEditTimer = null;
  const HISTORY_LIMIT = 40;
  const urls = new Set();

  function admitted(condition) {
    if (!condition) throw Error("HOLD: invalid or nonmatching PRIVATE source");
  }
  function notice(message, failed = false) {
    byId("notice").textContent = message;
    byId("notice").dataset.status = failed ? "hold" : "info";
  }
  function hex(input) {
    return Array.from(new Uint8Array(input), n => n.toString(16).padStart(2, "0")).join("");
  }
  async function readFile(file, maximum = MAX) {
    admitted(file && file.size > 0 && file.size <= maximum);
    const bytes = await file.arrayBuffer();
    admitted(bytes.byteLength === file.size);
    return bytes;
  }
  function utf8(bytes) {
    return new TextDecoder("utf-8", {fatal: true}).decode(bytes);
  }
  function unambiguousJson(value) {
    // Native Python object_pairs_hook rejects ALL duplicate JSON keys.
    // JS JSON.parse ordinarily overwrites them; parse a separate duplicate
    // key token stream first, including nested maps and escaped aliases.
    let offset = 0;
    const spaces = () => {
      while (offset < value.length && /[\u0009\u000a\u000d\u0020]/u.test(value[offset])) offset++;
    };
    function tokenString() {
      admitted(value[offset] === '"');
      const start = offset++;
      while (offset < value.length) {
        if (value[offset] === "\\") { offset += 2; continue; }
        if (value[offset++] === '"') return JSON.parse(value.slice(start, offset));
      }
      admitted(false);
    }
    function scan(depth) {
      admitted(depth <= 32);
      spaces();
      if (value[offset] === "{") {
        offset++;
        const keys = new Set();
        spaces();
        if (value[offset] === "}") { offset++; return; }
        while (offset < value.length) {
          spaces();
          const key = tokenString();
          admitted(!keys.has(key));
          keys.add(key);
          spaces();
          admitted(value[offset++] === ":");
          scan(depth + 1);
          spaces();
          if (value[offset] === "}") { offset++; return; }
          admitted(value[offset++] === ",");
        }
        admitted(false);
      } else if (value[offset] === "[") {
        offset++;
        spaces();
        if (value[offset] === "]") { offset++; return; }
        while (offset < value.length) {
          scan(depth + 1);
          spaces();
          if (value[offset] === "]") { offset++; return; }
          admitted(value[offset++] === ",");
        }
        admitted(false);
      } else if (value[offset] === '"') tokenString();
      else {
        const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/u.exec(value.slice(offset));
        admitted(match);
        offset += match[0].length;
      }
    }
    scan(0);
    spaces();
    admitted(offset === value.length);
    return JSON.parse(value);
  }
  function receiptRows(text) {
    const doc = unambiguousJson(text);
    admitted(doc && typeof doc === "object" && !Array.isArray(doc));
    admitted(doc.schema === "lightup.assessment_disclosure_preflight.v1" &&
             doc.status === "REVIEW_ONLY" && doc.source_byte_bound === false);
    admitted(FLAGS.every(flag => doc[flag] === false));
    const rows = doc.inspected_declarations_only;
    admitted(Array.isArray(rows) && rows.length >= 1 && rows.length <= 12 &&
             doc.source_count === rows.length);
    rows.forEach((row, index) => {
      admitted(row && typeof row === "object" && !Array.isArray(row) &&
               row.ordinal === index + 1 && KINDS.includes(row.kind));
    });
    return rows.map(row => ({ordinal: row.ordinal, kind: row.kind}));
  }
  function csvRows(value, expectedFields = FIELDS) {
    const rows = [], text = value.replace(/^\uFEFF/u, "");
    let row = [], field = "", quoted = false, afterQuote = false;
    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      if (quoted) {
        if (char === '"') {
          if (text[i + 1] === '"') { field += '"'; i++; }
          else { quoted = false; afterQuote = true; }
        } else {
          admitted(char !== "\r" && char !== "\n");
          field += char;
        }
      } else if (afterQuote) {
        if (char === ",") { row.push(field); field = ""; afterQuote = false; }
        else if (char === "\r" || char === "\n") {
          row.push(field); rows.push(row);
          row = []; field = ""; afterQuote = false;
          if (char === "\r" && text[i + 1] === "\n") i++;
        } else admitted(false);
      } else if (char === '"') {
        admitted(field === ""); quoted = true;
      } else if (char === ",") { row.push(field); field = ""; }
      else if (char === "\r" || char === "\n") {
        row.push(field); rows.push(row);
        row = []; field = "";
        if (char === "\r" && text[i + 1] === "\n") i++;
      } else field += char;
    }
    admitted(!quoted);
    if (afterQuote || field || row.length) { row.push(field); rows.push(row); }
    admitted(rows.length >= 2 && rows.length <= 13);
    admitted(rows[0].length === expectedFields.length &&
             rows[0].every((cell, index) => cell === expectedFields[index]));
    return rows.slice(1);
  }
  function humanSafe(text) {
    return typeof text === "string" && text.length <= 1200 &&
           !/[\u0000-\u001f\u007f]/u.test(text) &&
           !/^\s*[=+\-@]/u.test(text);
  }
  function humanRows(csv, originals, digest) {
    const rows = csvRows(csv);
    admitted(rows.length === originals.length);
    return rows.map((row, i) => {
      admitted(row.length === FIELDS.length && row[0] === digest &&
               row[1] === String(i + 1) && row[2] === originals[i].kind &&
               STAGES.includes(row[3]) && humanSafe(row[4]) && humanSafe(row[5]));
      return {ordinal: i + 1, kind: row[2], stage: row[3],
              question: row[4], next_action: row[5]};
    });
  }
  function sameBytes(left, right) {
    const a = new Uint8Array(left), b = new Uint8Array(right);
    if (a.byteLength !== b.byteLength) return false;
    let difference = 0;
    for (let i = 0; i < a.byteLength; ++i) difference |= a[i] ^ b[i];
    return difference === 0;
  }
  async function readReviewer(file, format, passwordId, originalReceipt, receiptDigest) {
    admitted(["csv", "vault", "bundle"].includes(format));
    if (format === "csv") {
      const raw = await readFile(file);
      return {csv: utf8(raw), digest: hex(await crypto.subtle.digest("SHA-256", raw))};
    }
    admitted(globalThis.LightUpHumanVault);
    const limit = format === "vault" ? LightUpHumanVault.maxVaultBytes :
                                             LightUpHumanVault.maxBundleBytes;
    const raw = await readFile(file, limit);
    const field = byId(passwordId);
    const password = field.value;
    try {
      admitted(password.length >= 14 && password.length <= 256);
      let csv;
      if (format === "vault") {
        csv = await LightUpHumanVault.open(raw, password, receiptDigest);
      } else {
        const packageData = await LightUpHumanVault.openBundle(raw, password);
        admitted(sameBytes(packageData.receipt, originalReceipt));
        csv = packageData.csv;
      }
      admitted(typeof csv === "string");
      // Existing native finalizer pins the ORIGINAL HUMAN plaintext CSV bytes,
      // never ciphertext. The original decryptor now preserves an optional
      // leading UTF-8 BOM, so this re-encoding retains exact source bytes.
      const originalCsv = new TextEncoder().encode(csv);
      admitted(originalCsv.byteLength > 0 && originalCsv.byteLength <= MAX);
      return {csv, digest: hex(await crypto.subtle.digest("SHA-256", originalCsv))};
    } finally { field.value = ""; }
  }
  async function open() {
    if (source && dirty && !confirm("Discard unsaved PRIVATE HUMAN decisions?")) return;
    const sequence = ++epoch;
    try {
      admitted(window.isSecureContext && globalThis.crypto && crypto.subtle);
      const receiptRaw = await readFile(byId("receipt").files[0]);
      const receiptDigest = hex(await crypto.subtle.digest("SHA-256", receiptRaw));
      const originals = receiptRows(utf8(receiptRaw));
      const sourceA = await readReviewer(byId("reviewA").files[0],
                                        byId("formatA").value, "passwordA",
                                        receiptRaw, receiptDigest);
      const sourceB = await readReviewer(byId("reviewB").files[0],
                                        byId("formatB").value, "passwordB",
                                        receiptRaw, receiptDigest);
      admitted(sequence === epoch);
      const a = humanRows(sourceA.csv, originals, receiptDigest);
      const b = humanRows(sourceB.csv, originals, receiptDigest);
      const digest = [receiptDigest, sourceA.digest, sourceB.digest];
      const rows = originals.map((original, i) => ({
        original, a: a[i], b: b[i],
        different: ["stage", "question", "next_action"].some(field => a[i][field] !== b[i][field]),
      }));
      // All inputs admitted BEFORE replacing a previous HUMAN workroom.
      if (source && source.receipt) new Uint8Array(source.receipt).fill(0);
      source = {digest, rows, receipt: receiptRaw.slice(0)};
      decisions = rows.map(() => ({choice: "HOLD", reason: ""}));
      discardHistory();
      dirty = false;
      decisionRevision++;
      exportedRevision = -1;
      byId("desk").hidden = false;
      byId("save").disabled = false;
      byId("view").value = "all";
      byId("query").value = "";
      refresh();
      notice("REVIEW_ONLY: exact receipt and TWO native HUMAN CSV plaintext streams admitted locally; no authority. " +
             (digest[1] === digest[2] ? "REVIEWER PLAINTEXT IS BYTE-IDENTICAL; no separate authorship is proven." :
              "Different HUMAN text/digests do not prove independent authorship."));
    } catch (_) {
      if (sequence === epoch) notice("HOLD: encrypted/CSV HUMAN input, password, original receipt bytes or source schema not admitted. Previous HUMAN choices retained.", true);
    } finally {
      byId("passwordA").value = "";
      byId("passwordB").value = "";
    }
  }
  function node(tag, text, parent, className) {
    const element = document.createElement(tag);
    if (text !== undefined) element.textContent = text;
    if (className) element.className = className;
    if (parent) parent.appendChild(element);
    return element;
  }
  function reviewer(title, reviewer, parent) {
    const el = node("div", undefined, parent, "review");
    node("h4", title, el);
    node("p", "HUMAN stage: " + reviewer.stage, el);
    node("h5", "PRIVATE question", el);
    node("p", reviewer.question || "—", el, "notes");
    node("h5", "PRIVATE next action", el);
    node("p", reviewer.next_action || "—", el, "notes");
  }
  function matchesView(row, choice, filter, query) {
    if (filter === "different" && !row.different ||
        filter === "same" && row.different ||
        filter === "undecided" && choice.choice !== "HOLD" ||
        filter === "selected" && choice.choice === "HOLD") return false;
    const searchable = [row.original.ordinal, row.original.kind, row.a.stage,
      row.a.question, row.a.next_action, row.b.stage, row.b.question,
      row.b.next_action, choice.choice, choice.reason].join(" ").toLocaleLowerCase();
    return !query || searchable.includes(query);
  }
  function originalChoiceSnapshot() {
    return decisions.map(item => ({choice: item.choice, reason: item.reason}));
  }
  function discardHistory() {
    if (noteEditTimer !== null) clearTimeout(noteEditTimer);
    noteEditTimer = null;
    undoStack = []; redoStack = [];
  }
  function checkpoint(explicit) {
    // The previous state is recorded BEFORE a HUMAN mutation. Local typing
    // is coalesced for 650 ms, while selections and imported drafts form a
    // distinct undo step. Nothing is written outside browser memory.
    if (!explicit && noteEditTimer !== null) {
      clearTimeout(noteEditTimer);
      noteEditTimer = setTimeout(() => { noteEditTimer = null; }, 650);
      return;
    }
    if (noteEditTimer !== null) clearTimeout(noteEditTimer);
    noteEditTimer = null;
    undoStack.push(originalChoiceSnapshot());
    if (undoStack.length > HISTORY_LIMIT) undoStack.shift();
    redoStack = [];
    if (!explicit) noteEditTimer = setTimeout(() => { noteEditTimer = null; }, 650);
  }
  function navigateHistory(direction) {
    if (!source) return;
    if (noteEditTimer !== null) clearTimeout(noteEditTimer);
    noteEditTimer = null;
    const backward = direction === "undo";
    const from = backward ? undoStack : redoStack;
    const to = backward ? redoStack : undoStack;
    if (!from.length) return;
    to.push(originalChoiceSnapshot());
    if (to.length > HISTORY_LIMIT) to.shift();
    const next = from.pop();
    admitted(next.length === source.rows.length);
    decisions = next;
    dirty = true;
    decisionRevision++;
    exportedRevision = -1;
    refresh();
    byId("historyStatus").textContent =
      (backward ? "Undid" : "Redid") +
      " one PRIVATE HUMAN edit. The earlier exported decision CSV is STALE until re-export.";
  }
  function filteredSelectedIndices() {
    if (!source) return [];
    const filter = byId("view").value;
    const query = byId("query").value.trim().toLocaleLowerCase();
    return source.rows.flatMap((row, index) =>
      decisions[index].choice !== "HOLD" &&
      matchesView(row, decisions[index], filter, query) ? [index] : []);
  }
  function holdVisibleSelections() {
    const selected = filteredSelectedIndices();
    if (!selected.length) return;
    const ordinals = selected.map(index => source.rows[index].original.ordinal).join(", ");
    if (!confirm("Set ONLY these currently matching HUMAN selections to HOLD and clear their reasons? Original ordinals: " +
                 ordinals + ". No hidden or already-held row will be changed; nothing is approved or released.")) return;
    checkpoint(true);
    selected.forEach(index => { decisions[index] = {choice: "HOLD", reason: ""}; });
    dirty = true;
    decisionRevision++;
    exportedRevision = -1;
    refresh();
    byId("historyStatus").textContent =
      "Set " + selected.length + " explicitly selected matching HUMAN rows to HOLD. Undo is available; audit CSV must be re-exported.";
  }
  function updateHistoryControls() {
    byId("undo").disabled = !source || undoStack.length === 0;
    byId("redo").disabled = !source || redoStack.length === 0;
    const eligible = filteredSelectedIndices().length;
    byId("holdFiltered").disabled = eligible === 0;
    if (!source) return;
    byId("historyStatus").textContent =
      undoStack.length + " local undo steps / " + redoStack.length +
      " redo steps (maximum " + HISTORY_LIMIT + ") · " +
      eligible + " visible selected rows eligible for explicit HOLD. " +
      (exportedRevision === decisionRevision ?
        "Current HUMAN decision CSV was exported." :
        "Re-export decision CSV before sealing.");
  }
  function refresh() {
    if (!source) return;
    const visible = byId("entries");
    visible.replaceChildren();
    const filter = byId("view").value;
    const query = byId("query").value.trim().toLocaleLowerCase();
    let shown = 0, changed = 0, selected = 0;
    source.rows.forEach((row, index) => {
      const choice = decisions[index];
      if (row.different) changed++;
      if (choice.choice !== "HOLD") selected++;
      if (!matchesView(row, choice, filter, query)) return;
      shown++;
      const section = node("article", undefined, visible, "case");
      const heading = node("h3", "Ordinal " + row.original.ordinal +
                           " · " + row.original.kind.replaceAll("_", " "), section);
      heading.id = "ordinal-" + row.original.ordinal;
      const status = node("p", row.different ?
         "DIFFERENT HUMAN text — manual decision required" :
         "SAME HUMAN text — neither authenticated nor verified", section, "pill");
      if (row.different) status.dataset.kind = "different";
      const columns = node("div", undefined, section, "comparison");
      reviewer("Reviewer A · original submission", row.a, columns);
      reviewer("Reviewer B · original submission", row.b, columns);
      const controls = node("div", undefined, section, "controls");
      const label = node("label", "Explicit HUMAN choice", controls);
      const select = node("select", undefined, label);
      select.setAttribute("aria-label", "Explicit HUMAN choice for ordinal " + row.original.ordinal);
      for (const option of ["HOLD", "A", "B"]) {
        const item = node("option", option === "HOLD" ? "HOLD — take neither" : "Use reviewer " + option, select);
        item.value = option;
      }
      select.value = choice.choice;
      const why = node("label", "PRIVATE HUMAN reason (required for A or B)", controls);
      const input = node("textarea", undefined, why);
      input.maxLength = 1200;
      input.rows = 2;
      input.value = choice.reason;
      input.setAttribute("aria-label", "PRIVATE HUMAN selection reason for ordinal " + row.original.ordinal);
      input.placeholder = "Why is this HUMAN proposal selected? No consent or authority claim.";
      select.addEventListener("change", () => {
        if (choice.choice === select.value) return;
        checkpoint(true);
        choice.choice = select.value;
        if (choice.choice === "HOLD") { choice.reason = ""; input.value = ""; }
        dirty = true;
        decisionRevision++;
        exportedRevision = -1;
        if (byId("view").value !== "all" || byId("query").value.trim()) refresh();
        else updateCounts();
      });
      input.addEventListener("input", () => {
        if (choice.reason === input.value) return;
        checkpoint(false);
        choice.reason = input.value;
        dirty = true;
        decisionRevision++;
        exportedRevision = -1;
        updateCounts();
      });
    });
    byId("visible").textContent = shown + " displayed / " + source.rows.length + " original ordinals";
    updateCounts();
  }
  function renderFinalPreview() {
    const parent = byId("finalPreview");
    parent.replaceChildren();
    if (!source) return;
    // PRIVATE notes are shown only after a local operator expands the row.
    source.rows.forEach((row, index) => {
      const choice = decisions[index];
      const selected = choice.choice === "A" ? row.a :
                       choice.choice === "B" ? row.b : null;
      const wrapper = node("article", undefined, parent, "outcome");
      const summary = node("p", "Ordinal " + row.original.ordinal + " · " +
        (selected ? "HUMAN reviewer " + choice.choice + " tentatively selected" :
                    "HOLD — no HUMAN reviewer selected"), wrapper, "outcomeTitle");
      summary.dataset.mode = selected ? "selected" : "hold";
      node("span", row.original.kind.replaceAll("_", " "), wrapper, "outcomeKind");
      node("p", "Final HUMAN stage: " + (selected ? selected.stage : "unreviewed"), wrapper);
      if (selected) {
        node("p", "Operator's PRIVATE reason: " + choice.reason, wrapper);
        const disclosure = node("details", undefined, wrapper);
        node("summary", "Show original PRIVATE selected question and action", disclosure);
        node("p", "Question: " + (selected.question || "—"), disclosure, "notes");
        node("p", "Next action: " + (selected.next_action || "—"), disclosure, "notes");
      } else {
        node("p", "No prior HUMAN note or next action is inherited.", wrapper);
      }
    });
  }
  function updateCounts() {
    if (!source) return;
    const changed = source.rows.filter(row => row.different).length;
    const selected = decisions.filter(row => row.choice !== "HOLD").length;
    const invalid = decisions.filter(row => !humanSafe(row.reason) ||
                    row.choice !== "HOLD" && !row.reason.trim()).length;
    byId("totals").textContent = source.rows.length + " source-free ordinals";
    byId("different").textContent = changed + " literal HUMAN differences";
    byId("selected").textContent = selected + " explicit HUMAN selections";
    byId("saveState").textContent = invalid ? invalid + " selections missing safe reason · HOLD" :
      dirty ? "Unsaved PRIVATE HUMAN choices · no release" : "All decisions HOLD by default";
    byId("save").disabled = Boolean(invalid);
    updateHistoryControls();
    renderFinalPreview();
    const ready = !invalid && exportedRevision === decisionRevision &&
                  Boolean(source.receipt) && globalThis.LightUpHumanVault;
    byId("seal").disabled = !ready;
    byId("counts").disabled = !ready;
  }
  async function restoreDecisions() {
    const sequence = epoch;
    const current = source;
    try {
      admitted(current && decisions.length === current.rows.length);
      const file = byId("resume").files[0];
      const raw = await readFile(file);
      const records = csvRows(utf8(raw), CHOICE_FIELDS);
      admitted(sequence === epoch && source === current);
      admitted(records.length === current.rows.length);
      const next = records.map((row, index) => {
        const original = current.rows[index].original;
        admitted(row.length === CHOICE_FIELDS.length &&
                 row[0] === current.digest[0] &&
                 row[1] === current.digest[1] &&
                 row[2] === current.digest[2] &&
                 row[3] === String(original.ordinal) &&
                 row[4] === original.kind &&
                 ["HOLD", "A", "B"].includes(row[5]) &&
                 humanSafe(row[6]) &&
                 (row[5] === "HOLD" || Boolean(row[6].trim())));
        return {choice: row[5], reason: row[6]};
      });
      admitted(confirm("Replace current PRIVATE HUMAN choices with this entire EXACT-RECEIPT + EXACT-TWO-REVIEWER draft? No consent or release is inferred."));
      admitted(sequence === epoch && source === current);
      checkpoint(true);
      decisions = next;
      dirty = true;
      decisionRevision++;
      exportedRevision = -1;
      refresh();
      notice("REVIEW_ONLY: exact-source-bound HUMAN decision draft restored. Every choice still requires original native finalize, separate authorization and HUMAN review.");
    } catch (_) {
      if (sequence === epoch) notice("HOLD: source-bound decision CSV, original receipt/reviewer bytes or explicit operator confirmation did not match. Prior choices kept.", true);
    } finally { byId("resume").value = ""; }
  }
  function quoted(value) {
    return '"' + String(value).replaceAll('"', '""') + '"';
  }
  function exportDecisions() {
    try {
      admitted(source && decisions.length === source.rows.length);
      admitted(decisions.every(row => ["HOLD", "A", "B"].includes(row.choice) &&
                                humanSafe(row.reason) &&
                                (row.choice === "HOLD" || row.reason.trim().length > 0)));
      admitted(confirm("Download an UNSIGNED PRIVATE HUMAN decision CSV? No consent, approval, grant or release is conferred. Store it owner-only and re-admit with native reconcile.py finalize."));
      const lines = [CHOICE_FIELDS.map(quoted).join(",")];
      source.rows.forEach((row, index) => {
        const choice = decisions[index];
        lines.push([source.digest[0], source.digest[1], source.digest[2],
                    row.original.ordinal, row.original.kind, choice.choice,
                    choice.reason].map(quoted).join(","));
      });
      const output = lines.join("\n") + "\n";
      const url = URL.createObjectURL(new Blob([output], {type:"text/csv;charset=utf-8"}));
      urls.add(url);
      const a = document.createElement("a");
      a.href = url;
      a.download = "PRIVATE-reconcile-browser-decisions.csv";
      a.click();
      setTimeout(() => { URL.revokeObjectURL(url); urls.delete(url); }, 10000);
      dirty = false;
      exportedRevision = decisionRevision;
      updateCounts();
      notice("REVIEW_ONLY: local PRIVATE decision file exported. Use unchanged native finalizer with the exact receipt and reviewer CSV bytes. No authorization.");
    } catch (_) {
      notice("HOLD: incomplete or unsafe HUMAN selection or cancelled download. No new export.", true);
    }
  }
  function nativeSelectedRows() {
    admitted(source && decisions.length === source.rows.length);
    admitted(decisions.every(row => ["HOLD", "A", "B"].includes(row.choice) &&
      humanSafe(row.reason) && (row.choice === "HOLD" || row.reason.trim())));
    return source.rows.map((item, index) => {
      const selected = decisions[index].choice === "A" ? item.a :
                       decisions[index].choice === "B" ? item.b : null;
      return { ordinal: item.original.ordinal, kind: item.original.kind,
               stage: selected ? selected.stage : "unreviewed",
               question: selected ? selected.question : "",
               next_action: selected ? selected.next_action : "" };
    });
  }
  function nativeSelectedCsv(rows) {
    const lines = [FIELDS.map(quoted).join(",")];
    rows.forEach((row, index) => {
      admitted(row.ordinal === index + 1 && KINDS.includes(row.kind) &&
               STAGES.includes(row.stage) &&
               humanSafe(row.question) && humanSafe(row.next_action));
      lines.push([source.digest[0], row.ordinal, row.kind, row.stage,
                  row.question, row.next_action].map(quoted).join(","));
    });
    return lines.join("\n") + "\n";
  }
  function localDownload(data, filename, contentType) {
    const url = URL.createObjectURL(new Blob([data], {type: contentType}));
    urls.add(url);
    const anchor = document.createElement("a");
    anchor.href = url; anchor.download = filename;
    anchor.click();
    setTimeout(() => { URL.revokeObjectURL(url); urls.delete(url); }, 10000);
  }
  async function sealResult() {
    const pass = byId("sealPassword"), repeat = byId("sealConfirm");
    const capturedEpoch = epoch, capturedRevision = decisionRevision, captured = source;
    try {
      admitted(captured && globalThis.LightUpHumanVault &&
               window.isSecureContext && crypto?.subtle);
      admitted(exportedRevision === capturedRevision);
      admitted(pass.value === repeat.value && pass.value.length >= 14 &&
               pass.value.length <= 256 && !/[\u0000-\u001f\u007f]/u.test(pass.value));
      const nativeCsv = nativeSelectedCsv(nativeSelectedRows());
      admitted(confirm("Create ONE password-encrypted LOCAL PRIVATE source-free HUMAN result? Retain your separately saved exact A/B decision CSV with HUMAN reasons. Neither file is a release or approval."));
      const result = await LightUpHumanVault.sealBundle(
        captured.receipt.slice(0), nativeCsv, pass.value);
      admitted(capturedEpoch === epoch && captured === source &&
               capturedRevision === decisionRevision &&
               exportedRevision === capturedRevision);
      localDownload(result, "PRIVATE-browser-reconciled-human.luhb",
                    "application/octet-stream");
      byId("sealStatus").textContent =
        "REVIEW_ONLY: encrypted native-compatible HUMAN receipt+choices saved locally. Preserve separately exported A/B reasoning. No approved disclosure.";
      notice("REVIEW_ONLY: new encrypted local HUMAN result. No consent, source proof, grant or release.");
    } catch (_) {
      byId("sealStatus").textContent =
        "HOLD: encryption, changed HUMAN choices, incomplete password, browser context or consent prompt refused. Existing decisions retained.";
    } finally {
      pass.value = ""; repeat.value = "";
    }
  }
  function countsCsv(rows) {
    const minimum = 5;
    const values = STAGES.map(stage => rows.filter(row => row.stage === stage).length);
    const showSource = rows.length >= minimum;
    const showGroups = showSource && values.every(count => count === 0 || count >= minimum);
    const entries = [
      ["field","value"], ["status","REVIEW_ONLY"],
      ["original_source_authenticated","FALSE"], ["current_consent_verified","FALSE"],
      ["release_allowed","FALSE"], ["not_anonymity_guarantee","TRUE"],
      ["HUMAN_receipt_identity","UNSIGNED_BYTES_ONLY"],
      ["source_count", showSource ? String(rows.length) : "SUPPRESSED_SMALL_COHORT"],
      ["human_stages","DECLARED_NON_AUTHORITATIVE"]
    ];
    if (showGroups) {
      STAGES.forEach((stage, i) => entries.push(["HUMAN_" + stage, String(values[i])]));
    } else entries.push(["HUMAN_stage_breakdown", "SUPPRESSED_SMALL_GROUP"]);
    return entries.map(row => row.map(quoted).join(",")).join("\n") + "\n";
  }
  function exportCounts() {
    try {
      admitted(source && exportedRevision === decisionRevision);
      const summary = countsCsv(nativeSelectedRows());
      admitted(confirm("Save PRIVATE counts only with small-cohort suppression? It is NOT guaranteed anonymous or approved for sharing."));
      localDownload(summary, "PRIVATE-browser-reconciled-counts.csv", "text/csv;charset=utf-8");
      notice("REVIEW_ONLY: source/note-free local suppressed HUMAN counts exported. This is not anonymization or authorization.");
    } catch (_) {
      notice("HOLD: counts were not generated or operator cancelled; no disclosure approval.", true);
    }
  }
  function clear() {
    if (source && dirty && !confirm("Discard unexported PRIVATE HUMAN decisions?")) return;
    epoch++;
    if (source && source.receipt) new Uint8Array(source.receipt).fill(0);
    source = null; decisions = []; dirty = false;
    discardHistory();
    decisionRevision++;
    exportedRevision = -1;
    byId("entries").replaceChildren();
    byId("desk").hidden = true;
    for (const id of ["receipt", "reviewA", "reviewB", "resume", "passwordA", "passwordB", "sealPassword", "sealConfirm"]) byId(id).value = "";
    for (const url of urls) URL.revokeObjectURL(url);
    urls.clear();
    notice("PRIVATE session cleared from this page. Previously downloaded files remain on your device; browser memory erasure is not guaranteed.");
  }
  byId("open").addEventListener("click", open);
  byId("clear").addEventListener("click", clear);
  byId("save").addEventListener("click", exportDecisions);
  byId("seal").addEventListener("click", sealResult);
  byId("counts").addEventListener("click", exportCounts);
  byId("restore").addEventListener("click", restoreDecisions);
  byId("undo").addEventListener("click", () => navigateHistory("undo"));
  byId("redo").addEventListener("click", () => navigateHistory("redo"));
  byId("holdFiltered").addEventListener("click", holdVisibleSelections);
  byId("view").addEventListener("change", refresh);
  byId("query").addEventListener("input", refresh);
  addEventListener("beforeunload", event => {
    if (dirty) { event.preventDefault(); event.returnValue = ""; }
  });
  addEventListener("pagehide", () => {
    epoch++;
    if (source && source.receipt) new Uint8Array(source.receipt).fill(0);
    source = null; decisions = []; dirty = false;
    discardHistory();
    decisionRevision++;
    exportedRevision = -1;
    byId("entries").replaceChildren();
    byId("desk").hidden = true;
    for (const id of ["receipt", "reviewA", "reviewB", "resume", "passwordA", "passwordB", "sealPassword", "sealConfirm"]) byId(id).value = "";
    urls.forEach(url => URL.revokeObjectURL(url)); urls.clear();
  });
})();