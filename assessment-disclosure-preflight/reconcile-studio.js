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
  async function readFile(file) {
    admitted(file && file.size > 0 && file.size <= MAX);
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
  async function open() {
    const sequence = ++epoch;
    const files = ["receipt", "reviewA", "reviewB"].map(id => byId(id).files[0]);
    if (source && dirty && !confirm("Discard unsaved PRIVATE HUMAN decisions?")) return;
    try {
      admitted(window.isSecureContext && globalThis.crypto && crypto.subtle);
      admitted(files.every(file => file && file.size <= MAX && file.size > 0));
      const buffers = await Promise.all(files.map(readFile));
      const digest = await Promise.all(buffers.map(b => crypto.subtle.digest("SHA-256", b).then(hex)));
      admitted(sequence === epoch);
      const originals = receiptRows(utf8(buffers[0]));
      const a = humanRows(utf8(buffers[1]), originals, digest[0]);
      const b = humanRows(utf8(buffers[2]), originals, digest[0]);
      const rows = originals.map((original, i) => ({
        original, a: a[i], b: b[i],
        different: ["stage", "question", "next_action"].some(field => a[i][field] !== b[i][field]),
      }));
      // Commit atomically AFTER every original admission and async digest.
      source = {digest, rows};
      decisions = rows.map(() => ({choice: "HOLD", reason: ""}));
      dirty = false;
      byId("desk").hidden = false;
      byId("save").disabled = false;
      byId("view").value = "all";
      byId("query").value = "";
      refresh();
      notice("REVIEW_ONLY: exact original receipt + both HUMAN CSV streams admitted. Both remain unsigned. " +
             (digest[1] === digest[2] ? "REVIEWER FILES ARE BYTE-IDENTICAL: no independent authorship is proven." :
              "Different reviewer files do not prove independent authorship."));
    } catch (_) {
      if (sequence === epoch) notice("HOLD: secure browser, original source, receipt digest, HUMAN rows or CSV rejected. Prior session retained.", true);
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
      if (filter === "different" && !row.different ||
          filter === "same" && row.different ||
          filter === "undecided" && choice.choice !== "HOLD" ||
          filter === "selected" && choice.choice === "HOLD") return;
      const searchable = [row.original.ordinal, row.original.kind, row.a.stage,
                          row.a.question, row.a.next_action, row.b.stage, row.b.question,
                          row.b.next_action, choice.choice, choice.reason].join(" ").toLocaleLowerCase();
      if (query && !searchable.includes(query)) return;
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
        choice.choice = select.value;
        if (choice.choice === "HOLD") { choice.reason = ""; input.value = ""; }
        dirty = true;
        updateCounts();
      });
      input.addEventListener("input", () => {
        choice.reason = input.value;
        dirty = true;
        updateCounts();
      });
    });
    byId("visible").textContent = shown + " displayed / " + source.rows.length + " original ordinals";
    updateCounts();
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
      decisions = next;
      dirty = true;
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
      updateCounts();
      notice("REVIEW_ONLY: local PRIVATE decision file exported. Use unchanged native finalizer with the exact receipt and reviewer CSV bytes. No authorization.");
    } catch (_) {
      notice("HOLD: incomplete or unsafe HUMAN selection or cancelled download. No new export.", true);
    }
  }
  function clear() {
    if (source && dirty && !confirm("Discard unexported PRIVATE HUMAN decisions?")) return;
    epoch++;
    source = null; decisions = []; dirty = false;
    byId("entries").replaceChildren();
    byId("desk").hidden = true;
    for (const id of ["receipt", "reviewA", "reviewB", "resume"]) byId(id).value = "";
    for (const url of urls) URL.revokeObjectURL(url);
    urls.clear();
    notice("PRIVATE session cleared from this page. Previously downloaded files remain on your device; browser memory erasure is not guaranteed.");
  }
  byId("open").addEventListener("click", open);
  byId("clear").addEventListener("click", clear);
  byId("save").addEventListener("click", exportDecisions);
  byId("restore").addEventListener("click", restoreDecisions);
  byId("view").addEventListener("change", refresh);
  byId("query").addEventListener("input", refresh);
  addEventListener("beforeunload", event => {
    if (dirty) { event.preventDefault(); event.returnValue = ""; }
  });
  addEventListener("pagehide", () => {
    epoch++; source = null; decisions = []; dirty = false;
    byId("entries").replaceChildren();
    byId("desk").hidden = true;
    for (const id of ["receipt", "reviewA", "reviewB", "resume"]) byId(id).value = "";
    urls.forEach(url => URL.revokeObjectURL(url)); urls.clear();
  });
})();