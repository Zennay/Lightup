"use strict";
/* PRIVATE HUMAN disclosure review studio. Memory-only, never a release gate.
 * Final CSV is still strictly re-admitted by human_review.py.
 */
(() => {
  const FIELDS = ["receipt_sha256", "ordinal", "source_kind", "stage", "question", "next_action"];
  const STAGES = ["unreviewed", "privacy_hold", "source_owner_hold", "consent_hold",
                  "follow_up_required", "human_reviewed_no_release"];
  const KINDS = ["isolated_lab_input_preview", "offline_lab_benchmark_source", "isolated_lab_assessment"];
  const FALSE_FLAGS = ["source_authenticated", "ground_truth_verified", "client_consent_verified",
                       "operator_consent_verified", "authorization_granted", "dispatch_allowed", "release_allowed"];
  const MAX = 256 * 1024;
  const byId = id => document.getElementById(id);
  let records = [], receiptDigest = "", dirty = false;

  function notice(message, isError = false) {
    const box = byId("notice");
    box.textContent = message;
    box.dataset.status = isError ? "error" : "info";
    box.setAttribute("role", isError ? "alert" : "status");
  }
  function ensure(ok) {
    if (!ok) throw new Error("HOLD: PRIVATE receipt/CSV mismatch or unadmitted source");
  }
  async function bounded(file) {
    ensure(file && file.size > 0 && file.size <= MAX);
    return file.arrayBuffer();
  }
  function hex(bytes) {
    return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, "0")).join("");
  }
  function parseCsv(source) {
    const rows = [];
    let record = [], field = "", quoted = false, afterQuote = false;
    for (let i = 0; i < source.length; ++i) {
      const c = source[i];
      if (quoted) {
        if (c === '"') {
          if (source[i + 1] === '"') { field += '"'; ++i; }
          else { quoted = false; afterQuote = true; }
        } else {
          ensure(c !== "\r" && c !== "\n");
          field += c;
        }
      } else if (afterQuote) {
        if (c === ",") { record.push(field); field = ""; afterQuote = false; }
        else if (c === "\n" || c === "\r") {
          record.push(field); rows.push(record); record = []; field = ""; afterQuote = false;
          if (c === "\r" && source[i + 1] === "\n") ++i;
        } else ensure(false);
      } else if (c === '"') {
        ensure(field === "");
        quoted = true;
      } else if (c === ",") {
        record.push(field); field = "";
      } else if (c === "\n" || c === "\r") {
        record.push(field); rows.push(record); record = []; field = "";
        if (c === "\r" && source[i + 1] === "\n") ++i;
      } else {
        field += c;
      }
    }
    ensure(!quoted);
    if (afterQuote || field || record.length) { record.push(field); rows.push(record); }
    ensure(rows.length > 1 && rows.length <= 13);
    ensure(rows[0].length === FIELDS.length && rows[0].every((x, i) => x === FIELDS[i]));
    return rows.slice(1);
  }
  function safeText(value) {
    return typeof value === "string" && value.length <= 1200 && !/[\u0000-\u001f\u007f]/u.test(value);
  }
  function validateReceipt(value) {
    ensure(value && typeof value === "object" && !Array.isArray(value));
    ensure(value.schema === "lightup.assessment_disclosure_preflight.v1" &&
           value.status === "REVIEW_ONLY" && value.source_byte_bound === false);
    ensure(FALSE_FLAGS.every(k => value[k] === false));
    const rows = value.inspected_declarations_only;
    ensure(Array.isArray(rows) && rows.length >= 1 && rows.length <= 12 &&
           value.source_count === rows.length);
    rows.forEach((row, i) => {
      ensure(row && typeof row === "object" && !Array.isArray(row) &&
             row.ordinal === i + 1 && KINDS.includes(row.kind));
    });
    return rows;
  }
  function validateRows(rawRows, sourceRows, digest) {
    ensure(rawRows.length === sourceRows.length);
    return rawRows.map((row, i) => {
      ensure(row.length === FIELDS.length && row[0] === digest &&
             row[1] === String(i + 1) && row[2] === sourceRows[i].kind &&
             STAGES.includes(row[3]) && safeText(row[4]) && safeText(row[5]));
      return { digest, ordinal: i + 1, kind: row[2], stage: row[3],
               question: row[4], action: row[5] };
    });
  }
  function element(tag, text, parent) {
    const el = document.createElement(tag);
    if (text !== undefined) el.textContent = text;
    if (parent) parent.appendChild(el);
    return el;
  }
  function editCell(row, field, label) {
    const td = element("td");
    if (field === "stage") {
      const select = element("select", undefined, td);
      select.setAttribute("aria-label", label + " for source ordinal " + row.ordinal);
      for (const stage of STAGES) {
        const option = element("option", stage.replaceAll("_", " "), select);
        option.value = stage;
      }
      select.value = row.stage;
      select.addEventListener("change", () => { row.stage = select.value; dirty = true; refresh(); });
    } else {
      const input = element("textarea", undefined, td);
      input.rows = 2;
      input.maxLength = 1200;
      input.value = row[field];
      input.setAttribute("aria-label", label + " for source ordinal " + row.ordinal);
      input.addEventListener("input", () => {
        row[field] = input.value;
        dirty = true;
        byId("unsaved").textContent = "Unsaved HUMAN changes (memory only)";
      });
    }
    return td;
  }
  function refresh() {
    const body = byId("rows");
    body.replaceChildren();
    const filter = byId("stageFilter").value;
    const query = byId("query").value.trim().toLowerCase();
    let visible = 0;
    records.forEach(row => {
      if (filter !== "all" && row.stage !== filter) return;
      if (query && !(String(row.ordinal) + " " + row.kind + " " + row.question +
                    " " + row.action + " " + row.stage).toLowerCase().includes(query)) return;
      visible++;
      const tr = element("tr", undefined, body);
      element("th", String(row.ordinal), tr).scope = "row";
      element("td", row.kind.replaceAll("_", " "), tr);
      tr.appendChild(editCell(row, "stage", "HUMAN-only stage"));
      tr.appendChild(editCell(row, "question", "PRIVATE question"));
      tr.appendChild(editCell(row, "action", "PRIVATE next action"));
    });
    byId("visible").textContent = visible + " shown / " + records.length + " local ordinals";
    byId("unsaved").textContent = dirty ? "Unsaved HUMAN changes (memory only)" : "Original CSV loaded; no edit exported";
  }
  async function load() {
    try {
      ensure(window.isSecureContext && crypto && crypto.subtle);
      const raw = await bounded(byId("receipt").files[0]);
      const digest = hex(await crypto.subtle.digest("SHA-256", raw));
      const decoded = new TextDecoder("utf-8", {fatal: true}).decode(raw);
      const sourceRows = validateReceipt(JSON.parse(decoded));
      const csvBytes = await bounded(byId("csv").files[0]);
      const csvText = new TextDecoder("utf-8", {fatal: true}).decode(csvBytes).replace(/^\uFEFF/u, "");
      const rows = validateRows(parseCsv(csvText), sourceRows, digest);
      if (dirty && !confirm("Discard unsaved HUMAN edits in memory?")) return;
      records = rows;
      receiptDigest = digest;
      dirty = false;
      byId("editor").hidden = false;
      byId("export").disabled = false;
      refresh();
      notice("REVIEW_ONLY: exact receipt bytes and matching HUMAN CSV admitted locally. No authority.");
    } catch (_) {
      notice("HOLD: files, secure local browser context, or source equality not admitted. Current edits retained.", true);
    }
  }
  function csvField(value) {
    return '"' + String(value).replaceAll('"', '""') + '"';
  }
  function exportCsv() {
    try {
      ensure(records.length >= 1 && /^[0-9a-f]{64}$/u.test(receiptDigest));
      const lines = [FIELDS.map(csvField).join(",")];
      records.forEach((row, i) => {
        ensure(row.ordinal === i + 1 && KINDS.includes(row.kind) &&
               STAGES.includes(row.stage) && safeText(row.question) && safeText(row.action));
        lines.push([receiptDigest, row.ordinal, row.kind, row.stage,
                    row.question, row.action].map(csvField).join(","));
      });
      ensure(confirm("Save a PRIVATE plaintext HUMAN CSV locally? It may contain sensitive notes. This NEVER releases an assessment."));
      const blob = new Blob([lines.join("\n") + "\n"], {type: "text/csv;charset=utf-8"});
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url; link.download = "PRIVATE-human-reviewed.csv";
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
      dirty = false;
      refresh();
      notice("REVIEW_ONLY: source-free HUMAN CSV exported. Use native render to re-admit; no release.");
    } catch (_) {
      notice("HOLD: invalid or incomplete HUMAN fields; no export.", true);
    }
  }
  byId("load").addEventListener("click", load);
  byId("export").addEventListener("click", exportCsv);
  byId("stageFilter").addEventListener("change", refresh);
  byId("query").addEventListener("input", refresh);
  window.addEventListener("beforeunload", event => {
    if (dirty) { event.preventDefault(); event.returnValue = ""; }
  });
})();
