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
  let records = [], receiptDigest = "", receiptRaw = null, dirty = false, revision = 0;

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
  function parseUnambiguousJson(source) {
    // JSON.parse silently accepts duplicate keys. PRIVATE receipt authority
    // declarations and original ordinals must reject *all* ambiguous names.
    let offset = 0;
    const whitespace = () => {
      while (offset < source.length && /[\u0009\u000a\u000d\u0020]/u.test(source[offset])) ++offset;
    };
    const stringToken = () => {
      ensure(source[offset] === '"');
      const start = offset++;
      while (offset < source.length) {
        if (source[offset] === "\\") { offset += 2; continue; }
        if (source[offset++] === '"') {
          const raw = source.slice(start, offset);
          return JSON.parse(raw); // decode escaped property names canonically
        }
      }
      ensure(false);
    };
    const parseValue = depth => {
      ensure(depth <= 32);
      whitespace();
      const c = source[offset];
      if (c === "{") {
        ++offset;
        const keys = new Set();
        whitespace();
        if (source[offset] === "}") { ++offset; return; }
        while (offset < source.length) {
          whitespace();
          const key = stringToken();
          ensure(!keys.has(key));
          keys.add(key);
          whitespace();
          ensure(source[offset++] === ":");
          parseValue(depth + 1);
          whitespace();
          if (source[offset] === "}") { ++offset; return; }
          ensure(source[offset++] === ",");
        }
        ensure(false);
      } else if (c === "[") {
        ++offset;
        whitespace();
        if (source[offset] === "]") { ++offset; return; }
        while (offset < source.length) {
          parseValue(depth + 1);
          whitespace();
          if (source[offset] === "]") { ++offset; return; }
          ensure(source[offset++] === ",");
        }
        ensure(false);
      } else if (c === '"') {
        stringToken();
      } else {
        const remainder = source.slice(offset);
        const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/u.exec(remainder);
        ensure(token);
        offset += token[0].length;
      }
    };
    parseValue(0);
    whitespace();
    ensure(offset === source.length);
    const parsed = JSON.parse(source);
    ensure(parsed && typeof parsed === "object" && !Array.isArray(parsed));
    return parsed;
  }
  function safeText(value) {
    return typeof value === "string" && value.length <= 1200 && !/[\u0000-\u001f\u007f]/u.test(value) &&
           !/^[\s]*[=+\-@]/u.test(value);
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
      select.addEventListener("change", () => { row.stage = select.value; dirty = true; revision++; refresh(); });
    } else {
      const input = element("textarea", undefined, td);
      input.rows = 2;
      input.maxLength = 1200;
      input.value = row[field];
      input.setAttribute("aria-label", label + " for source ordinal " + row.ordinal);
      input.addEventListener("input", () => {
        row[field] = input.value;
        dirty = true;
        revision++;
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
      const receiptFile = byId("receipt").files[0];
      const csvFile = byId("csv").files[0];
      const vaultFile = byId("vault").files[0];
      const bundleFile = byId("bundle").files[0];
      ensure(bundleFile
        ? !receiptFile && !csvFile && !vaultFile
        : Boolean(receiptFile) && (Boolean(csvFile) !== Boolean(vaultFile)));
      let raw, csvText;
      if (bundleFile) {
        const pw = byId("openPassword");
        try {
          ensure(globalThis.LightUpHumanVault &&
                 bundleFile.size <= LightUpHumanVault.maxBundleBytes);
          const unpacked = await LightUpHumanVault.openBundle(
            await bundleFile.arrayBuffer(), pw.value);
          raw = unpacked.receipt;
          csvText = unpacked.csv;
        } finally { pw.value = ""; }
      } else {
        raw = await bounded(receiptFile);
      }
      const digest = hex(await crypto.subtle.digest("SHA-256", raw));
      const decoded = new TextDecoder("utf-8", {fatal:true}).decode(raw);
      const sourceRows = validateReceipt(parseUnambiguousJson(decoded));
      if (!bundleFile && vaultFile) {
        const pw = byId("openPassword");
        try {
          ensure(LightUpHumanVault && vaultFile.size <= LightUpHumanVault.maxVaultBytes);
          csvText = await LightUpHumanVault.open(
            await vaultFile.arrayBuffer(), pw.value, digest);
        } finally { pw.value = ""; }
      } else if (!bundleFile) {
        const csvBytes = await bounded(csvFile);
        csvText = new TextDecoder("utf-8", {fatal:true}).decode(csvBytes);
      }
      const rows = validateRows(parseCsv(csvText.replace(/^\uFEFF/u, "")), sourceRows, digest);
      if (dirty && !confirm("Discard unsaved HUMAN edits in memory?")) return;
      records = rows;
      receiptDigest = digest;
      receiptRaw = raw.slice(0);
      dirty = false;
      revision++;
      byId("compareSection").hidden = true;
      byId("compareRows").replaceChildren();
      byId("editor").hidden = false;
      byId("export").disabled = false;
      byId("exportEncrypted").disabled = false;
      byId("exportBundle").disabled = false;
      byId("compare").disabled = false;
      byId("exportCounts").disabled = false;
      byId("exportPrint").disabled = false;
      refresh();
      notice("REVIEW_ONLY: exact receipt bytes and matching HUMAN CSV admitted locally. No authority.");
    } catch (_) {
      notice("HOLD: files, secure local browser context, or source equality not admitted. Current edits retained.", true);
    }
  }
  function csvField(value) {
    return '"' + String(value).replaceAll('"', '""') + '"';
  }
  function serializedCsv() {
    ensure(records.length >= 1 && /^[0-9a-f]{64}$/u.test(receiptDigest));
    const lines = [FIELDS.map(csvField).join(",")];
    records.forEach((row, i) => {
      ensure(row.ordinal === i + 1 && KINDS.includes(row.kind) &&
             STAGES.includes(row.stage) && safeText(row.question) && safeText(row.action));
      lines.push([receiptDigest, row.ordinal, row.kind, row.stage,
                  row.question, row.action].map(csvField).join(","));
    });
    return lines.join("\n") + "\n";
  }
  function download(bytes, filename, contentType) {
    const url = URL.createObjectURL(new Blob([bytes], {type:contentType}));
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  }
  function exportCsv() {
    try {
      const csv = serializedCsv();
      ensure(confirm("Save a PRIVATE plaintext HUMAN CSV locally? It may contain sensitive notes. This NEVER releases an assessment."));
      download(csv, "PRIVATE-human-reviewed.csv", "text/csv;charset=utf-8");
      dirty = false;
      refresh();
      notice("REVIEW_ONLY: source-free HUMAN CSV exported. Use native render to re-admit; no release.");
    } catch (_) {
      notice("HOLD: invalid or incomplete HUMAN fields; no export.", true);
    }
  }
  async function exportEncrypted() {
    const pass = byId("newPassword"), repeated = byId("confirmPassword");
    try {
      ensure(globalThis.LightUpHumanVault);
      const csv = serializedCsv();
      const capturedRevision = revision;
      ensure(pass.value === repeated.value && pass.value.length >= 14 &&
             pass.value.length <= 256 && !/[\u0000-\u001f\u007f]/u.test(pass.value));
      ensure(confirm("Create a new locally encrypted PRIVATE HUMAN .luhd file? Keep a separately authenticated receipt and passphrase. Password encryption does not prove client authority, source authenticity or consent."));
      const encrypted = await LightUpHumanVault.seal(csv, pass.value, receiptDigest);
      download(encrypted, "PRIVATE-human-reviewed.luhd", "application/octet-stream");
      if (revision === capturedRevision) dirty = false;
      refresh();
      notice(revision === capturedRevision
        ? "REVIEW_ONLY: encrypted HUMAN vault exported. Reopen with exact receipt bytes and password."
        : "REVIEW_ONLY: encrypted earlier snapshot exported; additional HUMAN edits remain unsaved.");
    } catch (_) {
      notice("HOLD: encrypted HUMAN export refused. Check notes and matching passphrase; previous edits retained.", true);
    } finally { pass.value = ""; repeated.value = ""; }
  }
  async function exportBundle() {
    const pass = byId("newPassword"), repeat = byId("confirmPassword");
    try {
      ensure(globalThis.LightUpHumanVault && receiptRaw instanceof ArrayBuffer);
      const csv = serializedCsv();
      const capturedRevision = revision;
      ensure(pass.value === repeat.value && pass.value.length >= 14 &&
        pass.value.length <= 256 && !/[\u0000-\u001f\u007f]/u.test(pass.value));
      ensure(confirm("Create one fully encrypted PRIVATE assessment-HUMAN packet? Both the unsigned receipt and HUMAN notes will be encrypted. The password is unrecoverable and does not authenticate clients, original evidence or permission."));
      const packet = await LightUpHumanVault.sealBundle(receiptRaw, csv, pass.value);
      download(packet, "PRIVATE-human-handoff.luhb", "application/octet-stream");
      if (revision === capturedRevision) dirty = false;
      refresh();
      notice(revision === capturedRevision ?
        "REVIEW_ONLY: one completely encrypted PRIVATE HUMAN packet saved; no external transfer or grant." :
        "REVIEW_ONLY: earlier HUMAN snapshot encrypted; newer edits remain unsaved.");
    } catch (_) {
      notice("HOLD: encrypted complete HUMAN handoff refused; existing edits retained.", true);
    } finally { pass.value = ""; repeat.value = ""; }
  }
  function exportCounts() {
    try {
      serializedCsv(); // Require exact current admitted ordinal, stage and note shape.
      const floor = 5;
      const counters = Object.fromEntries(STAGES.map(stage => [
        stage, records.filter(row => row.stage === stage).length
      ]));
      const showTotal = records.length >= floor;
      const showKinds = showTotal && STAGES.every(stage =>
        counters[stage] === 0 || counters[stage] >= floor);
      ensure(confirm("Save a PRIVATE small-cohort-suppressed HUMAN counts-only CSV? Even summary counts can disclose sensitive context. No authorization or public anonymity is asserted."));
      const values = [
        ["field", "value"],["status", "REVIEW_ONLY"],
        ["original_source_authenticated", "FALSE"],
        ["current_consent_verified", "FALSE"],
        ["release_allowed", "FALSE"],
        ["not_anonymity_guarantee", "TRUE"],
        ["HUMAN_receipt_identity", "UNSIGNED_BYTES_ONLY"],
        ["source_count", showTotal ? records.length : "SUPPRESSED_SMALL_COHORT"],
        ["human_stages", "DECLARED_NON_AUTHORITATIVE"]
      ];
      if (showKinds) {
        for (const stage of STAGES) values.push(["HUMAN_" + stage,counters[stage]]);
      } else values.push(["HUMAN_stage_breakdown","SUPPRESSED_SMALL_GROUP"]);
      download(values.map(row => row.map(csvField).join(",")).join("\n") + "\n",
               "PRIVATE-human-summary.csv","text/csv;charset=utf-8");
      notice("REVIEW_ONLY: locally saved source-free small-cohort-suppressed PRIVATE HUMAN counts.");
    } catch (_) {
      notice("HOLD: PRIVATE HUMAN summary not admitted, no export.", true);
    }
  }
  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/gu, char =>
      ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[char]);
  }
  function exportPrintableReport() {
    try {
      serializedCsv(); // Full original receipt/ordinal/stage/text admission.
      ensure(confirm("Export PRIVATE plaintext HUMAN notes into a printable HTML report? Downloads may sync with cloud storage. Only separately authenticated recipients may receive it. No finding, consent or release is verified."));
      const totals = STAGES.map(stage => ({
        stage, count: records.filter(row => row.stage === stage).length
      }));
      const counts = totals.map(item =>
        "<li>" + escapeHtml(item.stage) + ": " + item.count + "</li>").join("");
      const rows = records.map(row =>
        "<tr><th scope='row'>" + row.ordinal + "</th><td>" +
        escapeHtml(row.kind) + "</td><td>" + escapeHtml(row.stage) +
        "</td><td>" + escapeHtml(row.question) + "</td><td>" +
        escapeHtml(row.action) + "</td></tr>").join("");
      const html = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; ',
        'style-src &#39;unsafe-inline&#39;; img-src &#39;none&#39;; connect-src &#39;none&#39;; ',
        'form-action &#39;none&#39;; frame-src &#39;none&#39;">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<title>PRIVATE HUMAN assessment follow-up — non-authorizing</title>',
        '<style>body{font:16px/1.5 system-ui;max-width:1080px;margin:2rem auto;padding:1rem}',
        'header{border:2px solid #773;padding:1rem}table{border-collapse:collapse;width:100%}',
        'th,td{border:1px solid #999;padding:.6rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}',
        '@media print{body{margin:0}header{border:1px solid #444}}</style></head><body>',
        '<header><h1>PRIVATE HUMAN follow-up · REVIEW ONLY</h1>',
        '<p>This is an unsigned local HUMAN transcription from a source-free ',
        'offline receipt and manually entered notes. No source-byte provenance, ',
        'reviewer identity, original findings, consent, authorization, verified ',
        'fix, client grant, retest, approval or release has been established. ',
        'This report contains PRIVATE plaintext HUMAN notes; manual disclosure ',
        'review is required before any external handoff.</p></header>',
        '<h2>Self-declared HUMAN stages (not security findings)</h2><ul>',
        counts, '</ul><h2>HUMAN-only follow-up</h2>',
        '<table><thead><tr><th>Local ordinal</th><th>Source-declared kind</th>',
        '<th>HUMAN stage</th><th>HUMAN question</th><th>HUMAN next action</th>',
        '</tr></thead><tbody>',rows,'</tbody></table>',
        '<p>Keep PRIVATE. A count, SHA, HUMAN answer or printable page ',
        'cannot grant assessment rights. Original security and consent gates ',
        'remain mandatory.</p></body></html>'
      ].join("");
      download(html,"PRIVATE-human-browser-report.html","text/html;charset=utf-8");
      notice("REVIEW_ONLY: local source-free HUMAN printable report exported as PRIVATE plaintext. No release.");
    } catch (_) {
      notice("HOLD: printable HUMAN report not admitted or privacy confirmation declined.", true);
    }
  }
  async function comparePrevious() {
    const password = byId("comparePassword");
    try {
      ensure(records.length > 0 && /^[a-f0-9]{64}$/u.test(receiptDigest));
      ensure(globalThis.LightUpHumanVault);
      const selected = byId("compareVault").files[0];
      ensure(selected && selected.size <= LightUpHumanVault.maxVaultBytes);
      const previous = await LightUpHumanVault.open(
        await selected.arrayBuffer(), password.value, receiptDigest);
      const earlier = validateRows(parseCsv(previous.replace(/^\uFEFF/u, "")),
                                   records.map(row => ({kind:row.kind})), receiptDigest);
      const changes = [];
      let same = 0;
      for (let i = 0; i < earlier.length; ++i) {
        const before = earlier[i], after = records[i];
        const different = ["stage", "question", "action"].filter(key => before[key] !== after[key]);
        if (!different.length) { same++; continue; }
        changes.push({ordinal:after.ordinal,kind:after.kind,before,after,different});
      }
      const target = byId("compareRows");
      target.replaceChildren();
      for (const change of changes) {
        const tr = element("tr",undefined,target);
        element("th",String(change.ordinal),tr).scope = "row";
        element("td",change.kind.replaceAll("_"," "),tr);
        element("td",change.different.join(", "),tr);
        element("td",change.before.stage + "; " + change.before.question + "; " + change.before.action,tr);
        element("td",change.after.stage + "; " + change.after.question + "; " + change.after.action,tr);
      }
      byId("compareCounts").textContent = changes.length + " changed HUMAN row(s); " +
        same + " literal matches. Text equality never authenticates reviewers or source.";
      byId("compareSection").hidden = false;
      notice("REVIEW_ONLY: encrypted older HUMAN round compared in memory against current receipt; no decisions copied.");
    } catch (_) {
      notice("HOLD: older vault, passphrase or exact receipt mismatch. Current edits and comparison retained.", true);
    } finally { password.value = ""; }
  }
  byId("bundle").addEventListener("change", () => {
    if (byId("bundle").files.length) {
      for (const name of ["receipt","csv","vault"]) byId(name).value = "";
    }
  });
  byId("receipt").addEventListener("change", () => {
    if (byId("receipt").files.length) byId("bundle").value = "";
  });
  byId("csv").addEventListener("change", () => {
    if (byId("csv").files.length) {
      byId("vault").value = "";
      byId("bundle").value = "";
    }
  });
  byId("vault").addEventListener("change", () => {
    if (byId("vault").files.length) {
      byId("csv").value = "";
      byId("bundle").value = "";
    }
  });
  byId("load").addEventListener("click", load);
  byId("export").addEventListener("click", exportCsv);
  byId("exportEncrypted").addEventListener("click", exportEncrypted);
  byId("exportBundle").addEventListener("click", exportBundle);
  byId("compare").addEventListener("click", comparePrevious);
  byId("exportCounts").addEventListener("click", exportCounts);
  byId("exportPrint").addEventListener("click", exportPrintableReport);
  byId("stageFilter").addEventListener("change", refresh);
  byId("query").addEventListener("input", refresh);
  window.addEventListener("beforeunload", event => {
    if (dirty) { event.preventDefault(); event.returnValue = ""; }
  });
})();
