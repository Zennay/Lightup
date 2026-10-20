"use strict";

/* Offline HUMAN workflow for already-exported LightUp CSV summaries.
 * No original source mutation, persistence, network, authentication or grant. */
(function () {
  const HEADER = ["finding_id", "title", "severity", "retest_status", "remediation"];
  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const RETEST = ["not_tested", "fix_pending", "fixed", "regression"];
  const STAGES = ["unreviewed", "triage", "queued", "waiting_owner", "needs_evidence", "followup_requested", "human_reviewed"];
  const MAX_FILE = 2 * 1024 * 1024;
  const MAX_ROWS = 128;
  const MAX_CELL_BYTES = 32768;
  const MAX_JOURNAL_BYTES = 512 * 1024;
  const DECODER = new TextDecoder("utf-8", {fatal: true});
  const SCHEMA = "lightup.offline_human_csv_review.v1";
  const AGGREGATE = "lightup.anonymous_human_csv_counts.v1";
  const NO_AUTHORITY = Object.freeze({
    verified_findings: false, verified_remediation: false,
    authenticated_source: false, authenticated_consent: false,
    authorization_grant: false, permission_to_scan: false
  });
  const $ = (id) => document.getElementById(id);
  const enc = new TextEncoder();
  const state = {rows: [], digest: "", journal: [], selected: -1, dirty: false, pending: false, filename: "", bulkUndo: null};

  function fail(message) { throw new Error(message); }
  function exactObject(obj, keys) {
    return obj !== null && typeof obj === "object" && !Array.isArray(obj) &&
      Object.keys(obj).length === keys.length &&
      keys.every((key) => Object.prototype.hasOwnProperty.call(obj, key));
  }
  function textOK(value, maxBytes, allowEmpty) {
    return typeof value === "string" &&
      (allowEmpty || value.trim().length > 0) &&
      enc.encode(value).length <= maxBytes &&
      !/[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}]/u.test(value);
  }
  function safeDisplay(value, maxBytes, allowEmpty) {
    if (!textOK(value, maxBytes, allowEmpty)) return false;
    if (!value) return !!allowEmpty;
    const normalized = value.normalize("NFKC");
    if (!textOK(normalized, maxBytes * 4, allowEmpty)) return false;
    // The existing LightUp exporter prefixes a real ASCII formula with "'".
    // Never interpret an invisible or compatibility-disguised expression.
    let prefix = normalized.replace(/^[\p{Zs}\p{M}]+/gu, "");
    if (/^[=+\-@]/u.test(prefix)) return false;
    if (/^[\p{M}]+$/u.test(normalized)) return false;
    return true;
  }
  function csvRows(input) {
    // Require the exact all-quoted CRLF shape of the existing CSV serializer.
    // Reject partial/malformed records before touching any displayed state.
    const rows = [];
    let i = 0;
    if (!input || input.charCodeAt(0) === 0xFEFF) fail("Unexpected CSV encoding or BOM");
    while (i < input.length) {
      const cells = [];
      for (let col = 0; col < 5; col++) {
        if (input[i++] !== '"') fail("Expected quoted CSV cell");
        let value = "";
        let closed = false;
        while (i < input.length) {
          const ch = input[i++];
          if (ch === '"') {
            if (input[i] === '"') { i++; value += '"'; continue; }
            closed = true; break;
          }
          value += ch;
          if (value.length > MAX_CELL_BYTES) fail("CSV field exceeds limit");
        }
        if (!closed) fail("Unterminated CSV cell");
        if (enc.encode(value).length > MAX_CELL_BYTES) fail("CSV field exceeds UTF-8 limit");
        cells.push(value);
        if (col < 4 && input[i++] !== ",") fail("Incorrect CSV column count");
      }
      if (input.slice(i, i + 2) !== "\r\n") fail("Expected canonical CSV record boundary");
      i += 2;
      rows.push(cells);
      if (rows.length > MAX_ROWS + 1) fail("CSV row limit exceeded");
    }
    if (rows.length === 0 || rows[0].some((v, j) => v !== HEADER[j])) fail("Unexpected CSV header");
    return rows.slice(1);
  }
  function admitCsv(input) {
    const rows = csvRows(input);
    const seen = new Set();
    const displaySeen = new Set();
    return rows.map((cells) => {
      if (!cells.every((v, idx) => safeDisplay(v, MAX_CELL_BYTES, idx === 4))) {
        fail("Invalid source display text or unsafe formula prefix");
      }
      const [id, title, severity, retest, remediation] = cells;
      if (!id || id !== id.trim() || !title || !remediation ||
          !SEVERITIES.includes(severity) || !RETEST.includes(retest)) {
        fail("Invalid canonical finding fields");
      }
      if (seen.has(id) || displaySeen.has(id.normalize("NFKC"))) fail("Duplicate or ambiguous finding identity");
      seen.add(id);
      displaySeen.add(id.normalize("NFKC"));
      return Object.freeze({id, title, severity, retest, remediation});
    });
  }
  async function digest(bytes) {
    if (!crypto || !crypto.subtle) fail("Local SHA-256 is unavailable in this browser");
    const result = await crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(result), b => b.toString(16).padStart(2, "0")).join("");
  }
  function todayValid(value) {
    if (value === "") return true;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
    const d = new Date(value + "T00:00:00Z");
    return Number.isFinite(d.valueOf()) && d.toISOString().slice(0, 10) === value;
  }
  function blankEntry(id) { return {id, stage: STAGES[0], owner: "", due: "", note: ""}; }
  function admitEntry(entry, id) {
    if (!exactObject(entry, ["id", "stage", "owner", "due", "note"]) || entry.id !== id ||
        !STAGES.includes(entry.stage) || !textOK(entry.owner, 160, true) ||
        !textOK(entry.note, 2048, true) || !todayValid(entry.due) ||
        !safeDisplay(entry.owner, 160, true) || !safeDisplay(entry.note, 2048, true)) {
      fail("Human journal contains invalid or mismatched fields");
    }
    return {id, stage: entry.stage, owner: entry.owner, due: entry.due, note: entry.note};
  }
  function localDate() {
    const d = new Date();
    return [d.getFullYear(), String(d.getMonth() + 1).padStart(2, "0"), String(d.getDate()).padStart(2, "0")].join("-");
  }
  function status(message, error) {
    $("status").textContent = message;
    $("status").className = "status " + (error ? "error" : "ok");
  }
  function setEnabled(yes) {
    ["search", "severityFilter", "stageFilter", "bulkStage", "bulkApply", "saveJournal", "loadJournal", "saveVault", "loadVault", "saveBrief", "saveCounts", "clearAll"].forEach((id) => {
      $(id).disabled = !yes;
    });
  }
  function stageText(s) { return s.replaceAll("_", " "); }
  function wipe() {
    state.rows = []; state.digest = ""; state.journal = []; state.selected = -1;
    state.dirty = false; state.pending = false; state.filename = ""; state.bulkUndo = null;
    $("sourceFile").value = ""; $("journalFile").value = "";
    $("summary").textContent = "No source CSV loaded.";
    $("sourceId").textContent = "";
    $("list").replaceChildren();
    $("detail").hidden = true;
    $("noneSelected").hidden = false;
    setEnabled(false);
  }
  function selectedIndices() {
    const query = $("search").value.trim().toLocaleLowerCase();
    const severity = $("severityFilter").value;
    const stage = $("stageFilter").value;
    return state.rows.map((_, i) => i).filter((i) => {
      const r = state.rows[i];
      const j = state.journal[i];
      return (!severity || severity === r.severity) &&
        (!stage || stage === j.stage) &&
        (!query || [r.id, r.title, r.remediation].some(v => v.toLocaleLowerCase().includes(query)));
    }).sort((a, b) => SEVERITIES.indexOf(state.rows[a].severity) - SEVERITIES.indexOf(state.rows[b].severity)
      || state.rows[a].id.localeCompare(state.rows[b].id));
  }
  function renderList() {
    const list = $("list");
    list.replaceChildren();
    const indices = selectedIndices();
    $("counts").textContent = indices.length + " visible / " + state.rows.length + " total; " +
      state.journal.filter(j => j.stage !== "unreviewed").length + " human-updated; " +
      state.journal.filter(j => j.due && j.due < localDate()).length +
      " tentative overdue.";
    for (const index of indices) {
      const row = state.rows[index], journal = state.journal[index];
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "case" + (index === state.selected ? " active" : "");
      btn.setAttribute("aria-pressed", index === state.selected ? "true" : "false");
      const strong = document.createElement("strong");
      strong.textContent = row.severity.toUpperCase() + " · " + row.title;
      const small = document.createElement("span");
      small.textContent = row.id + " · " + stageText(journal.stage) + (journal.due ? " · due " + journal.due : "");
      btn.append(strong, small);
      btn.addEventListener("click", () => selectCase(index));
      list.append(btn);
    }
  }
  function selectCase(index) {
    if (state.pending && !confirm("Discard unapplied edits to the current HUMAN form?")) return;
    state.pending = false;
    state.selected = index;
    const row = state.rows[index], journal = state.journal[index];
    $("noneSelected").hidden = true; $("detail").hidden = false;
    $("findingId").textContent = row.id;
    $("findingTitle").textContent = row.title;
    $("findingMeta").textContent = "Source-declared " + row.severity + " · source retest " + row.retest +
      " (not independently verified)";
    $("remediation").textContent = row.remediation;
    $("humanStage").value = journal.stage;
    $("humanOwner").value = journal.owner;
    $("humanDue").value = journal.due;
    $("humanNote").value = journal.note;
    renderList();
  }
  function writeEntry() {
    if (state.selected < 0) return;
    const row = state.rows[state.selected];
    let entry;
    try {
      entry = admitEntry({
        id: row.id, stage: $("humanStage").value,
        owner: $("humanOwner").value.trim(), due: $("humanDue").value,
        note: $("humanNote").value
      }, row.id);
    } catch (error) { status(error.message, true); return; }
    if (JSON.stringify(entry) !== JSON.stringify(state.journal[state.selected])) {
      state.journal[state.selected] = entry;
      state.dirty = true;
      state.bulkUndo = null;
      $("bulkUndo").disabled = true;
    }
    state.pending = false;
    renderList();
    status("HUMAN note updated in memory only. Download a PRIVATE draft to keep it.", false);
  }
  async function readFile(file, limit) {
    if (!file || file.size < 1 || file.size > limit) fail("File absent or exceeds the bounded upload size");
    const bytes = await file.arrayBuffer();
    return {bytes, value: DECODER.decode(bytes)};
  }
  async function loadSource(file) {
    if ((state.dirty || state.pending) && !confirm("Discard unsaved or unapplied PRIVATE HUMAN changes and open a new source?")) return;
    try {
      const {bytes, value} = await readFile(file, MAX_FILE);
      const stagedRows = admitCsv(value);
      const sha = await digest(bytes);
      // No mutation until the complete source has been admitted.
      state.rows = stagedRows;
      state.digest = sha;
      state.journal = stagedRows.map(r => blankEntry(r.id));
      state.filename = file.name;
      state.selected = -1;
      state.dirty = false;
      state.pending = false;
      state.bulkUndo = null;
      $("bulkUndo").disabled = true;
      $("detail").hidden = true; $("noneSelected").hidden = false;
      $("sourceId").textContent = "Exact file SHA-256: " + sha + " (unsigned; NOT sender authentication)";
      $("summary").textContent = stagedRows.length + " original CSV finding(s), loaded into this local browser only.";
      setEnabled(true); renderList();
      status("CSV admitted. Source claims are not proof of a finding, fix or consent.", false);
    } catch (error) {
      status("CSV rejected without changing the existing workspace: " + error.message, true);
    }
  }
  function journalDocument() {
    return {
      schema: SCHEMA, classification: "PRIVATE_HUMAN_ONLY", authority: NO_AUTHORITY,
      csv_sha256: state.digest, count: state.rows.length,
      entries: state.journal.map(j => ({...j}))
    };
  }
  function download(content, name, mime) {
    const blob = new Blob([content], {type: mime});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = name;
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2500);
  }
  function saveJournal() {
    if (state.pending) { status("Apply or discard the current HUMAN form before exporting a journal.", true); return; }
    if (!confirm("PRIVATE export includes finding IDs, HUMAN owners and notes. Save only into a protected location. Continue?")) return;
    download(JSON.stringify(journalDocument(), null, 2) + "\n", "lightup-private-human-review.json", "application/json");
    state.dirty = false;
    status("PRIVATE HUMAN draft offered for local download. Confirm actual file storage yourself.", false);
  }
  function admitJournalDocument(parsed) {
    if (!exactObject(parsed, ["schema", "classification", "authority", "csv_sha256", "count", "entries"]) ||
        parsed.schema !== SCHEMA || parsed.classification !== "PRIVATE_HUMAN_ONLY" ||
        !exactObject(parsed.authority, Object.keys(NO_AUTHORITY)) ||
        Object.keys(NO_AUTHORITY).some(k => parsed.authority[k] !== false) ||
        parsed.csv_sha256 !== state.digest || parsed.count !== state.rows.length ||
        !Array.isArray(parsed.entries) || parsed.entries.length !== state.rows.length) {
      fail("PRIVATE HUMAN draft is not bound to this exact original CSV");
    }
    return parsed.entries.map((e, i) => admitEntry(e, state.rows[i].id));
  }
  async function loadJournal(file) {
    if (state.pending && !confirm("Discard unapplied HUMAN form edits before reopening a saved draft?")) return;
    try {
      const {value} = await readFile(file, MAX_JOURNAL_BYTES);
      const parsed = JSON.parse(value);
      if (value !== JSON.stringify(parsed, null, 2) + "\n") {
        fail("Only this tool's exact canonical journal format is accepted");
      }
      const staged = admitJournalDocument(parsed);
      if (!confirm("Replace the in-memory HUMAN notes with the exact-source PRIVATE draft?")) return;
      state.journal = staged; state.dirty = false; state.pending = false; state.selected = -1;
      state.bulkUndo = null; $("bulkUndo").disabled = true;
      $("detail").hidden = true; $("noneSelected").hidden = false;
      renderList();
      status("Original CSV byte-bound HUMAN journal restored locally (not an authenticated review).", false);
    } catch(error) {
      status("Draft rejected without changing the workspace: " + error.message, true);
    }
  }
  async function saveVault() {
    if (state.pending) { status("Apply or discard the HUMAN form edits before encrypting.", true); return; }
    const pass = $("vaultPass").value;
    if (!confirm("Encrypt an owner-private HUMAN journal, using a unique passphrase you must remember? No client identity, consent, or source authentication is established.")) return;
    $("saveVault").disabled = true;
    try {
      const blob = await LightUpEncryptedJournal.seal(journalDocument(), pass);
      download(blob, "lightup-private-human-review.luej", "application/json");
      state.dirty = false;
      status("Encrypted PRIVATE HUMAN journal offered for local save; confirm actual file storage.", false);
    } catch (error) {
      status("PRIVATE encryption HOLD: " + error.message, true);
    } finally {
      $("vaultPass").value = "";
      $("saveVault").disabled = !state.rows.length;
    }
  }
  async function loadVault(file) {
    if (state.pending && !confirm("Discard unapplied HUMAN form edits before encrypted restore?")) return;
    let pass = $("vaultPass").value;
    $("loadVault").disabled = true;
    try {
      const {value} = await readFile(file, 1024 * 1024);
      if (!pass) fail("Enter the PRIVATE passphrase before opening the encrypted journal");
      const document = await LightUpEncryptedJournal.unseal(value, pass);
      const staged = admitJournalDocument(document);
      if (!confirm("Original CSV SHA-256 and all HUMAN IDs match. Replace current in-memory HUMAN notes?")) return;
      state.journal = staged;
      state.dirty = false; state.pending = false; state.selected = -1;
      state.bulkUndo = null; $("bulkUndo").disabled = true;
      $("detail").hidden = true; $("noneSelected").hidden = false;
      renderList();
      status("Encrypted source-bound PRIVATE HUMAN journal opened in memory; not an authenticated source or permission.", false);
    } catch (error) {
      status("Encrypted journal rejected with current work unchanged: " + error.message, true);
    } finally {
      pass = "";
      $("vaultPass").value = "";
      $("loadVault").disabled = !state.rows.length;
    }
  }
  function htmlEscape(v) {
    return String(v).replace(/[&<>"']/g, ch => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    })[ch]);
  }
  async function saveBrief() {
    if (state.pending) {
      status("Apply or discard the current HUMAN form before preparing a PRIVATE brief.", true);
      return;
    }
    const onlyUpdated = $("briefFollowups").checked;
    const positions = selectedIndices().filter(i =>
      !onlyUpdated || state.journal[i].stage !== STAGES[0]);
    if (!positions.length) {
      status("No visible HUMAN findings match the PRIVATE brief selection.", true);
      return;
    }
    if (!confirm("PRIVATE printable brief for " + positions.length +
      " finding(s): includes original IDs, titles, remediation and HUMAN owner/notes. " +
      "This is not anonymous or an authorization. Save on a protected device only. Continue?")) return;
    // Scriptless, hash-pinned portable HTML. Source and HUMAN strings are escaped
    // as text and never interpreted as markup, attributes, CSS or JavaScript.
    const css = "html{font:15px/1.55 system-ui,sans-serif;color:#172522;max-width:880px;margin:auto;padding:20px}h1{font-size:2rem}header{border-bottom:2px solid #384b44;padding-bottom:14px}small{color:#52655f}article{page-break-inside:avoid;border:1px solid #abbab2;border-radius:9px;padding:15px;margin:16px 0}h2{margin:0;font-size:1.2rem}p{white-space:pre-wrap;overflow-wrap:anywhere}dt{font-weight:700}dd{margin:0 0 8px}strong{font-weight:800}.hold{padding:12px;border-left:4px solid #ab813e;background:#fcf1d9}@media print{html{padding:0}article{border-color:#777}a{color:inherit}}";
    let key;
    try {
      const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(css)));
      key = btoa(String.fromCharCode(...hash));
    } catch (error) {
      status("Browser cannot create a hash-pinned PRIVATE HTML brief.", true);
      return;
    }
    const rows = positions.map(i => {
      const source = state.rows[i], human = state.journal[i];
      const field = (label, v) => "<dt>" + htmlEscape(label) + "</dt><dd>" +
        htmlEscape(v || "—") + "</dd>";
      return "<article><h2>" + htmlEscape(source.title) + "</h2><small>Original finding ID: " +
        htmlEscape(source.id) + " · source-declared severity: " + htmlEscape(source.severity) +
        " · source-declared retest: " + htmlEscape(source.retest) +
        "</small><dl>" + field("Original proposed remediation (not verified)", source.remediation) +
        field("HUMAN stage", stageText(human.stage)) +
        field("HUMAN contact / owner", human.owner) +
        field("Tentative HUMAN review date", human.due) +
        field("HUMAN note", human.note) +
        "</dl></article>";
    }).join("\n");
    const csp = "default-src 'none'; style-src 'sha256-" + key +
      "'; img-src 'none'; connect-src 'none'; object-src 'none'; base-uri 'none'; " +
      "script-src 'none'; form-action 'none'";
    const markup = "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">" +
      "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
      "<meta http-equiv=\"Content-Security-Policy\" content=\"" + csp + "\">" +
      "<meta name=\"referrer\" content=\"no-referrer\">" +
      "<title>PRIVATE LightUp HUMAN follow-up brief</title><style>" + css +
      "</style></head><body><header><small>LIGHTUP · PRIVATE / HUMAN FOLLOW-UP</small>" +
      "<h1>Human next-action brief</h1><p class=\"hold\">PRIVATE, locally authored HUMAN-only work. " +
      "Original severity/remediation/retest values are unverified source claims. " +
      "NOT a client authentication, finding verification, remediation, grant, " +
      "retirement, consent or permission to act.</p></header>" +
      "<p>Exact imported source CSV SHA-256 (unsigned): <strong>" + htmlEscape(state.digest) +
      "</strong><br>Local preparation day (not authenticated chronology): " +
      htmlEscape(localDate()) + "<br>Included visible source items: " +
      positions.length + "</p>" + rows +
      "<footer><small>Self-contained offline PRIVATE human artifact. No script, storage, network, " +
      "client authorization or verified security result. Explicit disclosure approval required.</small></footer>" +
      "</body></html>\n";
    download(markup, "lightup-private-human-next-actions.html", "text/html");
    status("PRIVATE scriptless HUMAN brief offered; original source and local workroom remain unchanged.", false);
  }
  function saveCounts() {
    if (!confirm("Counts may reveal sensitive cohort sizes. Have you separately approved this disclosure?")) return;
    const severity = Object.fromEntries(SEVERITIES.map(s => [s, state.rows.filter(r => r.severity === s).length]));
    const human_stage = Object.fromEntries(STAGES.map(s => [s, state.journal.filter(r => r.stage === s).length]));
    const counts = {
      schema: AGGREGATE, classification: "ANONYMOUS_COUNTS_ONLY",
      authority: NO_AUTHORITY, total: state.rows.length, severity, human_stage,
      human_overdue_proposed: state.journal.filter(j => j.due && j.due < localDate()).length
    };
    download(JSON.stringify(counts, null, 2) + "\n", "lightup-anonymous-review-counts.json", "application/json");
    status("Counts-only file offered; no original IDs, title, source digest or HUMAN notes exported.", false);
  }
  function applyBulk() {
    if (state.pending) { status("Apply or discard individual HUMAN form edits before bulk staging.", true); return; }
    const selected = selectedIndices();
    const stage = $("bulkStage").value;
    if (!STAGES.includes(stage) || !selected.length) {
      status("No canonical HUMAN stage or visible findings were selected.", true);
      return;
    }
    const changed = selected.filter(i => state.journal[i].stage !== stage);
    if (!changed.length) { status("Visible records already have this HUMAN stage.", false); return; }
    if (!confirm("HUMAN-ONLY proposal: set " + changed.length +
      " visible finding(s) to '" + stageText(stage) +
      "'? This does NOT change original source, retest or remediation. Unfiltered rows stay unchanged.")) return;
    const previous = changed.map(i => ({index: i, stage: state.journal[i].stage}));
    for (const i of changed) state.journal[i] = {...state.journal[i], stage};
    state.bulkUndo = previous;
    state.dirty = true;
    $("bulkUndo").disabled = false;
    if (state.selected >= 0) $("humanStage").value = state.journal[state.selected].stage;
    renderList();
    status(changed.length + " visible HUMAN stage(s) updated in memory. Original CSV unchanged. Undo available.", false);
  }
  function undoBulk() {
    if (state.pending) { status("Apply or discard individual HUMAN form edits first.", true); return; }
    const previous = state.bulkUndo;
    if (!previous || !previous.length) return;
    for (const item of previous) {
      state.journal[item.index] = {...state.journal[item.index], stage: item.stage};
    }
    state.bulkUndo = null;
    $("bulkUndo").disabled = true;
    state.dirty = true;
    if (state.selected >= 0) $("humanStage").value = state.journal[state.selected].stage;
    renderList();
    status("Last bulk HUMAN stage changes reversed in memory only.", false);
  }
  function init() {
    STAGES.forEach(v => {
      for (const id of ["humanStage", "stageFilter", "bulkStage"]) {
        const opt = document.createElement("option"); opt.value = v; opt.textContent = stageText(v);
        $(id).append(opt);
      }
    });
    SEVERITIES.forEach(v => {
      const opt = document.createElement("option"); opt.value = v; opt.textContent = v;
      $("severityFilter").append(opt);
    });
    $("sourceFile").addEventListener("change", e => {
      if (e.target.files[0]) loadSource(e.target.files[0]);
    });
    $("journalFile").addEventListener("change", e => {
      if (e.target.files[0]) loadJournal(e.target.files[0]);
      e.target.value = "";
    });
    ["search", "severityFilter", "stageFilter"].forEach(id =>
      $(id).addEventListener("input", renderList));
    ["humanStage", "humanOwner", "humanDue", "humanNote"].forEach(id => {
      $(id).addEventListener("input", () => { state.pending = true; status("Unapplied HUMAN form edits — click Apply before switching findings or exporting a PRIVATE draft.", true); });
    });
    $("applyHuman").addEventListener("click", writeEntry);
    $("bulkApply").addEventListener("click", applyBulk);
    $("bulkUndo").addEventListener("click", undoBulk);
    $("saveJournal").addEventListener("click", saveJournal);
    $("loadJournal").addEventListener("click", () => $("journalFile").click());
    $("saveCounts").addEventListener("click", saveCounts);
    $("saveVault").addEventListener("click", saveVault);
    $("loadVault").addEventListener("click", () => $("vaultFile").click());
    $("vaultFile").addEventListener("change", e => {
      if (e.target.files[0]) loadVault(e.target.files[0]);
      e.target.value = "";
    });
    $("saveBrief").addEventListener("click", saveBrief);
    $("clearAll").addEventListener("click", () => {
      if ((state.dirty || state.pending) && !confirm("Discard unsaved or unapplied PRIVATE HUMAN notes?")) return;
      wipe(); status("All loaded application state released from the interface.", false);
    });
    window.addEventListener("beforeunload", e => {
      if (state.dirty || state.pending) { e.preventDefault(); e.returnValue = ""; }
    });
    wipe();
  }
  document.addEventListener("DOMContentLoaded", init);
})();
