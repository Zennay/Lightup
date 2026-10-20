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
  const WORKROOM_SCHEMA = "lightup.offline_csv_human_workroom_payload.v1";
  const AGGREGATE = "lightup.anonymous_human_csv_counts.v1";
  const NO_AUTHORITY = Object.freeze({
    verified_findings: false, verified_remediation: false,
    authenticated_source: false, authenticated_consent: false,
    authorization_grant: false, permission_to_scan: false
  });
  const $ = (id) => document.getElementById(id);
  const enc = new TextEncoder();
  const state = {rows: [], digest: "", journal: [], selected: -1, dirty: false, pending: false, filename: "", bulkUndo: null, sourceText: "", revisionCandidate: null, revisionHistory: []};

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
    ["search", "severityFilter", "stageFilter", "dueFilter", "ownerFilter", "orderBy", "revisionFile", "bulkStage", "bulkApply", "saveJournal", "loadJournal", "saveVault", "loadVault", "saveWorkroom", "saveBrief", "saveCounts", "saveCalendar", "clearAll"].forEach((id) => {
      $(id).disabled = !yes;
    });
  }
  function stageText(s) { return s.replaceAll("_", " "); }
  function clearRevisionCandidate() {
    state.revisionCandidate = null;
    $("revisionPreview").hidden = true;
    $("revisionFile").value = "";
    $("revisionChangedList").replaceChildren();
    $("revisionAbsentList").replaceChildren();
    $("revisionAddedList").replaceChildren();
  }
  function refreshRevisionArchive() {
    const hasHistory = state.revisionHistory.length > 0;
    $("revisionHistoryDownload").disabled = !hasHistory;
    $("revisionHistoryToggle").disabled = !hasHistory;
    $("revisionHistoryDownload").textContent = hasHistory
      ? "Download PRIVATE prior HUMAN archive (" + state.revisionHistory.length + " revision(s))"
      : "No prior HUMAN archive";
    if (!hasHistory) $("revisionArchiveDesk").hidden = true;
    if (!$("revisionArchiveDesk").hidden) renderRevisionHistory();
  }
  function renderRevisionHistory() {
    const container = $("revisionHistoryList");
    container.replaceChildren();
    const query = $("revisionHistorySearch").value.trim().toLocaleLowerCase();
    let visible = 0;
    let total = 0;
    for (let index = state.revisionHistory.length - 1; index >= 0; index--) {
      const revision = state.revisionHistory[index];
      total += revision.affected.length;
      const matching = revision.affected.filter(item =>
        !query || [item.id, item.source_title, item.human.owner]
          .some(value => value.toLocaleLowerCase().includes(query)));
      if (!matching.length && query) continue;
      visible += matching.length;
      const block = document.createElement("details");
      block.className = "revision-history-moment";
      const title = document.createElement("summary");
      title.textContent = "PRIVATE human-selected source transition " + (index + 1) +
        " · " + revision.counts.changed + " changed · " +
        revision.counts.absent + " absent (NOT FIXED)";
      block.append(title);
      const hashes = document.createElement("p");
      hashes.className = "mono";
      hashes.textContent = "Prior unsigned CSV SHA-256 " + revision.from_sha256 +
        " → selected unsigned CSV SHA-256 " + revision.to_sha256 +
        " · HUMAN choice " + revision.changed_policy +
        " (not chronological or client-authenticated)";
      block.append(hashes);
      for (const item of matching) {
        const row = document.createElement("details");
        const summary = document.createElement("summary");
        summary.textContent = (item.type === "absent" ? "ABSENT, not fixed" : "CHANGED, not verified") +
          " · " + item.id + " · " + item.source_title.slice(0, 150);
        row.append(summary);
        const description = document.createElement("p");
        description.textContent = "PRIOR source-declared severity " + item.source_severity +
          " / retest " + item.source_retest +
          " · HUMAN stage " + stageText(item.human.stage);
        const followup = document.createElement("p");
        followup.textContent = "PRIOR PRIVATE HUMAN owner: " + (item.human.owner || "—") +
          " · tentative due: " + (item.human.due || "—");
        const note = document.createElement("p");
        note.textContent = "PRIOR PRIVATE HUMAN note: " + (item.human.note || "—");
        row.append(description, followup, note);
        block.append(row);
      }
      container.append(block);
    }
    $("revisionHistoryCounts").textContent = visible + " visible / " + total +
      " prior changed/absent source records. These are PRIVATE HUMAN-only notes, never retest or closure evidence.";
  }
  async function previewRevision(file) {
    if (state.pending) {
      status("Apply or discard unapplied HUMAN edits before source comparison.", true);
      return;
    }
    if (!state.rows.length) {
      status("Open an original source CSV before comparing another snapshot.", true);
      return;
    }
    try {
      const {bytes, value} = await readFile(file, MAX_FILE);
      const nextRows = admitCsv(value);
      if (!nextRows.length) fail("An empty next source cannot be promoted; missing records are not fixed");
      const sha = await digest(bytes);
      const plan = LightUpCsvRevision.build(state.rows, nextRows, state.journal, state.digest, sha);
      clearRevisionCandidate();
      state.revisionCandidate = {...plan, csvText: value};
      $("revisionPreview").hidden = false;
      $("revisionChanged").value = "reset";
      $("revisionDigest").textContent = "Current (unsigned): " + state.digest +
        " · selected incoming (unsigned): " + sha;
      $("revisionCounts").textContent = plan.stats.unchanged + " unchanged · " +
        plan.stats.changed + " source-edited · " + plan.stats.added +
        " new · " + plan.stats.absent + " absent (NOT fixed)";
      const previous = new Map(state.rows.map(row => [row.id, row]));
      const nextById = new Map(plan.incomingRows.map(row => [row.id, row]));
      const textSnippet = value => value.length > 1600 ?
        value.slice(0, 1600) + "\n[DISPLAY TRUNCATED; accepted source remains byte-exact]" : value;
      const makeDifference = (label, a, b) => {
        const box = document.createElement("div");
        const name = document.createElement("strong");
        name.textContent = label + " · old → selected incoming";
        const previousText = document.createElement("p");
        previousText.textContent = "OLD: " + textSnippet(a);
        const nextText = document.createElement("p");
        nextText.textContent = "NEW (source-declared): " + textSnippet(b);
        box.append(name, previousText, nextText);
        return box;
      };
      for (const item of plan.affected) {
        const entry = document.createElement("details");
        const heading = document.createElement("summary");
        const current = nextById.get(item.id);
        const original = previous.get(item.id);
        const columns = item.type === "changed" && current ?
          ["title","severity","retest","remediation"].filter(name => original[name] !== current[name]) : [];
        heading.textContent = item.id + " · PRIOR " + item.source_severity.toUpperCase() +
          " · " + item.source_title.slice(0, 160) +
          (item.source_title.length > 160 ? "…" : "") +
          (columns.length ? " · CHANGED: " + columns.join(", ") : "") +
          (item.type === "absent" ? " · MISSING IS NOT FIXED" : " · NEEDS HUMAN REVIEW");
        entry.append(heading);
        if (columns.length) {
          for (const field of columns) {
            entry.append(makeDifference(field, original[field], current[field]));
          }
        } else {
          const previousStage = document.createElement("p");
          previousStage.textContent = "Prior HUMAN stage: " + stageText(item.human.stage) +
            " · original absence is not closure/retest/revocation. Retained in PRIVATE archive.";
          entry.append(previousStage);
        }
        (item.type === "changed" ? $("revisionChangedList") : $("revisionAbsentList")).append(entry);
      }
      for (let i = 0; i < plan.incomingRows.length; i++) {
        if (plan.kinds[i] !== "added") continue;
        const row = plan.incomingRows[i];
        const entry = document.createElement("details");
        const heading = document.createElement("summary");
        heading.textContent = row.id + " · source-declared " + row.severity.toUpperCase() +
          " · " + row.title.slice(0,160) + " · NEW HUMAN REVIEW";
        const details = document.createElement("p");
        details.textContent = "Source remediation proposal (unverified): " + textSnippet(row.remediation);
        entry.append(heading, details);
        $("revisionAddedList").append(entry);
      }
      status("New source fully admitted for local comparison. Current source and HUMAN choices remain intact.", false);
    } catch (error) {
      clearRevisionCandidate();
      status("Incoming source rejected without changing the current workspace: " + error.message, true);
    }
  }
  function exportRevisionCounts() {
    const plan = state.revisionCandidate;
    if (!plan || plan.fromDigest !== state.digest) return;
    if (!confirm("Download source-free comparison counts? Tiny cohorts can still be sensitive. " +
        "Only a separately approved disclosure may leave this PRIVATE device. No source identity " +
        "or actual chronological, security, consent or remediation verdict is provided.")) return;
    const data = {
      schema: "lightup.anonymous_csv_human_delta_counts.v1",
      classification: "ANONYMOUS_COUNTS_ONLY", authority: NO_AUTHORITY,
      declared_temporal_order: false, verified_fix: false,
      unchanged: plan.stats.unchanged, source_changed: plan.stats.changed,
      newly_present: plan.stats.added, absent_not_fixed: plan.stats.absent
    };
    download(JSON.stringify(data, null, 2) + "\n", "lightup-source-free-human-delta-counts.json", "application/json");
    status("Source-free delta totals offered, without source hashes, original IDs, text or HUMAN notes.", false);
  }
  function commitRevision() {
    const plan = state.revisionCandidate;
    if (!plan || plan.fromDigest !== state.digest || state.pending) {
      status("Candidate is stale or current HUMAN edits are still pending. Compare the source again.", true);
      return;
    }
    let staged;
    try {
      staged = LightUpCsvRevision.migrate(plan, $("revisionChanged").value,
        blankEntry, state.revisionHistory);
    } catch (error) {
      status("PRIVATE source transition held: " + error.message, true);
      return;
    }
    if (!confirm("Replace the active source with this separately selected CSV? " +
        "Unchanged literal records retain HUMAN notes. New records start unreviewed. " +
        "Changed records are " + ($("revisionChanged").value === "reset"
          ? "RESET for HUMAN reassessment" : "retained only as HUMAN NEEDS EVIDENCE") +
        "; absent and changed PRIOR HUMAN details are archived privately. " +
        "Save a new encrypted COMPLETE workroom afterward to preserve the private archive. " +
        "No removed source record is deemed fixed, revoked or approved.")) return;
    state.sourceText = plan.csvText;
    state.rows = plan.incomingRows;
    state.digest = plan.toDigest;
    state.journal = staged.journal;
    state.revisionHistory = staged.history;
    state.selected = -1; state.bulkUndo = null; state.pending = false;
    state.dirty = true; state.filename = "[HUMAN-SELECTED SOURCE SNAPSHOT]";
    $("bulkUndo").disabled = true;
    $("sourceFile").value = "";
    $("detail").hidden = true; $("noneSelected").hidden = false;
    $("sourceId").textContent = "Human-selected source CSV SHA-256: " + state.digest +
      " (unsigned; NOT chronological or client-authenticated)";
    $("summary").textContent = state.rows.length + " selected source finding(s). " +
      state.revisionHistory.length + " PRIVATE HUMAN source revision(s) retained.";
    ["search", "severityFilter", "stageFilter", "dueFilter", "ownerFilter"].forEach(id => { $(id).value = ""; });
    $("orderBy").value = "severity";
    clearRevisionCandidate();
    refreshRevisionArchive();
    renderList();
    status("New source selected with explicit HUMAN migration. PRIVATE history is in memory only: save encrypted complete workroom.", false);
  }
  function exportRevisionArchive() {
    if (!state.revisionHistory.length) return;
    if (state.pending) {
      status("Apply or discard the active HUMAN form before exporting PRIVATE revision history.", true);
      return;
    }
    if (!confirm("Download PRIVATE previous-source revision records containing old IDs, titles, HUMAN owner and notes? " +
        "They are not anonymous or independently source-authenticated. Save only to a separately authorized private device.")) return;
    const output = {
      schema: "lightup.private_human_csv_source_revision_archive.v1",
      classification: "PRIVATE_HUMAN_ONLY", authority: NO_AUTHORITY,
      current_source_sha256: state.digest,
      revisions: state.revisionHistory
    };
    download(JSON.stringify(output, null, 2) + "\n", "lightup-private-prior-human-revisions.json", "application/json");
    status("PRIVATE prior-human source archive offered. Original or absent finding not verified or fixed.", false);
  }
  function wipe() {
    state.rows = []; state.digest = ""; state.journal = []; state.selected = -1;
    state.dirty = false; state.pending = false; state.filename = ""; state.bulkUndo = null; state.sourceText = ""; state.revisionHistory = [];
    clearRevisionCandidate(); refreshRevisionArchive();
    $("revisionArchiveDesk").hidden = true; $("revisionHistorySearch").value = "";
    $("sourceFile").value = ""; $("journalFile").value = ""; $("workroomFile").value = ""; $("vaultPass").value = "";
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
    const dueFilter = $("dueFilter").value;
    const ownerFilter = $("ownerFilter").value;
    const sortMode = $("orderBy").value;
    const today = localDate();
    const end = new Date(today + "T00:00:00Z");
    end.setUTCDate(end.getUTCDate() + 7);
    const weekEnd = end.toISOString().slice(0, 10);
    const matched = state.rows.map((_, i) => i).filter(i => {
      const r = state.rows[i], j = state.journal[i];
      return (!severity || severity === r.severity) &&
        (!stage || stage === j.stage) &&
        (!query || [r.id, r.title, r.remediation].some(v => v.toLocaleLowerCase().includes(query))) &&
        (!ownerFilter || (ownerFilter === "assigned" ? j.owner.length > 0 : !j.owner)) &&
        (!dueFilter || (dueFilter === "unscheduled" ? !j.due :
          dueFilter === "overdue" ? !!j.due && j.due < today :
          dueFilter === "today" ? j.due === today :
          !!j.due && j.due >= today && j.due <= weekEnd));
    });
    const bySeverity = (a, b) => SEVERITIES.indexOf(state.rows[a].severity) -
      SEVERITIES.indexOf(state.rows[b].severity);
    return matched.sort((a, b) =>
      (sortMode === "due" ? ((state.journal[a].due || "9999-12-31")
        .localeCompare(state.journal[b].due || "9999-12-31")) :
        sortMode === "id" ? state.rows[a].id.localeCompare(state.rows[b].id) :
        bySeverity(a, b)) ||
      bySeverity(a, b) || state.rows[a].id.localeCompare(state.rows[b].id));
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
      clearRevisionCandidate();
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
      state.sourceText = value;
      state.revisionHistory = [];
      clearRevisionCandidate(); refreshRevisionArchive();
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
      ["search", "severityFilter", "stageFilter", "dueFilter", "ownerFilter"].forEach(id => { $(id).value = ""; });
      $("orderBy").value = "severity";
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
    state.dirty = state.revisionHistory.length > 0;
    status(state.dirty ? "PRIVATE active journal offered, but PRIOR SOURCE HUMAN HISTORY is not included. Save the encrypted COMPLETE workroom to preserve that history." :
      "PRIVATE HUMAN draft offered for local download. Confirm actual file storage yourself.", state.dirty);
  }
  function admitJournalDocument(parsed, rows = state.rows, csvSha = state.digest) {
    if (!exactObject(parsed, ["schema", "classification", "authority", "csv_sha256", "count", "entries"]) ||
        parsed.schema !== SCHEMA || parsed.classification !== "PRIVATE_HUMAN_ONLY" ||
        !exactObject(parsed.authority, Object.keys(NO_AUTHORITY)) ||
        Object.keys(NO_AUTHORITY).some(k => parsed.authority[k] !== false) ||
        parsed.csv_sha256 !== csvSha || parsed.count !== rows.length ||
        !Array.isArray(parsed.entries) || parsed.entries.length !== rows.length) {
      fail("PRIVATE HUMAN draft is not bound to this exact original CSV");
    }
    return parsed.entries.map((e, i) => admitEntry(e, rows[i].id));
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
      state.journal = staged; clearRevisionCandidate(); state.dirty = state.revisionHistory.length > 0; state.pending = false; state.selected = -1;
      state.bulkUndo = null; $("bulkUndo").disabled = true;
      $("detail").hidden = true; $("noneSelected").hidden = false;
      renderList();
      status(state.dirty ? "HUMAN journal reopened. Existing prior-source history remains UNSAVED by this journal; save encrypted COMPLETE workroom." :
        "Original CSV byte-bound HUMAN journal restored locally (not an authenticated review).", state.dirty);
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
      state.dirty = state.revisionHistory.length > 0;
      status(state.dirty ? "Encrypted HUMAN-only journal offered; PRIOR SOURCE HUMAN HISTORY is NOT included. Save a complete encrypted workroom." :
        "Encrypted PRIVATE HUMAN journal offered for local save; confirm actual file storage.", state.dirty);
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
      state.journal = staged; clearRevisionCandidate();
      state.dirty = state.revisionHistory.length > 0; state.pending = false; state.selected = -1;
      state.bulkUndo = null; $("bulkUndo").disabled = true;
      $("detail").hidden = true; $("noneSelected").hidden = false;
      renderList();
      status(state.dirty ? "Encrypted HUMAN-only journal opened; previous source history still requires an encrypted COMPLETE workroom save." :
        "Encrypted source-bound PRIVATE HUMAN journal opened in memory; not an authenticated source or permission.", state.dirty);
    } catch (error) {
      status("Encrypted journal rejected with current work unchanged: " + error.message, true);
    } finally {
      pass = "";
      $("vaultPass").value = "";
      $("loadVault").disabled = !state.rows.length;
    }
  }
  async function saveWorkroom() {
    if (state.pending) { status("Apply or discard unfinished HUMAN fields before encryption.", true); return; }
    if (!state.sourceText) { status("No original locally admitted CSV is present.", true); return; }
    if (!confirm("Encrypt the COMPLETE original source CSV and PRIVATE HUMAN journal into one local file? " +
        "It contains confidential original findings. Use a strong, separate remembered password; " +
        "possession does not prove source, client, consent or disclosure permission.")) return;
    const pass = $("vaultPass").value;
    $("saveWorkroom").disabled = true;
    try {
      const doc = {
        schema: WORKROOM_SCHEMA, classification: "PRIVATE_SOURCE_AND_HUMAN_ONLY",
        authority: NO_AUTHORITY, csv_utf8: state.sourceText,
        csv_sha256: state.digest, journal: journalDocument(),
        revision_history: state.revisionHistory
      };
      const sealed = await LightUpEncryptedJournal.sealWorkroom(doc, pass);
      download(sealed, "lightup-private-entire-workroom.luew", "application/json");
      state.dirty = false;
      status("Encrypted complete source+HUMAN workroom offered for local PRIVATE save; no external transfer.", false);
    } catch (error) {
      status("Complete PRIVATE workroom encryption HOLD: " + error.message, true);
    } finally {
      $("vaultPass").value = "";
      $("saveWorkroom").disabled = !state.rows.length;
    }
  }
  async function loadWorkroom(file) {
    if ((state.dirty || state.pending) && !confirm("Discard local unsaved HUMAN state before encrypted full-workroom restore?")) return;
    let pass = $("vaultPass").value;
    $("loadWorkroom").disabled = true;
    try {
      if (!pass) fail("Enter the complete workroom passphrase first");
      const {value} = await readFile(file, 5 * 1024 * 1024);
      const doc = await LightUpEncryptedJournal.unsealWorkroom(value, pass);
      const legacy = exactObject(doc, ["schema", "classification", "authority", "csv_utf8", "csv_sha256", "journal"]);
      const current = exactObject(doc, ["schema", "classification", "authority", "csv_utf8", "csv_sha256", "journal", "revision_history"]);
      if ((!legacy && !current) ||
          doc.schema !== WORKROOM_SCHEMA || doc.classification !== "PRIVATE_SOURCE_AND_HUMAN_ONLY" ||
          !exactObject(doc.authority, Object.keys(NO_AUTHORITY)) ||
          Object.keys(NO_AUTHORITY).some(k => doc.authority[k] !== false) ||
          typeof doc.csv_utf8 !== "string" ||
          enc.encode(doc.csv_utf8).length > MAX_FILE ||
          typeof doc.csv_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(doc.csv_sha256)) {
        fail("Invalid complete source+HUMAN workspace");
      }
      const admittedRows = admitCsv(doc.csv_utf8);
      const candidateSha = await digest(enc.encode(doc.csv_utf8));
      if (candidateSha !== doc.csv_sha256) fail("Original CSV byte digest mismatch");
      const admittedJournal = admitJournalDocument(doc.journal, admittedRows, candidateSha);
      const admittedHistory = LightUpCsvRevision.admitHistory(
        current ? doc.revision_history : [], candidateSha, admitEntry, safeDisplay);
      if (!confirm("The encrypted packet's contained original CSV and HUMAN journal were admitted. " +
          "Replace this browser's current workspace? This does not establish authenticated tenant lineage.")) return;
      state.rows = admittedRows; state.digest = candidateSha; state.sourceText = doc.csv_utf8;
      state.journal = admittedJournal; state.revisionHistory = admittedHistory;
      clearRevisionCandidate(); refreshRevisionArchive();
      state.filename = "[PRIVATE ENCRYPTED WORKROOM]";
      state.selected = -1; state.dirty = false; state.pending = false; state.bulkUndo = null;
      $("bulkUndo").disabled = true;
      $("sourceFile").value = "";
      $("detail").hidden = true; $("noneSelected").hidden = false;
      $("sourceId").textContent = "Recovered exact source CSV SHA-256: " + candidateSha + " (unsigned)";
      $("summary").textContent = admittedRows.length + " original CSV finding(s) and source-matched PRIVATE HUMAN notes reopened in browser memory.";
      ["search", "severityFilter", "stageFilter", "dueFilter", "ownerFilter"].forEach(id => { $(id).value = ""; });
      $("orderBy").value = "severity";
      setEnabled(true); renderList();
      status("Encrypted complete workroom opened locally. No client authenticity, grant, consent or verified remediation established.", false);
    } catch (error) {
      status("Encrypted workroom HOLD; previous state preserved: " + error.message, true);
    } finally {
      pass = "";
      $("vaultPass").value = "";
      $("loadWorkroom").disabled = false;
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
  function saveCalendar() {
    if (state.pending) {
      status("Apply or discard the current HUMAN form edits before PRIVATE calendar export.", true);
      return;
    }
    const dated = selectedIndices().filter(i =>
      state.journal[i].due && state.journal[i].stage !== "unreviewed");
    if (!dated.length) {
      status("No visible HUMAN-updated findings have a tentative date.", true);
      return;
    }
    if (!confirm("Offer " + dated.length + " tentative all-day HUMAN follow-up event(s) as a PRIVATE .ics file? " +
      "Calendar apps may synchronize it. This contains no original IDs, titles, targets, evidence or owner text. " +
      "It is NOT a scheduled scan/retest, authenticated finding or actual calendar booking.")) return;
    const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
    const lines = ["BEGIN:VCALENDAR", "VERSION:2.0",
      "PRODID:-//LightUp//PRIVATE HUMAN Offline Follow-up//EN",
      "CALSCALE:GREGORIAN"];
    for (const position of dated) {
      const record = state.journal[position];
      const start = record.due.replaceAll("-", "");
      const end = new Date(record.due + "T00:00:00Z");
      end.setUTCDate(end.getUTCDate() + 1);
      const endValue = end.toISOString().slice(0, 10).replaceAll("-", "");
      const random = new Uint8Array(16);
      try { crypto.getRandomValues(random); }
      catch (_) { status("Secure random UID generation unavailable; calendar not exported.", true); return; }
      const uid = Array.from(random, byte => byte.toString(16).padStart(2, "0")).join("") + "@lightup.invalid";
      lines.push("BEGIN:VEVENT", "UID:" + uid, "DTSTAMP:" + stamp,
        "DTSTART;VALUE=DATE:" + start, "DTEND;VALUE=DATE:" + endValue,
        "CLASS:PRIVATE", "TRANSP:TRANSPARENT",
        "SUMMARY:Tentative HUMAN follow-up (review only)",
        "DESCRIPTION:Manually proposed PRIVATE follow-up; no verified finding or authorization.",
        "END:VEVENT");
    }
    lines.push("END:VCALENDAR");
    download(lines.join("\r\n") + "\r\n", "lightup-tentative-human-calendar.ics", "text/calendar");
    status("Tentative PRIVATE HUMAN calendar offered locally; not sent, booked or authorized.", false);
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
    clearRevisionCandidate();
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
    clearRevisionCandidate();
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
    ["search", "severityFilter", "stageFilter", "dueFilter", "ownerFilter", "orderBy"].forEach(id =>
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
    $("saveCalendar").addEventListener("click", saveCalendar);
    $("saveVault").addEventListener("click", saveVault);
    $("saveWorkroom").addEventListener("click", saveWorkroom);
    $("loadWorkroom").addEventListener("click", () => $("workroomFile").click());
    $("workroomFile").addEventListener("change", e => {
      if (e.target.files[0]) loadWorkroom(e.target.files[0]);
      e.target.value = "";
    });
    $("loadVault").addEventListener("click", () => $("vaultFile").click());
    $("vaultFile").addEventListener("change", e => {
      if (e.target.files[0]) loadVault(e.target.files[0]);
      e.target.value = "";
    });
    $("saveBrief").addEventListener("click", saveBrief);
    $("revisionFile").addEventListener("change", e => {
      if (e.target.files[0]) previewRevision(e.target.files[0]);
      e.target.value = "";
    });
    $("revisionCommit").addEventListener("click", commitRevision);
    $("revisionCountsExport").addEventListener("click", exportRevisionCounts);
    $("revisionCancel").addEventListener("click", () => {
      clearRevisionCandidate(); status("Source candidate discarded; original workspace remains unchanged.", false);
    });
    $("revisionHistoryDownload").addEventListener("click", exportRevisionArchive);
    $("revisionHistoryToggle").addEventListener("click", () => {
      const desk = $("revisionArchiveDesk");
      desk.hidden = !desk.hidden;
      if (!desk.hidden) renderRevisionHistory();
    });
    $("revisionHistorySearch").addEventListener("input", renderRevisionHistory);
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
