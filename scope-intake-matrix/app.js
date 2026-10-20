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
    lab_review: "Isolated LAB review proposal"
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
      !/[\u0000-\u001f\u007f-\u009f]/u.test(value) &&
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
    $("total-count").textContent = state.rows.length;
    $("excluded-count").textContent = state.rows.filter(row => row.excluded).length;
    $("review-count").textContent = state.rows.filter(row => row.status === "needs-client-review" ||
      row.ownership !== "claimed").length;
    $("blocked-count").textContent = state.rows.filter(row => row.status === "blocked").length;
    const issues = validate(state);
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
      declared_ownership_unverified_count: state.rows.filter(r => r.ownership !== "claimed").length,
      human_status_counts: counts, proposed_capability_counts: categories
    };
    download("lightup-scope-intake-COUNTS.json", JSON.stringify(receipt, null, 2) + "\n");
    announce("Counts-only receipt prepared. No target, client, identity or scope evidence included; still not an authorization.");
  }
  async function readFile(file) {
    if (!file || file.size > MAX_BYTES) throw Error("Select a JSON file no larger than 64 KiB.");
    return decodeOwnExport(await file.text());
  }
  async function importDraft(file) {
    try {
      const next = await readFile(file);
      if (!confirm("Replace all current unsaved PRIVATE draft data with the selected validated file?")) return;
      state = next;
      rowNumber = Math.max(0, ...state.rows.map(row => Number(row.id.slice(1))));
      $("filter").value = ""; $("status-filter").value = "all";
      $("compare-section").hidden = true;
      syncForm(); renderRows(); refresh();
      announce("PRIVATE draft opened locally after full strict admission. Still DRAFT/HOLD.");
    } catch (error) { announce("OPEN REJECTED: " + error.message + " Existing draft was retained.", true); }
  }
  async function compareDraft(file) {
    try {
      const before = await readFile(file);
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
    $("filter").addEventListener("input", renderRows);
    $("status-filter").addEventListener("change", renderRows);
    $("export").addEventListener("click", exportDraft);
    $("receipt").addEventListener("click", exportCounts);
    $("print").addEventListener("click", () => {
      const problems = validate(state);
      if (problems.length) { announce("Complete draft before printing: " + problems[0], true); return; }
      if (confirm("Print PRIVATE unverified scope proposal? Only use an approved destination.")) window.print();
    });
    $("choose-import").addEventListener("click", () => $("file-import").click());
    $("choose-compare").addEventListener("click", () => $("file-compare").click());
    $("file-import").addEventListener("change", async event => {
      const file = event.target.files[0]; event.target.value = ""; if (file) await importDraft(file);
    });
    $("file-compare").addEventListener("change", async event => {
      const file = event.target.files[0]; event.target.value = ""; if (file) await compareDraft(file);
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
