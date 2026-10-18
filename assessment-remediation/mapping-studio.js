/* LightUp offline human-only assessment/remediation mapping Studio.
   No network, persisted browser data, execution or authorization. */
"use strict";
(() => {
  const FLAGS = ["authorized", "consent_verified", "dispatch_allowed", "release_allowed"];
  const COLUMNS = ["finding_id", "title", "severity", "retest_status", "remediation"];
  const STAGES = ["needs_review", "investigating", "documented"];
  const LIMITS = { comparison: 262144, findings: 1048576, links: 262144 };
  const $ = id => document.getElementById(id);
  const app = { source: null, links: [], filtered: [] };
  const bytes = new TextDecoder("utf-8", { fatal: true });
  const encoder = new TextEncoder();

  function refuse(message) { throw new Error(message); }
  function exactKeys(obj, keys) {
    return obj && typeof obj === "object" && !Array.isArray(obj) &&
      Object.keys(obj).length === keys.length && keys.every(key => Object.hasOwn(obj, key));
  }
  function hasNoAuthority(doc) {
    return FLAGS.every(flag => doc && doc[flag] === false);
  }
  function safeText(value, max = 500) {
    return typeof value === "string" && value.length <= max &&
      !/[\u0000-\u0008\u000b-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u.test(value);
  }
  function announce(message, isBad = false) {
    $("messages").textContent = message;
    $("messages").className = isBad ? "message error" : "message";
  }
  function short(str, max = 74) { return str.length > max ? str.slice(0, max - 1) + "…" : str; }
  function showNode(parent, tag, content, className = "") {
    const node = document.createElement(tag);
    if (className) node.className = className;
    node.textContent = content;
    parent.appendChild(node);
    return node;
  }
  async function sourceFile(input, bound) {
    const file = input.files && input.files[0];
    if (!file || file.size < 1 || file.size > bound) refuse("An original source file is missing or exceeds its private size limit.");
    const raw = new Uint8Array(await file.arrayBuffer());
    if (raw.byteLength !== file.size) refuse("Original source file changed during local read.");
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", raw));
    const hash = Array.from(digest).map(b => b.toString(16).padStart(2, "0")).join("");
    return { text: bytes.decode(raw), hash };
  }

  function parseCsv(text) {
    // RFC 4180 quoted fields, including quoted commas, doubled quotes and line breaks.
    const records = [], row = []; let token = "", quote = false, endedQuote = false;
    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      if (quote) {
        if (char === '"' && text[i + 1] === '"') { token += '"'; i++; }
        else if (char === '"') { quote = false; endedQuote = true; }
        else { token += char; }
        continue;
      }
      if (char === '"' && token.length === 0 && !endedQuote) { quote = true; continue; }
      if (char === '"') refuse("Malformed original CSV quoting.");
      if (endedQuote && char !== "," && char !== "\r" && char !== "\n") refuse("Unexpected data after quoted original CSV cell.");
      if (char === ",") { row.push(token); token = ""; endedQuote = false; continue; }
      if (char === "\r" || char === "\n") {
        if (char === "\r" && text[i + 1] === "\n") i++;
        row.push(token); records.push([...row]); row.length = 0;
        token = ""; endedQuote = false;
        continue;
      }
      if (endedQuote) refuse("Malformed original CSV quote boundary.");
      token += char;
    }
    if (quote) refuse("Unclosed quoted original finding.");
    if (token || row.length || endedQuote) { row.push(token); records.push([...row]); }
    if (!records.length || records[0].join("\u0000") !== COLUMNS.join("\u0000"))
      refuse("Requires original five-column LightUp findings CSV.");
    const entries = records.slice(1), findings = new Map();
    if (entries.length < 1 || entries.length > 350) refuse("Original findings count outside allowed bounds.");
    for (const row of entries) {
      if (row.length !== 5 || !row[0] || row[0].trim() !== row[0] ||
          !/^[\x20-\x7e]{1,256}$/.test(row[0]) ||
          !["critical", "high", "medium", "low", "info"].includes(row[2]) ||
          !["not_tested", "fix_pending", "fixed", "regression"].includes(row[3]) ||
          !row[1].trim() || !row[4].trim() ||
          row[1].length > 2048 || row[4].length > 8192 ||
          findings.has(row[0])) refuse("Invalid, ambiguous or repeated original finding row.");
      findings.set(row[0], { finding_id: row[0], title: row[1], severity: row[2],
        retest_status: row[3], remediation: row[4] });
    }
    return findings;
  }

  function parseComparison(text) {
    const doc = JSON.parse(text);
    if (!exactKeys(doc, ["status", "regressed_scenarios", "comparisons", ...FLAGS]) ||
        !hasNoAuthority(doc) || !Array.isArray(doc.comparisons) ||
        doc.comparisons.length < 1 || doc.comparisons.length > 64 ||
        !["HOLD", "REVIEW_ONLY"].includes(doc.status) ||
        !Array.isArray(doc.regressed_scenarios)) refuse("Original comparator report is incomplete or claims authority.");
    const scenarios = new Map();
    const adverse = [];
    for (const row of doc.comparisons) {
      if (!exactKeys(row, ["scenario_id", "status", "regressions", "changes"]) ||
          !/^[\x20-\x7e]{1,256}$/.test(row.scenario_id || "") ||
          row.scenario_id.trim() !== row.scenario_id ||
          scenarios.has(row.scenario_id) || !Array.isArray(row.regressions) ||
          !Array.isArray(row.changes) || row.changes.length !== 15 ||
          !["HOLD", "REVIEW_ONLY"].includes(row.status)) refuse("Invalid or repeated scenario in original comparison.");
      if (row.status === "HOLD") adverse.push(row.scenario_id);
      scenarios.set(row.scenario_id, row);
    }
    if (doc.status !== (adverse.length ? "HOLD" : "REVIEW_ONLY") ||
        JSON.stringify(adverse) !== JSON.stringify(doc.regressed_scenarios))
      refuse("Original comparator status is contradictory.");
    // Standalone UI is never the canonical parser: the Python export CLI independently
    // verifies all original numeric deltas, regressions, metrics and source byte hashes.
    return { scenarios, status: doc.status };
  }

  function prepareSelector(select, options, valueFn, labelFn) {
    select.replaceChildren();
    for (const item of options) {
      const option = document.createElement("option");
      option.value = valueFn(item);
      option.textContent = labelFn(item);
      select.appendChild(option);
    }
  }

  async function importOriginals() {
    announce("Reading original files locally. No server or target is contacted.");
    try {
      const [comparison, csv] = await Promise.all([
        sourceFile($("comparison"), LIMITS.comparison),
        sourceFile($("findings"), LIMITS.findings)
      ]);
      const report = parseComparison(comparison.text);
      const findings = parseCsv(csv.text);
      const newSource = { comparisonSha: comparison.hash, findingsSha: csv.hash,
        scenarios: report.scenarios, findings, status: report.status };
      app.source = newSource;
      app.links = [];
      prepareSelector($("scenario"), [...report.scenarios.keys()], value => value, value => short(value, 110));
      prepareSelector($("finding"), [...findings.values()], value => value.finding_id,
        value => short(value.severity.toUpperCase() + " · " + value.title + " · " + value.finding_id, 110));
      prepareSelector($("stage"), STAGES, value => value, value => value.replaceAll("_", " "));
      $("studio").hidden = false;
      $("source-summary").textContent = report.scenarios.size + " original lab cases, " +
        findings.size + " original findings · source " + report.status +
        " · unsigned SHA " + comparison.hash.slice(0, 16) + " / " + csv.hash.slice(0, 16);
      render();
      announce("Original sources loaded locally. Links are human statements, never automatic evidence of the same engagement.");
    } catch (error) {
      announce("HOLD · could not accept the original sources: " + error.message, true);
    }
  }

  function currentLink() {
    if (!app.source) refuse("Select valid original files first.");
    const link = {
      scenario_id: $("scenario").value,
      finding_id: $("finding").value,
      stage: $("stage").value,
      reviewer: $("reviewer").value.trim(),
      next_action: $("action").value.trim(),
      note: $("note").value.trim()
    };
    if (!app.source.scenarios.has(link.scenario_id) ||
        !app.source.findings.has(link.finding_id) ||
        !STAGES.includes(link.stage) ||
        !safeText(link.reviewer, 100) || !safeText(link.next_action, 300) ||
        !safeText(link.note, 500)) refuse("Invalid human mapping fields.");
    return link;
  }

  function addOrUpdate() {
    try {
      const link = currentLink();
      const existing = app.links.findIndex(a =>
        a.scenario_id === link.scenario_id && a.finding_id === link.finding_id);
      if (existing < 0 && app.links.length >= 512) refuse("Maximum of 512 manual links.");
      if (existing < 0) app.links.push(link); else app.links[existing] = link;
      render();
      announce(existing < 0 ? "Manual link added. Source records unchanged." :
        "Manual follow-up updated. Original security status unchanged.");
    } catch (error) {
      announce("HOLD · " + error.message, true);
    }
  }

  function selectLink(link) {
    $("scenario").value = link.scenario_id;
    $("finding").value = link.finding_id;
    $("stage").value = link.stage;
    $("reviewer").value = link.reviewer;
    $("action").value = link.next_action;
    $("note").value = link.note;
    $("form").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function removeLink(link) {
    app.links = app.links.filter(a =>
      a.scenario_id !== link.scenario_id || a.finding_id !== link.finding_id);
    render();
    announce("Manual link removed; original records remain unchanged.");
  }

  function render() {
    if (!app.source) return;
    const body = $("links-body");
    body.replaceChildren();
    const filter = $("filter").value.toLowerCase();
    const links = [...app.links].sort((a, b) =>
      a.scenario_id.localeCompare(b.scenario_id) || a.finding_id.localeCompare(b.finding_id));
    const visible = links.filter(link => {
      const f = app.source.findings.get(link.finding_id);
      return (link.scenario_id + " " + link.finding_id + " " + f.title + " " +
        link.reviewer + " " + link.stage).toLowerCase().includes(filter);
    });
    for (const link of visible) {
      const tr = document.createElement("tr");
      const finding = app.source.findings.get(link.finding_id);
      showNode(tr, "td", short(link.scenario_id, 60));
      showNode(tr, "td", short(finding.severity.toUpperCase() + " · " + finding.title, 75));
      showNode(tr, "td", link.stage.replaceAll("_", " "));
      const action = document.createElement("td");
      const edit = showNode(action, "button", "Edit", "minor");
      edit.type = "button";
      edit.addEventListener("click", () => selectLink(link));
      const remove = showNode(action, "button", "Remove", "minor danger");
      remove.type = "button";
      remove.addEventListener("click", () => removeLink(link));
      tr.appendChild(action);
      body.appendChild(tr);
    }
    $("link-count").textContent = app.links.length + " manual link(s) · " +
      visible.length + " visible · " +
      new Set(app.links.map(link => link.scenario_id)).size + " scenario(s) linked · " +
      (app.source.scenarios.size - new Set(app.links.map(link => link.scenario_id)).size) +
      " scenario(s) unlinked (not proof of no findings)";
  }

  function handoff() {
    if (!app.source) refuse("No original source accepted.");
    if (!app.links.every(link => app.source.scenarios.has(link.scenario_id) &&
      app.source.findings.has(link.finding_id))) refuse("Unbound manual link.");
    return {
      schema: "lightup.assessment_remediation_links.v1",
      comparison_sha256: app.source.comparisonSha,
      findings_sha256: app.source.findingsSha,
      links: [...app.links],
      authorized: false, consent_verified: false, dispatch_allowed: false,
      release_allowed: false
    };
  }

  function downloadMapping() {
    try {
      const content = JSON.stringify(handoff(), null, 2) + "\n";
      if (encoder.encode(content).length > LIMITS.links)
        refuse("Manual mapping exceeds private CLI import limit.");
      const url = URL.createObjectURL(new Blob([content], { type: "application/json" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = "lightup-private-manual-links.json";
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      announce("Private, unsigned source-bound mapping saved locally; pass to bridge.py --links for strict original validation.");
    } catch (error) {
      announce("HOLD · " + error.message, true);
    }
  }

  async function restoreMapping() {
    try {
      if (!app.source) refuse("Load the two original sources first.");
      const file = $("restore").files[0];
      if (!file || file.size < 1 || file.size > LIMITS.links)
        refuse("Private mapping missing or oversized.");
      const document = JSON.parse(bytes.decode(new Uint8Array(await file.arrayBuffer())));
      if (!exactKeys(document, ["schema", "comparison_sha256", "findings_sha256",
        "links", ...FLAGS]) ||
          document.schema !== "lightup.assessment_remediation_links.v1" ||
          document.comparison_sha256 !== app.source.comparisonSha ||
          document.findings_sha256 !== app.source.findingsSha ||
          !hasNoAuthority(document) ||
          !Array.isArray(document.links) || document.links.length > 512)
        refuse("Private draft is not bound to these exact original source bytes.");
      const checked = [], keys = new Set();
      for (const row of document.links) {
        if (!exactKeys(row, ["scenario_id", "finding_id", "stage", "reviewer",
          "next_action", "note"]) ||
            !app.source.scenarios.has(row.scenario_id) ||
            !app.source.findings.has(row.finding_id) ||
            !STAGES.includes(row.stage) ||
            !safeText(row.reviewer, 100) || !safeText(row.next_action, 300) ||
            !safeText(row.note, 500))
          refuse("Private mapping contains an invalid source reference or human note.");
        const pair = JSON.stringify([row.scenario_id, row.finding_id]);
        if (keys.has(pair)) refuse("Duplicate manual link.");
        keys.add(pair); checked.push({ ...row });
      }
      app.links = checked; render();
      announce("Private unsigned follow-up draft restored against exact original bytes; human authorship still unverified.");
    } catch (error) {
      announce("HOLD · mapping not restored: " + error.message, true);
    }
  }

  $("load").addEventListener("click", importOriginals);
  $("form").addEventListener("submit", event => { event.preventDefault(); addOrUpdate(); });
  $("filter").addEventListener("input", render);
  $("export").addEventListener("click", downloadMapping);
  $("restore").addEventListener("change", restoreMapping);
})();