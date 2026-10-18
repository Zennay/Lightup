"use strict";
/* LightUp assessment-runtime human review desk.
 * Parses only output from the existing OFFLINE lab comparator CLI.
 * No scanner, no policy decision, no network, no grants and no persistence.
 */
(() => {
  const METRICS = [
    "valid_findings", "invalid_findings", "missed_findings", "coverage_assessed",
    "coverage_unknown", "scope_violations", "policy_violations",
    "human_interventions", "tool_calls", "evidence_quality",
    "reproducibility", "remediation_quality", "retest_correctness",
    "runtime_seconds", "compute_cost_usd"
  ];
  const HIGHER = new Set(["valid_findings", "coverage_assessed", "evidence_quality", "reproducibility", "remediation_quality", "retest_correctness"]);
  const LOWER = new Set(["invalid_findings", "missed_findings", "scope_violations", "policy_violations"]);
  const COUNTERS = new Set(["valid_findings", "invalid_findings", "missed_findings", "coverage_assessed", "coverage_unknown", "scope_violations", "policy_violations", "human_interventions", "tool_calls"]);
  const SCORES = new Set(["evidence_quality", "reproducibility", "remediation_quality", "retest_correctness"]);
  const STAGES = new Set(["todo", "investigating", "waiting", "planned", "reviewed"]);
  const AUTH = ["authorized", "consent_verified", "dispatch_allowed", "release_allowed"];
  const CASE_KEYS = ["scenario_id", "status", "regressions", "changes"];
  const CHANGE_KEYS = ["name", "baseline", "candidate", "delta", "regression"];
  const $ = id => document.getElementById(id);
  let report = null, selected = -1, digest = null, sourceKind = null;
  const exactKeys = (x, keys) => !!x && Object.getPrototypeOf(x) === Object.prototype &&
    Object.keys(x).length === keys.length && keys.every(k => Object.hasOwn(x, k));
  const fail = () => { throw new Error("Source structure or values do not match canonical lab CLI output."); };
  const finite = n => typeof n === "number" && Number.isFinite(n);
  const safeLabel = x => typeof x === "string" && x.length > 0 && x.length <= 256 &&
    x === x.trim() && /^[\x20-\x7e]+$/.test(x);
  const duplicates = list => new Set(list).size !== list.length;
  const boolFalseAuthority = doc => AUTH.every(key => doc[key] === false);
  const ensure = condition => { if (!condition) fail(); };
  const closeNumber = (a, b) => Math.abs(a - b) <= 1e-8 * Math.max(1, Math.abs(a), Math.abs(b));

  function parseChange(change) {
    ensure(exactKeys(change, CHANGE_KEYS) && METRICS.includes(change.name));
    const {name, baseline, candidate, delta, regression} = change;
    ensure(finite(baseline) && finite(candidate) && finite(delta) &&
      baseline >= 0 && candidate >= 0 && typeof regression === "boolean");
    if (COUNTERS.has(name)) {
      ensure(Number.isSafeInteger(baseline) && Number.isSafeInteger(candidate) &&
        baseline <= 1e9 && candidate <= 1e9);
    }
    if (SCORES.has(name)) ensure(baseline <= 1 && candidate <= 1);
    if (name === "runtime_seconds" || name === "compute_cost_usd") {
      ensure(baseline <= 1e12 && candidate <= 1e12);
    }
    ensure(closeNumber(candidate - baseline, delta));
    const derived = (HIGHER.has(name) && candidate < baseline) ||
      (LOWER.has(name) && candidate > baseline);
    ensure(regression === derived);
    return {name, baseline, candidate, delta, regression};
  }
  function parseComparison(input, cohort) {
    const keys = cohort ? CASE_KEYS : ["status", "regressions", "changes"];
    ensure(exactKeys(input, keys) && ["REVIEW_ONLY", "HOLD"].includes(input.status) &&
      Array.isArray(input.regressions) && Array.isArray(input.changes));
    if (cohort) ensure(safeLabel(input.scenario_id));
    ensure(input.regressions.length <= METRICS.length &&
      input.regressions.every(x => METRICS.includes(x)) &&
      !duplicates(input.regressions));
    if (input.changes.length === 0) {
      ensure(input.status === "HOLD" && input.regressions.length === 0);
      return {sourceId: cohort ? input.scenario_id : null, status: "HOLD", changes: [], regressions: [], stage: "todo", due: ""};
    }
    ensure(input.changes.length === METRICS.length);
    const changes = input.changes.map(parseChange);
    ensure(!duplicates(changes.map(x => x.name)));
    const derived = changes.filter(x => x.regression).map(x => x.name);
    ensure(derived.length === input.regressions.length &&
      derived.every(name => input.regressions.includes(name)));
    ensure(input.status === (derived.length ? "HOLD" : "REVIEW_ONLY"));
    return {sourceId: cohort ? input.scenario_id : null, status: input.status,
      changes, regressions: derived, stage: "todo", due: ""};
  }
  function readReport(doc) {
    ensure(doc && Object.getPrototypeOf(doc) === Object.prototype && boolFalseAuthority(doc));
    const hasCohort = Object.hasOwn(doc, "comparisons");
    let cases, kind;
    if (hasCohort) {
      ensure(exactKeys(doc, ["status", "regressed_scenarios", "comparisons", ...AUTH]));
      ensure(Array.isArray(doc.comparisons) && doc.comparisons.length <= 64 &&
        Array.isArray(doc.regressed_scenarios) && doc.regressed_scenarios.length <= 64 &&
        doc.regressed_scenarios.every(safeLabel) && !duplicates(doc.regressed_scenarios));
      cases = doc.comparisons.map(x => parseComparison(x, true));
      ensure(!duplicates(cases.map(x => x.sourceId)));
      const regressed = cases.filter(x => x.regressions.length).map(x => x.sourceId);
      ensure(regressed.length === doc.regressed_scenarios.length &&
        regressed.every(x => doc.regressed_scenarios.includes(x)));
      const verdict = cases.length === 0 || cases.some(x => x.status === "HOLD") ? "HOLD" : "REVIEW_ONLY";
      ensure(doc.status === verdict);
      kind = "cohort";
    } else {
      ensure(exactKeys(doc, ["status", "regressions", "changes", ...AUTH]));
      const result = parseComparison({
        status: doc.status, regressions: doc.regressions, changes: doc.changes
      }, false);
      cases = result.changes.length ? [result] : [];
      ensure(doc.status === (cases.length ? result.status : "HOLD"));
      kind = "single";
    }
    return {kind, verdict: doc.status, cases};
  }
  const countRegressions = () => report.cases.reduce((n, c) => n + c.regressions.length, 0);
  const priority = c => !c.regressions.length ? "No regression" :
    c.regressions.some(x => x === "scope_violations" || x === "policy_violations") ? "Critical drift" :
    c.regressions.some(x => ["missed_findings", "invalid_findings", "valid_findings"].includes(x)) ? "High drift" : "Review drift";
  const urgency = c => ["Critical drift", "High drift", "Review drift", "No regression"].indexOf(priority(c));
  const label = i => "Case " + String(i + 1).padStart(2, "0");
  const nice = s => s.replaceAll("_", " ");
  const stageText = s => ({
    todo:"Needs triage", investigating:"Investigating", waiting:"Awaiting reviewer",
    planned:"Mitigation planned", reviewed:"Human review recorded"
  })[s];

  function alert(text, cls = "") {
    $("message").textContent = text;
    $("message").className = "message " + cls;
  }
  function child(parent, tag, value, cls) {
    const node = document.createElement(tag);
    if (value !== undefined && value !== null) node.textContent = String(value);
    if (cls) node.className = cls;
    parent.append(node);
    return node;
  }
  function badge(parent, text, cls) { return child(parent, "span", text, "badge " + (cls || "")); }
  const fmt = n => Number.isInteger(n) ? String(n) : String(Number(n.toPrecision(8)));

  function renderOverview() {
    $("board").hidden = false;
    $("verdict").textContent = report.verdict;
    $("total").textContent = String(report.cases.length);
    $("regression-count").textContent = String(countRegressions());
    $("pending").textContent = String(report.cases.filter(c => c.stage !== "reviewed").length);
    $("source-hash").textContent = digest ? "Local source SHA-256: " + digest : "Source hash unavailable in this browser; no provenance assertion.";
  }
  function renderQueue() {
    const filter = $("filter").value;
    const parent = $("cases");
    parent.replaceChildren();
    const sorted = report.cases.map((c, i) => ({c, i}))
      .filter(({c}) => filter === "all" ||
        (filter === "regressed" && c.regressions.length > 0) ||
        (filter === "open" && c.stage !== "reviewed") ||
        (filter === "waiting" && c.stage === "waiting") ||
        (filter === "reviewed" && c.stage === "reviewed"))
      .sort((a,b) => urgency(a.c) - urgency(b.c) || a.i - b.i);
    $("no-matches").hidden = sorted.length > 0;
    for (const {c, i} of sorted) {
      const row = child(parent, "button", "", "case" + (i === selected ? " selected" : ""));
      row.type = "button";
      row.setAttribute("aria-pressed", String(i === selected));
      const left = child(row, "span");
      child(left, "strong", label(i));
      child(left, "small", c.regressions.length + " regression(s) · " + stageText(c.stage));
      badge(row, priority(c), c.regressions.length ? "bad" : "ok");
      row.addEventListener("click", () => {selected = i; render();});
    }
  }
  function renderDetails() {
    const c = report.cases[selected];
    $("case-details").hidden = !c;
    $("case-title").textContent = c ? label(selected) + " · " + priority(c) : "Case details";
    $("case-subtitle").textContent = c ? "Untrusted local " + sourceKind + " output · " + c.status + " · no security authority" :
      "Choose a scenario from the queue.";
    const chips = $("flags"); chips.replaceChildren();
    const table = $("metrics"); table.replaceChildren();
    if (!c) return;
    badge(chips, c.status, c.status === "HOLD" ? "bad" : "ok");
    badge(chips, c.regressions.length + " regressed metrics", c.regressions.length ? "bad" : "ok");
    $("stage").value = c.stage;
    $("due").value = c.due;
    for (const m of [...c.changes].sort((a,b) => Number(b.regression)-Number(a.regression))) {
      const tr = child(table, "tr", undefined, m.regression ? "bad" : "");
      child(tr, "td", nice(m.name));
      child(tr, "td", fmt(m.baseline));
      child(tr, "td", fmt(m.candidate));
      child(tr, "td", (m.delta >= 0 ? "+" : "") + fmt(m.delta) + (m.regression ? " ↓" : ""));
    }
  }
  function render() { renderOverview(); renderQueue(); renderDetails(); }
  function reset() {
    report = null; selected = -1; digest = null; sourceKind = null;
    $("file").value = ""; $("board").hidden = true; $("filter").value = "all";
    $("cases").replaceChildren(); $("metrics").replaceChildren();
    alert("Local workspace cleared. No browser storage was used.");
  }
  async function load(file) {
    reset();
    try {
      ensure(file && file.size > 0 && file.size <= 524288 && file.name.toLowerCase().endsWith(".json"));
      const raw = await file.text();
      ensure(new TextEncoder().encode(raw).length <= 524288);
      const parsed = JSON.parse(raw);
      const candidate = readReport(parsed);
      // The SHA identifies only the bytes just read. It does NOT authenticate the source.
      if (globalThis.crypto && crypto.subtle) {
        const bytes = new TextEncoder().encode(raw);
        const hash = await crypto.subtle.digest("SHA-256", bytes);
        digest = Array.from(new Uint8Array(hash), n => n.toString(16).padStart(2,"0")).join("");
      }
      report = candidate; sourceKind = candidate.kind;
      selected = candidate.cases.length ? 0 : -1;
      alert(candidate.cases.length ? "Untrusted canonical-shape report loaded locally. Human review only." :
        "Source says HOLD with no comparable cases. No partial details accepted.", candidate.cases.length ? "good" : "error");
      render();
    } catch (_) {
      reset();
      alert("HOLD · Unsupported, oversized, inconsistent or malformed local report. No partial review imported.", "error");
    }
  }
  function reviewExport() {
    const rows = report.cases.map((c,i) => ({
      case: label(i), priority: priority(c), source_status: c.status,
      metric_regressions: c.regressions.slice().sort(), human_stage: c.stage,
      follow_up_date: c.due || null
    }));
    return {schema:"lightup-offline-human-triage-v1", source_sha256: digest,
      source_kind: sourceKind, source_status: report.verdict,
      authorized:false,consent_verified:false,dispatch_allowed:false,release_allowed:false,
      release_approved:false,scan_allowed:false, review_only:true,
      cases:rows, warning:"UNAUTHENTICATED OFFLINE HUMAN PLANNING. NEVER AUTHORIZES ACTIVITY."};
  }
  function download(name, content, mime) {
    const blob = new Blob([content], {type:mime});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = name; document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }
  function csvCell(v) {
    const s = String(v == null ? "" : v).replace(/[\r\n]/g," ");
    const safe = /^[=+\-@\t]/.test(s) ? "'" + s : s;
    return '"' + safe.replaceAll('"','""') + '"';
  }
  $("file").addEventListener("change", async e => {if(e.target.files[0]) await load(e.target.files[0]);});
  $("clear").addEventListener("click", reset);
  $("filter").addEventListener("change", renderQueue);
  $("stage").addEventListener("change", e => {
    if (!report || selected < 0 || !STAGES.has(e.target.value)) return;
    report.cases[selected].stage = e.target.value; render();
  });
  $("due").addEventListener("change", e => {
    if (!report || selected < 0) return;
    const value = e.target.value;
    if (value && !/^\d{4}-\d{2}-\d{2}$/.test(value)) {e.target.value = ""; return;}
    report.cases[selected].due = value; renderOverview();
  });
  $("export-json").addEventListener("click", () => {
    if (!report) return;
    download("lightup-human-review.json", JSON.stringify(reviewExport(),null,2)+"\n", "application/json");
  });
  $("export-csv").addEventListener("click", () => {
    if (!report) return;
    const out = reviewExport();
    const cols = ["case","priority","source_status","metric_regressions","human_stage","follow_up_date"];
    const rows = [cols.map(csvCell).join(",")];
    for (const item of out.cases) rows.push(cols.map(key =>
      csvCell(Array.isArray(item[key]) ? item[key].join(";") : item[key])).join(","));
    download("lightup-human-follow-up.csv", rows.join("\r\n")+"\r\n", "text/csv;charset=utf-8");
  });
  $("print").addEventListener("click", () => {if(report) window.print();});
})();
