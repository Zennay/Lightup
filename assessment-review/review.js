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
  const ROUTES = new Set(["unassigned","lab-runtime","scope-review",
    "evidence-review","independent-review"]);
  const AUTH = ["authorized", "consent_verified", "dispatch_allowed", "release_allowed"];
  const CASE_KEYS = ["scenario_id", "status", "regressions", "changes"];
  const CHANGE_KEYS = ["name", "baseline", "candidate", "delta", "regression"];
  const $ = id => document.getElementById(id);
  let report = null, selected = -1, digest = null, sourceKind = null, trend = null, metricFocus = null, planDelta = null;
  // User choice is authoritative: stale local file completions cannot clear
  // or silently replace a newer HUMAN planning workspace.
  let lastHumanUndo = null;
  let readGeneration = 0;
  const beginRead = () => ++readGeneration;
  const invalidateReads = () => { readGeneration++; };
  const currentRead = generation => generation === readGeneration;
  const exactKeys = (x, keys) => !!x && Object.getPrototypeOf(x) === Object.prototype &&
    Object.keys(x).length === keys.length && keys.every(k => Object.hasOwn(x, k));
  const fail = () => { throw new Error("Source structure or values do not match canonical lab CLI output."); };
  const finite = n => typeof n === "number" && Number.isFinite(n);
  const safeLabel = x => typeof x === "string" && x.length > 0 && x.length <= 256 &&
    x === x.trim() && /^[\x20-\x7e]+$/.test(x);
  const duplicates = list => new Set(list).size !== list.length;
  const boolFalseAuthority = doc => AUTH.every(key => doc[key] === false);
  const ensure = condition => { if (!condition) fail(); };
  // Strict JSON admission: JSON.parse silently accepts duplicate object keys.
  // Decode each key before checking duplicates, including escaped spellings.
  function parseStrictJson(raw, maxBytes = 524288) {
    ensure(typeof raw === "string" && new TextEncoder().encode(raw).length <= maxBytes);
    let pos = 0;
    const ws = () => { while (pos < raw.length && [0x20,0x09,0x0a,0x0d].includes(raw.charCodeAt(pos))) pos++; };
    const string = () => {
      const start = pos;
      ensure(raw[pos] === '"');
      pos++;
      while (pos < raw.length) {
        const ch = raw[pos];
        if (ch === '"') { pos++; return JSON.parse(raw.slice(start, pos)); }
        if (ch === "\\") {
          pos++;
          ensure(pos < raw.length);
          if (raw[pos] === "u") {
            ensure(/^[0-9a-fA-F]{4}$/.test(raw.slice(pos + 1, pos + 5)));
            pos += 5;
          } else {
            ensure('"\\/bfnrt'.includes(raw[pos]));
            pos++;
          }
        } else {
          ensure(raw.charCodeAt(pos) >= 0x20);
          pos++;
        }
      }
      fail();
    };
    const value = () => {
      ws();
      const ch = raw[pos];
      if (ch === '"') return string();
      if (ch === '{') {
        pos++;
        ws();
        const out = {}, keys = new Set();
        if (raw[pos] === '}') { pos++; return out; }
        while (true) {
          ws();
          const key = string();
          ensure(!keys.has(key));
          keys.add(key);
          ws();
          ensure(raw[pos++] === ':');
          const item = value();
          Object.defineProperty(out, key, {value:item, enumerable:true, writable:true, configurable:true});
          ws();
          if (raw[pos] === '}') { pos++; return out; }
          ensure(raw[pos++] === ',');
        }
      }
      if (ch === '[') {
        pos++;
        ws();
        const out = [];
        if (raw[pos] === ']') { pos++; return out; }
        while (true) {
          out.push(value());
          ws();
          if (raw[pos] === ']') { pos++; return out; }
          ensure(raw[pos++] === ',');
        }
      }
      for (const [literal, result] of [['true',true],['false',false],['null',null]]) {
        if (raw.startsWith(literal, pos)) { pos += literal.length; return result; }
      }
      const match = raw.slice(pos).match(/^-?(?:0|[1-9][0-9]*)(?:[.][0-9]+)?(?:[eE][+-]?[0-9]+)?/);
      ensure(match);
      pos += match[0].length;
      const number = Number(match[0]);
      ensure(Number.isFinite(number));
      return number;
    };
    const result = value();
    ws();
    ensure(pos === raw.length);
    return result;
  }
  const closeNumber = (a, b) => Math.abs(a - b) <= 1e-8 * Math.max(1, Math.abs(a), Math.abs(b));

  function parseChange(change) {
    ensure(exactKeys(change, CHANGE_KEYS) && METRICS.includes(change.name));
    const {name, baseline, candidate, delta, regression} = change;
    ensure(finite(baseline) && finite(candidate) && finite(delta) &&
      baseline >= 0 && candidate >= 0 && typeof regression === "boolean");
    if (COUNTERS.has(name)) {
      ensure(Number.isSafeInteger(baseline) && Number.isSafeInteger(candidate) &&
        Number.isSafeInteger(delta) && delta === candidate - baseline &&
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
      return {sourceId: cohort ? input.scenario_id : null, status: "HOLD", changes: [], regressions: [], stage: "todo", due: "", route: "unassigned"};
    }
    ensure(input.changes.length === METRICS.length);
    const changes = input.changes.map(parseChange);
    ensure(!duplicates(changes.map(x => x.name)));
    const derived = changes.filter(x => x.regression).map(x => x.name);
    ensure(derived.length === input.regressions.length &&
      derived.every(name => input.regressions.includes(name)));
    ensure(input.status === (derived.length ? "HOLD" : "REVIEW_ONLY"));
    return {sourceId: cohort ? input.scenario_id : null, status: input.status,
      changes, regressions: derived, stage: "todo", due: "", route: "unassigned"};
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
      ensure(cases.every(c => c.changes.length === METRICS.length));
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

  function nextHumanAction(c) {
    if (c.regressions.includes("scope_violations") || c.regressions.includes("policy_violations"))
      return "Escalate policy drift to an independent scope reviewer. Do not expand or execute assessment activity.";
    if (c.regressions.includes("missed_findings"))
      return "Reconcile missed planted lab findings against original ground truth with the source owner.";
    if (c.regressions.includes("invalid_findings"))
      return "Examine evidence quality and false-positive classification in the isolated lab records.";
    if (c.regressions.includes("valid_findings"))
      return "Review detector/model version changes and loss of previously valid lab findings.";
    if (c.regressions.includes("coverage_assessed"))
      return "Review lab scenario coverage mapping and omitted assessment surfaces.";
    if (c.regressions.some(x => ["evidence_quality","reproducibility","remediation_quality","retest_correctness"].includes(x)))
      return "Request independent rubric/evidence review and a proposed remediation plan.";
    if (c.regressions.length)
      return "Compare source metric details and prepare an independent human follow-up.";
    return "No scored regression reported. Review informational performance/cost changes if relevant.";
  }
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
  function filteredQueueRows() {
    if (!report) return [];
    const filter = $("filter").value;
    const routeFilter = $("route-filter").value;
    const priorityFilter = $("priority-filter").value;
    return report.cases.map((c, i) => ({c, i}))
      .filter(({c}) => routeFilter === "all" || c.route === routeFilter)
      .filter(({c}) => priorityFilter === "all" || priority(c) === priorityFilter)
      .filter(({c}) => !metricFocus || c.regressions.includes(metricFocus))
      .filter(({c}) => filter === "all" ||
        (filter === "regressed" && c.regressions.length > 0) ||
        (filter === "open" && c.stage !== "reviewed") ||
        (filter === "waiting" && c.stage === "waiting") ||
        (filter === "reviewed" && c.stage === "reviewed"))
      .sort((a,b) => urgency(a.c) - urgency(b.c) || a.i - b.i);
  }
  function renderQueue() {
    const parent = $("cases");
    parent.replaceChildren();
    const sorted = filteredQueueRows();
    $("queue-export-summary").textContent = sorted.length
      ? "Filtered export includes " + sorted.length + " of " + report.cases.length +
        " cases. Current status, workstream and metric filters are applied; raw scenario IDs stay excluded."
      : "No cases match the current filters; filtered exports are disabled.";
    $("queue-export-csv").disabled = !sorted.length;
    $("queue-export-json").disabled = !sorted.length;
    $("queue-export-html").disabled = !sorted.length;
    $("queue-import-button").disabled = !(report && digest);
    $("print-filtered").disabled = !sorted.length;
    $("no-matches").hidden = sorted.length > 0;
    for (const {c, i} of sorted) {
      const row = child(parent, "button", "", "case" + (i === selected ? " selected" : ""));
      row.type = "button";
      row.setAttribute("aria-pressed", String(i === selected));
      const left = child(row, "span");
      child(left, "strong", label(i));
      child(left, "small", c.regressions.length + " regression(s) · " + stageText(c.stage) + " · " + c.route);
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
    $("guidance").textContent = nextHumanAction(c);
    $("route").value = c.route;
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

  function renderPrintBrief() {
    const box = $("print-brief"); box.replaceChildren();
    child(box, "h2", "All-case human follow-up brief");
    child(box, "p", "Source " + report.verdict + " | " +
      report.cases.length + " cases | " + countRegressions() +
      " metric regressions | AUTHORIZATION / CONSENT / RELEASE = FALSE", "print-note");
    const table = child(box, "table");
    const head = child(table, "thead");
    const headings = child(head, "tr");
    ["Case", "Priority", "Source", "Workstream", "Follow-up stage", "Due", "Regressed metrics"].forEach(x => child(headings,"th",x));
    const body = child(table, "tbody");
    report.cases.map((c,i) => ({c,i})).sort((a,b) =>
      urgency(a.c)-urgency(b.c) || a.i-b.i).forEach(({c,i}) => {
      const tr=child(body,"tr");
      [label(i), priority(c), c.status, c.route, stageText(c.stage),
        c.due || "-", c.regressions.join(", ") || "None"].forEach(x => child(tr,"td",x));
    });
    if (planDelta) {
      child(box, "h2", "Saved HUMAN plan comparison");
      child(box, "p", planDelta.rows.length + " changed case(s) · " +
        planDelta.stageChanges + " stage changes · " + planDelta.routeChanges +
        " workstream changes · " + planDelta.dateChanges +
        " date changes. Prior/current labels are operator supplied, not authenticated chronology.", "print-note");
      const deltaTable = child(box, "table");
      const deltaHead = child(child(deltaTable, "thead"), "tr");
      ["Case","Changed fields","Prior stage","Current stage","Prior workstream",
       "Current workstream","Prior date","Current date"].forEach(x => child(deltaHead,"th",x));
      const deltaBody = child(deltaTable, "tbody");
      if (!planDelta.rows.length) {
        const tr = child(deltaBody,"tr");
        const td = child(tr,"td","No HUMAN planning-field differences.");
        td.colSpan = 8;
      } else {
        planDelta.rows.forEach(row => {
          const tr = child(deltaBody,"tr");
          [row.case,row.changed.join("; "),row.before.stage,row.after.stage,
           row.before.route,row.after.route,row.before.due || "-",row.after.due || "-"]
            .forEach(x => child(tr,"td",x));
        });
      }
    }
    child(box, "p", "Unsigned, unverified lab review data. No targets, case identities, actual permission or grant asserted.", "print-note");
  }

  function renderFilteredPrintBrief() {
    const box = $("print-filtered-brief");
    box.replaceChildren();
    if (!report) return;
    const rows = filteredQueueRows();
    child(box, "h2", "Filtered HUMAN follow-up queue");
    const filterSummary = [
      "status: " + $("filter").selectedOptions[0].textContent,
      "workstream: " + $("route-filter").selectedOptions[0].textContent,
      "priority: " + $("priority-filter").selectedOptions[0].textContent,
      "metric: " + (metricFocus || "All metrics")
    ].join(" · ");
    const regressionFlags = rows.reduce((sum, {c}) => sum + c.regressions.length, 0);
    child(box, "p", "Source " + report.verdict + " | " + rows.length + " filtered cases of " +
      report.cases.length + " total | " + regressionFlags +
      " metric regression flags | AUTHORIZATION / CONSENT / RELEASE = FALSE", "print-note");
    child(box, "p", "Filters applied: " + filterSummary, "print-note");
    if (!rows.length) {
      child(box, "p", "No cases match the current filters.", "print-note");
      return;
    }
    const table = child(box, "table");
    const head = child(table, "thead");
    const headings = child(head, "tr");
    ["Case", "Priority", "Source", "Workstream", "Follow-up stage", "Due", "Regressed metrics"]
      .forEach(x => child(headings, "th", x));
    const body = child(table, "tbody");
    rows.forEach(({c, i}) => {
      const tr = child(body, "tr");
      [label(i), priority(c), c.status, c.route, stageText(c.stage),
        c.due || "-", c.regressions.join(", ") || "None"].forEach(x => child(tr, "td", x));
      const evidenceRow = child(body, "tr", undefined, "print-evidence-row");
      const evidenceCell = child(evidenceRow, "td");
      evidenceCell.colSpan = 7;
      const evidence = c.changes.filter(m => c.regressions.includes(m.name)).map(m =>
        nice(m.name) + ": baseline " + fmt(m.baseline) + " → candidate " + fmt(m.candidate) +
        " (Δ " + (m.delta >= 0 ? "+" : "") + fmt(m.delta) + ")"
      );
      child(evidenceCell, "strong", "Metric evidence: ");
      child(evidenceCell, "span", evidence.join(" · ") || "No source-flagged metric regressions.");
      child(evidenceCell, "br");
      child(evidenceCell, "strong", "Suggested next HUMAN action: ");
      child(evidenceCell, "span", nextHumanAction(c));
    });
    child(box, "p", "Only cases matching the filters above are included. Numeric values are source-reported, unverified observations. This is an unsigned HUMAN planning view, not evidence of remediation, identity, permission or release.", "print-note");
  }

  // Match source scenario identities internally; never export them.
  function compareHistorical(candidate) {
    ensure(report && report.kind === "cohort" && candidate.kind === "cohort" &&
      report.cases.length > 0 && candidate.cases.length === report.cases.length);
    const next = new Map(candidate.cases.map(c => [c.sourceId,c]));
    ensure(next.size === report.cases.length);
    const rows = report.cases.map((before,index) => {
      const after = next.get(before.sourceId);
      ensure(after && before.changes.length === METRICS.length &&
        after.changes.length === METRICS.length);
      const prev = new Map(before.changes.map(m => [m.name,m]));
      for (const m of after.changes) ensure(prev.has(m.name) &&
        prev.get(m.name).baseline === m.baseline);
      const prior = new Set(before.regressions);
      const recent = new Set(after.regressions);
      const introduced = after.regressions.filter(x => !prior.has(x));
      const cleared = before.regressions.filter(x => !recent.has(x));
      const intensified = after.changes.filter(m =>
        prior.has(m.name) && m.regression &&
        ((HIGHER.has(m.name) && m.candidate < prev.get(m.name).candidate) ||
         (LOWER.has(m.name) && m.candidate > prev.get(m.name).candidate))
      ).map(m=>m.name);
      return {index,introduced,cleared,intensified,
        oldStatus:before.status,newStatus:after.status};
    });
    return {rows,status:candidate.verdict};
  }
  function renderHistorical() {
    const parent = $("trend-rows"); parent.replaceChildren();
    $("trend-results").hidden = !trend;
    if (!trend) return;
    const sum = key => trend.rows.reduce((n,x) => n+x[key].length,0);
    $("trend-new").textContent = sum("introduced")+" newly reported regressions";
    $("trend-cleared").textContent = sum("cleared")+" no longer flagged (unverified)";
    $("trend-intensified").textContent = sum("intensified")+" further worsened metrics";
    for (const row of trend.rows) {
      const tr=child(parent,"tr");
      [label(row.index),row.introduced.join(", ") || "None",
       row.cleared.join(", ") || "None",
       row.intensified.join(", ") || "None"].forEach(value=>child(tr,"td",value));
    }
  }
  function clearHistorical() {
    trend = null; $("trend-file").value = "";
    $("trend-results").hidden = true; $("trend-rows").replaceChildren();
    $("trend-status").textContent = "No follow-up report compared.";
  }

  async function loadHistorical(file) {
    const generation = beginRead();
    try {
      ensure(report && report.kind === "cohort" && file &&
        file.size > 0 && file.size <= 524288 &&
        file.name.toLowerCase().endsWith(".json"));
      const raw = await file.text();
      ensure(currentRead(generation));
      ensure(new TextEncoder().encode(raw).length <= 524288);
      const next = readReport(parseStrictJson(raw));
      const nextTrend = compareHistorical(next);
      ensure(currentRead(generation));
      trend = nextTrend;
      $("trend-status").textContent = "Informational comparison only. Original source " +
        report.verdict + ", follow-up source " + next.verdict +
        ". Neither verdict permits assessment activity.";
      renderHistorical();
    } catch (_) {
      if (currentRead(generation)) $("trend-status").textContent =
        "HOLD: source scenario set or metric baseline mismatch, or unsupported local report. Previous historical comparison preserved.";
    }
  }
  $("trend-file").addEventListener("change", e => {
    if(e.target.files[0]) loadHistorical(e.target.files[0]);
  });
  $("trend-clear").addEventListener("click", () => {invalidateReads();clearHistorical();});
  $("trend-csv").addEventListener("click", () => {
    if (!trend) return;
    const cols=["case","newly_reported_regressions","no_longer_flagged_unverified",
      "further_worsened_metrics","prior_status","follow_up_status",
      "authorized","consent_verified","dispatch_allowed","release_allowed"];
    const rows=[cols.map(csvCell).join(",")];
    trend.rows.forEach(r => {
      const cells=[label(r.index),r.introduced.join(";"),r.cleared.join(";"),
        r.intensified.join(";"),r.oldStatus,r.newStatus,"false","false","false","false"];
      rows.push(cells.map(csvCell).join(","));
    });
    download("lightup-lab-report-change-review.csv",
      rows.join("\r\n")+"\r\n","text/csv;charset=utf-8");
  });

  function renderLandscape() {
    const parent=$("metric-bars");
    parent.replaceChildren();
    const counts=METRICS.map(name=>({
      name,count:report.cases.filter(c=>c.regressions.includes(name)).length
    })).filter(x=>x.count>0).sort((a,b)=>b.count-a.count ||
      a.name.localeCompare(b.name));
    if (!counts.length) {
      child(parent,"p","No source-reported metric regression in this accepted report.","muted-copy");
    } else {
      counts.forEach(({name,count})=>{
        const row=child(parent,"button",undefined,
          "metric-bar"+(metricFocus===name?" active":""));
        row.type="button";
        row.setAttribute("aria-pressed",String(metricFocus===name));
        row.title="Filter to cases with "+nice(name)+" regression";
        child(row,"span",nice(name));
        const track=child(row,"div",undefined,"track");
        const bar=child(track,"i");
        bar.style.width=(100*count/report.cases.length).toFixed(1)+"%";
        child(row,"b",count);
        row.addEventListener("click",()=>{
          metricFocus=metricFocus===name?null:name;
          render();
        });
      });
    }
    function sumCost(name) {
      return report.cases.reduce((result,c)=>{
        const m=c.changes.find(x=>x.name===name);
        return m ? {baseline:result.baseline+m.baseline,
          candidate:result.candidate+m.candidate} : result;
      },{baseline:0,candidate:0});
    }
    const runtime=sumCost("runtime_seconds"), cost=sumCost("compute_cost_usd");
    $("runtime-summary").textContent=fmt(runtime.baseline)+" → "+fmt(runtime.candidate);
    $("cost-summary").textContent=fmt(cost.baseline)+" → "+fmt(cost.candidate);
    $("metric-focus").textContent=metricFocus ?
      "Filtering only "+nice(metricFocus)+" regressions in the local case queue. Exports retain all cases." :
      "Showing all regression categories. Costs and times are untrusted lab report totals.";
  }
  $("metric-reset").addEventListener("click",()=>{
    metricFocus=null;
    if(report) render();
  });
  // An in-memory single-step HUMAN-only undo never mutates original metrics
  // and can never restore state across changed original source bytes.
  function rememberHumanEdit() {
    if (!report || !digest) return;
    lastHumanUndo = {source:digest,rows:report.cases.map(c=>({
      stage:c.stage,route:c.route,due:c.due||""
    }))};
  }
  function undoHumanEdit() {
    if (!report || !lastHumanUndo || lastHumanUndo.source!==digest ||
        lastHumanUndo.rows.length!==report.cases.length) return;
    invalidateReads();
    lastHumanUndo.rows.forEach((row,i)=>{
      report.cases[i].stage=row.stage;
      report.cases[i].route=row.route;
      report.cases[i].due=row.due;
    });
    lastHumanUndo=null;
    render();
    alert("The last local HUMAN planning edit was reversed. Source findings, report status and authorization remain unchanged.", "good");
  }
  function render() {
    renderOverview();renderLandscape();renderQueue();renderDetails();
    renderPrintBrief();renderFilteredPrintBrief();
    $("undo-human").disabled=!(report&&lastHumanUndo&&lastHumanUndo.source===digest);
  }
  function reset(invalidate = true) {
    if (invalidate) invalidateReads();
    report = null; selected = -1; digest = null; sourceKind = null;
    lastHumanUndo = null;
    clearHistorical(); clearPlanComparison(); metricFocus = null;
    $("file").value = ""; $("board").hidden = true; $("filter").value = "all"; $("route-filter").value = "all";
    $("cases").replaceChildren(); $("metrics").replaceChildren();
    alert("Local workspace cleared. No browser storage was used.");
  }
  // file:// contexts may lack Web Crypto. This fallback hashes only locally
  // supplied bytes and is not a signature, trusted source identity or authorization.
  function portableSHA256(bytes) {
    const data = Array.from(bytes), bitLength = data.length * 8;
    data.push(0x80);
    while (data.length % 64 !== 56) data.push(0);
    data.push(0, 0, 0, 0, (bitLength >>> 24) & 255, (bitLength >>> 16) & 255,
      (bitLength >>> 8) & 255, bitLength & 255);
    const K = [
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ];
    const H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    const rotate = (x, n) => (x >>> n) | (x << (32 - n));
    for (let offset = 0; offset < data.length; offset += 64) {
      const w = new Array(64);
      for (let i = 0; i < 16; i++) {
        const p = offset + i * 4;
        w[i] = ((data[p] << 24) | (data[p + 1] << 16) | (data[p + 2] << 8) | data[p + 3]) >>> 0;
      }
      for (let i = 16; i < 64; i++) {
        const x = w[i - 15], y = w[i - 2];
        w[i] = (w[i - 16] + (rotate(x, 7) ^ rotate(x, 18) ^ (x >>> 3)) +
          w[i - 7] + (rotate(y, 17) ^ rotate(y, 19) ^ (y >>> 10))) >>> 0;
      }
      let [a,b,c,d,e,f,g,h] = H;
      for (let i = 0; i < 64; i++) {
        const t1 = (h + (rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25)) +
          ((e & f) ^ (~e & g)) + K[i] + w[i]) >>> 0;
        const t2 = ((rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22)) +
          ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
        h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
      }
      H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
      H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
    }
    return H.map(word => word.toString(16).padStart(8, "0")).join("");
  }
  async function hashBytes(bytes) {
    if (globalThis.crypto && globalThis.crypto.subtle) {
      try {
        const hash = await globalThis.crypto.subtle.digest("SHA-256", bytes);
        return Array.from(new Uint8Array(hash), n => n.toString(16).padStart(2, "0")).join("");
      } catch (_) { /* Use deterministic local fallback below. */ }
    }
    return portableSHA256(bytes);
  }

  async function load(file) {
    const generation = beginRead();
    try {
      ensure(file && file.size > 0 && file.size <= 524288 && file.name.toLowerCase().endsWith(".json"));
      const raw = await file.text();
      ensure(currentRead(generation));
      ensure(new TextEncoder().encode(raw).length <= 524288);
      const candidate = readReport(parseStrictJson(raw));
      // The digest binds HUMAN planning to exact local bytes, not source identity.
      const nextDigest = await hashBytes(new TextEncoder().encode(raw));
      ensure(currentRead(generation) && /^[a-f0-9]{64}$/.test(nextDigest));
      // Commit only after all original source validation and local hashing succeeds.
      reset(false);
      report = candidate; digest = nextDigest; sourceKind = candidate.kind;
      selected = candidate.cases.length ? 0 : -1;
      alert(candidate.cases.length ? "Untrusted canonical-shape report loaded locally. Human review only." :
        "Source says HOLD with no comparable cases. No partial details accepted.", candidate.cases.length ? "good" : "error");
      render();
    } catch (_) {
      if (currentRead(generation)) alert(
        "HOLD · Unsupported, oversized, inconsistent or malformed local report. Previous HUMAN workspace preserved.", "error");
    }
  }
  function filteredQueueExport() {
    const rows = filteredQueueRows();
    return {
      schema: "lightup-offline-human-triage-filtered-v1",
      source_sha256: digest,
      source_kind: sourceKind,
      source_status: report.verdict,
      filters: {
        case_status: $("filter").value,
        workstream: $("route-filter").value,
        priority: $("priority-filter").value,
        metric: metricFocus || "all"
      },
      authorized: false,
      consent_verified: false,
      dispatch_allowed: false,
      release_allowed: false,
      release_approved: false,
      scan_allowed: false,
      review_only: true,
      case_count: rows.length,
      cases: rows.map(({c,i}) => ({
        case: label(i),
        priority: priority(c),
        source_status: c.status,
        metric_regressions: c.regressions.slice().sort(),
        metric_changes: c.changes.filter(m => metricFocus ? m.name === metricFocus : m.regression)
          .map(m => ({metric:m.name,baseline:m.baseline,candidate:m.candidate,
            delta:m.delta,regression:m.regression})),
        human_stage: c.stage,
        follow_up_date: c.due || null,
        routing_group: c.route,
        suggested_human_action: nextHumanAction(c)
      })),
      warning: "FILTERED UNSIGNED OFFLINE HUMAN PLANNING ONLY. No source identity, remediation, consent or execution authority is asserted."
    };
  }
  function exportFilteredQueueJson() {
    if (!report) return;
    const output = filteredQueueExport();
    if (!output.case_count) {
      $("queue-export-summary").textContent = "Nothing exported: no cases match the current filters.";
      return;
    }
    download("lightup-human-follow-up-filtered-queue.json",
      JSON.stringify(output, null, 2) + "\n", "application/json");
    $("queue-export-summary").textContent = "Exported " + output.case_count +
      " filtered case(s) as anonymous JSON. No raw scenario IDs or source evidence included.";
  }
  async function importFilteredQueue(file) {
    const generation = beginRead();
    if (!report || !digest) {
      alert("HOLD · Load the exact original report first; filtered planning is bound to its local source-byte digest.", "error");
      return;
    }
    try {
      ensure(file && file.name.toLowerCase().endsWith(".json") &&
        file.size > 0 && file.size <= 131072);
      const raw = await file.text();
      ensure(currentRead(generation));
      const saved = parseStrictJson(raw, 131072);
      ensure(exactKeys(saved, ["schema","source_sha256","source_kind","source_status","filters",
        "authorized","consent_verified","dispatch_allowed","release_allowed","release_approved",
        "scan_allowed","review_only","case_count","cases","warning"]));
      ensure(saved.schema === "lightup-offline-human-triage-filtered-v1" &&
        saved.source_sha256 === digest && saved.source_kind === sourceKind &&
        saved.source_status === report.verdict && saved.release_approved === false &&
        saved.scan_allowed === false && saved.review_only === true &&
        boolFalseAuthority(saved) &&
        saved.warning === "FILTERED UNSIGNED OFFLINE HUMAN PLANNING ONLY. No source identity, remediation, consent or execution authority is asserted." &&
        exactKeys(saved.filters, ["case_status","workstream","priority","metric"]));
      const filters = saved.filters;
      ensure(["all","regressed","open","waiting","reviewed"].includes(filters.case_status) &&
        (filters.workstream === "all" || ROUTES.has(filters.workstream)) &&
        ["all","Critical drift","High drift","Review drift","No regression"].includes(filters.priority) &&
        (filters.metric === "all" || METRICS.includes(filters.metric)));
      ensure(Array.isArray(saved.cases) && Number.isInteger(saved.case_count) &&
        saved.case_count === saved.cases.length && saved.cases.length > 0 &&
        saved.cases.length <= report.cases.length);
      const updates = [];
      const rowKeys = ["case","priority","source_status","metric_regressions","metric_changes",
        "human_stage","follow_up_date","routing_group","suggested_human_action"];
      const metricKeys = ["metric","baseline","candidate","delta","regression"];
      const seenIndices = new Set();
      let previousUrgency = -1, previousIndex = -1;
      for (let position = 0; position < saved.cases.length; position++) {
        const row = saved.cases[position];
        ensure(exactKeys(row, rowKeys));
        const match = typeof row.case === "string" ? row.case.match(/^Case ([0-9]{2,})$/) : null;
        ensure(match);
        const index = Number(match[1]) - 1;
        ensure(Number.isSafeInteger(index) && index >= 0 && index < report.cases.length &&
          !seenIndices.has(index) && row.case === label(index));
        seenIndices.add(index);
        const c = report.cases[index];
        ensure(row.priority === priority(c) && row.source_status === c.status &&
          Array.isArray(row.metric_regressions) &&
          JSON.stringify(row.metric_regressions) === JSON.stringify(c.regressions.slice().sort()) &&
          Array.isArray(row.metric_changes) &&
          row.metric_changes.every(metric => exactKeys(metric, metricKeys)) &&
          STAGES.has(row.human_stage) && ROUTES.has(row.routing_group));
        ensure((filters.case_status !== "regressed" || c.regressions.length > 0) &&
          (filters.case_status !== "open" || row.human_stage !== "reviewed") &&
          (filters.case_status !== "waiting" || row.human_stage === "waiting") &&
          (filters.case_status !== "reviewed" || row.human_stage === "reviewed") &&
          (filters.workstream === "all" || row.routing_group === filters.workstream) &&
          (filters.priority === "all" || row.priority === filters.priority) &&
          (filters.metric === "all" || c.regressions.includes(filters.metric)));
        const currentUrgency = urgency(c);
        ensure(currentUrgency > previousUrgency ||
          (currentUrgency === previousUrgency && index > previousIndex));
        previousUrgency = currentUrgency;
        previousIndex = index;
        const expectedChanges = c.changes.filter(m=>filters.metric !== "all" ? m.name === filters.metric : m.regression)
          .map(m=>({metric:m.name,baseline:m.baseline,candidate:m.candidate,delta:m.delta,regression:m.regression}));
        ensure(JSON.stringify(row.metric_changes) === JSON.stringify(expectedChanges) &&
          row.suggested_human_action === nextHumanAction(c));
        const due = row.follow_up_date;
        ensure(due === null || (typeof due === "string" &&
          /^\d{4}-\d{2}-\d{2}$/.test(due) &&
          !Number.isNaN(Date.parse(due + "T00:00:00Z")) &&
          new Date(due + "T00:00:00Z").toISOString().startsWith(due)));
        updates.push({index,stage:row.human_stage,route:row.routing_group,due:due||""});
      }
      ensure(currentRead(generation));
      invalidateReads();
      rememberHumanEdit();
      updates.forEach(row=>Object.assign(report.cases[row.index],
        {stage:row.stage,route:row.route,due:row.due}));
      render();
      $("queue-export-summary").textContent = "Imported source-bound HUMAN planning for " +
        updates.length + " filtered case(s); other cases and original findings were unchanged. No authorization imported.";
      alert("Filtered HUMAN planning restored for the exact same local source bytes. Original metrics, source verdict and authority remain unchanged.", "good");
    } catch (_) {
      if (currentRead(generation)) {
        $("queue-export-summary").textContent = "HOLD: filtered planning was not imported; the current HUMAN workspace was preserved.";
        alert("HOLD · Filtered planning is malformed, stale, incomplete, changed or not bound to this exact original report. Previous HUMAN workspace preserved.", "error");
      }
    }
  }

  function exportFilteredQueueHtml() {
    if (!report) return;
    const output = filteredQueueExport();
    if (!output.case_count) {
      $("queue-export-summary").textContent = "Nothing exported: no cases match the current filters.";
      return;
    }
    const escapeHtml = value => String(value).replace(/[&<>"']/g, char => ({
      "&":"&amp;", "<":"&lt;", ">":"&gt;", "\"":"&quot;", "'":"&#39;"
    })[char]);
    const e = escapeHtml;
    const filterSummary = [
      "status: " + $("filter").selectedOptions[0].textContent,
      "workstream: " + $("route-filter").selectedOptions[0].textContent,
      "priority: " + $("priority-filter").selectedOptions[0].textContent,
      "metric: " + (metricFocus || "All metrics")
    ].join(" · ");
    const bodyRows = output.cases.map(item => {
      const movements = item.metric_changes.map(metric =>
        e(metric.metric) + ": " + e(fmt(metric.baseline)) + " → " + e(fmt(metric.candidate)) +
        " (Δ " + (metric.delta >= 0 ? "+" : "") + e(fmt(metric.delta)) + ")"
      ).join("<br>") || "No selected metric changes.";
      return "<tr>" + [
        item.case, item.priority, item.source_status, item.routing_group, item.human_stage,
        item.follow_up_date || "—", item.metric_regressions.join(", ") || "None",
        movements, item.suggested_human_action
      ].map((value, index) => "<td>" + (index === 7 ? value : e(value)) + "</td>").join("") + "</tr>";
    }).join("\n");
    const html = [
      "<!doctype html>",
      '<html lang="en"><head><meta charset="utf-8">',
      '<meta name="viewport" content="width=device-width, initial-scale=1">',
      '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'none\'; style-src \'none\'; img-src \'none\'; connect-src \'none\'; object-src \'none\'; base-uri \'none\'; form-action \'none\'">',
      "<title>LightUp filtered HUMAN follow-up queue</title></head><body><main>",
      "<h1>Filtered HUMAN follow-up queue</h1>",
      "<p>Source status: <strong>" + e(output.source_status) + "</strong>. Included cases: " +
        e(output.case_count) + ". Source cases: " + e(report.cases.length) + ".</p>",
      "<p>Filters: " + e(filterSummary) + "</p>",
      "<p>Local source-byte SHA-256: " + e(output.source_sha256 || "unavailable") +
        ". This digest is unsigned byte binding, not source authentication.</p>",
      "<table><thead><tr><th>Case</th><th>Priority</th><th>Source status</th><th>Workstream</th>" +
        "<th>HUMAN stage</th><th>Follow-up date</th><th>Flagged metrics</th><th>Selected metric evidence</th>" +
        "<th>Suggested HUMAN action</th></tr></thead><tbody>",
      bodyRows,
      "</tbody></table>",
      "<h2>Review boundary</h2><p>Private offline HUMAN planning only. Numeric values are source-reported and unverified. " +
        "Authorization, consent, dispatch, release approval and scan permission are all false. " +
        "This handoff does not establish source authenticity, reviewer identity, remediation or authorization.</p>",
      "<p>Only cases matching the filters above are included. No raw scenario IDs, targets, source paths, notes or client/operator identifiers are included.</p>",
      "</main></body></html>",""
    ].join("\n");
    download("lightup-human-follow-up-filtered-queue.html", html, "text/html;charset=utf-8");
    $("queue-export-summary").textContent = "Exported " + output.case_count +
      " filtered case(s) as a scriptless standalone HTML handoff.";
  }
  function exportFilteredQueueCsv() {
    if (!report) return;
    const output = filteredQueueExport();
    if (!output.case_count) {
      $("queue-export-summary").textContent = "Nothing exported: no cases match the current filters.";
      return;
    }
    const columns = ["case","priority","source_status","metric_regressions","metric_changes","human_stage",
      "follow_up_date","routing_group","suggested_human_action","source_sha256","source_kind",
      "overall_source_status","filter_case_status","filter_workstream","filter_priority","filter_metric",
      "authorized","consent_verified","dispatch_allowed","release_allowed","release_approved","scan_allowed"];
    const lines = [columns.map(csvCell).join(",")];
    for (const item of output.cases) {
      const row = {...item,
        metric_regressions: item.metric_regressions.join(";"),
        metric_changes: JSON.stringify(item.metric_changes),
        follow_up_date: item.follow_up_date || "",
        source_sha256: output.source_sha256 || "",
        source_kind: output.source_kind,
        overall_source_status: output.source_status,
        filter_case_status: output.filters.case_status,
        filter_workstream: output.filters.workstream,
        filter_priority: output.filters.priority,
        filter_metric: output.filters.metric,
        authorized: false,
        consent_verified: false,
        dispatch_allowed: false,
        release_allowed: false,
        release_approved: false,
        scan_allowed: false
      };
      lines.push(columns.map(key => csvCell(row[key])).join(","));
    }
    download("lightup-human-follow-up-filtered-queue.csv",
      lines.join("\r\n") + "\r\n", "text/csv;charset=utf-8");
    $("queue-export-summary").textContent = "Exported " + output.case_count +
      " filtered case(s) as anonymous CSV. Formula-leading cells are escaped; authority flags remain false.";
  }

  function reviewExport() {
    const rows = report.cases.map((c,i) => ({
      case: label(i), priority: priority(c), source_status: c.status,
      metric_regressions: c.regressions.slice().sort(), human_stage: c.stage,
      follow_up_date: c.due || null, routing_group: c.route
    }));
    return {schema:"lightup-offline-human-triage-v2", source_sha256: digest,
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

  // Restore only human planning state, never underlying metrics, source identity,
  // release verdict or authority. A byte-identical original source is required.
  async function restoreReview(file) {
    const generation = beginRead();
    if (!report || !digest) {
      alert("HOLD · Load the exact original lab report first; a local source-byte digest is required to restore the private review.", "error");
      return;
    }
    try {
      ensure(file && file.name.toLowerCase().endsWith(".json") &&
        file.size > 0 && file.size <= 131072);
      const raw = await file.text();
      ensure(currentRead(generation));
      const saved = parseStrictJson(raw, 131072);
      ensure(exactKeys(saved, ["schema","source_sha256","source_kind","source_status",
        ...AUTH,"release_approved","scan_allowed","review_only","cases","warning"]));
      const v2 = saved.schema === "lightup-offline-human-triage-v2";
      ensure((v2 || saved.schema === "lightup-offline-human-triage-v1") &&
        saved.source_sha256 === digest && saved.source_kind === sourceKind &&
        saved.source_status === report.verdict && saved.release_approved === false &&
        saved.scan_allowed === false && saved.review_only === true &&
        boolFalseAuthority(saved) && Array.isArray(saved.cases) &&
        saved.cases.length === report.cases.length);
      const expected = reviewExport().cases;
      const updates = [];
      for (let i = 0; i < expected.length; i++) {
        const row = saved.cases[i], current = expected[i];
        ensure(exactKeys(row, ["case","priority","source_status",
          "metric_regressions","human_stage","follow_up_date",
          ...(v2 ? ["routing_group"] : [])]));
        ensure(!v2 || ROUTES.has(row.routing_group));
        ensure(row.case === current.case && row.priority === current.priority &&
          row.source_status === current.source_status &&
          Array.isArray(row.metric_regressions) &&
          row.metric_regressions.length === current.metric_regressions.length &&
          row.metric_regressions.every((name,j) => name === current.metric_regressions[j]) &&
          STAGES.has(row.human_stage));
        const due = row.follow_up_date;
        ensure(due === null || (typeof due === "string" &&
          /^\d{4}-\d{2}-\d{2}$/.test(due) &&
          !Number.isNaN(Date.parse(due + "T00:00:00Z")) &&
          new Date(due + "T00:00:00Z").toISOString().startsWith(due)));
        updates.push({stage: row.human_stage, due: due || "", route: v2 ? row.routing_group : "unassigned"});
      }
      ensure(currentRead(generation));
      rememberHumanEdit();
      updates.forEach((step,i) => Object.assign(report.cases[i], step));
      alert("Saved human follow-up restored for the exact same local report. No approval imported.", "good");
      render();
    } catch (_) {
      if(currentRead(generation))alert("HOLD · Saved review does not match the source bytes or canonical planning schema. No changes applied.", "error");
    } finally {
      $("restore-file").value = "";
    }
  }
  // A saved plan is admitted only against the exact currently loaded source.
  // Its HUMAN labels remain proposals; neither plan is merged into live state.
  function readSavedPlan(raw) {
    ensure(report && digest && typeof raw === "string");
    const saved = parseStrictJson(raw, 131072);
    ensure(exactKeys(saved, ["schema","source_sha256","source_kind","source_status",
      ...AUTH,"release_approved","scan_allowed","review_only","cases","warning"]));
    const v2 = saved.schema === "lightup-offline-human-triage-v2";
    ensure((v2 || saved.schema === "lightup-offline-human-triage-v1") &&
      saved.source_sha256 === digest && saved.source_kind === sourceKind &&
      saved.source_status === report.verdict && saved.release_approved === false &&
      saved.scan_allowed === false && saved.review_only === true &&
      boolFalseAuthority(saved) && Array.isArray(saved.cases) &&
      saved.cases.length === report.cases.length);
    const cases = saved.cases.map((row,i) => {
      const current = report.cases[i];
      ensure(exactKeys(row, ["case","priority","source_status","metric_regressions",
        "human_stage","follow_up_date", ...(v2 ? ["routing_group"] : [])]));
      ensure(row.case === label(i) && row.priority === priority(current) &&
        row.source_status === current.status && Array.isArray(row.metric_regressions) &&
        row.metric_regressions.length === current.regressions.length &&
        row.metric_regressions.every((name,j) => name === current.regressions.slice().sort()[j]) &&
        STAGES.has(row.human_stage) && (!v2 || ROUTES.has(row.routing_group)));
      const due = row.follow_up_date;
      ensure(due === null || (typeof due === "string" &&
        /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(due) &&
        !Number.isNaN(Date.parse(due + "T00:00:00Z")) &&
        new Date(due + "T00:00:00Z").toISOString().startsWith(due)));
      return {case:row.case, priority:row.priority, source_status:row.source_status,
        metric_regressions:row.metric_regressions.slice(),
        stage:row.human_stage, route:v2 ? row.routing_group : "unassigned", due:due || ""};
    });
    return cases;
  }
  function renderPlanComparison() {
    const box = $("plan-results"), body = $("plan-rows");
    body.replaceChildren();
    box.hidden = !planDelta;
    if (!planDelta) { if (report) renderPrintBrief(); return; }
    const {rows, stageChanges, routeChanges, dateChanges} = planDelta;
    $("plan-changed").textContent = rows.length + " changed case(s)";
    $("plan-stage-changes").textContent = stageChanges + " stage change(s)";
    $("plan-route-changes").textContent = routeChanges + " workstream change(s)";
    $("plan-date-changes").textContent = dateChanges + " date change(s)";
    rows.forEach(row => {
      const tr = child(body,"tr");
      [row.case,row.changed.join("; "),row.before.stage,row.after.stage,
       row.before.route,row.after.route,row.before.due || "-",row.after.due || "-"]
        .forEach(value => child(tr,"td",value));
    });
    if (!rows.length) {
      const tr = child(body,"tr");
      const td = child(tr,"td","No HUMAN planning-field changes between these snapshots.");
      td.colSpan = 8;
    }
    if (report) renderPrintBrief();
  }
  async function compareSavedPlans() {
    const generation = beginRead();
    try {
      const beforeFile = $("plan-before-file").files[0];
      const afterFile = $("plan-after-file").files[0];
      ensure(report && digest && beforeFile && afterFile &&
        beforeFile.name.toLowerCase().endsWith(".json") &&
        afterFile.name.toLowerCase().endsWith(".json") &&
        beforeFile.size > 0 && beforeFile.size <= 131072 &&
        afterFile.size > 0 && afterFile.size <= 131072);
      const [beforeRaw, afterRaw] = await Promise.all([beforeFile.text(),afterFile.text()]);
      ensure(currentRead(generation));
      const before = readSavedPlan(beforeRaw), after = readSavedPlan(afterRaw);
      ensure(before.length === after.length && before.length === report.cases.length);
      const rows = [], fields = ["stage","route","due"];
      let stageChanges = 0, routeChanges = 0, dateChanges = 0;
      for (let i=0; i<before.length; i++) {
        const left = before[i], right = after[i];
        ensure(left.case === right.case && left.priority === right.priority &&
          left.source_status === right.source_status &&
          JSON.stringify(left.metric_regressions) === JSON.stringify(right.metric_regressions));
        const changed = fields.filter(key => left[key] !== right[key]);
        if (!changed.length) continue;
        stageChanges += Number(left.stage !== right.stage);
        routeChanges += Number(left.route !== right.route);
        dateChanges += Number(left.due !== right.due);
        rows.push({case:left.case, changed, before:left, after:right});
      }
      ensure(currentRead(generation));
      planDelta = {rows,stageChanges,routeChanges,dateChanges};
      renderPlanComparison();
      $("plan-status").textContent = rows.length ?
        "Comparison complete. Only HUMAN planning-field differences are shown; order and labels are unverified." :
        "No HUMAN planning-field differences. Both saved plans match the same current original source.";
    } catch (_) {
      if (currentRead(generation)) $("plan-status").textContent =
        "HOLD: one saved plan is malformed, has duplicate JSON keys, or is not bound to the exact source. Previous comparison preserved.";
    }
  }
  function clearPlanComparison(clearFiles = true) {
    planDelta = null;
    if (clearFiles) {
      $("plan-before-file").value = "";
      $("plan-after-file").value = "";
    }
    renderPlanComparison();
    $("plan-status").textContent = "No saved plan comparison. Load the original report and select two source-bound review exports.";
  }

  $("plan-compare").addEventListener("click", compareSavedPlans);
  $("plan-clear").addEventListener("click", () => {invalidateReads();clearPlanComparison();});
  ["plan-before-file","plan-after-file"].forEach(id => $(id).addEventListener("change", () => {
    invalidateReads();
    planDelta = null;
    renderPlanComparison();
    $("plan-status").textContent = "A selected file changed. Compare again to replace the previous result.";
  }));
  $("plan-csv").addEventListener("click", () => {
    if (!planDelta) return;
    const cols = ["case","changed_fields","prior_stage","current_stage","prior_workstream",
      "current_workstream","prior_due_date","current_due_date","authorized",
      "consent_verified","dispatch_allowed","release_allowed"];
    const rows = [cols.map(csvCell).join(",")];
    if (!planDelta.rows.length) {
      rows.push(["NO_CHANGES","","","","","","","","false","false","false","false"].map(csvCell).join(","));
    } else {
      planDelta.rows.forEach(row => rows.push([
        row.case,row.changed.join(";"),row.before.stage,row.after.stage,
        row.before.route,row.after.route,row.before.due,row.after.due,
        "false","false","false","false"
      ].map(csvCell).join(",")));
    }
    download("lightup-human-review-plan-delta.csv",rows.join("\r\n")+"\r\n","text/csv;charset=utf-8");
  });
  $("restore-button").addEventListener("click", () => {
    if (!report) return;
    $("restore-file").click();
  });
  $("restore-file").addEventListener("change", async e => {
    if (e.target.files[0]) await restoreReview(e.target.files[0]);
  });
  $("file").addEventListener("change", async e => {if(e.target.files[0]) await load(e.target.files[0]);});

  $("undo-human").addEventListener("click",undoHumanEdit);
  $("batch-triage").addEventListener("click", () => {
    if (!report) return;
    const pending = report.cases.filter(c => c.regressions.length && c.stage === "todo");
    if (!pending.length) {
      alert("No new regressed cases need triage.");
      return;
    }
    if (!window.confirm("Move " + pending.length +
       " new regressed lab cases to human investigation? This is NOT assessment authorization.")) return;
    invalidateReads();
    rememberHumanEdit();
    pending.forEach(c => {
      c.stage = "investigating";
      if (c.route === "unassigned") {
        c.route = c.regressions.some(x => ["scope_violations","policy_violations"].includes(x))
          ? "scope-review" : c.regressions.some(x =>
            ["invalid_findings","missed_findings","evidence_quality"].includes(x))
          ? "evidence-review" : "lab-runtime";
      }
    });
    alert("Queued " + pending.length +
      " human investigations. Original report HOLD and security flags are unchanged.", "good");
    render();
  });
  $("clear").addEventListener("click", reset);
  $("filter").addEventListener("change", renderQueue);
  $("route-filter").addEventListener("change", renderQueue);
  $("priority-filter").addEventListener("change", renderQueue);
  $("queue-export-csv").addEventListener("click", exportFilteredQueueCsv);
  $("queue-export-json").addEventListener("click", exportFilteredQueueJson);
  $("queue-export-html").addEventListener("click", exportFilteredQueueHtml);
  $("queue-import-button").addEventListener("click", () => {
    if (report && digest) $("queue-import-file").click();
  });
  $("queue-import-file").addEventListener("change", async e => {
    const file = e.target.files && e.target.files[0];
    e.target.value = "";
    if (file) await importFilteredQueue(file);
  });
  $("route").addEventListener("change", e => {
    if (!report || selected < 0 || !ROUTES.has(e.target.value)) return;
    invalidateReads();
    rememberHumanEdit();
    report.cases[selected].route = e.target.value;
    render();
  });
  $("stage").addEventListener("change", e => {
    if (!report || selected < 0 || !STAGES.has(e.target.value)) return;
    invalidateReads();
    rememberHumanEdit();
    report.cases[selected].stage = e.target.value; render();
  });
  $("due").addEventListener("change", e => {
    if (!report || selected < 0) return;
    const value = e.target.value;
    if (value && !/^\d{4}-\d{2}-\d{2}$/.test(value)) {e.target.value = ""; return;}
    invalidateReads();
    rememberHumanEdit();
    report.cases[selected].due = value; renderOverview();
    $("undo-human").disabled = false;
  });
  $("export-json").addEventListener("click", () => {
    if (!report) return;
    download("lightup-human-review.json", JSON.stringify(reviewExport(),null,2)+"\n", "application/json");
  });
  $("export-csv").addEventListener("click", () => {
    if (!report) return;
    const out = reviewExport();
    const cols = ["case","priority","source_status","metric_regressions","human_stage","follow_up_date","routing_group"];
    cols.push("suggested_human_action");
    const rows = [cols.map(csvCell).join(",")];
    for (let i = 0; i < out.cases.length; i++) {
      const item = {...out.cases[i], suggested_human_action: nextHumanAction(report.cases[i])};
      rows.push(cols.map(key =>
        csvCell(Array.isArray(item[key]) ? item[key].join(";") : item[key])).join(","));
    }
    download("lightup-human-follow-up.csv", rows.join("\r\n")+"\r\n", "text/csv;charset=utf-8");
  });

  function calendarDownload() {
    if (!report) return;
    const todo = report.cases.map((c,i) => ({c,i})).filter(({c}) =>
      !!c.due && c.stage !== "reviewed");
    if (!todo.length) {
      alert("No dated open human follow-ups. Add a target date to an unreviewed case first.");
      return;
    }
    const lines = ["BEGIN:VCALENDAR","VERSION:2.0",
      "PRODID:-//LightUp//Offline Lab Human Planning//EN","CALSCALE:GREGORIAN",
      "X-WR-CALNAME:LightUp Offline Lab Follow-ups"];
    const stamp = new Date().toISOString().replaceAll("-","").replaceAll(":","")
      .replace(/\.\d{3}Z$/,"Z");
    todo.forEach(({c,i}) => {
      const due = c.due.replaceAll("-","");
      lines.push("BEGIN:VTODO",
        "UID:lightup-local-" + String(i+1) + "-" + Date.now() + "@local.invalid",
        "DTSTAMP:" + stamp,
        "DUE;VALUE=DATE:" + due,
        "SUMMARY:LightUp lab follow-up " + label(i) + " / " + c.route,
        "DESCRIPTION:Unverified offline human planning only. Source " + c.status +
          ". No authorization consent grant or scan rights.",
        "STATUS:NEEDS-ACTION",
        "PRIORITY:" + (urgency(c)===0 ? "1" : urgency(c)===1 ? "4" : "7"),
        "END:VTODO");
    });
    lines.push("END:VCALENDAR");
    // No actual asset names, raw scenario IDs, personnel or source hashes in iCalendar.
    download("lightup-human-follow-ups.ics",lines.join("\r\n")+"\r\n","text/calendar;charset=utf-8");
  }
  $("calendar").addEventListener("click", calendarDownload);
  $("print").addEventListener("click", () => {
    if (!report) return;
    document.body.classList.remove("print-filtered");
    window.print();
  });
  $("print-filtered").addEventListener("click", () => {
    if (!report || !filteredQueueRows().length) return;
    renderFilteredPrintBrief();
    document.body.classList.add("print-filtered");
    const cleanup = () => {
      document.body.classList.remove("print-filtered");
      window.removeEventListener("afterprint", cleanup);
    };
    window.addEventListener("afterprint", cleanup);
    window.print();
  });
})();
