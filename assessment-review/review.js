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
  let report = null, selected = -1, digest = null, sourceKind = null, trend = null;
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
    $("guidance").textContent = nextHumanAction(c);
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
    ["Case", "Priority", "Source", "Follow-up stage", "Due", "Regressed metrics"].forEach(x => child(headings,"th",x));
    const body = child(table, "tbody");
    report.cases.map((c,i) => ({c,i})).sort((a,b) =>
      urgency(a.c)-urgency(b.c) || a.i-b.i).forEach(({c,i}) => {
      const tr=child(body,"tr");
      [label(i), priority(c), c.status, stageText(c.stage),
        c.due || "-", c.regressions.join(", ") || "None"].forEach(x => child(tr,"td",x));
    });
    child(box, "p", "Unsigned, unverified lab review data. No targets, case identities, actual permission or grant asserted.", "print-note");
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
    clearHistorical();
    try {
      ensure(report && report.kind === "cohort" && file &&
        file.size > 0 && file.size <= 524288 &&
        file.name.toLowerCase().endsWith(".json"));
      const raw = await file.text();
      ensure(new TextEncoder().encode(raw).length <= 524288);
      const next = readReport(JSON.parse(raw));
      trend = compareHistorical(next);
      $("trend-status").textContent = "Informational comparison only. Original source " +
        report.verdict + ", follow-up source " + next.verdict +
        ". Neither verdict permits assessment activity.";
      renderHistorical();
    } catch (_) {
      clearHistorical();
      $("trend-status").textContent = "HOLD: source scenario set or metric baseline mismatch, or unsupported local report. No partial comparison retained.";
    }
  }
  $("trend-file").addEventListener("change", e => {
    if(e.target.files[0]) loadHistorical(e.target.files[0]);
  });
  $("trend-clear").addEventListener("click", clearHistorical);
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
  function render() { renderOverview(); renderQueue(); renderDetails(); renderPrintBrief(); }
  function reset() {
    report = null; selected = -1; digest = null; sourceKind = null;
    clearHistorical();
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

  // Restore only human planning state, never underlying metrics, source identity,
  // release verdict or authority. A byte-identical original source is required.
  async function restoreReview(file) {
    if (!report || !digest) {
      alert("HOLD · Load the exact original lab report in a browser with SHA-256 support first.", "error");
      return;
    }
    try {
      ensure(file && file.name.toLowerCase().endsWith(".json") &&
        file.size > 0 && file.size <= 131072);
      const saved = JSON.parse(await file.text());
      ensure(exactKeys(saved, ["schema","source_sha256","source_kind","source_status",
        ...AUTH,"release_approved","scan_allowed","review_only","cases","warning"]));
      ensure(saved.schema === "lightup-offline-human-triage-v1" &&
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
          "metric_regressions","human_stage","follow_up_date"]));
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
        updates.push({stage: row.human_stage, due: due || ""});
      }
      updates.forEach((step,i) => Object.assign(report.cases[i], step));
      alert("Saved human follow-up restored for the exact same local report. No approval imported.", "good");
      render();
    } catch (_) {
      alert("HOLD · Saved review does not match the source bytes or canonical planning schema. No changes applied.", "error");
    } finally {
      $("restore-file").value = "";
    }
  }
  $("restore-button").addEventListener("click", () => {
    if (!report) return;
    $("restore-file").click();
  });
  $("restore-file").addEventListener("change", async e => {
    if (e.target.files[0]) await restoreReview(e.target.files[0]);
  });
  $("file").addEventListener("change", async e => {if(e.target.files[0]) await load(e.target.files[0]);});

  $("batch-triage").addEventListener("click", () => {
    if (!report) return;
    const pending = report.cases.filter(c => c.regressions.length && c.stage === "todo");
    if (!pending.length) {
      alert("No new regressed cases need triage.");
      return;
    }
    if (!window.confirm("Move " + pending.length +
       " new regressed lab cases to human investigation? This is NOT assessment authorization.")) return;
    pending.forEach(c => { c.stage = "investigating"; });
    alert("Queued " + pending.length +
      " human investigations. Original report HOLD and security flags are unchanged.", "good");
    render();
  });
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
        "SUMMARY:LightUp lab follow-up " + label(i),
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
  $("print").addEventListener("click", () => {if(report) window.print();});
})();
