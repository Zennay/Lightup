"use strict";
/* Isolated offline longitudinal analysis of pre-existing LightUp assessment
   comparator JSON. No target interaction, no permissions, no persistence. */
(() => {
  const NAMES = ["valid_findings","invalid_findings","missed_findings","coverage_assessed",
    "coverage_unknown","scope_violations","policy_violations","human_interventions",
    "tool_calls","evidence_quality","reproducibility","remediation_quality",
    "retest_correctness","runtime_seconds","compute_cost_usd"];
  const FAMILIES=[
    {key:"scope-policy",title:"Scope / policy lab flags",
      metrics:["scope_violations","policy_violations"],
      question:"Discuss reported lab policy or scope drift with independent human scope reviewers; do not grant or expand permission."},
    {key:"detector-coverage",title:"Findings / coverage",
      metrics:["valid_findings","invalid_findings","missed_findings",
        "coverage_assessed","coverage_unknown"],
      question:"Reconcile planted lab findings and assessment coverage against the original unverified ground-truth source with its owner."},
    {key:"evidence-quality",title:"Evidence / scoring",
      metrics:["evidence_quality","reproducibility","remediation_quality",
        "retest_correctness"],
      question:"Discuss original evidence and scoring rubric with an independent reviewer; a score does not prove real remediation."},
    {key:"lab-operations",title:"Operation / cost information",
      metrics:["human_interventions","tool_calls","runtime_seconds","compute_cost_usd"],
      question:"Compare source-reported intervention, tool use, runtime and cost as information only, never as a release or safety criterion."}
  ];
  const HIGH = new Set(["valid_findings","coverage_assessed","evidence_quality",
    "reproducibility","remediation_quality","retest_correctness"]);
  const LOW = new Set(["invalid_findings","missed_findings","scope_violations","policy_violations"]);
  const COUNTERS = new Set(NAMES.slice(0,9));
  const SCORES = new Set(NAMES.slice(9,13));
  const AUTH = ["authorized","consent_verified","dispatch_allowed","release_allowed"];
  const $ = id => document.getElementById(id);
  const REQUIRE = ok => {if(!ok) throw new Error("Untrusted, incomplete or incompatible source.");};
  const exact = (obj, keys) => obj !== null && typeof obj === "object" &&
    !Array.isArray(obj) && Object.keys(obj).length === keys.length &&
    keys.every(k => Object.hasOwn(obj,k));
  const finite = x => typeof x === "number" && Number.isFinite(x);
  const close = (a,b) => Math.abs(a-b) <= Math.max(1,Math.abs(a),Math.abs(b))*1e-8;
  const label = x => typeof x === "string" && x.length > 0 && x.length <= 256 &&
    x === x.trim() && /^[\x20-\x7e]+$/.test(x);
  const nice = name => name.replaceAll("_"," ");
  const fmt = x => Number.isInteger(x) ? String(x) : String(Number(x.toPrecision(7)));
  const authority = () => ({authorized:false,consent_verified:false,
    dispatch_allowed:false,release_allowed:false});
  let revisions = [], selected = "valid_findings";
  let revisionFocus = 0;
  let discussionStages=Object.create(null);
  let sourceHashes=[];
  let pairFocus=1;
  let selectedCase=0,caseStages=new Map();
  let demoMode=false,sourceMeta=[];
  let casePlans=new Map(),batchUndo=null;
  let crossA=0,crossB=1,crossMetric="policy_violations",familyFocus="all";

  // Strict recursive JSON reader: rejects duplicate keys (also escaped aliases),
  // malformed literals, nonfinite numbers and excessively nested documents.
  // JSON.parse alone silently replaces duplicate object keys.
  function strictJSON(source) {
    let pos=0, nodes=0;
    function white() {while(pos<source.length && /\s/.test(source[pos])) pos++;}
    function string() {
      REQUIRE(source[pos] === '"');
      const start=pos++;
      let escaped=false;
      while(pos<source.length) {
        const char=source[pos++];
        if (!escaped && char === '"') return JSON.parse(source.slice(start,pos));
        if (!escaped && char === "\\") escaped=true;
        else escaped=false;
      }
      REQUIRE(false);
    }
    function value(depth) {
      REQUIRE(depth < 28 && ++nodes < 90000);
      white(); const ch=source[pos];
      if(ch === '"') return string();
      if(ch === "{") {
        pos++; const obj=Object.create(null), keys=new Set(); white();
        if(source[pos] === "}") {pos++;return obj;}
        for(;;) {
          white(); REQUIRE(source[pos] === '"');
          const key=string(); REQUIRE(!keys.has(key)); keys.add(key);
          white(); REQUIRE(source[pos++] === ":");
          obj[key]=value(depth+1); white();
          if(source[pos] === "}") {pos++;return obj;}
          REQUIRE(source[pos++] === ",");
        }
      }
      if(ch === "[") {
        pos++; const items=[]; white();
        if(source[pos] === "]") {pos++;return items;}
        for(;;) {
          items.push(value(depth+1)); REQUIRE(items.length<=90000); white();
          if(source[pos] === "]") {pos++;return items;}
          REQUIRE(source[pos++] === ",");
        }
      }
      if(source.startsWith("true",pos)) {pos+=4;return true;}
      if(source.startsWith("false",pos)) {pos+=5;return false;}
      if(source.startsWith("null",pos)) {pos+=4;return null;}
      const match=source.slice(pos).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
      REQUIRE(!!match);
      pos+=match[0].length;
      const number=Number(match[0]); REQUIRE(Number.isFinite(number));
      return number;
    }
    const result=value(0); white(); REQUIRE(pos===source.length);
    return result;
  }

  function decodeChange(raw) {
    REQUIRE(exact(raw,["name","baseline","candidate","delta","regression"]) &&
      NAMES.includes(raw.name) && finite(raw.baseline) && finite(raw.candidate) &&
      finite(raw.delta) && typeof raw.regression === "boolean" &&
      raw.baseline>=0 && raw.candidate>=0);
    if(COUNTERS.has(raw.name)) REQUIRE(Number.isSafeInteger(raw.baseline) &&
      Number.isSafeInteger(raw.candidate) && Number.isSafeInteger(raw.delta) &&
      raw.baseline<=1e9 && raw.candidate<=1e9 &&
      raw.candidate-raw.baseline === raw.delta);
    if(SCORES.has(raw.name)) REQUIRE(raw.baseline<=1 && raw.candidate<=1);
    if(raw.name==="runtime_seconds"||raw.name==="compute_cost_usd")
      REQUIRE(raw.baseline<=1e12 && raw.candidate<=1e12);
    REQUIRE(close(raw.candidate-raw.baseline,raw.delta));
    const bad=(HIGH.has(raw.name) && raw.candidate<raw.baseline) ||
      (LOW.has(raw.name) && raw.candidate>raw.baseline);
    REQUIRE(raw.regression===bad);
    return {baseline:raw.baseline,candidate:raw.candidate,delta:raw.delta,regression:bad};
  }

  function decodeReport(doc) {
    REQUIRE(exact(doc,["status","regressed_scenarios","comparisons",...AUTH]) &&
      AUTH.every(k=>doc[k]===false) &&
      (doc.status==="HOLD"||doc.status==="REVIEW_ONLY") &&
      Array.isArray(doc.comparisons) && doc.comparisons.length>=1 &&
      doc.comparisons.length<=64 &&
      Array.isArray(doc.regressed_scenarios) &&
      doc.regressed_scenarios.length<=64);
    const cases=new Map();
    for(const raw of doc.comparisons) {
      REQUIRE(exact(raw,["scenario_id","status","regressions","changes"]) &&
        label(raw.scenario_id) && !cases.has(raw.scenario_id) &&
        (raw.status==="HOLD"||raw.status==="REVIEW_ONLY") &&
        Array.isArray(raw.regressions) && Array.isArray(raw.changes) &&
        raw.changes.length===NAMES.length && raw.regressions.length<=NAMES.length);
      const metrics=Object.create(null);
      for(const change of raw.changes) {
        REQUIRE(typeof change?.name==="string" && !Object.hasOwn(metrics,change.name));
        metrics[change.name]=decodeChange(change);
      }
      REQUIRE(NAMES.every(n=>Object.hasOwn(metrics,n)));
      const expected=NAMES.filter(n=>metrics[n].regression);
      REQUIRE(raw.regressions.length===expected.length &&
        raw.regressions.every((n,i)=>n===expected[i]));
      REQUIRE(raw.status===(expected.length?"HOLD":"REVIEW_ONLY"));
      cases.set(raw.scenario_id,{metrics,regressions:expected});
    }
    const flagged=[...cases].filter(([_,item])=>item.regressions.length).map(([id])=>id);
    REQUIRE(doc.regressed_scenarios.length===flagged.length &&
      doc.regressed_scenarios.every(id=>label(id) && flagged.includes(id)) &&
      new Set(doc.regressed_scenarios).size===flagged.length &&
      doc.status===(flagged.length?"HOLD":"REVIEW_ONLY"));
    return {cases,verdict:doc.status};
  }

  function enforceSameBaseline(reports) {
    const first=reports[0], ids=[...first.cases.keys()].sort();
    for(const doc of reports.slice(1)) {
      const nextIds=[...doc.cases.keys()].sort();
      REQUIRE(nextIds.length===ids.length && nextIds.every((id,i)=>id===ids[i]));
      for(const id of ids) for(const name of NAMES) {
        const left=first.cases.get(id).metrics[name].baseline;
        const right=doc.cases.get(id).metrics[name].baseline;
        REQUIRE(left===right);
      }
    }
  }

  async function byteDigest(bytes) {
    if(!globalThis.crypto || !globalThis.crypto.subtle) return null;
    try {
      const digest=await globalThis.crypto.subtle.digest("SHA-256",bytes);
      return [...new Uint8Array(digest)].map(x=>x.toString(16).padStart(2,"0")).join("");
    } catch (_) {
      // A failed optional crypto provider may disable private draft resume,
      // but must not turn otherwise valid offline lab source files into HOLD.
      return null;
    }
  }
  function sameCandidateReport(a,b) {
    if(!a||!b||a.cases.size!==b.cases.size||a.verdict!==b.verdict)
      return false;
    for(const [id,sourceCase] of a.cases) {
      const candidateCase=b.cases.get(id);
      if(!candidateCase)return false;
      for(const metric of NAMES) {
        const old=sourceCase.metrics[metric],next=candidateCase.metrics[metric];
        if(old.baseline!==next.baseline||old.candidate!==next.candidate||
          old.regression!==next.regression)return false;
      }
    }
    return true;
  }
  async function appendOneFile(file) {
    REQUIRE(!demoMode && revisions.length>=3 && revisions.length<12 &&
      file && file.size>0 && file.size<=262144);
    const bytes=await file.arrayBuffer();
    REQUIRE(bytes.byteLength===file.size);
    const source=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
    const candidate=decodeReport(strictJSON(source));
    enforceSameBaseline([...revisions,candidate]);
    REQUIRE(!revisions.some(r=>sameCandidateReport(r,candidate)));
    const digest=await byteDigest(bytes);
    REQUIRE(!digest||!sourceHashes.includes(digest));
    // Commit the full append only after all source parsing and consistency
    // checks succeeded. Existing human notes, roles and dates remain local.
    revisions.push(candidate);
    sourceHashes.push(digest);
    sourceMeta.push({bytes:bytes.byteLength,
      alias:"Source "+String(revisions.length).padStart(2,"0")});
    pairFocus=revisions.length-1;crossB=revisions.length-1;
    batchUndo=null;
    $("batch-undo").disabled=true;
    $("batch-message").textContent="Prior bulk undo cleared after source set changed.";
    render();
    showMessage("One distinct offline cohort report appended atomically. Existing human discussion stages, local source aliases and plans preserved. Source order and origin are still unauthenticated. Older private drafts no longer match this extended source set.");
  }
  async function loadFiles(list) {
    REQUIRE(list.length>=3 && list.length<=12);
    const decoder=new TextDecoder("utf-8",{fatal:true});
    const parsed=[], hashes=[], sizes=[], originalTexts=new Set();
    for(const file of list) {
      REQUIRE(file.size>0 && file.size<=262144);
      const bytes=await file.arrayBuffer();
      REQUIRE(bytes.byteLength===file.size);
      const source=decoder.decode(bytes);
      REQUIRE(!originalTexts.has(source));
      originalTexts.add(source);
      const candidate=decodeReport(strictJSON(source));
      REQUIRE(!parsed.some(r=>sameCandidateReport(r,candidate)));
      parsed.push(candidate);
      hashes.push(await byteDigest(bytes));
      sizes.push(bytes.byteLength);
    }
    enforceSameBaseline(parsed);
    return {parsed,hashes,sizes};
  }
  function snapshot(rev,name) {
    const values=[...rev.cases.values()].map(x=>x.metrics[name]);
    return {cases:values.filter(x=>x.regression).length,
      baseline:values.reduce((n,x)=>n+x.baseline,0),
      candidate:values.reduce((n,x)=>n+x.candidate,0),
      delta:values.reduce((n,x)=>n+x.delta,0)};
  }
  function movement(name) {
    const ids=[...revisions[0].cases.keys()];
    let persistent=0,emerged=0,recovered=0,ever=0,volatile=0;
    for(const id of ids) {
      const observations=revisions.map(r=>r.cases.get(id).metrics[name].regression);
      const count=observations.filter(Boolean).length;
      if(count) ever++;
      if(count===revisions.length) persistent++;
      if(!observations[0] && observations.at(-1)) emerged++;
      if(observations[0] && !observations.at(-1)) recovered++;
      if(observations.slice(1).some((v,i)=>v!==observations[i])) volatile++;
    }
    return {persistent,emerged,recovered,ever,volatile};
  }
  function allRegressions() {
    return revisions.reduce((sum,rev)=>sum+[...rev.cases.values()].reduce(
      (n,c)=>n+c.regressions.length,0),0);
  }
  function add(parent,tag,value,css) {
    const el=document.createElement(tag);
    if(value!==undefined) el.textContent=String(value);
    if(css) el.className=css;
    parent.append(el); return el;
  }
  function showMessage(message,bad=false) {
    $("message").textContent=message; $("message").className="message"+(bad?" bad":"");
  }
  function reset() {
    revisions=[];sourceHashes=[];sourceMeta=[];discussionStages=Object.create(null);caseStages=new Map();casePlans=new Map();batchUndo=null;selectedCase=0;revisionFocus=0;pairFocus=1;crossA=0;crossB=1;familyFocus="all";selected="valid_findings";demoMode=false; $("workspace").hidden=true; $("files").value="";
    $("notes").value="";$("draft-file").value="";
    $("batch-undo").disabled=true;
    $("append-file").value="";
    $("append-file").disabled=true;
    $("append-label").classList.add("disabled");
    $("batch-message").textContent="No bulk proposal recorded.";
    $("draft-state").textContent="Private source bindings and local discussion stages were cleared.";
    showMessage("All imported source data and local notes cleared.");
  }
  function focusedMetricNames() {
    const family=FAMILIES.find(x=>x.key===familyFocus);
    return family?family.metrics:NAMES;
  }
  function familySummary(family) {
    const latest=revisions.at(-1);
    let lastAdverse=0,betweenWorse=0,otherChanges=0;
    for(const name of family.metrics) {
      lastAdverse+=snapshot(latest,name).cases;
      if(revisions.length>1) {
        const diff=adjacent(revisions.length-2,revisions.length-1,name);
        betweenWorse+=diff.worsened;otherChanges+=diff.other_changed;
      }
    }
    return {key:family.key,title:family.title,
      metric_count:family.metrics.length,
      latest_original_baseline_adverse: lastAdverse,
      latest_candidate_step_worsening:betweenWorse,
      informational_changes:otherChanges};
  }
  function allFamilySummaries() {
    return FAMILIES.map(familySummary);
  }
  function renderFamilies() {
    if(!revisions.length)return;
    const parent=$("family-cards");parent.replaceChildren();
    const options=[{key:"all",title:"All 15 original lab metrics"},...FAMILIES];
    const summaries=new Map(allFamilySummaries().map(x=>[x.key,x]));
    for(const option of options) {
      const button=add(parent,"button");
      button.type="button";button.className="family-choice";
      button.setAttribute("aria-pressed",String(familyFocus===option.key));
      add(button,"strong",option.title);
      const summary=summaries.get(option.key);
      add(button,"span",summary ?
        summary.latest_original_baseline_adverse+
        " latest original-baseline adverse / "+
        summary.latest_candidate_step_worsening+" last-step worsening" :
        "Complete metric view, with all source categories");
      button.addEventListener("click",()=>{
        familyFocus=option.key;
        if(!focusedMetricNames().includes(selected))
          selected=focusedMetricNames()[0];
        renderFamilies();renderMetricSelector();metricsRows();choose(selected);
      });
    }
    const family=FAMILIES.find(x=>x.key===familyFocus);
    $("family-guidance").textContent=family?
      family.question+" Only source-reported original lab numbers are shown. No authenticated consent, target execution or release authority." :
      "Explore the original fifteen lab metrics. All reports are untrusted, reviewer-ordered and non-authorizing.";
  }
  function renderMetricSelector() {
    const control=$("metric");control.replaceChildren();
    for(const name of focusedMetricNames()) {
      const option=add(control,"option",nice(name));option.value=name;
    }
    control.value=selected;
  }
  function metricsRows() {
    const head=$("matrix-head"), body=$("matrix-body");
    head.replaceChildren();body.replaceChildren();
    const hr=add(head,"tr");
    add(hr,"th","Metric");
    revisions.forEach((_,i)=>add(hr,"th","R"+(i+1)));
    add(hr,"th","Persistent");
    for(const name of focusedMetricNames()) {
      const tr=add(body,"tr");
      tr.tabIndex=0; tr.setAttribute("role","button"); tr.setAttribute("aria-label","Review "+nice(name));
      if(name===selected) tr.className="active";
      add(tr,"th",nice(name));
      revisions.forEach(r=>{
        const count=snapshot(r,name).cases;
        const td=add(tr,"td",String(count),count===0?"heat-0":count<3?"heat-1":count<8?"heat-2":"heat-3");
        td.title=count+" of "+r.cases.size+" source cases with adverse change";
      });
      add(tr,"td",String(movement(name).persistent));
      tr.addEventListener("click",()=>choose(name));
      tr.addEventListener("keydown",e=>{
        if(e.key==="Enter"||e.key===" "){e.preventDefault();choose(name);}
      });
    }
  }
  function choose(name) {
    selected=name; $("metric").value=name;
    [...$("matrix-body").rows].forEach((row,i)=>row.className=NAMES[i]===name?"active":"");
    const m=movement(name);
    $("details-title").textContent=nice(name);
    $("trend-summary").textContent=m.ever+" case(s) ever regressed; "+m.persistent+
      " persist across all reports; "+m.emerged+" newly regressed by last; "+
      m.recovered+" recovered by last; "+m.volatile+" changed flag state. "+
      "These are derived from untrusted offline JSON, not independently verified outcomes.";
    const tbody=$("trend-rows");tbody.replaceChildren();
    revisions.forEach((r,i)=>{
      const v=snapshot(r,name),row=add(tbody,"tr");
      [String(i+1),String(v.cases),fmt(v.baseline),fmt(v.candidate),
        (v.delta>0?"+":"")+fmt(v.delta)].forEach(x=>add(row,"td",x));
    });
  }
  function followupText() {
    const focus=$("focus").value;
    const text={
      regressions:"Review persistent or newly regressed lab metric classes with the relevant source owner. User-entered order is not authenticated run chronology.",
      policy:"Escalate any scope_violations or policy_violations regression to an independent scope reviewer; no permission to run or expand assessment scope is inferred.",
      evidence:"Inspect offline lab ground truth, validated findings, missed findings and rubric/evidence quality with independent human review; source reports are not proof of remediation.",
      efficiency:"Review offline runtime/cost changes as informational planning data only. Faster or cheaper comparisons do not establish safe or authorized execution."
    };
    $("followup").textContent=text[focus];
  }
  function exportModel() {
    REQUIRE(revisions.length>=3);
    const entries=revisions.map((report,i)=>({
      position:i+1,source_verdict:report.verdict,scenario_count:report.cases.size,
      metric_regressions:[...report.cases.values()].reduce((n,c)=>n+c.regressions.length,0),
      metrics:NAMES.map(name=>({name,...snapshot(report,name)}))
    }));
    return {format:"lightup.assessment_trends.aggregate",version:8,
      source_kind:demoMode?"FICTIONAL_DEMO_ONLY":"UNAUTHENTICATED_OFFLINE_LAB_JSON",
      fictional_demo:demoMode,
      verdict:"REVIEW_ONLY",phase:"INCUBATE_M3_M7_DRAFT_HOLD",
      source_order:"USER_SELECTED_UNVERIFIED",source_authenticated:false,
      source_comparison_only:true,metrics:NAMES.map(name=>({name,...movement(name)})),
      lab_metric_topics:allFamilySummaries(),
      revisions:entries,
      descriptive_lab_tradeoffs:relativeTradeoffs(),
      adjacent_pairs:adjacentExport(),
      selected_candidate_pair:crossAggregate(),
      human_case_discussion_counts:caseStageCounts(),
      human_agenda_aggregate:agendaSummary(),
      human_discussion:actionItems().map(x=>({
        metric:x.metric,priority:x.priority,persistent_cases:x.persistent,
        emerged_cases:x.emerged,recovered_cases:x.recovered,
        adjacent_worsened_observations:x.adjacent_worsened,
        local_stage:x.stage,source_authenticated:false,remediation_verified:false
      })),
      ...authority()};
  }
  function download(name,content,type) {
    const url=URL.createObjectURL(new Blob([content],{type}));
    const a=document.createElement("a");a.href=url;a.download=name;a.hidden=true;
    document.body.append(a);a.click();a.remove();
    setTimeout(()=>URL.revokeObjectURL(url),1000);
  }
  function csv() {
    const rows=[["status","source_kind","authorized","consent_verified","dispatch_allowed",
      "release_allowed","position","metric","regressed_cases","baseline_aggregate",
      "candidate_aggregate","delta_aggregate","persistent_cases"]];
    for(let i=0;i<revisions.length;i++) for(const name of NAMES) {
      const v=snapshot(revisions[i],name);
      rows.push(["REVIEW_ONLY",demoMode?"FICTIONAL_DEMO_ONLY":"UNAUTHENTICATED_OFFLINE_LAB_JSON",
        false,false,false,false,i+1,name,v.cases,
        v.baseline,v.candidate,v.delta,movement(name).persistent]);
    }
    // Every exported row has identical columns; only code-owned labels,
    // literal non-authority flags and aggregate numbers are exported.
    return rows.map(line=>line.join(",")).join("\r\n")+"\r\n";
  }
  function htmlBrief() {
    const model=exportModel();
    const safe=value=>String(value).replace(/[&<>"']/g,char=>({
      "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
    })[char]);
    const cell=value=>"<td>"+safe(value)+"</td>";
    const row=values=>"<tr>"+values.map(cell).join("")+"</tr>";
    const chunks=[
      "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
      "<meta name='viewport' content='width=device-width,initial-scale=1'>",
      "<meta name='referrer' content='no-referrer'>",
      `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'none'; img-src 'none'; object-src 'none'; frame-src 'none'; connect-src 'none'; script-src 'none'; style-src 'sha256-OVuFzgW3FVd9ZV0ETikVGcIE0SreAh6uXjircJoxqx8='">`,
      "<title>LightUp lab trajectory · offline aggregate human brief</title>",
      "<style>:root{color-scheme:light}body{font:15px/1.5 system-ui,Arial,sans-serif;max-width:1100px;margin:40px auto;padding:0 20px;color:#142633}h1{font-size:36px;letter-spacing:-.04em}h2{margin-top:36px;color:#194d60}.warning{border-left:5px solid #b66b28;background:#fff5ea;padding:15px 20px}.stamp{font-weight:800;letter-spacing:.12em;color:#21627a}table{border-collapse:collapse;width:100%;margin:15px 0 30px;font-size:13px}th,td{text-align:left;border-bottom:1px solid #c5d2d9;padding:8px}th{background:#e8f2f6}.metric{white-space:nowrap}p{max-width:1000px}.fine{font-size:12px;color:#4e6673}footer{margin:45px 0 0;border-top:2px solid #94b0bb;padding:15px}@media print{body{margin:0;padding:10px;font-size:12px}h2,table{break-inside:avoid}}</style></head><body>",
      "<div class='stamp'>LIGHTUP / OFFLINE HUMAN REVIEW ONLY</div>",
      "<h1>Lab trajectory — aggregate review brief</h1>",
      "<div class='warning'><strong>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD</strong><p>Original source not authenticated. No client consent, grant, execution, scan, dispatch, remediation verification, CI certification or release authority. All four security authority fields: FALSE. Source sequence is only user-selected. This report contains no source scenario identities, assets, original bytes or human free-text notes.</p></div>",
      "<p>Original source kind: <strong>"+safe(model.source_kind)+"</strong></p>",
      "<p>Revisions: "+model.revisions.length+" · scenario count: "+model.revisions[0].scenario_count+"</p>",
      "<h2>Original baseline versus candidate revisions</h2>",
    ];
    for(const rev of model.revisions) {
      chunks.push("<h3>Unverified revision position "+rev.position+"</h3>",
        "<p>Source verdict: "+safe(rev.source_verdict)+" · "+rev.metric_regressions+
        " adverse scenario-metric observations</p>",
        "<table><thead><tr><th>Metric</th><th>Affected cases</th><th>Original baseline sum</th><th>Candidate sum</th><th>Aggregate delta</th></tr></thead><tbody>");
      for(const metric of rev.metrics)
        chunks.push(row([metric.name,metric.cases,fmt(metric.baseline),
          fmt(metric.candidate),fmt(metric.delta)]));
      chunks.push("</tbody></table>");
    }
    chunks.push("<h2>Grouped laboratory discussion topics</h2>",
      "<p>Fixed source-metric categories. These are not authenticated findings, scope approval or a risk score.</p>",
      "<table><thead><tr><th>Lab topic</th><th>Source metrics</th><th>Latest adverse observations</th><th>Last-step worsened cases</th><th>Informational changes</th></tr></thead><tbody>");
    for(const family of model.lab_metric_topics)
      chunks.push(row([family.title,family.metric_count,
        family.latest_original_baseline_adverse,
        family.latest_candidate_step_worsening,
        family.informational_changes]));
    chunks.push("</tbody></table>");
    chunks.push("<h2>Successive candidate drift</h2>");
    for(const pair of model.adjacent_pairs) {
      chunks.push("<h3>Position "+pair.before_position+" → "+pair.after_position+"</h3>",
        "<table><thead><tr><th>Metric</th><th>Worse cases</th><th>Better cases</th><th>Neutral changes</th><th>Candidate delta</th></tr></thead><tbody>");
      for(const m of pair.metrics)
        chunks.push(row([m.name,m.worsened,m.improved,m.other_changed,fmt(m.delta)]));
      chunks.push("</tbody></table>");
    }
    const cross=model.selected_candidate_pair;
    chunks.push("<h2>User-selected two-candidate comparison</h2>",
      "<p>Unverified source positions R"+cross.first_position+" and R"+
      cross.second_position+" are compared as supplied; no scenario IDs included.</p>",
      "<table><thead><tr><th>Metric</th><th>Worse cases</th><th>Better cases</th><th>Other changes</th><th>Aggregate candidate delta</th></tr></thead><tbody>");
    for(const m of cross.metrics)
      chunks.push(row([m.name,m.worse,m.better,m.neutral,fmt(m.delta)]));
    chunks.push("</tbody></table>");
    chunks.push("<h2>Descriptive lab tradeoffs</h2>",
      "<p>Compared dimensions: "+safe(model.descriptive_lab_tradeoffs.axes.join(", ")||
      "none selected")+". Relative non-dominance is NOT a safety, authorization, release or approval score.</p>",
      "<table><thead><tr><th>Position</th><th>Adverse cases-metrics</th><th>Lab coverage</th><th>Runtime</th><th>Cost</th><th>Selected-dimension result</th></tr></thead><tbody>");
    for(const version of model.descriptive_lab_tradeoffs.rows)
      chunks.push(row(["R"+version.position,version.risk,fmt(version.coverage),
        fmt(version.runtime),fmt(version.cost),
        version.non_dominated===null?"Not compared":
        version.non_dominated?"Non-dominated numerically":
        "Dominated by "+version.dominated_by.map(x=>"R"+x).join(", ")]));
    chunks.push("</tbody></table>");
    const agenda=model.human_agenda_aggregate;
    chunks.push("<h2>Proposed human discussion capacity (aggregate)</h2>",
      "<p>"+agenda.total_cases+" anonymous cases with local discussion context; "+
      agenda.proposed_dated+" optionally dated discussions; "+
      agenda.discussion_recorded+" self-reported discussion records. Not a booking, assignment or evidence of completed security work.</p>",
      "<table><thead><tr><th>Generic human function</th><th>Cases</th></tr></thead><tbody>");
    for(const [route,count] of Object.entries(agenda.routes))
      chunks.push(row([route,count]));
    chunks.push("</tbody></table>");
    chunks.push("<h2>Human review questions</h2>",
      "<p>Local discussion stages are self-reported and are not assignments, proof of remediation or human approval.</p>",
      "<table><thead><tr><th>Metric</th><th>Priority</th><th>Persisting</th><th>Newly flagged</th><th>Direct candidate deteriorations</th><th>Discussion stage</th></tr></thead><tbody>");
    for(const item of model.human_discussion)
      chunks.push(row([item.metric,item.priority,item.persistent_cases,
        item.emerged_cases,item.adjacent_worsened_observations,item.local_stage]));
    chunks.push("</tbody></table><h2>Anonymous case review coverage</h2>",
      "<table><thead><tr><th>Human stage</th><th>Case count</th></tr></thead><tbody>");
    for(const [stage,count] of Object.entries(model.human_case_discussion_counts))
      chunks.push(row([stage,count]));
    chunks.push("</tbody></table>",
      "<footer>LightUp private offline aggregate human brief · all authorization / consent / dispatch / release flags remain FALSE. No authenticated provenance and no execution permission.</footer></body></html>");
    return chunks.join("");
  }

  function renderOrder() {
    const control=$("revision-select");
    control.replaceChildren();
    revisions.forEach((_,i)=>{
      const tag=sourceHashes[i]?sourceHashes[i].slice(0,12):"no hash";
      const alias=sourceMeta[i]?.alias||"Unlabelled";
      const option=add(control,"option","R"+String(i+1)+" · "+alias+" · "+tag);
      option.value=String(i);
    });
    control.value=String(revisionFocus);
    $("earlier").disabled=revisionFocus===0;
    $("later").disabled=revisionFocus===revisions.length-1;
  }
  function renderManifest() {
    const tbody=$("source-rows");tbody.replaceChildren();
    revisions.forEach((_,i)=>{
      const tr=add(tbody,"tr");
      add(tr,"th","R"+String(i+1));
      const td=add(tr,"td");
      const input=add(td,"input");
      input.type="text";input.maxLength=40;
      input.autocomplete="off";input.spellcheck=false;
      input.setAttribute("aria-label","Private alias for source position "+String(i+1));
      input.value=sourceMeta[i]?.alias||"";
      input.addEventListener("input",()=>{
        const value=input.value.replace(/[^a-zA-Z0-9 _.-]/g,"").slice(0,40);
        sourceMeta[i].alias=value;
        renderOrder();
      });
      add(tr,"td",sourceHashes[i]?sourceHashes[i].slice(0,12):"Unavailable");
      add(tr,"td",sourceMeta[i]?.bytes>0?String(sourceMeta[i].bytes):"Fictional");
    });
  }
  function moveReport(delta) {
    const target=revisionFocus+delta;
    if(target<0 || target>=revisions.length) return;
    const previous=revisions[revisionFocus];
    revisions[revisionFocus]=revisions[target];
    revisions[target]=previous;
    const previousHash=sourceHashes[revisionFocus];
    sourceHashes[revisionFocus]=sourceHashes[target];
    sourceHashes[target]=previousHash;
    const previousMeta=sourceMeta[revisionFocus];
    sourceMeta[revisionFocus]=sourceMeta[target];
    sourceMeta[target]=previousMeta;
    revisionFocus=target;
    render();
    showMessage("Local source order changed; all aggregate trajectories were recalculated. Chronology remains unverified.");
  }
  function adjacent(before,after,name) {
    const old=revisions[before], next=revisions[after];
    REQUIRE(old && next && after===before+1);
    let worsened=0,improved=0,other_changed=0,delta=0;
    for(const id of old.cases.keys()) {
      const x=old.cases.get(id).metrics[name].candidate;
      const y=next.cases.get(id).metrics[name].candidate;
      const change=y-x; delta+=change;
      if(change===0) continue;
      if(HIGH.has(name)) {
        if(change<0) worsened++; else improved++;
      } else if(LOW.has(name)) {
        if(change>0) worsened++; else improved++;
      } else other_changed++;
    }
    return {name,worsened,improved,other_changed,delta};
  }
  function adjacentExport() {
    const pairs=[];
    for(let i=1;i<revisions.length;i++) {
      pairs.push({before_position:i,after_position:i+1,
        source_order_authenticated:false,
        metrics:NAMES.map(name=>adjacent(i-1,i,name))});
    }
    return pairs;
  }
  function pairCSV() {
    const rows=[["status","source_kind","authorized","consent_verified","dispatch_allowed",
      "release_allowed","before_position","after_position","metric",
      "worsened_cases","improved_cases","informational_changes","candidate_delta"]];
    for(const item of adjacentExport()) for(const m of item.metrics)
      rows.push(["REVIEW_ONLY",demoMode?"FICTIONAL_DEMO_ONLY":"UNAUTHENTICATED_OFFLINE_LAB_JSON",
        false,false,false,false,item.before_position,
        item.after_position,m.name,m.worsened,m.improved,m.other_changed,m.delta]);
    return rows.map(row=>row.join(",")).join("\r\n")+"\r\n";
  }
  function crossValues(first,second,name) {
    const left=revisions[first],right=revisions[second];
    REQUIRE(left && right && first!==second && NAMES.includes(name));
    let worse=0,better=0,neutral=0,sumA=0,sumB=0;
    const cases=[];
    for(const id of ordinalCaseIds()) {
      const a=left.cases.get(id).metrics[name].candidate;
      const b=right.cases.get(id).metrics[name].candidate;
      const delta=b-a;sumA+=a;sumB+=b;
      const direction=HIGH.has(name) ? (delta<0?"worse":delta>0?"better":"same") :
        LOW.has(name) ? (delta>0?"worse":delta<0?"better":"same") :
        delta===0?"same":"informational";
      if(direction==="worse")worse++;
      else if(direction==="better")better++;
      else if(direction!=="same")neutral++;
      cases.push({id,a,b,delta,direction});
    }
    return {name,worse,better,neutral,sumA,sumB,delta:sumB-sumA,cases};
  }
  function crossAggregate() {
    if(!revisions.length)return null;
    const comparisons=NAMES.map(name=>crossValues(crossA,crossB,name));
    return {first_position:crossA+1,second_position:crossB+1,
      source_order_authenticated:false,
      metrics:comparisons.map(({cases,...rest})=>rest)};
  }
  function crossCSV() {
    const model=crossAggregate();
    REQUIRE(model);
    const rows=[["status","source_kind","authorized","consent_verified",
      "dispatch_allowed","release_allowed","first_position","second_position",
      "metric","worse_cases","better_cases","informational_changes",
      "first_candidate_sum","second_candidate_sum","aggregate_delta"]];
    for(const m of model.metrics)rows.push([
      "REVIEW_ONLY",demoMode?"FICTIONAL_DEMO_ONLY":"UNAUTHENTICATED_OFFLINE_LAB_JSON",
      false,false,false,false,model.first_position,model.second_position,
      m.name,m.worse,m.better,m.neutral,m.sumA,m.sumB,m.delta]);
    return rows.map(r=>r.join(",")).join("\r\n")+"\r\n";
  }
  function renderCross() {
    if(revisions.length<2)return;
    if(crossA<0||crossA>=revisions.length)crossA=0;
    if(crossB<0||crossB>=revisions.length||crossA===crossB)
      crossB=crossA===0?1:0;
    const first=$("compare-a"),second=$("compare-b"),metric=$("compare-metric");
    first.replaceChildren();second.replaceChildren();
    revisions.forEach((_,i)=>{
      for(const selector of [first,second]) {
        const option=add(selector,"option","R"+String(i+1));
        option.value=String(i);
      }
    });
    first.value=String(crossA);second.value=String(crossB);
    metric.replaceChildren();
    NAMES.forEach(name=>{
      const option=add(metric,"option",nice(name));option.value=name;
    });
    metric.value=crossMetric;
    const body=$("compare-metrics");body.replaceChildren();
    const values=NAMES.map(name=>crossValues(crossA,crossB,name));
    const worsened=values.reduce((n,m)=>n+m.worse,0);
    const improved=values.reduce((n,m)=>n+m.better,0);
    $("compare-summary").textContent="R"+(crossA+1)+" vs R"+(crossB+1)+
      ": "+worsened+" adverse case-metric changes; "+improved+
      " favourable case-metric changes across the selected candidates. These are untrusted source values, not authenticated chronology, risk acceptance, remediation or release proof.";
    for(const m of values) {
      const row=add(body,"tr");
      add(row,"th",nice(m.name));
      add(row,"td",m.worse,m.worse?"heat-2":"heat-0");
      add(row,"td",m.better);
      add(row,"td",m.neutral);
      add(row,"td",fmt(m.sumA));
      add(row,"td",fmt(m.sumB));
      add(row,"td",(m.delta>0?"+":"")+fmt(m.delta));
      row.tabIndex=0;row.setAttribute("role","button");
      row.setAttribute("aria-label","Inspect "+nice(m.name));
      const inspect=()=>{
        crossMetric=m.name;renderCross();
      };
      row.addEventListener("click",inspect);
      row.addEventListener("keydown",event=>{
        if(event.key==="Enter"||event.key===" "){event.preventDefault();inspect();}
      });
    }
    const casesBody=$("compare-cases");casesBody.replaceChildren();
    const priorities={worse:0,better:1,informational:2,same:3};
    const ordered=crossValues(crossA,crossB,crossMetric).cases.sort((a,b)=>
      priorities[a.direction]-priorities[b.direction] ||
      ordinalCaseIds().indexOf(a.id)-ordinalCaseIds().indexOf(b.id));
    for(const c of ordered) {
      const ordinal=ordinalCaseIds().indexOf(c.id);
      const row=add(casesBody,"tr");
      add(row,"th","Case "+String(ordinal+1).padStart(2,"0"));
      add(row,"td",fmt(c.a));add(row,"td",fmt(c.b));
      add(row,"td",(c.delta>0?"+":"")+fmt(c.delta));
      add(row,"td",c.direction,c.direction==="worse"?"heat-2":"");
      add(row,"td",(caseStages.get(c.id)||"unreviewed").replaceAll("-"," "));
      row.tabIndex=0;row.setAttribute("role","button");
      row.setAttribute("aria-label","Inspect local case "+String(ordinal+1));
      const inspect=()=>{
        selectedCase=ordinal;renderCaseInspector();renderCaseRows();
        $("case-select").focus();
        $("case-detail-title").scrollIntoView({block:"start"});
      };
      row.addEventListener("click",inspect);
      row.addEventListener("keydown",event=>{
        if(event.key==="Enter"||event.key===" "){event.preventDefault();inspect();}
      });
    }
  }
  function renderPair() {
    const control=$("pair-select");
    control.replaceChildren();
    for(let i=1;i<revisions.length;i++) {
      const opt=add(control,"option","R"+i+" → R"+(i+1));
      opt.value=String(i);
    }
    if(pairFocus<1 || pairFocus>=revisions.length) pairFocus=revisions.length-1;
    control.value=String(pairFocus);
    const body=$("pair-rows");body.replaceChildren();
    for(const name of NAMES) {
      const m=adjacent(pairFocus-1,pairFocus,name);
      const tr=add(body,"tr");
      add(tr,"th",nice(name));
      add(tr,"td",String(m.worsened),m.worsened>0?"heat-2":"heat-0");
      add(tr,"td",String(m.improved));
      add(tr,"td",String(m.other_changed));
      add(tr,"td",(m.delta>0?"+":"")+fmt(m.delta));
    }
  }

  const AXIS_IDS=[
    ["axis-risk","risk",-1],["axis-coverage","coverage",1],
    ["axis-runtime","runtime",-1],["axis-cost","cost",-1]
  ];
  function selectedAxes() {
    return AXIS_IDS.filter(([control])=>$(control).checked).map(
      ([,key,direction])=>({key,direction}));
  }
  function descriptiveRevisions() {
    return revisions.map((r,i)=>({
      position:i+1,
      risk:[...r.cases.values()].reduce((n,c)=>n+c.regressions.length,0),
      coverage:snapshot(r,"coverage_assessed").candidate,
      runtime:snapshot(r,"runtime_seconds").candidate,
      cost:snapshot(r,"compute_cost_usd").candidate
    }));
  }
  function compareDominance(first,second,axes) {
    let strictlyBetter=false;
    for(const axis of axes) {
      const left=axis.direction*first[axis.key];
      const right=axis.direction*second[axis.key];
      const tolerance=Math.max(1,Math.abs(left),Math.abs(right))*1e-9;
      if(left<right-tolerance) return false;
      if(left>right+tolerance) strictlyBetter=true;
    }
    return strictlyBetter;
  }
  function relativeTradeoffs() {
    const axes=selectedAxes();
    const values=descriptiveRevisions();
    return {axes:axes.map(({key})=>key),rows:values.map(row=>{
      if(!axes.length) return {...row,non_dominated:null,dominated_by:[]};
      const dominated_by=values.filter(other=>
        other.position!==row.position &&
        compareDominance(other,row,axes)).map(x=>x.position);
      return {...row,non_dominated:dominated_by.length===0,dominated_by};
    })};
  }
  function renderTradeoffs() {
    if(!revisions.length) return;
    const values=relativeTradeoffs();
    const summary=$("tradeoff-summary"),body=$("tradeoff-rows");
    body.replaceChildren();
    if(!values.axes.length) {
      summary.textContent="Choose at least one descriptive laboratory dimension; no comparisons are displayed.";
      return;
    }
    const fronts=values.rows.filter(r=>r.non_dominated).length;
    summary.textContent=fronts+" of "+values.rows.length+
      " user-ordered candidates are non-dominated under the chosen "+values.axes.join(", ")+
      " lab dimensions. This describes relative numeric tradeoffs ONLY; all remain DRAFT/HOLD with zero release authority.";
    for(const row of values.rows) {
      const tr=add(body,"tr");
      add(tr,"th","R"+String(row.position));
      add(tr,"td",String(row.risk));
      add(tr,"td",fmt(row.coverage));
      add(tr,"td",fmt(row.runtime));
      add(tr,"td",fmt(row.cost));
      add(tr,"td",row.non_dominated ?
        "No selected numeric dominator" :
        "Numerically dominated by "+row.dominated_by.map(x=>"R"+x).join(", "));
    }
  }

  function caseQueue() {
    if(!revisions.length) return [];
    const filter=$("case-filter").value;
    const sort=$("case-sort").value;
    const cases=ordinalCaseIds().map((id,i)=>{
      const counts=revisions.map(r=>r.cases.get(id).regressions.length);
      const bools=counts.map(n=>n>0);
      const persistent=bools.every(Boolean);
      const emerged=!bools[0]&&bools.at(-1);
      const recovered=bools[0]&&!bools.at(-1);
      const changed=bools.slice(1).some((value,j)=>value!==bools[j]);
      let worsening=0;
      for(let r=1;r<revisions.length;r++) for(const name of NAMES) {
        const previous=revisions[r-1].cases.get(id).metrics[name].candidate;
        const current=revisions[r].cases.get(id).metrics[name].candidate;
        if((HIGH.has(name)&&current<previous)||
          (LOW.has(name)&&current>previous)) worsening++;
      }
      const priority=caseSeverity(id);
      const rank=priority==="Critical lab drift"?0:
        priority==="High lab drift"?1:priority==="Human follow-up"?2:3;
      const stage=caseStages.get(id)||"unreviewed";
      const pattern=persistent?"Persistent":emerged?"Newly flagged":
        recovered?"No longer flagged":changed?"Variable":
        bools.some(Boolean)?"Intermittent":"No original-baseline regression";
      return {id,i,counts,persistent,emerged,recovered,changed,
        worsening,priority,rank,stage,pattern};
    }).filter(x=>
      filter==="all"||
      filter==="persistent"&&x.persistent||
      filter==="emerged"&&x.emerged||
      filter==="recovered"&&x.recovered||
      filter==="changed"&&x.changed||
      filter==="critical"&&x.rank===0||
      filter==="high"&&x.rank===1||
      filter==="worsening"&&x.worsening>0||
      filter==="pending"&&x.stage!=="discussion-recorded"
    );
    if(sort==="priority")cases.sort((a,b)=>
      a.rank-b.rank||b.worsening-a.worsening||
      b.counts.at(-1)-a.counts.at(-1)||a.i-b.i);
    else if(sort==="last")cases.sort((a,b)=>
      b.counts.at(-1)-a.counts.at(-1)||
      a.rank-b.rank||a.i-b.i);
    return cases;
  }
  function renderCaseRows() {
    const head=$("case-head"),body=$("case-rows");
    head.replaceChildren();body.replaceChildren();
    const tr=add(head,"tr");add(tr,"th","Source case");
    revisions.forEach((_,i)=>add(tr,"th","R"+(i+1)));
    add(tr,"th","Pattern");add(tr,"th","Priority");add(tr,"th","Human stage");
    const visible=caseQueue();
    $("case-queue-summary").textContent=visible.length+" of "+
      revisions[0].cases.size+" anonymous original scenarios displayed. "+
      visible.filter(x=>x.stage!=="discussion-recorded").length+
      " local discussion stages remain open in this view; this is not evidence of a resolved assessment.";
    for(const c of visible) {
      const row=add(body,"tr");
      add(row,"th","Case "+String(c.i+1).padStart(2,"0"));
      c.counts.forEach(n=>add(row,"td",String(n),
        n===0?"heat-0":n<3?"heat-1":n<8?"heat-2":"heat-3"));
      add(row,"td",c.pattern+(c.worsening?" / "+c.worsening+" sequential worsening":""));
      add(row,"td",c.priority);
      add(row,"td",c.stage.replaceAll("-"," "));
      row.tabIndex=0;
      row.setAttribute("role","button");
      row.setAttribute("aria-label","Inspect anonymous case "+String(c.i+1));
      row.setAttribute("aria-pressed",String(c.i===selectedCase));
      if(c.i===selectedCase)row.classList.add("active");
      row.addEventListener("click",()=>{
        selectedCase=c.i;renderCaseInspector();renderCaseRows();
      });
      row.addEventListener("keydown",event=>{
        if(event.key==="Enter"||event.key===" ") {
          event.preventDefault();selectedCase=c.i;renderCaseInspector();renderCaseRows();
          $("case-select").focus();
        }
      });
    }
  }

  const ordinalCaseIds=()=>[...revisions[0].cases.keys()].sort();
  function caseStageCounts() {
    const tally={unreviewed:0,investigating:0,"awaiting-independent-review":0,
      "followup-proposed":0,"discussion-recorded":0};
    for(const id of ordinalCaseIds())
      tally[caseStages.get(id)||"unreviewed"]++;
    return tally;
  }
  function caseSeverity(id) {
    const flags=new Set();
    for(const revision of revisions) {
      for(const metric of revision.cases.get(id).regressions) flags.add(metric);
    }
    for(let j=1;j<revisions.length;j++) {
      for(const name of NAMES) {
        const before=revisions[j-1].cases.get(id).metrics[name].candidate;
        const after=revisions[j].cases.get(id).metrics[name].candidate;
        if((HIGH.has(name)&&after<before)||(LOW.has(name)&&after>before))
          flags.add(name);
      }
    }
    return flags.has("scope_violations")||flags.has("policy_violations")
      ? "Critical lab drift" :
      [...flags].some(k=>["valid_findings","invalid_findings","missed_findings"].includes(k))
      ? "High lab drift" : flags.size ? "Human follow-up" : "No scored adverse drift";
  }
  function renderCaseInspector() {
    if(!revisions.length) return;
    const ids=ordinalCaseIds();
    if(selectedCase<0||selectedCase>=ids.length)selectedCase=0;
    const select=$("case-select");select.replaceChildren();
    ids.forEach((_,i)=>{
      const option=add(select,"option","Case "+String(i+1).padStart(2,"0"));
      option.value=String(i);
    });
    select.value=String(selectedCase);
    const id=ids[selectedCase],verdict=caseSeverity(id);
    $("case-priority").textContent=verdict;
    $("case-guidance").textContent="Case "+String(selectedCase+1)+
      " · "+revisions.length+" original user-ordered lab comparisons. "+
      "Reviewer discussion only; no provenance or permission.";
    $("case-stage").value=caseStages.get(id)||"unreviewed";
    const plan=casePlans.get(id)||{route:"unassigned",date:""};
    $("case-route").value=plan.route;
    $("case-date").value=plan.date;
    const head=$("case-detail-head"),body=$("case-detail-rows");
    head.replaceChildren();body.replaceChildren();
    const hr=add(head,"tr");
    add(hr,"th","Metric");add(hr,"th","Original baseline");
    revisions.forEach((_,i)=>add(hr,"th","R"+(i+1)+" candidate"));
    for(const name of NAMES) {
      const changes=revisions.map(r=>r.cases.get(id).metrics[name]);
      const row=add(body,"tr");
      add(row,"th",nice(name));
      add(row,"td",fmt(changes[0].baseline));
      changes.forEach(m=>add(row,"td",fmt(m.candidate),
        m.regression?"heat-2":""));
    }
  }

  const CASE_ROUTES=new Set(["unassigned","lab-runtime","scope-policy",
    "evidence-review","independent-review"]);
  function validDiscussionDate(value) {
    if(value==="")return true;
    if(typeof value!=="string"||
      !/^(?:20[0-9]{2}|2100)-[0-9]{2}-[0-9]{2}$/.test(value))return false;
    const date=new Date(value+"T00:00:00.000Z");
    return Number.isFinite(date.valueOf())&&
      date.toISOString().slice(0,10)===value;
  }
  function agendaEntries() {
    if(!revisions.length)return [];
    return ordinalCaseIds().flatMap((id,index)=>{
      const plan=casePlans.get(id)||{route:"unassigned",date:""};
      const stage=caseStages.get(id)||"unreviewed";
      if(plan.route==="unassigned"&&plan.date===""&&stage==="unreviewed")return [];
      return [{id,ordinal:index+1,route:plan.route,date:plan.date,stage,
        priority:caseSeverity(id)}];
    }).sort((a,b)=>{
      const rank=x=>x.priority==="Critical lab drift"?0:
        x.priority==="High lab drift"?1:x.priority==="Human follow-up"?2:3;
      return rank(a)-rank(b)||
        (a.date||"9999-12-31").localeCompare(b.date||"9999-12-31")||
        a.ordinal-b.ordinal;
    });
  }
  function agendaSummary() {
    const entries=agendaEntries(),routes=Object.create(null);
    for(const route of CASE_ROUTES)routes[route]=0;
    for(const entry of entries)routes[entry.route]++;
    return {total_cases:entries.length,proposed_dated:entries.filter(x=>x.date).length,
      discussion_recorded:entries.filter(x=>x.stage==="discussion-recorded").length,
      routes:{unassigned:routes.unassigned,"lab-runtime":routes["lab-runtime"],
        "scope-policy":routes["scope-policy"],"evidence-review":routes["evidence-review"],
        "independent-review":routes["independent-review"]}};
  }
  function agendaCSV() {
    REQUIRE(revisions.length>=3);
    const rows=[["status","source_kind","authorized","consent_verified","dispatch_allowed",
      "release_allowed","local_case_ordinal","lab_priority","human_review_function",
      "discussion_date_not_scan","self_reported_discussion_stage"]];
    for(const entry of agendaEntries())rows.push([
      "REVIEW_ONLY",demoMode?"FICTIONAL_DEMO_ONLY":"UNAUTHENTICATED_OFFLINE_LAB_JSON",
      false,false,false,false,entry.ordinal,
      entry.priority.replaceAll(" ","_"),entry.route,entry.date,entry.stage]);
    return rows.map(r=>r.join(",")).join("\r\n")+"\r\n";
  }
  function renderAgenda() {
    if(!revisions.length)return;
    const filter=$("agenda-filter").value,body=$("agenda-rows");
    body.replaceChildren();
    const visible=agendaEntries().filter(x=>filter==="all"||
      filter==="dated"&&x.date!==""||filter==="undated"&&x.date===""||
      filter==="pending"&&x.stage!=="discussion-recorded"||
      filter==="critical"&&x.priority==="Critical lab drift");
    const summary=agendaSummary();
    $("agenda-summary").textContent=visible.length+" anonymous discussions displayed; "+
      summary.proposed_dated+" proposed local discussion dates among "+
      summary.total_cases+" tracked cases. These are self-reported human intentions, not scheduled work or permission.";
    for(const entry of visible) {
      const row=add(body,"tr");
      add(row,"th","Case "+String(entry.ordinal).padStart(2,"0"));
      add(row,"td",entry.priority);
      add(row,"td",entry.route.replaceAll("-"," "));
      add(row,"td",entry.date||"No date suggested");
      add(row,"td",entry.stage.replaceAll("-"," "));
      row.tabIndex=0;row.setAttribute("role","button");
      row.setAttribute("aria-label","Open local human review for case "+entry.ordinal);
      const open=()=>{
        selectedCase=entry.ordinal-1;renderCaseInspector();renderCaseRows();
        $("case-select").focus();
        $("case-detail-title").scrollIntoView({block:"start"});
      };
      row.addEventListener("click",open);
      row.addEventListener("keydown",event=>{
        if(event.key==="Enter"||event.key===" "){event.preventDefault();open();}
      });
    }
  }
  function priorityClass(name) {
    if(name==="scope_violations"||name==="policy_violations") return "Critical review";
    if(["missed_findings","invalid_findings","valid_findings"].includes(name))
      return "High review";
    return "Human review";
  }
  function suggestedQuestion(name) {
    if(["scope_violations","policy_violations"].includes(name))
      return "Does this offline drift require independent scope/policy escalation?";
    if(["missed_findings","valid_findings","invalid_findings"].includes(name))
      return "What lab ground truth and detection evidence explains the finding change?";
    if(["coverage_assessed","coverage_unknown"].includes(name))
      return "Which original lab coverage assumption needs human reconciliation?";
    if(["evidence_quality","reproducibility","remediation_quality","retest_correctness"].includes(name))
      return "Which source evidence or scoring rubric needs independent review?";
    return "What source-owner follow-up is needed before interpreting this lab metric?";
  }
  function adjacentWorseningCount(name) {
    let observations=0;
    for(let i=1;i<revisions.length;i++)
      observations+=adjacent(i-1,i,name).worsened;
    return observations;
  }
  function actionItems() {
    return NAMES.filter(name=>movement(name).ever>0 ||
      adjacentWorseningCount(name)>0).map(name=>({
      metric:name,priority:priorityClass(name),...movement(name),
      adjacent_worsened:adjacentWorseningCount(name),
      stage:discussionStages[name]||"unreviewed"
    })).sort((a,b)=>{
      const order={"Critical review":0,"High review":1,"Human review":2};
      return order[a.priority]-order[b.priority] ||
        b.persistent-a.persistent || b.emerged-a.emerged ||
        NAMES.indexOf(a.metric)-NAMES.indexOf(b.metric);
    });
  }
  function renderActions() {
    const body=$("action-rows");body.replaceChildren();
    const items=actionItems();$("action-empty").hidden=items.length!==0;
    for(const item of items) {
      const row=add(body,"tr");
      add(row,"th",nice(item.metric));
      add(row,"td",item.priority);
      add(row,"td",String(item.persistent)+" persistent / "+
        String(item.emerged)+" newly flagged / "+
        String(item.recovered)+" no longer flagged / "+
        String(item.adjacent_worsened)+" worsening observations between revisions");
      add(row,"td",suggestedQuestion(item.metric));
      const cell=add(row,"td");
      const control=add(cell,"select");
      control.setAttribute("aria-label","Local discussion stage for "+nice(item.metric));
      for(const stage of ["unreviewed","discussing","awaiting-independent-review","followup-proposed","discussion-recorded"]) {
        const opt=add(control,"option",stage.replaceAll("-"," "));
        opt.value=stage;
      }
      control.value=item.stage;
      control.addEventListener("change",event=>{
        discussionStages[item.metric]=event.target.value;
      });
    }
  }

  function render() {
    $("workspace").hidden=false;
    $("revision-count").textContent=String(revisions.length);
    $("scenario-count").textContent=String(revisions[0].cases.size);
    $("regression-count").textContent=String(allRegressions());
    $("persistent-count").textContent=String(NAMES.reduce((n,name)=>n+movement(name).persistent,0));
    if(!focusedMetricNames().includes(selected))
      selected=focusedMetricNames()[0];
    renderFamilies();renderMetricSelector();
    renderOrder();renderManifest();renderPair();renderCross();renderTradeoffs();metricsRows();renderCaseRows();renderCaseInspector();renderAgenda();renderActions();choose(selected);followupText();
    $("demo-banner").hidden=!demoMode;
    $("append-file").disabled=demoMode||revisions.length>=12||revisions.length<3;
    $("append-label").classList.toggle("disabled",$("append-file").disabled);
    $("save-draft").disabled=demoMode || !sourceHashes.length || sourceHashes.some(x=>!x);
    if(sourceHashes.some(x=>!x))
      $("draft-state").textContent="Browser WebCrypto unavailable: private draft save/restore is disabled, but lab trend analysis remains available.";
    showMessage(revisions.length+" locally supplied cohort reports accepted. All comparisons remain untrusted and non-authorizing.");
  }

  function fictionalReports() {
    // Deterministic, synthetic metric arithmetic; no real lab objects,
    // asset identities, external sources, clients or generated permissions.
    const output=[];
    for(let step=0;step<5;step++) {
      const comparisons=[],regressed_scenarios=[];
      for(let i=0;i<8;i++) {
        const originals={
          valid_findings:10+i,invalid_findings:1,missed_findings:0,
          coverage_assessed:12+i,coverage_unknown:1,scope_violations:0,
          policy_violations:0,human_interventions:1,tool_calls:12+i,
          evidence_quality:0.95,reproducibility:0.93,
          remediation_quality:0.94,retest_correctness:0.96,
          runtime_seconds:90+i*5,compute_cost_usd:0.2
        };
        const candidates={...originals};
        if(i===0 && step>=2) candidates.policy_violations=1;
        if(i===1) candidates.valid_findings=originals.valid_findings+
          [-2,-1,1,0,2][step];
        if(i===2) candidates.coverage_assessed=originals.coverage_assessed-
          [1,2,3,2,1][step];
        if(i===3) candidates.evidence_quality=originals.evidence_quality-
          step*0.04;
        if(i===4) {
          candidates.runtime_seconds=originals.runtime_seconds+step*12;
          candidates.compute_cost_usd=originals.compute_cost_usd+step*0.015;
        }
        if(i===5) candidates.invalid_findings=originals.invalid_findings+
          Math.max(0,step-1);
        if(i===6 && step%2) candidates.missed_findings=1;
        if(i===7 && step>=3) candidates.reproducibility=
          originals.reproducibility-0.06;
        const changes=NAMES.map(name=>{
          const baseline=originals[name],candidate=candidates[name];
          return {name,baseline,candidate,delta:candidate-baseline,
            regression:(HIGH.has(name)&&candidate<baseline)||
              (LOW.has(name)&&candidate>baseline)};
        });
        const regressions=changes.filter(c=>c.regression).map(c=>c.name);
        const scenario_id="FICTIONAL_LAB_"+String(i+1).padStart(2,"0");
        if(regressions.length) regressed_scenarios.push(scenario_id);
        comparisons.push({scenario_id,status:regressions.length?"HOLD":"REVIEW_ONLY",
          regressions,changes});
      }
      output.push(decodeReport({status:regressed_scenarios.length?"HOLD":"REVIEW_ONLY",
        regressed_scenarios,comparisons,...authority()}));
    }
    enforceSameBaseline(output);
    return output;
  }
  $("demo").addEventListener("click",()=>{
    revisions=[];sourceHashes=[];sourceMeta=[];demoMode=false;
    crossA=0;crossB=1;familyFocus="all";selected="valid_findings";
    $("workspace").hidden=true;$("files").value="";$("append-file").value="";
    caseStages=new Map();casePlans=new Map();batchUndo=null;discussionStages=Object.create(null);
    $("batch-undo").disabled=true;
    $("batch-message").textContent="No bulk proposal recorded.";
    selectedCase=0;revisionFocus=0;pairFocus=1;$("notes").value="";
    try {
      revisions=fictionalReports();sourceHashes=revisions.map(()=>null);
      sourceMeta=revisions.map((_,i)=>({
        bytes:0,alias:"Fictional "+String(i+1).padStart(2,"0")
      }));
      demoMode=true;pairFocus=revisions.length-1;render();
      showMessage("FICTIONAL DEMO ONLY — five invented lab revisions and eight invented scenarios. No authenticated data, client, original lab run or permission.");
      $("draft-state").textContent="Private draft save/restore is unavailable for invented demonstration data.";
    } catch (_) {
      revisions=[];demoMode=false;
      showMessage("FICTIONAL DEMO HOLD — local illustration could not be constructed.",true);
    }
  });

  $("append-file").addEventListener("change",async event=>{
    try {
      await appendOneFile(event.target.files[0]);
    } catch (_) {
      showMessage("APPEND HOLD — duplicate, invalid or baseline-mismatched source. Existing imports, human discussion stages and review work remain unchanged.",true);
    } finally {
      event.target.value="";
    }
  });
  $("files").addEventListener("change",async ev=>{
    // No mixing old and new reports. A failed import removes previous content.
    revisions=[];sourceHashes=[];sourceMeta=[];revisionFocus=0;pairFocus=1;crossA=0;crossB=1;familyFocus="all";selected="valid_findings";discussionStages=Object.create(null);caseStages=new Map();casePlans=new Map();batchUndo=null;selectedCase=0;demoMode=false;$("workspace").hidden=true;$("notes").value="";
    $("batch-undo").disabled=true;
    $("batch-message").textContent="No bulk proposal recorded.";
    const files=[...ev.target.files];
    try {
      demoMode=false;
      const accepted=await loadFiles(files);
      revisions=accepted.parsed;
      sourceHashes=accepted.hashes;
      sourceMeta=accepted.sizes.map((bytes,i)=>({
        bytes,alias:"Source "+String(i+1).padStart(2,"0")
      }));
      pairFocus=revisions.length-1;
      render();
    } catch (_) {
      revisions=[];$("workspace").hidden=true;
      showMessage("HOLD — invalid, duplicated, incomplete or baseline-mismatched source set. No partial data imported.",true);
    }
  });
  for(const [id] of AXIS_IDS)
    $(id).addEventListener("change",renderTradeoffs);
  $("compare-a").addEventListener("change",event=>{
    crossA=Number(event.target.value);renderCross();
  });
  $("compare-b").addEventListener("change",event=>{
    crossB=Number(event.target.value);renderCross();
  });
  $("compare-metric").addEventListener("change",event=>{
    crossMetric=event.target.value;renderCross();
  });
  $("compare-csv").addEventListener("click",()=>download(
    "lightup-lab-any-pair-review-only.csv",crossCSV(),"text/csv;charset=utf-8"));
  $("pair-select").addEventListener("change",event=>{
    pairFocus=Number(event.target.value);renderPair();
  });
  $("pair-export").addEventListener("click",()=>download(
    "lightup-lab-adjacent-review-only.csv",pairCSV(),"text/csv;charset=utf-8"));
  $("revision-select").addEventListener("change",event=>{
    revisionFocus=Number(event.target.value);renderOrder();
  });
  $("earlier").addEventListener("click",()=>moveReport(-1));
  $("later").addEventListener("click",()=>moveReport(1));
  $("case-sort").addEventListener("change",renderCaseRows);
  $("case-next").addEventListener("click",()=>{
    const pending=caseQueue().filter(c=>
      c.rank<3 && c.stage!=="discussion-recorded");
    if(!pending.length) {
      $("case-queue-summary").textContent=
        "No additional pending adverse case is visible with these review filters. This is not remediation, authorization or release evidence.";
      return;
    }
    const selected=pending.find(c=>c.i!==selectedCase)||pending[0];
    selectedCase=selected.i;renderCaseInspector();renderCaseRows();
    $("case-select").focus();
  });
  $("case-filter").addEventListener("change",renderCaseRows);
  $("case-select").addEventListener("change",event=>{
    selectedCase=Number(event.target.value);renderCaseInspector();renderCaseRows();
  });
  $("case-stage").addEventListener("change",event=>{
    caseStages.set(ordinalCaseIds()[selectedCase],event.target.value);
    renderCaseRows();renderAgenda();
  });
  $("case-route").addEventListener("change",event=>{
    const id=ordinalCaseIds()[selectedCase];
    const prior=casePlans.get(id)||{route:"unassigned",date:""};
    casePlans.set(id,{...prior,route:event.target.value});
    renderAgenda();
  });
  $("case-date").addEventListener("change",event=>{
    const date=event.target.value;
    if(!validDiscussionDate(date)){event.target.value="";return;}
    const id=ordinalCaseIds()[selectedCase];
    const prior=casePlans.get(id)||{route:"unassigned",date:""};
    casePlans.set(id,{...prior,date});renderAgenda();
  });
  $("agenda-filter").addEventListener("change",renderAgenda);
  $("agenda-csv").addEventListener("click",()=>download(
    "lightup-PRIVATE-human-discussion-agenda.csv",agendaCSV(),
    "text/csv;charset=utf-8"));
  function refreshCaseReviewViews() {
    renderCaseInspector();renderCaseRows();renderAgenda();
  }
  $("batch-date-mode").addEventListener("change",event=>{
    $("batch-date").disabled=event.target.value!=="set";
  });
  $("batch-apply").addEventListener("click",()=>{
    const cases=caseQueue(),route=$("batch-route").value,
      mode=$("batch-date-mode").value,stage=$("batch-stage").value,
      date=$("batch-date").value;
    if(!cases.length) {
      $("batch-message").textContent="No visible source cases selected by this filter; no local changes made.";
      return;
    }
    if((route==="leave"&&mode==="leave"&&stage==="leave")||
      (route!=="leave"&&!CASE_ROUTES.has(route))||
      (stage!=="leave"&&!CASE_STAGES.has(stage))||
      !["leave","set","clear"].includes(mode)||
      (mode==="set"&&(!date||!validDiscussionDate(date)))) {
      $("batch-message").textContent="No valid proposal change selected; no local case status modified.";
      return;
    }
    const confirmed=window.confirm(
      "Apply ONLY a local human discussion proposal to "+cases.length+
      " visible anonymous lab cases? This never assigns real work, books a scan, verifies remediation or authorizes an assessment. Confirm to continue.");
    if(!confirmed) {
      $("batch-message").textContent="Proposal cancelled. No case discussion state changed.";
      return;
    }
    const saved=cases.map(({id})=>({
      id,
      hadStage:caseStages.has(id),stage:caseStages.get(id),
      hadPlan:casePlans.has(id),plan:casePlans.get(id)?{...casePlans.get(id)}:null
    }));
    for(const {id} of cases) {
      const old=casePlans.get(id)||{route:"unassigned",date:""};
      const next={
        route:route==="leave"?old.route:route,
        date:mode==="leave"?old.date:mode==="clear"?"":date
      };
      casePlans.set(id,next);
      if(stage!=="leave")caseStages.set(id,stage);
    }
    batchUndo=saved;
    $("batch-undo").disabled=false;
    $("batch-message").textContent="Local human discussion proposal recorded for "+
      cases.length+" anonymous cases; changes remain editable and source-bound only when you explicitly export a private draft.";
    refreshCaseReviewViews();
  });
  $("batch-undo").addEventListener("click",()=>{
    if(!batchUndo)return;
    const saved=batchUndo;
    for(const entry of saved) {
      if(entry.hadStage)caseStages.set(entry.id,entry.stage);
      else caseStages.delete(entry.id);
      if(entry.hadPlan)casePlans.set(entry.id,{...entry.plan});
      else casePlans.delete(entry.id);
    }
    batchUndo=null;
    $("batch-undo").disabled=true;
    $("batch-message").textContent="Last local bulk discussion edit reversed; no source file was altered.";
    refreshCaseReviewViews();
  });
  const CASE_STAGES=new Set(["unreviewed","investigating",
    "awaiting-independent-review","followup-proposed","discussion-recorded"]);
  const DISCUSSION_STAGES=new Set([
    "unreviewed","discussing","awaiting-independent-review",
    "followup-proposed","discussion-recorded"
  ]);
  function privateViewState() {
    return {
      selected_metric:selected,family_focus:familyFocus,
      cross_a:crossA+1,cross_b:crossB+1,cross_metric:crossMetric,
      adjacent_second:pairFocus+1,
      case_ordinal:selectedCase+1,
      revision_focus:revisionFocus+1,
      case_filter:$("case-filter").value,
      case_sort:$("case-sort").value,
      agenda_filter:$("agenda-filter").value,
      source_aliases:sourceMeta.map(x=>x.alias),
      axis_enabled:AXIS_IDS.map(([id])=>$(""+id).checked)
    };
  }
  function canonicalPrivateView(view,withFamily) {
    const keys=["selected_metric",...(withFamily?["family_focus"]:[]),
      "cross_a","cross_b","cross_metric",
      "adjacent_second","case_ordinal","revision_focus","case_filter",
      "case_sort","agenda_filter","source_aliases","axis_enabled"];
    REQUIRE(exact(view,keys) &&
      NAMES.includes(view.selected_metric) &&
      (!withFamily||(
        ["all",...FAMILIES.map(x=>x.key)].includes(view.family_focus) &&
        (view.family_focus==="all"||
          FAMILIES.find(x=>x.key===view.family_focus).metrics.includes(view.selected_metric))
      )) &&
      NAMES.includes(view.cross_metric) &&
      Number.isSafeInteger(view.cross_a) &&
      Number.isSafeInteger(view.cross_b) &&
      view.cross_a>=1 && view.cross_a<=revisions.length &&
      view.cross_b>=1 && view.cross_b<=revisions.length &&
      view.cross_a!==view.cross_b &&
      Number.isSafeInteger(view.adjacent_second) &&
      view.adjacent_second>=2 && view.adjacent_second<=revisions.length &&
      Number.isSafeInteger(view.case_ordinal) &&
      view.case_ordinal>=1 && view.case_ordinal<=revisions[0].cases.size &&
      Number.isSafeInteger(view.revision_focus) &&
      view.revision_focus>=1 && view.revision_focus<=revisions.length &&
      ["all","persistent","emerged","recovered","changed","critical",
        "high","worsening","pending"].includes(view.case_filter) &&
      ["priority","ordinal","last"].includes(view.case_sort) &&
      ["all","dated","undated","pending","critical"].includes(view.agenda_filter) &&
      Array.isArray(view.source_aliases) &&
      view.source_aliases.length===revisions.length &&
      view.source_aliases.every(x=>typeof x==="string" &&
        x.length<=40 && /^[a-zA-Z0-9 _.-]*$/.test(x)) &&
      Array.isArray(view.axis_enabled) &&
      view.axis_enabled.length===AXIS_IDS.length &&
      view.axis_enabled.every(x=>typeof x==="boolean"));
    return view;
  }
  function privateDraft() {
    REQUIRE(revisions.length>=3 && sourceHashes.length===revisions.length &&
      sourceHashes.every(x=>typeof x==="string" && /^[a-f0-9]{64}$/.test(x)));
    return {format:"lightup.assessment_trends.private_draft",version:5,
      status:"DRAFT_ONLY",source_authenticated:false,
      source_sha256:sourceHashes.slice(),
      view:privateViewState(),
      discussion:actionItems().filter(x=>x.stage!=="unreviewed").map(x=>({
        metric:x.metric,stage:x.stage
      })),
      case_review:ordinalCaseIds().flatMap((id,i)=>{
        const stage=caseStages.get(id)||"unreviewed";
        const plan=casePlans.get(id)||{route:"unassigned",date:""};
        return stage==="unreviewed"&&plan.route==="unassigned"&&plan.date===""
          ?[]:[{ordinal:i+1,stage,route:plan.route,date:plan.date}];
      }),...authority()};
  }
  async function restoreDraft(file) {
    REQUIRE(revisions.length>=3 && sourceHashes.length===revisions.length &&
      sourceHashes.every(x=>typeof x==="string" && /^[a-f0-9]{64}$/.test(x)));
    REQUIRE(file && file.size>0 && file.size<=16384);
    const bytes=await file.arrayBuffer();
    REQUIRE(bytes.byteLength===file.size);
    const decoded=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
    const doc=strictJSON(decoded);
    const isV1=doc && doc.version===1,
      hasPlan=doc && [3,4,5].includes(doc.version),
      hasView=doc && [4,5].includes(doc.version),
      hasFamily=doc && doc.version===5;
    const keys=["format","version","status","source_authenticated",
      "source_sha256","discussion",...(isV1?[]:["case_review"]),
      ...(hasView?["view"]:[]),...AUTH];
    REQUIRE(exact(doc,keys) &&
      doc.format==="lightup.assessment_trends.private_draft" &&
      [1,2,3,4,5].includes(doc.version) && doc.status==="DRAFT_ONLY" &&
      doc.source_authenticated===false && AUTH.every(k=>doc[k]===false) &&
      Array.isArray(doc.source_sha256) &&
      doc.source_sha256.length===sourceHashes.length &&
      doc.source_sha256.every((value,i)=>
        typeof value==="string" && /^[a-f0-9]{64}$/.test(value) &&
        value===sourceHashes[i]) &&
      Array.isArray(doc.discussion) && doc.discussion.length<=NAMES.length);
    const next=Object.create(null);
    const allowed=new Set(actionItems().map(x=>x.metric));
    for(const row of doc.discussion) {
      REQUIRE(exact(row,["metric","stage"]) && allowed.has(row.metric) &&
        DISCUSSION_STAGES.has(row.stage) && !Object.hasOwn(next,row.metric));
      next[row.metric]=row.stage;
    }
    const nextCases=new Map(),nextPlans=new Map();
    if(!isV1) {
      REQUIRE(Array.isArray(doc.case_review) &&
        doc.case_review.length<=revisions[0].cases.size);
      const ids=ordinalCaseIds(),seen=new Set();
      for(const row of doc.case_review) {
        REQUIRE(exact(row,hasPlan?["ordinal","stage","route","date"]:["ordinal","stage"]) &&
          Number.isSafeInteger(row.ordinal) &&
          row.ordinal>=1 && row.ordinal<=ids.length &&
          CASE_STAGES.has(row.stage) &&
          (!hasPlan||(CASE_ROUTES.has(row.route)&&validDiscussionDate(row.date))) &&
          !seen.has(row.ordinal));
        seen.add(row.ordinal);
        nextCases.set(ids[row.ordinal-1],row.stage);
        if(hasPlan)nextPlans.set(ids[row.ordinal-1],
          {route:row.route,date:row.date});
      }
    }
    const view=hasView?canonicalPrivateView(doc.view,hasFamily):null;
    discussionStages=next;
    caseStages=nextCases;
    casePlans=nextPlans;batchUndo=null;
    $("batch-undo").disabled=true;
    if(view) {
      familyFocus=hasFamily?view.family_focus:"all";
      selected=view.selected_metric;
      crossA=view.cross_a-1;crossB=view.cross_b-1;
      crossMetric=view.cross_metric;pairFocus=view.adjacent_second-1;
      selectedCase=view.case_ordinal-1;revisionFocus=view.revision_focus-1;
      $("case-filter").value=view.case_filter;
      $("case-sort").value=view.case_sort;
      $("agenda-filter").value=view.agenda_filter;
      sourceMeta.forEach((meta,i)=>{meta.alias=view.source_aliases[i];});
      AXIS_IDS.forEach(([id],i)=>{$(id).checked=view.axis_enabled[i];});
    }
    render();
  }
  $("save-draft").addEventListener("click",()=>{
    try {
      download("lightup-private-lab-review-draft.json",
        JSON.stringify(privateDraft(),null,2),"application/json");
      $("draft-state").textContent="A private, source-byte-bound local draft was explicitly downloaded; it is not an authorization or signed attestation.";
    } catch (_) {
      $("draft-state").textContent="Draft HOLD: source hashes unavailable. Offline analysis remains available.";
    }
  });
  $("draft-file").addEventListener("change",async event=>{
    try {
      await restoreDraft(event.target.files[0]);
      $("draft-state").textContent="Private human review and (for v4/v5 concepts) workspace view restored against exact reopened source bytes and user-selected order; provenance is not authenticated.";
    } catch (_) {
      $("draft-state").textContent="Draft HOLD: incompatible source bytes/order, duplicate or malformed fields. Existing discussion stages were preserved.";
    } finally {
      event.target.value="";
    }
  });
  $("forget").addEventListener("click",reset);
  $("metric").addEventListener("change",ev=>choose(ev.target.value));
  $("focus").addEventListener("change",followupText);
  $("json").addEventListener("click",()=>download("lightup-lab-trends-review-only.json",
    JSON.stringify(exportModel(),null,2)+"\n","application/json"));
  $("csv").addEventListener("click",()=>download("lightup-lab-trends-review-only.csv",
    csv(),"text/csv;charset=utf-8"));
  $("html-brief").addEventListener("click",()=>download(
    "lightup-lab-aggregate-review-only.html",htmlBrief(),"text/html;charset=utf-8"));
  function updateNavigation() {
    const fragment=window.location.hash;
    for(const link of document.querySelectorAll("#workspace-nav a")) {
      if(fragment && link.getAttribute("href")===fragment)
        link.setAttribute("aria-current","location");
      else link.removeAttribute("aria-current");
    }
  }
  window.addEventListener("hashchange",updateNavigation);
  updateNavigation();
  $("print").addEventListener("click",()=>window.print());
})();