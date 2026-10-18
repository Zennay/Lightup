"use strict";
/* Isolated offline longitudinal analysis of pre-existing LightUp assessment
   comparator JSON. No target interaction, no permissions, no persistence. */
(() => {
  const NAMES = ["valid_findings","invalid_findings","missed_findings","coverage_assessed",
    "coverage_unknown","scope_violations","policy_violations","human_interventions",
    "tool_calls","evidence_quality","reproducibility","remediation_quality",
    "retest_correctness","runtime_seconds","compute_cost_usd"];
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
      parsed.push(decodeReport(strictJSON(source)));
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
    revisions=[];sourceHashes=[];sourceMeta=[];discussionStages=Object.create(null);caseStages=new Map();selectedCase=0;revisionFocus=0;pairFocus=1;demoMode=false; $("workspace").hidden=true; $("files").value="";
    $("notes").value="";$("draft-file").value="";
    $("draft-state").textContent="Private source bindings and local discussion stages were cleared.";
    showMessage("All imported source data and local notes cleared.");
  }
  function metricsRows() {
    const head=$("matrix-head"), body=$("matrix-body");
    head.replaceChildren();body.replaceChildren();
    const hr=add(head,"tr");
    add(hr,"th","Metric");
    revisions.forEach((_,i)=>add(hr,"th","R"+(i+1)));
    add(hr,"th","Persistent");
    for(const name of NAMES) {
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
    return {format:"lightup.assessment_trends.aggregate",version:4,
      source_kind:demoMode?"FICTIONAL_DEMO_ONLY":"UNAUTHENTICATED_OFFLINE_LAB_JSON",
      fictional_demo:demoMode,
      verdict:"REVIEW_ONLY",phase:"INCUBATE_M3_M7_DRAFT_HOLD",
      source_order:"USER_SELECTED_UNVERIFIED",source_authenticated:false,
      source_comparison_only:true,metrics:NAMES.map(name=>({name,...movement(name)})),
      revisions:entries,
      adjacent_pairs:adjacentExport(),
      human_case_discussion_counts:caseStageCounts(),
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
    chunks.push("<h2>Successive candidate drift</h2>");
    for(const pair of model.adjacent_pairs) {
      chunks.push("<h3>Position "+pair.before_position+" → "+pair.after_position+"</h3>",
        "<table><thead><tr><th>Metric</th><th>Worse cases</th><th>Better cases</th><th>Neutral changes</th><th>Candidate delta</th></tr></thead><tbody>");
      for(const m of pair.metrics)
        chunks.push(row([m.name,m.worsened,m.improved,m.other_changed,fmt(m.delta)]));
      chunks.push("</tbody></table>");
    }
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

  function renderCaseRows() {
    const head=$("case-head"),body=$("case-rows");
    head.replaceChildren();body.replaceChildren();
    const tr=add(head,"tr");add(tr,"th","Source case");
    revisions.forEach((_,i)=>add(tr,"th","R"+(i+1)));
    add(tr,"th","Pattern");
    const filter=$("case-filter").value;
    const ids=[...revisions[0].cases.keys()].sort();
    ids.forEach((id,i)=>{
      const counts=revisions.map(r=>r.cases.get(id).regressions.length);
      const bools=counts.map(n=>n>0);
      const persistent=bools.every(Boolean);
      const emerged=!bools[0] && bools.at(-1);
      const recovered=bools[0] && !bools.at(-1);
      const changed=bools.slice(1).some((value,j)=>value!==bools[j]);
      if(filter==="persistent"&&!persistent ||
         filter==="emerged"&&!emerged ||
         filter==="recovered"&&!recovered ||
         filter==="changed"&&!changed) return;
      const pattern=persistent?"Persistent":emerged?"Newly flagged":
        recovered?"No longer flagged":changed?"Variable":
        bools.some(Boolean)?"Intermittent":"No reported regression";
      const row=add(body,"tr");
      add(row,"th","Case "+String(i+1).padStart(2,"0"));
      counts.forEach(n=>add(row,"td",String(n),
        n===0?"heat-0":n<3?"heat-1":n<8?"heat-2":"heat-3"));
      add(row,"td",pattern);
      row.tabIndex=0;
      row.setAttribute("role","button");
      row.setAttribute("aria-label","Inspect anonymous case "+String(i+1));
      row.setAttribute("aria-pressed",String(i===selectedCase));
      if(i===selectedCase) row.classList.add("active");
      row.addEventListener("click",()=>{selectedCase=i;renderCaseInspector();renderCaseRows();});
      row.addEventListener("keydown",event=>{
        if(event.key==="Enter"||event.key===" ") {
          event.preventDefault();selectedCase=i;renderCaseInspector();renderCaseRows();
        }
      });
    });
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
    const select=$("metric");select.replaceChildren();
    for(const name of NAMES) {
      const option=add(select,"option",nice(name));option.value=name;
    }
    renderOrder();renderManifest();renderPair();metricsRows();renderCaseRows();renderCaseInspector();renderActions();choose(selected);followupText();
    $("demo-banner").hidden=!demoMode;
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
    $("workspace").hidden=true;$("files").value="";
    caseStages=new Map();discussionStages=Object.create(null);
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

  $("files").addEventListener("change",async ev=>{
    // No mixing old and new reports. A failed import removes previous content.
    revisions=[];sourceHashes=[];sourceMeta=[];revisionFocus=0;pairFocus=1;discussionStages=Object.create(null);caseStages=new Map();selectedCase=0;demoMode=false;$("workspace").hidden=true;$("notes").value="";
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
  $("case-filter").addEventListener("change",renderCaseRows);
  $("case-select").addEventListener("change",event=>{
    selectedCase=Number(event.target.value);renderCaseInspector();renderCaseRows();
  });
  $("case-stage").addEventListener("change",event=>{
    caseStages.set(ordinalCaseIds()[selectedCase],event.target.value);
  });
  const CASE_STAGES=new Set(["unreviewed","investigating",
    "awaiting-independent-review","followup-proposed","discussion-recorded"]);
  const DISCUSSION_STAGES=new Set([
    "unreviewed","discussing","awaiting-independent-review",
    "followup-proposed","discussion-recorded"
  ]);
  function privateDraft() {
    REQUIRE(revisions.length>=3 && sourceHashes.length===revisions.length &&
      sourceHashes.every(x=>typeof x==="string" && /^[a-f0-9]{64}$/.test(x)));
    return {format:"lightup.assessment_trends.private_draft",version:2,
      status:"DRAFT_ONLY",source_authenticated:false,
      source_sha256:sourceHashes.slice(),
      discussion:actionItems().filter(x=>x.stage!=="unreviewed").map(x=>({
        metric:x.metric,stage:x.stage
      })),
      case_review:ordinalCaseIds().flatMap((id,i)=>{
        const stage=caseStages.get(id)||"unreviewed";
        return stage==="unreviewed"?[]:[{ordinal:i+1,stage}];
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
    const isV1=doc && doc.version===1;
    const keys=["format","version","status","source_authenticated",
      "source_sha256","discussion",...(isV1?[]:["case_review"]),...AUTH];
    REQUIRE(exact(doc,keys) &&
      doc.format==="lightup.assessment_trends.private_draft" &&
      (doc.version===1||doc.version===2) && doc.status==="DRAFT_ONLY" &&
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
    const nextCases=new Map();
    if(!isV1) {
      REQUIRE(Array.isArray(doc.case_review) &&
        doc.case_review.length<=revisions[0].cases.size);
      const ids=ordinalCaseIds(),seen=new Set();
      for(const row of doc.case_review) {
        REQUIRE(exact(row,["ordinal","stage"]) &&
          Number.isSafeInteger(row.ordinal) &&
          row.ordinal>=1 && row.ordinal<=ids.length &&
          CASE_STAGES.has(row.stage) &&
          !seen.has(row.ordinal));
        seen.add(row.ordinal);
        nextCases.set(ids[row.ordinal-1],row.stage);
      }
    }
    discussionStages=next;
    caseStages=nextCases;
    renderActions();renderCaseInspector();
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
      $("draft-state").textContent="Private discussion stages restored against exact reopened source bytes and current displayed order (not authenticated origin).";
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
  $("print").addEventListener("click",()=>window.print());
})();