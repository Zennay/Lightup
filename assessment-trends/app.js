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

  async function loadFiles(list) {
    REQUIRE(list.length>=3 && list.length<=12);
    const decoder=new TextDecoder("utf-8",{fatal:true});
    const parsed=[];
    for(const file of list) {
      REQUIRE(file.size>0 && file.size<=262144);
      const bytes=await file.arrayBuffer();
      REQUIRE(bytes.byteLength===file.size);
      parsed.push(decodeReport(strictJSON(decoder.decode(bytes))));
    }
    enforceSameBaseline(parsed);
    return parsed;
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
    revisions=[]; $("workspace").hidden=true; $("files").value="";
    $("notes").value=""; showMessage("All imported source data and local notes cleared.");
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
    return {format:"lightup.assessment_trends.aggregate",version:1,
      verdict:"REVIEW_ONLY",phase:"INCUBATE_M3_M7_DRAFT_HOLD",
      source_order:"USER_SELECTED_UNVERIFIED",source_authenticated:false,
      source_comparison_only:true,metrics:NAMES.map(name=>({name,...movement(name)})),
      revisions:entries,...authority()};
  }
  function download(name,content,type) {
    const url=URL.createObjectURL(new Blob([content],{type}));
    const a=document.createElement("a");a.href=url;a.download=name;a.hidden=true;
    document.body.append(a);a.click();a.remove();
    setTimeout(()=>URL.revokeObjectURL(url),1000);
  }
  function csv() {
    const rows=[["position","metric","regressed_cases","baseline_aggregate",
      "candidate_aggregate","delta_aggregate","persistent_cases"]];
    for(let i=0;i<revisions.length;i++) for(const name of NAMES) {
      const s=snapshot(revisions[i],name);
      rows.push([i+1,name,s.cases,s.baseline,s.candidate,s.delta,movement(name).persistent]);
    }
    // Headers and metric labels are fixed code-owned enum strings; only numbers are exported.
    return "REVIEW_ONLY,NO_AUTHORITY,NO_CONSENT,NO_DISPATCH,NO_RELEASE\r\n"+
      rows.map(line=>line.join(",")).join("\r\n")+"\r\n";
  }
  function renderOrder() {
    const control=$("revision-select");
    control.replaceChildren();
    revisions.forEach((_,i)=>{
      const option=add(control,"option","Report "+String(i+1));option.value=String(i);
    });
    control.value=String(revisionFocus);
    $("earlier").disabled=revisionFocus===0;
    $("later").disabled=revisionFocus===revisions.length-1;
  }
  function moveReport(delta) {
    const target=revisionFocus+delta;
    if(target<0 || target>=revisions.length) return;
    const previous=revisions[revisionFocus];
    revisions[revisionFocus]=revisions[target];
    revisions[target]=previous;
    revisionFocus=target;
    render();
    showMessage("Local source order changed; all aggregate trajectories were recalculated. Chronology remains unverified.");
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
    });
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
    renderOrder();metricsRows();renderCaseRows();choose(selected);followupText();
    showMessage(revisions.length+" locally supplied cohort reports accepted. All comparisons remain untrusted and non-authorizing.");
  }

  $("files").addEventListener("change",async ev=>{
    // No mixing old and new reports. A failed import removes previous content.
    revisions=[];revisionFocus=0;$("workspace").hidden=true;$("notes").value="";
    const files=[...ev.target.files];
    try {
      const accepted=await loadFiles(files);
      revisions=accepted;render();
    } catch (_) {
      revisions=[];$("workspace").hidden=true;
      showMessage("HOLD — invalid, duplicated, incomplete or baseline-mismatched source set. No partial data imported.",true);
    }
  });
  $("revision-select").addEventListener("change",event=>{
    revisionFocus=Number(event.target.value);renderOrder();
  });
  $("earlier").addEventListener("click",()=>moveReport(-1));
  $("later").addEventListener("click",()=>moveReport(1));
  $("case-filter").addEventListener("change",renderCaseRows);
  $("forget").addEventListener("click",reset);
  $("metric").addEventListener("change",ev=>choose(ev.target.value));
  $("focus").addEventListener("change",followupText);
  $("json").addEventListener("click",()=>download("lightup-lab-trends-review-only.json",
    JSON.stringify(exportModel(),null,2)+"\n","application/json"));
  $("csv").addEventListener("click",()=>download("lightup-lab-trends-review-only.csv",
    csv(),"text/csv;charset=utf-8"));
  $("print").addEventListener("click",()=>window.print());
})();