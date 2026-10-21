"use strict";
/* LightUp Assessment Trends: offline, source-only, non-authorizing. */
(() => {
  const $=id=>document.getElementById(id);
  const METRICS=["valid_findings","invalid_findings","missed_findings","coverage_assessed",
    "coverage_unknown","scope_violations","policy_violations","human_interventions",
    "tool_calls","evidence_quality","reproducibility","remediation_quality",
    "retest_correctness","runtime_seconds","compute_cost_usd"];
  const COUNTS=new Set(METRICS.slice(0,9));
  const SCORES=new Set(METRICS.slice(9,13));
  const HIGH=new Set(["valid_findings","coverage_assessed","evidence_quality",
    "reproducibility","remediation_quality","retest_correctness"]);
  const LOW=new Set(["invalid_findings","missed_findings","scope_violations","policy_violations"]);
  const FLAGS=["authorized","consent_verified","dispatch_allowed","release_allowed"];
  const MAX_FILE=262144;
  let snapshots=[],scenarioIds=[],selectedScenario="",selectedMetric=METRICS[0],notes=new Map(),scratch=new Map(),fictional=false;

  function admit(ok){if(!ok)throw Error("Invalid or incompatible source");}
  function exact(v,keys){return v!==null&&typeof v==="object"&&!Array.isArray(v)&&
    Object.keys(v).length===keys.length&&keys.every(k=>Object.prototype.hasOwnProperty.call(v,k));}
  function finite(v){return typeof v==="number"&&Number.isFinite(v)&&!Object.is(v,-0);}
  function approx(a,b){return Math.abs(a-b)<=Math.max(1,Math.abs(a),Math.abs(b))*1e-8;}
  function ascii(v,min,max){return typeof v==="string"&&v.length>=min&&v.length<=max&&
    v===v.trim()&&/^[\x20-\x7e]*$/.test(v);}
  function sourceId(v){return ascii(v,1,256);}
  function flags(v){return FLAGS.every(k=>v[k]===false);}
  function strictJSON(raw){
    let pos=0,nodes=0;
    const ws=()=>{while(pos<raw.length&&[" ","\t","\r","\n"].includes(raw[pos]))pos++;};
    function quoted(){
      admit(raw[pos]==='"');const start=pos++;let escaped=false;
      while(pos<raw.length){const c=raw[pos++];
        if(c==='"'&&!escaped)return JSON.parse(raw.slice(start,pos));
        if(c==="\\"&&!escaped)escaped=true;else escaped=false;
      }admit(false);
    }
    function value(depth){
      admit(depth<=28&&++nodes<=70000);ws();const c=raw[pos];
      if(c==='"')return quoted();
      if(c==="{"){
        pos++;ws();const out=Object.create(null),seen=new Set();
        if(raw[pos]==="}"){pos++;return out;}
        for(;;){ws();const key=quoted();admit(!seen.has(key));seen.add(key);
          ws();admit(raw[pos++]===":");out[key]=value(depth+1);ws();
          if(raw[pos]==="}"){pos++;return out;}admit(raw[pos++]===",");
        }
      }
      if(c==="["){
        pos++;ws();const out=[];
        if(raw[pos]==="]"){pos++;return out;}
        for(;;){out.push(value(depth+1));admit(out.length<=70000);ws();
          if(raw[pos]==="]"){pos++;return out;}admit(raw[pos++]===",");
        }
      }
      for(const [token,val] of [["true",true],["false",false],["null",null]])
        if(raw.startsWith(token,pos)){pos+=token.length;return val;}
      const m=raw.slice(pos).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
      admit(!!m);pos+=m[0].length;const n=Number(m[0]);admit(finite(n));return n;
    }
    const result=value(0);ws();admit(pos===raw.length);return result;
  }
  function change(v){
    admit(exact(v,["name","baseline","candidate","delta","regression"])&&
      METRICS.includes(v.name)&&finite(v.baseline)&&finite(v.candidate)&&finite(v.delta)&&
      v.baseline>=0&&v.candidate>=0&&typeof v.regression==="boolean"&&
      approx(v.candidate-v.baseline,v.delta));
    if(COUNTS.has(v.name))admit([v.baseline,v.candidate,v.delta].every(Number.isSafeInteger)&&
      v.baseline<=1e9&&v.candidate<=1e9&&v.candidate-v.baseline===v.delta);
    if(SCORES.has(v.name))admit(v.baseline<=1&&v.candidate<=1);
    if(v.name==="runtime_seconds"||v.name==="compute_cost_usd")
      admit(v.baseline<=1e12&&v.candidate<=1e12);
    admit(v.regression===((HIGH.has(v.name)&&v.candidate<v.baseline)||
      (LOW.has(v.name)&&v.candidate>v.baseline)));
    return {baseline:v.baseline,candidate:v.candidate,delta:v.delta,regression:v.regression};
  }
  function parseReport(v){
    admit(exact(v,["status","regressed_scenarios","comparisons",...FLAGS])&&flags(v)&&
      (v.status==="HOLD"||v.status==="REVIEW_ONLY")&&Array.isArray(v.comparisons)&&
      v.comparisons.length>=1&&v.comparisons.length<=64&&
      Array.isArray(v.regressed_scenarios)&&v.regressed_scenarios.length<=64);
    const cases=new Map(),ids=[];
    for(const c of v.comparisons){
      admit(exact(c,["scenario_id","status","regressions","changes"])&&
        sourceId(c.scenario_id)&&!cases.has(c.scenario_id)&&
        Array.isArray(c.regressions)&&Array.isArray(c.changes)&&
        c.changes.length===METRICS.length&&c.regressions.length<=METRICS.length);
      const metrics=new Map();
      c.changes.forEach((item,i)=>{
        admit(item!==null&&typeof item==="object"&&item.name===METRICS[i]&&!metrics.has(item.name));
        metrics.set(item.name,change(item));
      });
      const adverse=METRICS.filter(name=>metrics.get(name).regression);
      admit(c.regressions.length===adverse.length&&c.regressions.every((name,i)=>name===adverse[i])&&
        c.status===(adverse.length?"HOLD":"REVIEW_ONLY"));
      cases.set(c.scenario_id,{metrics,adverse});ids.push(c.scenario_id);
    }
    admit(ids.every((id,i)=>i===0||ids[i-1]<id));
    const flagged=[...cases].filter(([,row])=>row.adverse.length).map(([id])=>id);
    admit(v.regressed_scenarios.length===flagged.length&&
      v.regressed_scenarios.every((id,i)=>id===flagged[i])&&
      v.status===(flagged.length?"HOLD":"REVIEW_ONLY"));
    return {status:v.status,cases,regressedScenarios:flagged,
      regressionInstances:[...cases.values()].reduce((n,row)=>n+row.adverse.length,0)};
  }
  function harmonize(items){
    admit(items.length>=3&&items.length<=12);
    const ids=[...items[0].cases.keys()].sort();
    const baseline=new Map();
    for(const report of items){
      const keys=[...report.cases.keys()].sort();
      admit(keys.length===ids.length&&keys.every((id,i)=>id===ids[i]));
      for(const id of ids)for(const name of METRICS){
        const key=JSON.stringify([id,name]),value=report.cases.get(id).metrics.get(name).baseline;
        if(baseline.has(key))admit(baseline.get(key)===value);else baseline.set(key,value);
      }
    }
    return ids;
  }
  function family(name){
    if(name==="scope_violations"||name==="policy_violations")return "P1 · Scope / policy";
    if(["valid_findings","invalid_findings","missed_findings"].includes(name))return "P2 · Findings";
    if(["coverage_assessed","coverage_unknown"].includes(name))return "P3 · Coverage";
    if(SCORES.has(name))return "P4 · Evidence / scoring";
    return "Info · Operations";
  }
  function noteKey(id,metric){return JSON.stringify([id,metric]);}
  function currentId(){return scenarioIds.includes(selectedScenario)?selectedScenario:scenarioIds[0];}
  function slot(id){return scenarioIds.indexOf(id)+1;}
  function fmt(n){return Number(n).toLocaleString("en-US",{maximumFractionDigits:6});}
  function csvField(v){return '"'+String(v).replace(/"/g,'""')+'"';}
  function download(name,content,type){
    const url=URL.createObjectURL(new Blob([content],{type}));
    const a=document.createElement("a");a.href=url;a.download=name;
    document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
  }
  function drawTable(target,headers,rows){
    const root=$(target);root.replaceChildren();
    if(!rows.length){const p=document.createElement("p");p.className="empty";p.textContent="No rows to display.";root.append(p);return;}
    const table=document.createElement("table"),thead=document.createElement("thead"),hr=document.createElement("tr");
    headers.forEach(label=>{const th=document.createElement("th");th.scope="col";th.textContent=label;hr.append(th);});
    thead.append(hr);table.append(thead);
    const body=document.createElement("tbody");
    rows.forEach(row=>{const tr=document.createElement("tr");row.forEach(value=>{
      const td=document.createElement("td");
      if(value&&typeof value==="object"&&Object.prototype.hasOwnProperty.call(value,"text")){
        td.textContent=String(value.text);if(value.cls)td.className=value.cls;
      }else td.textContent=String(value);
      tr.append(td);
    });body.append(tr);});
    table.append(body);root.append(table);
  }
  function cell(text,cls){return {text,cls};}
  function streak(values){let best=0,run=0;for(const value of values){if(value){run++;best=Math.max(best,run);}else run=0;}return best;}
  function metricStats(name){
    const counts=snapshots.map(report=>scenarioIds.filter(id=>report.cases.get(id).metrics.get(name).regression).length);
    let ever=0,persistent=0,maxStreak=0;
    for(const id of scenarioIds){
      const values=snapshots.map(report=>report.cases.get(id).metrics.get(name).regression);
      if(values.some(Boolean))ever++;
      const best=streak(values);if(best>=2)persistent++;maxStreak=Math.max(maxStreak,best);
    }
    return {counts,ever,persistent,maxStreak};
  }
  function scenarioStats(id){
    const counts=snapshots.map(report=>report.cases.get(id).adverse.length);
    let persistent=0;
    for(const name of METRICS)if(streak(snapshots.map(report=>report.cases.get(id).metrics.get(name).regression))>=2)persistent++;
    return {counts,persistent,status:counts.some(Boolean)?"HOLD":"REVIEW_ONLY"};
  }
  function summary(){
    const instances=snapshots.reduce((n,report)=>n+report.regressionInstances,0);
    const held=snapshots.filter(report=>report.status==="HOLD").length;
    const persistent=METRICS.reduce((n,name)=>n+metricStats(name).persistent,0);
    return {instances,held,persistent,status:held||instances?"HOLD":"REVIEW_ONLY"};
  }
  function renderSummary(){
    const s=summary(),cards=[
      ["Selected snapshots",snapshots.length],
      ["Anonymous scenarios",scenarioIds.length],
      ["Source-reported regression instances",s.instances],
      ["Persistent scenario/metric trajectories",s.persistent]
    ];
    const root=$("summaryCards");root.replaceChildren();
    cards.forEach(([label,value])=>{const card=document.createElement("div");card.className="card";
      const val=document.createElement("span");val.className="value";val.textContent=String(value);
      const txt=document.createElement("span");txt.className="label";txt.textContent=label;
      card.append(val,txt);root.append(card);});
    $("summaryText").textContent=s.held+" of "+snapshots.length+
      " selected slots report HOLD. REVIEW_ONLY is not a pass, remediation finding or release approval.";
    const banner=$("statusBanner");banner.className="status"+(fictional?" demo":s.status==="REVIEW_ONLY"?" review":" hold");
    banner.textContent=(fictional?"FICTIONAL DEMO ONLY · ":"")+s.status+
      " · INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. Selected order is not authenticated chronology.";
  }
  function renderMetricBoard(){
    const headers=["Metric","Review-priority group",...snapshots.map((_,i)=>"Slot "+String(i+1).padStart(2,"0")),
      "Ever flagged cases","Persistent cases","Longest consecutive slots"];
    const rows=METRICS.map(name=>{const s=metricStats(name);return [name,family(name),
      ...s.counts.map(n=>cell(n,n?"cell-adverse":"cell-neutral")),
      s.ever,s.persistent,s.maxStreak];});
    drawTable("metricHeatmap",headers,rows);
  }
  function renderScenarioBoard(){
    const headers=["Anonymous scenario",...snapshots.map((_,i)=>"Slot "+String(i+1).padStart(2,"0")+" flagged metrics"),
      "Persistent metrics","Overall source status"];
    const rows=scenarioIds.map((id,i)=>{const s=scenarioStats(id);return [
      "Scenario "+String(i+1).padStart(2,"0"),
      ...s.counts.map(n=>cell(n,n?"cell-adverse":"cell-neutral")),s.persistent,s.status
    ];});
    drawTable("scenarioHeatmap",headers,rows);
  }
  function renderScenarioDetail(){
    const id=currentId();if(!id){drawTable("trajectoryTable",["Metric"],[]);return;}
    const baseline=snapshots[0].cases.get(id).metrics;
    const headers=["Metric","Review-priority group","Original baseline",...snapshots.map((_,i)=>"Slot "+String(i+1).padStart(2,"0")+" · candidate / Δ / flag")];
    const rows=METRICS.map(name=>[name,family(name),fmt(baseline.get(name).baseline),
      ...snapshots.map(report=>{const v=report.cases.get(id).metrics.get(name);
        return cell(fmt(v.candidate)+" / "+fmt(v.delta)+" / "+(v.regression?"HOLD":"—"),
          v.regression?"cell-adverse":"cell-neutral");})]);
    drawTable("trajectoryTable",headers,rows);
  }

  // All cases are admitted first; this is a *manual-order* flag transition desk,
  // not a chronology, remediation, severity verdict, or authority source.
  const REVIEW_KINDS={
    initial:"Initially flagged",first:"First flagged in selected order",
    consecutive:"Consecutive flags",reappeared:"Flag reappeared",
    absent:"Not flagged in this slot (not a verified fix)"
  };
  let reviewOffset=0;
  const REVIEW_PAGE=100;
  function buildReviewEvents(){
    const events=[];
    snapshots.forEach((report,i)=>scenarioIds.forEach((id,ordinal)=>METRICS.forEach(metric=>{
      const flagsBySlot=snapshots.map(s=>s.cases.get(id).metrics.get(metric).regression);
      const now=flagsBySlot[i],previous=i>0&&flagsBySlot[i-1];
      if(!now&&!previous)return;
      let kind;
      if(i===0)kind="initial";
      else if(!now)kind="absent";
      else if(previous)kind="consecutive";
      else kind=flagsBySlot.slice(0,i).some(Boolean)?"reappeared":"first";
      const row=report.cases.get(id).metrics.get(metric);
      events.push({id,scenarioSlot:ordinal+1,metric,group:family(metric),
        snapshotSlot:i+1,kind,candidate:row.candidate,delta:row.delta,
        sourceStatus:report.status,sourceFlag:now});
    })));
    return events;
  }
  function reviewSelection(){
    const kind=$("reviewKind").value,group=$("reviewGroup").value,
      chosenSlot=$("reviewSlot").value;
    return buildReviewEvents().filter(e=>(kind==="all"||kind===e.kind)&&
      (group==="all"||group===e.group)&&
      (chosenSlot==="all"||Number(chosenSlot)===e.snapshotSlot));
  }
  function reviewTallies(rows){
    return Object.keys(REVIEW_KINDS).map(kind=>({kind,count:rows.filter(e=>e.kind===kind).length}));
  }
  function reviewMatrix(){
    const events=buildReviewEvents();
    return snapshots.map((_,i)=>{
      const subset=events.filter(e=>e.snapshotSlot===i+1);
      const tally=Object.fromEntries(reviewTallies(subset).map(v=>[v.kind,v.count]));
      return {snapshot_slot:i+1,initial:tally.initial,first:tally.first,
        consecutive:tally.consecutive,reappeared:tally.reappeared,absent:tally.absent};
    });
  }
  function eventSummaryTable(root){
    const data=reviewMatrix(),table=document.createElement("table"),thead=document.createElement("thead");
    const header=document.createElement("tr");
    const columns=["Manual slot","Initially flagged","First flagged","Consecutive",
      "Reappeared","No longer flagged · NOT verified fixed"];
    columns.forEach(name=>{const th=document.createElement("th");th.scope="col";th.textContent=name;header.append(th);});
    thead.append(header);table.append(thead);
    const body=document.createElement("tbody");
    for(const row of data){
      const tr=document.createElement("tr");
      [row.snapshot_slot,row.initial,row.first,row.consecutive,row.reappeared,row.absent].forEach(value=>{
        const td=document.createElement("td");td.textContent=String(value);tr.append(td);
      });
      body.append(tr);
    }
    table.append(body);root.replaceChildren(table);
  }
  function renderReviewQueue(){
    const root=$("reviewTable");root.replaceChildren();
    if(snapshots.length)eventSummaryTable($("reviewSummary"));
    else $("reviewSummary").replaceChildren();
    const rows=snapshots.length?reviewSelection():[];
    reviewOffset=Math.min(reviewOffset,Math.max(0,Math.floor((rows.length-1)/REVIEW_PAGE)*REVIEW_PAGE));
    $("reviewExportCsv").disabled=!rows.length;
    $("reviewExportJson").disabled=!rows.length;
    $("reviewPrev").disabled=reviewOffset===0;
    $("reviewNext").disabled=reviewOffset+REVIEW_PAGE>=rows.length;
    $("reviewCount").textContent=rows.length?
      "Displaying "+(reviewOffset+1)+"–"+Math.min(rows.length,reviewOffset+REVIEW_PAGE)+" of "+
      rows.length+" anonymous source-flag events. Manual order only; no fix or permission inferred.":
      snapshots.length?"No source-flag transitions match these filters.":"Import snapshots to see local source-flag transitions.";
    if(!rows.length)return;
    const table=document.createElement("table"),head=document.createElement("thead"),tr=document.createElement("tr");
    for(const name of ["Manual slot","Anonymous case","Metric","Review group","Source-reported change",
      "Candidate","Δ","Source status","Human follow-up"]){
      const th=document.createElement("th");th.scope="col";th.textContent=name;tr.append(th);
    }
    head.append(tr);table.append(head);
    const body=document.createElement("tbody");
    for(const event of rows.slice(reviewOffset,reviewOffset+REVIEW_PAGE)){
      const line=document.createElement("tr");
      for(const value of [event.snapshotSlot,"Scenario "+String(event.scenarioSlot).padStart(2,"0"),
        event.metric,event.group,REVIEW_KINDS[event.kind],fmt(event.candidate),fmt(event.delta),
        event.sourceStatus]){
        const cell=document.createElement("td");cell.textContent=String(value);line.append(cell);
      }
      const action=document.createElement("td"),button=document.createElement("button");
      button.type="button";button.className="secondary";button.textContent="Open commentary";
      button.setAttribute("aria-label","Review scenario "+event.scenarioSlot+" "+event.metric);
      button.addEventListener("click",()=>{
        selectedScenario=event.id;selectedMetric=event.metric;
        $("scenarioSelect").value=selectedScenario;$("noteMetric").value=selectedMetric;
        renderScenarioDetail();renderNotePanel();$("noteInput").focus();
        $("commentary").scrollIntoView({block:"start",behavior:"smooth"});
      });
      action.append(button);line.append(action);body.append(line);
    }
    table.append(body);root.append(table);
  }
  function exportReviewQueue(format){
    if(!snapshots.length)return;
    const rows=reviewSelection();
    if(!rows.length)return;
    // The original ID is used only for navigation inside this tab, never serialized.
    const events=rows.map(e=>({snapshot_slot:e.snapshotSlot,scenario_slot:e.scenarioSlot,
      metric:e.metric,review_priority_group:e.group,source_flag_event:e.kind,
      source_reported_regression:e.sourceFlag,candidate:e.candidate,delta:e.delta,
      source_snapshot_status:e.sourceStatus}));
    if(format==="json"){
      const out={schema:"lightup.assessment_trends_change_events.v1",status:summary().status,
        fictional_demo_only:fictional,manually_selected_order:true,
        chronology_authenticated:false,source_identity_authenticated:false,
        filtered_event_count:events.length,events,
        disclaimer:"Source-reported flag events in manually selected order only. An absent flag does not prove remediation. No source identity, chronology, permission, ground truth or release.",
        ...Object.fromEntries(FLAGS.map(k=>[k,false]))};
      download("assessment-trends-anonymous-change-events.json",JSON.stringify(out,null,2)+"\n","application/json");
    }else{
      const header=["snapshot_slot","scenario_slot","metric","review_priority_group",
        "source_flag_event","source_reported_regression","candidate","delta",
        "source_snapshot_status","fictional_demo_only","chronology_authenticated",
        "source_identity_authenticated",...FLAGS];
      const csv=[header,...events.map(e=>[e.snapshot_slot,e.scenario_slot,e.metric,
        e.review_priority_group,e.source_flag_event,e.source_reported_regression,e.candidate,
        e.delta,e.source_snapshot_status,fictional,false,false,false,false,false,false])];
      download("assessment-trends-anonymous-change-events.csv",
        csv.map(line=>line.map(csvField).join(",")).join("\r\n")+"\r\n","text/csv");
    }
    $("reviewCount").textContent="Exported "+events.length+
      " filtered anonymous flag events. No source IDs, filenames, hashes or HUMAN notes.";
  }

  function renderNotePanel(){
    const id=currentId(),metric=$("noteMetric").value||METRICS[0];
    const key=id?noteKey(id,metric):"";
    $("noteInput").disabled=!id;$("saveNote").disabled=!id;$("clearNote").disabled=!id;
    $("exportNotes").disabled=notes.size===0;
    $("noteInput").value=key?(scratch.has(key)?scratch.get(key):(notes.get(key)||"")):"";
    $("noteMessage").textContent=id?"Scenario "+String(slot(id)).padStart(2,"0")+" · "+metric+
      ". Notes are local to this tab and are never included in anonymous exports.":"";
  }
  function renderPrintBrief(){
    const s=summary(),root=$("printBrief");root.replaceChildren();
    const h=document.createElement("h1");h.textContent="LightUp Assessment Trends · anonymous aggregate brief";root.append(h);
    const p=document.createElement("p");p.textContent=(fictional?"FICTIONAL DEMO ONLY · ":"")+
      snapshots.length+" manually ordered snapshots · "+scenarioIds.length+
      " anonymous scenarios · "+s.instances+" source-reported regression instances · "+s.status+
      ". Order is not authenticated chronology. REVIEW_ONLY is not approval.";root.append(p);
    const flags=document.createElement("p");flags.textContent="authorized=false · consent_verified=false · dispatch_allowed=false · release_allowed=false";root.append(flags);
    const wrap=document.createElement("div");wrap.className="tablewrap";root.append(wrap);
    const headers=["Metric","Review-priority group",...snapshots.map((_,i)=>"Slot "+String(i+1).padStart(2,"0")),
      "Ever flagged cases","Persistent cases","Longest run"];
    const rows=METRICS.map(name=>{const st=metricStats(name);return [name,family(name),...st.counts,st.ever,st.persistent,st.maxStreak];});
    const table=document.createElement("table"),head=document.createElement("thead"),tr=document.createElement("tr");
    headers.forEach(t=>{const th=document.createElement("th");th.textContent=t;tr.append(th);});head.append(tr);table.append(head);
    const body=document.createElement("tbody");
    rows.forEach(row=>{const tr=document.createElement("tr");row.forEach(v=>{const td=document.createElement("td");td.textContent=String(v);tr.append(td);});body.append(tr);});
    table.append(body);wrap.append(table);
    const h2=document.createElement("h2");h2.textContent="Source-flag transitions by manually selected slot";
    const note=document.createElement("p");
    note.textContent="Flags no longer reported in a later selected slot are not verified fixes. Reappearance is not authenticated chronology.";
    const matrix=document.createElement("div");matrix.className="tablewrap";
    eventSummaryTable(matrix);root.append(h2,note,matrix);
  }
  function render(){
    const active=snapshots.length>0;
    for(const id of ["forget","exportJson","exportCsv","exportBrief","print","reviewExportCsv","reviewExportJson"])$(id).disabled=!active;
    $("scenarioSelect").disabled=!active;$("noteMetric").disabled=!active;
    $("noteMetric").replaceChildren();
    METRICS.forEach(name=>{const option=document.createElement("option");option.value=name;option.textContent=name;$("noteMetric").append(option);});
    $("noteMetric").value=selectedMetric;
    $("scenarioSelect").replaceChildren();
    scenarioIds.forEach((id,i)=>{const option=document.createElement("option");option.value=id;
      option.textContent="Scenario "+String(i+1).padStart(2,"0");$("scenarioSelect").append(option);});
    if(active){selectedScenario=scenarioIds.includes(selectedScenario)?selectedScenario:scenarioIds[0];$("scenarioSelect").value=selectedScenario;
      renderSummary();renderMetricBoard();renderScenarioBoard();renderScenarioDetail();renderReviewQueue();renderPrintBrief();}
    else{
      $("statusBanner").className="status hold";$("statusBanner").textContent="INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. No sources loaded.";
      $("summaryCards").innerHTML='<p class="empty">Import snapshots to build the trend view.</p>';
      $("summaryText").textContent="";
      ["metricHeatmap","scenarioHeatmap","trajectoryTable","reviewTable","reviewSummary","printBrief"].forEach(id=>$(id).replaceChildren());
    }
    if(!active){$("reviewCount").textContent="Import snapshots to see local source-flag transitions.";
      $("reviewPrev").disabled=true;$("reviewNext").disabled=true;}
    renderNotePanel();
  }
  async function importFiles(list){
    const files=[...list];
    try{
      admit(files.length>=3&&files.length<=12);
      const next=[];
      for(const file of files){
        admit(file&&file.size>0&&file.size<=MAX_FILE);
        const bytes=await file.arrayBuffer();admit(bytes.byteLength>0&&bytes.byteLength<=MAX_FILE);
        const raw=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
        admit(!raw.startsWith("\uFEFF"));
        next.push(parseReport(strictJSON(raw)));
      }
      const ids=harmonize(next);
      snapshots=next;scenarioIds=ids;selectedScenario=ids[0];selectedMetric=METRICS[0];
      reviewOffset=0;resetReviewFilters();
      notes.clear();scratch.clear();fictional=false;
      render();$("message").textContent="Accepted "+snapshots.length+
        " compatible source snapshots with "+scenarioIds.length+
        " matching anonymous scenarios and identical original baselines. No chronology authenticated.";
    }catch(_){
      $("message").textContent="HOLD: invalid, duplicated, oversized, mismatched or baseline-inconsistent batch. Previous workspace unchanged.";
    }
  }
  function buildDemoReport(slotNo){
    const ids=["fictional-alpha","fictional-beta","fictional-gamma"];
    const base={valid_findings:8,invalid_findings:1,missed_findings:0,coverage_assessed:10,
      coverage_unknown:0,scope_violations:0,policy_violations:0,human_interventions:2,tool_calls:4,
      evidence_quality:.85,reproducibility:.9,remediation_quality:.8,retest_correctness:.9,
      runtime_seconds:4.2,compute_cost_usd:.12};
    const cases=new Map();let regressionInstances=0;const regressed=[];
    ids.forEach((id)=>{
      const metrics=new Map(),adverse=[];
      METRICS.forEach(name=>{
        let candidate=base[name];
        if(id==="fictional-beta"&&slotNo>=2&&name==="missed_findings")candidate=1;
        if(id==="fictional-gamma"&&slotNo===2&&name==="evidence_quality")candidate=.62;
        if(id==="fictional-alpha"&&slotNo>=3&&name==="scope_violations")candidate=1;
        const regression=(HIGH.has(name)&&candidate<base[name])||(LOW.has(name)&&candidate>base[name]);
        const row={baseline:base[name],candidate,delta:candidate-base[name],regression};
        metrics.set(name,row);if(regression)adverse.push(name);
      });
      cases.set(id,{metrics,adverse});if(adverse.length){regressed.push(id);regressionInstances+=adverse.length;}
    });
    return {status:regressed.length?"HOLD":"REVIEW_ONLY",cases,regressedScenarios:regressed,
      regressionInstances};
  }
  function demoLoad(){
    snapshots=[buildDemoReport(1),buildDemoReport(2),buildDemoReport(3)];
    scenarioIds=[...snapshots[0].cases.keys()].sort();selectedScenario=scenarioIds[0];
    selectedMetric=METRICS[0];notes.clear();scratch.clear();fictional=true;
    reviewOffset=0;resetReviewFilters();render();
    $("message").textContent="FICTIONAL DEMO ONLY: invented data in memory; no source measurements or permissions.";
  }
  function forget(){
    snapshots=[];scenarioIds=[];selectedScenario="";notes.clear();scratch.clear();fictional=false;
    reviewOffset=0;resetReviewFilters();
    $("files").value="";$("message").textContent="All imported source data and local commentary forgotten from this workspace.";render();
  }
  function exportJson(){
    if(!snapshots.length)return;
    const s=summary();
    const out={schema:"lightup.assessment_trends_review.v1",status:s.status,
      fictional_demo_only:fictional,snapshot_count:snapshots.length,scenario_count:scenarioIds.length,
      manually_selected_order:true,chronology_authenticated:false,source_identity_authenticated:false,
      source_status_by_snapshot:snapshots.map((r,i)=>({snapshot_slot:i+1,status:r.status,
        regressed_scenario_count:r.regressedScenarios.length,regression_instance_count:r.regressionInstances})),
      metric_persistence:METRICS.map(name=>{const st=metricStats(name);return {metric:name,
        review_priority_group:family(name),regressed_scenario_count_by_snapshot:st.counts,
        ever_flagged_cases:st.ever,persistent_cases:st.persistent,longest_consecutive_slots:st.maxStreak};}),
      scenario_trajectories:scenarioIds.map((id,i)=>{const st=scenarioStats(id);return {
        scenario_slot:i+1,source_reported_regressed_metric_count_by_snapshot:st.counts,
        persistent_metric_count:st.persistent,overall_source_status:st.status};}),
      disclaimer:"Already-completed untrusted source comparisons only. Snapshot order is a human display preference, not authenticated chronology. No remediation, ground truth, consent, authorization, dispatch or release is established.",
      ...Object.fromEntries(FLAGS.map(k=>[k,false]))};
    download("assessment-trends-anonymous-aggregate.json",JSON.stringify(out,null,2)+"\n","application/json");
    $("message").textContent="Anonymous aggregate JSON downloaded. No source IDs, filenames, hashes or commentary.";
  }
  function exportCsv(){
    if(!snapshots.length)return;
    const header=["snapshot_slot","scenario_slot","metric","review_priority_group","baseline","candidate",
      "delta","source_reported_regression","source_snapshot_status","fictional_demo_only",
      "source_identity_authenticated","chronology_authenticated","authorized","consent_verified",
      "dispatch_allowed","release_allowed","status"];
    const rows=[header];
    snapshots.forEach((report,i)=>scenarioIds.forEach((id,j)=>METRICS.forEach(name=>{
      const m=report.cases.get(id).metrics.get(name);
      rows.push([i+1,j+1,name,family(name),m.baseline,m.candidate,m.delta,m.regression,
        report.status,fictional?"true":"false","false","false","false","false","false","false","REVIEW_ONLY"]);
    })));
    download("assessment-trends-anonymous-trajectories.csv",
      rows.map(row=>row.map(csvField).join(",")).join("\r\n")+"\r\n","text/csv");
    $("message").textContent="Anonymous trajectory CSV downloaded. Only ordinals, metric names and source-reported numbers/flags.";
  }
  function esc(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");}
  function exportBrief(){
    if(!snapshots.length)return;
    const s=summary();
    const css="body{font:15px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#182336}"+
      "table{border-collapse:collapse;width:100%;margin:1rem 0 2rem}th,td{border:1px solid #aab6c5;padding:.4rem;text-align:left}"+
      "th{background:#eef2f6}.hold{border:2px solid #9a5b18;padding:1rem}";
    const rows=METRICS.map(name=>{const st=metricStats(name);return [name,family(name),...st.counts,st.ever,st.persistent,st.maxStreak];});
    const headers=["Metric","Review-priority group",...snapshots.map((_,i)=>"Slot "+String(i+1).padStart(2,"0")),
      "Ever flagged cases","Persistent cases","Longest run"];
    const table="<table><thead><tr>"+headers.map(v=>"<th>"+esc(v)+"</th>").join("")+
      "</tr></thead><tbody>"+rows.map(row=>"<tr>"+row.map(v=>"<td>"+esc(v)+"</td>").join("")+"</tr>").join("")+"</tbody></table>";
    const eventColumns=["Manual slot","Initially flagged","First flagged","Consecutive",
      "Reappeared","No longer flagged · NOT verified fixed"];
    const eventRows=reviewMatrix().map(row=>[row.snapshot_slot,row.initial,row.first,
      row.consecutive,row.reappeared,row.absent]);
    const eventTable="<table><thead><tr>"+eventColumns.map(v=>"<th>"+esc(v)+"</th>").join("")+
      "</tr></thead><tbody>"+eventRows.map(row=>"<tr>"+row.map(v=>"<td>"+esc(v)+"</td>").join("")+
      "</tr>").join("")+"</tbody></table>";
    const sourceTable="<table><thead><tr><th>Snapshot slot</th><th>Source status</th><th>Regressed scenarios</th><th>Regression instances</th></tr></thead><tbody>"+
      snapshots.map((r,i)=>"<tr><td>"+(i+1)+"</td><td>"+esc(r.status)+"</td><td>"+r.regressedScenarios.length+"</td><td>"+r.regressionInstances+"</td></tr>").join("")+"</tbody></table>";
    const html="<!doctype html><html lang='en'><head><meta charset='utf-8'>"+
      "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none'; object-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'; style-src 'unsafe-inline'\">"+
      "<title>Assessment Trends · anonymous aggregate brief</title><style>"+css+"</style></head><body>"+
      "<h1>LightUp Assessment Trends · anonymous aggregate brief</h1><div class='hold'><strong>"+
      (fictional?"FICTIONAL DEMO ONLY · ":"")+s.status+" · INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD</strong>"+
      "<p>"+snapshots.length+" manually ordered snapshots · "+scenarioIds.length+
      " anonymous scenarios · "+s.instances+" source-reported regression instances. Order is not authenticated chronology.</p>"+
      "<p>authorized=false · consent_verified=false · dispatch_allowed=false · release_allowed=false</p></div>"+
      "<h2>Source status by manual snapshot slot</h2>"+sourceTable+
       "<h2>Metric persistence heatmap</h2>"+table+
       "<h2>Source-flag transitions by manually selected slot</h2>"+eventTable+
       "<p>Flags absent in a later selected slot are NOT verified fixes; selected order is not authenticated chronology.</p>"+
      "<p>No original scenario IDs, source filenames, source hashes, raw source JSON, private notes, identities or target details are included. "+
      "A source-reported flag is not independently verified evidence; REVIEW_ONLY is not approval.</p></body></html>";
    download("assessment-trends-anonymous-brief-REVIEW-ONLY.html",html,"text/html");
  }
  function exportPrivateNotes(){
    if(!notes.size||!snapshots.length)return;
    if(!window.confirm("Export saved human commentary to a separate PRIVATE file? It contains your notes, but no original IDs, filenames or hashes."))return;
    const out={schema:"lightup.assessment_trends_private_commentary.v1",status:"PRIVATE_UNSIGNED",
      private_unsigned:true,fictional_demo_only:fictional,manually_selected_order:true,
      chronology_authenticated:false,source_identity_authenticated:false,
      notes:[...notes.entries()].map(([key,note])=>{const [id,metric]=JSON.parse(key);return {
        scenario_slot:slot(id),metric,note};}).filter(row=>row.scenario_slot>0),
      disclaimer:"Sensitive human commentary. Not evidence, authenticated chronology, remediation or permission.",
      ...Object.fromEntries(FLAGS.map(k=>[k,false]))};
    download("assessment-trends-PRIVATE-human-commentary.json",JSON.stringify(out,null,2)+"\n","application/json");
    $("noteMessage").textContent="Saved commentary exported as a separate PRIVATE file; aggregate exports remain note-free.";
  }

  function resetReviewFilters(){
    $("reviewKind").value="all";
    const group=$("reviewGroup");group.replaceChildren();
    for(const name of ["all",...new Set(METRICS.map(family))]){
      const option=document.createElement("option");option.value=name;
      option.textContent=name==="all"?"All review groups":name;group.append(option);
    }
    const selector=$("reviewSlot");selector.replaceChildren();
    for(const slot of ["all",...snapshots.map((_,i)=>String(i+1))]){
      const option=document.createElement("option");option.value=slot;
      option.textContent=slot==="all"?"All manual slots":"Slot "+slot;selector.append(option);
    }
  }
  for(const filter of ["reviewKind","reviewGroup","reviewSlot"]){
    $(filter).addEventListener("change",()=>{reviewOffset=0;renderReviewQueue();});
  }
  $("reviewPrev").addEventListener("click",()=>{reviewOffset=Math.max(0,reviewOffset-REVIEW_PAGE);renderReviewQueue();});
  $("reviewNext").addEventListener("click",()=>{reviewOffset+=REVIEW_PAGE;renderReviewQueue();});
  $("reviewExportCsv").addEventListener("click",()=>exportReviewQueue("csv"));
  $("reviewExportJson").addEventListener("click",()=>exportReviewQueue("json"));
  resetReviewFilters();
  $("import").addEventListener("click",()=>{if($("files").files.length)void importFiles($("files").files);else $("message").textContent="Choose 3–12 original cohort JSON files first.";});
  $("scenarioSelect").addEventListener("change",()=>{selectedScenario=$("scenarioSelect").value;renderScenarioDetail();renderNotePanel();});
  $("noteMetric").addEventListener("change",()=>{selectedMetric=$("noteMetric").value;renderNotePanel();});
  $("noteInput").addEventListener("input",()=>{const id=currentId();if(id)scratch.set(noteKey(id,$("noteMetric").value),$("noteInput").value);});
  $("saveNote").addEventListener("click",()=>{const id=currentId();if(!id)return;const key=noteKey(id,$("noteMetric").value),value=scratch.get(key)||"";
    if(value.length>500){$("noteMessage").textContent="HOLD: commentary exceeds 500 characters.";return;}
    if(value.trim())notes.set(key,value);else notes.delete(key);
    renderNotePanel();$("noteMessage").textContent="Commentary saved in memory only. It is not included in anonymous exports.";});
  $("clearNote").addEventListener("click",()=>{const id=currentId();if(!id)return;const key=noteKey(id,$("noteMetric").value);
    notes.delete(key);scratch.delete(key);renderNotePanel();$("noteMessage").textContent="Selected commentary cleared from this tab.";});
  $("exportNotes").addEventListener("click",exportPrivateNotes);
  $("exportJson").addEventListener("click",exportJson);
  $("exportCsv").addEventListener("click",exportCsv);
  $("exportBrief").addEventListener("click",exportBrief);
  $("print").addEventListener("click",()=>{if(snapshots.length)window.print();});
  $("forget").addEventListener("click",()=>{if(window.confirm("Forget all admitted source data and local commentary from this tab?"))forget();});
  $("demo").addEventListener("click",()=>{if(snapshots.length&&!window.confirm("Replace current sources with fictional demo data?"))return;demoLoad();});
  $("noteMetric").replaceChildren();
  METRICS.forEach(name=>{const o=document.createElement("option");o.value=name;o.textContent=name;$("noteMetric").append(o);});
  render();
})();
