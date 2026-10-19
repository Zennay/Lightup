"use strict";
/* Original-source declaration matrix: offline HUMAN interpretation, never a verifier. */
(() => {
  const $ = id => document.getElementById(id);
  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const METRICS = ["valid_findings","invalid_findings","missed_findings","coverage_assessed",
    "coverage_unknown","scope_violations","policy_violations","human_interventions",
    "tool_calls","evidence_quality","reproducibility","remediation_quality",
    "retest_correctness","runtime_seconds","compute_cost_usd","false_positive_rate"];
  const NUMERIC_COUNTS = new Set(METRICS.slice(0,9));
  const SCORES = new Set(["evidence_quality","reproducibility","remediation_quality",
    "retest_correctness","false_positive_rate"]);
  const FLAGS = Object.freeze({authorized:false,consent_verified:false,
    dispatch_allowed:false,release_allowed:false});
  const MAX_SOURCE_BYTES = 8 * 1024 * 1024;
  let sources = [], rows = [], visible = [], selected = null;
  const fail = (ok, message = "Untrusted or incompatible original lab result") => {
    if (!ok) throw new Error(message);
  };
  const obj = value => value !== null && typeof value === "object" && !Array.isArray(value);
  const shape = (value, names) => obj(value) &&
    Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value,name));
  const text = (value,max=8192) => typeof value === "string" && value.length <= max &&
    !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
  const int = (value,max=1e9) => Number.isSafeInteger(value) && value>=0 && value<=max;

  // JSON.parse silently accepts repeated keys. This bounded reader rejects them at all depths.
  function parseStrict(raw) {
    let pos=0, nodes=0;
    const ws=()=>{while(pos<raw.length && /[ \t\r\n]/.test(raw[pos]))pos++;};
    function stringValue() {
      fail(raw[pos] === '"'); const start=pos++; let escaped=false;
      while(pos<raw.length) {
        const c=raw[pos++];
        if(c === '"' && !escaped) return JSON.parse(raw.slice(start,pos));
        if(c === "\\" && !escaped) escaped=true; else escaped=false;
      }
      fail(false);
    }
    function read(depth) {
      fail(depth<32 && ++nodes<=160000,"Input structure exceeds private source limits");
      ws();const c=raw[pos];
      if(c === '"')return stringValue();
      if(c === "{") {
        pos++;const result=Object.create(null),seen=new Set();ws();
        if(raw[pos] === "}"){pos++;return result;}
        while(true) {
          ws();const key=stringValue();fail(!seen.has(key),"Repeated JSON key");
          seen.add(key);ws();fail(raw[pos++] === ":");
          result[key]=read(depth+1);ws();
          if(raw[pos] === "}"){pos++;return result;}
          fail(raw[pos++] === ",");
        }
      }
      if(c === "[") {
        pos++;const values=[];ws();
        if(raw[pos] === "]"){pos++;return values;}
        while(true){
          fail(values.length<160000);
          values.push(read(depth+1));ws();
          if(raw[pos] === "]"){pos++;return values;}
          fail(raw[pos++] === ",");
        }
      }
      for(const [literal,value] of [["true",true],["false",false],["null",null]]) {
        if(raw.startsWith(literal,pos)){pos+=literal.length;return value;}
      }
      const m=raw.slice(pos).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
      fail(Boolean(m));pos+=m[0].length;
      const value=Number(m[0]);fail(Number.isFinite(value));return value;
    }
    const value=read(0);ws();fail(pos===raw.length,"Trailing source data");
    return value;
  }
  function admitRecord(record,runId,scenarioId) {
    fail(shape(record,["record_id","scenario_id","run_id","engine_version",
      "model_bindings","metrics","created_at","notes"]));
    fail(text(record.record_id,256)&&record.record_id.length>0&&
      record.run_id===runId&&record.scenario_id===scenarioId&&
      text(record.engine_version,256)&&record.engine_version.length>0&&
      text(record.created_at,128)&&text(record.notes,32768));
    fail(Array.isArray(record.model_bindings)&&record.model_bindings.length<=64&&
      record.model_bindings.every(pair=>Array.isArray(pair)&&pair.length===2&&
        pair.every(item=>text(item,1024))));
    const m=record.metrics;fail(shape(m,METRICS));
    for(const name of METRICS) {
      const number=m[name];
      fail(typeof number==="number"&&Number.isFinite(number)&&number>=0);
      if(NUMERIC_COUNTS.has(name))fail(int(number));
      if(SCORES.has(name))fail(number<=1);
      if(name==="runtime_seconds"||name==="compute_cost_usd")fail(number<=1e12);
    }
    const total=m.valid_findings+m.invalid_findings;
    fail(Math.abs(m.false_positive_rate-(total?m.invalid_findings/total:0))<=1e-8);
  }
  function admit(source) {
    const required=["run_id","scenario_id","targets","plan","denied",
      "elevation_requests","findings","coverage","evaluation","report_markdown"];
    fail(obj(source)&&!Object.hasOwn(source,"mode")&&
      (shape(source,required)||shape(source,[...required,"benchmark_case"])));
    fail(text(source.run_id,256)&&source.run_id.length>0&&
      text(source.scenario_id,256)&&source.scenario_id.length>0);
    fail(Array.isArray(source.targets)&&source.targets.length>=1&&source.targets.length<=16&&
      source.targets.every(item=>text(item,2048)&&item.length>0)&&
      new Set(source.targets).size===source.targets.length);
    fail(Array.isArray(source.findings)&&source.findings.length<=2048);
    fail(Array.isArray(source.plan)&&source.plan.length<=512&&
      Array.isArray(source.denied)&&source.denied.length<=512&&
      Array.isArray(source.elevation_requests)&&source.elevation_requests.length<=512);
    fail(obj(source.coverage)&&text(source.report_markdown,MAX_SOURCE_BYTES));
    for(const step of source.plan) {
      fail(shape(step,["tool_id","asset","arguments"])&&
        text(step.tool_id,256)&&text(step.asset,2048)&&obj(step.arguments)&&
        Object.keys(step.arguments).length<=64);
    }
    for(const denial of source.denied) {
      fail(shape(denial,["tool_id","reason"])&&
        text(denial.tool_id,256)&&text(denial.reason,8192));
    }
    admitRecord(source.evaluation,source.run_id,source.scenario_id);
    if(Object.hasOwn(source,"benchmark_case")) {
      fail(shape(source.benchmark_case,["record","context"])&&
        obj(source.benchmark_case.context)&&
        source.benchmark_case.context.is_lab===true&&
        source.benchmark_case.context.authorization===null&&
        source.benchmark_case.context.run_id===source.run_id);
      admitRecord(source.benchmark_case.record,source.run_id,source.scenario_id);
      fail(JSON.stringify(source.benchmark_case.record)===JSON.stringify(source.evaluation));
    }
    const ids=new Set();
    for(const finding of source.findings) {
      fail(shape(finding,["finding","finding_id","severity","impact","fix","retest",
        "check_id","capability_id","target","evidence_ids","evidence_summary"]));
      fail(text(finding.finding_id,256)&&finding.finding_id.length>0&&
        !ids.has(finding.finding_id));ids.add(finding.finding_id);
      fail(SEVERITIES.includes(finding.severity)&&
        ["finding","impact","fix","retest","check_id","capability_id","target",
          "evidence_summary"].every(key=>text(finding[key]))&&
        finding.finding.length>0&&finding.target.length>0&&
        Array.isArray(finding.evidence_ids)&&finding.evidence_ids.length<=64&&
        finding.evidence_ids.every(id=>text(id,1024)));
    }
    return source;
  }
  function countsFor(items) {
    const severity=Object.fromEntries(SEVERITIES.map(s=>[s,0]));
    for(const item of items) severity[item.severity]++;
    return {total:items.length,severity,
      worst:SEVERITIES.find(s=>severity[s]>0)||null};
  }
  function aggregate(data) {
    const map=new Map();
    data.forEach((source,sourceIndex)=>{
      source.findings.forEach((f,sourceOrdinal)=>{
        // Structural JSON tuples, not evidence of the same vulnerable asset.
        const key=JSON.stringify([f.capability_id,f.check_id]);
        if(!map.has(key))map.set(key,{capability:f.capability_id,check:f.check_id,
          bySource:data.map(()=>[])});
        // Always map against FIRST source ordinals, regardless of each later file's target order.
        const endpointIndex=data[0].targets.indexOf(f.target);
        map.get(key).bySource[sourceIndex].push({finding:f,sourceOrdinal,
          endpointOrdinal:endpointIndex<0?null:endpointIndex+1});
      });
    });
    return [...map.values()].sort((a,b)=>
      a.capability.localeCompare(b.capability)||a.check.localeCompare(b.check));
  }
  function node(tag,word,className) {
    const item=document.createElement(tag);
    if(word!==undefined)item.textContent=String(word);
    if(className)item.className=className;
    return item;
  }
  function clear(target){target.replaceChildren();}
  function message(value,isError=false){
    $("message").textContent=value;$("message").dataset.error=String(isError);
  }
  function download(name,body,type) {
    const blob=new Blob([body],{type});const url=URL.createObjectURL(blob);
    const anchor=node("a");anchor.href=url;anchor.download=name;
    document.body.append(anchor);anchor.click();anchor.remove();
    setTimeout(()=>URL.revokeObjectURL(url),1500);
  }
  function filteredPairs(row) {
    const ep=Number($("endpoint").value);
    const severity=$("severity").value;
    return row.bySource.map(list=>list.filter(({finding,endpointOrdinal})=>
      (!ep||endpointOrdinal===ep)&&
      (severity==="all"||finding.severity===severity)));
  }
  function renderSourceMetrics() {
    const area=$("sourceMetrics");clear(area);
    area.append(node("h3","Original evaluation · source-reported adverse counters"));
    area.append(node("p","These counters are literal declarations in already-created lab artifacts, not established scanner coverage, safety or policy compliance. An original source can be inaccurate or forged."));
    const wrap=node("div",undefined,"metrics-scroll");
    const table=node("table");
    const h=node("tr");h.append(node("th","Source-declared numeric metric"));
    sources.forEach((_,index)=>h.append(node("th","Local file "+(index+1))));
    const thead=node("thead");thead.append(h);table.append(thead);
    const tbody=node("tbody");
    const fields=[
      ["valid_findings","Source-reported valid count"],
      ["invalid_findings","Source-reported invalid count"],
      ["missed_findings","Source-reported missed count"],
      ["coverage_unknown","Source-reported unknown coverage units"],
      ["scope_violations","Source-reported scope violations"],
      ["policy_violations","Source-reported policy violations"],
      ["human_interventions","Source-reported human interventions"]
    ];
    for(const [key,label] of fields){
      const line=node("tr");line.append(node("td",label));
      for(const source of sources){
        const value=source.evaluation.metrics[key];
        line.append(node("td",value,value>0&&
          ["invalid_findings","missed_findings","coverage_unknown","scope_violations",
            "policy_violations"].includes(key)?"metric-alert":""));
      }
      tbody.append(line);
    }
    table.append(tbody);wrap.append(table);area.append(wrap);
  }
  function renderAttention() {
    const area=$("attention");clear(area);
    const heading=node("h3","HUMAN attention · source-declaration differences");
    const notice=node("p","Prioritized for human discussion only. Numeric variability, changed declared severity or unmatched endpoint labels are NOT new, fixed or verified vulnerabilities.");
    area.append(heading,notice);
    const candidates=rows.map(row=>{
      const counts=row.bySource.map(list=>list.length);
      const worst=row.bySource.map(list=>countsFor(list.map(r=>r.finding)).worst);
      const changedCount=new Set(counts).size>1;
      const changedSeverity=new Set(worst.filter(Boolean)).size>1;
      const unmatched=row.bySource.some(items=>items.some(item=>item.endpointOrdinal===null));
      const priority=(unmatched?5:0)+(changedSeverity?3:0)+(changedCount?2:0)+
        (row.bySource.some(list=>list.some(x=>x.finding.severity==="critical"))?1:0);
      return {row,counts,changedCount,changedSeverity,unmatched,priority};
    }).filter(item=>item.changedCount||item.changedSeverity||item.unmatched)
      .sort((a,b)=>b.priority-a.priority||
        a.row.capability.localeCompare(b.row.capability)||
        a.row.check.localeCompare(b.row.check));
    const count=node("p",candidates.length+
      " literal tuple groups suggest HUMAN discussion; showing at most 24. No clinical or security significance attached to ranking.");
    area.append(count);
    if(!candidates.length)return;
    const list=node("ol","", "attention-list");
    candidates.slice(0,24).forEach(item=>{
      const li=node("li"),button=node("button",
        (item.row.capability||"(empty capability)")+" · "+(item.row.check||"(empty check)"),
        "attention-link");
      button.type="button";
      button.addEventListener("click",()=>{
        $("query").value=item.row.capability+" "+item.row.check;
        $("severity").value="all";$("endpoint").value="0";refresh();
        const first=item.row.bySource.findIndex(items=>items.length>0);
        if(first>=0)details(item.row,first,filteredPairs(item.row)[first]);
        $("matrix").scrollIntoView({behavior:"smooth",block:"start"});
      });
      const descriptions=[
        item.changedCount?"reported counts vary ("+item.counts.join(" / ")+")":null,
        item.changedSeverity?"source severity labels differ":null,
        item.unmatched?"at least one reported target is not an exact declared endpoint":null
      ].filter(Boolean).join(" · ");
      li.append(button,node("small",descriptions));list.append(li);
    });
    area.append(list);
  }
  function refresh() {
    const needle=$("query").value.trim().toLocaleLowerCase();
    visible=rows.filter(row=>(row.capability+" "+row.check).toLocaleLowerCase().includes(needle));
    const table=$("matrix");clear(table);
    const thead=node("thead"),head=node("tr");
    head.append(node("th","Original capability · check"));
    sources.forEach((_,i)=>head.append(node("th","Local file "+(i+1))));
    thead.append(head);table.append(thead);
    const tbody=node("tbody");let noDeclaration=0;
    visible.forEach((row,index)=>{
      const tr=node("tr");
      const label=node("td");label.append(node("strong",row.capability||"(empty source capability)"));
      label.append(node("small",row.check||"(empty source check)"));tr.append(label);
      const pairs=filteredPairs(row);
      pairs.forEach((cell,sourceIndex)=>{
        const evidence=countsFor(cell.map(item=>item.finding));
        const td=node("td"),button=node("button",
          evidence.total ? evidence.total+" · "+evidence.worst : "— not declared",
          evidence.total?"count "+evidence.worst:"empty-cell");
        button.type="button";
        button.title=evidence.total?"View local source declarations":"Not declared ≠ safe, fixed, assessed or authorized";
        button.addEventListener("click",()=>details(row,sourceIndex,cell));
        td.append(button);tr.append(td);
        if(!evidence.total)noDeclaration++;
      });
      tbody.append(tr);
    });
    table.append(tbody);
    $("visible").textContent=visible.length+" source-declared check groups · "+
      noDeclaration+" empty cells (not declared, never PASS)";
    $("exportCSV").disabled=!sources.length;
    $("exportJSON").disabled=!sources.length;
    if(selected) {
      const row=rows.find(r=>r===selected.row);
      if(row)details(row,selected.sourceIndex,
        filteredPairs(row)[selected.sourceIndex],false);
    }
  }
  function details(row,index,cell,focus=true) {
    selected={row,sourceIndex:index};const pane=$("details");clear(pane);
    pane.append(node("h3","Local file "+(index+1)+" · source-declared items"));
    pane.append(node("p","Capability: "+row.capability+" · check: "+row.check));
    if(!cell.length)pane.append(node("p","This source does not declare a matching finding under the current filters. This says nothing about assessment coverage or remediation."));
    for(const {finding,sourceOrdinal,endpointOrdinal} of cell) {
      const article=node("article");
      article.append(node("strong","#"+(sourceOrdinal+1)+" · "+finding.severity+
        " · endpoint "+(endpointOrdinal??"unmatched")));
      article.append(node("p",finding.finding));
      article.append(node("p","Source mitigation: "+finding.fix));
      article.append(node("p","Source retest proposal: "+finding.retest));
      const evidence=node("details"),summary=node("summary","PRIVATE unverified evidence summary");
      evidence.append(summary,node("p",finding.evidence_summary||"(none declared)"));
      article.append(evidence);pane.append(article);
    }
    if(focus)pane.focus({preventScroll:true});
  }
  function privateExport() {
    return {kind:"lightup.offline_lab_declared_check_matrix",
      version:1,disposition:"REVIEW_ONLY_DRAFT_HOLD",
      ...FLAGS,local_file_slots:sources.length,source_claimed_endpoint_slots:sources[0].targets.length,
      source_reported_finding_totals:sources.map(source=>source.findings.length),
      source_reported_adverse_counters:sources.map(source=>{
        const m=source.evaluation.metrics;
        return {invalid_findings:m.invalid_findings,missed_findings:m.missed_findings,
          coverage_unknown:m.coverage_unknown,scope_violations:m.scope_violations,
          policy_violations:m.policy_violations,human_interventions:m.human_interventions};
      }),
      declared_tuple_rows:visible.map((row,ordinal)=>{
        const perSource=filteredPairs(row).map(list=>countsFor(list.map(x=>x.finding)));
        return {ordinal:ordinal+1,appearances:perSource.map(r=>r.total),
          source_reported_severities:perSource.map(r=>r.severity)};
      }),interpretation:"Unsigned source claims only; absent is not assessed, safe or fixed. Source order is operator-selected, not verified chronology."};
  }
  function csv(rowsData) {
    const lines=[["tuple_ordinal",...sources.map((_,i)=>"source_"+(i+1)+"_reported")]];
    rowsData.declared_tuple_rows.forEach(item=>lines.push([item.ordinal,...item.appearances]));
    return lines.map(line=>line.join(",")).join("\r\n")+"\r\n";
  }
  async function importFiles() {
    const files=[...$("files").files];
    if(files.length<2||files.length>8){
      message("Select 2–8 existing original PRIVATE lab JSON files in your chosen display order.",true);return;
    }
    $("load").disabled=true;message("Reading selected local originals. No network or scan.");
    try {
      const next=[];
      for(const file of files) {
        fail(file.size>0&&file.size<=MAX_SOURCE_BYTES,"Source file outside the 8 MiB bound");
        const data=new Uint8Array(await file.arrayBuffer());
        const decoded=new TextDecoder("utf-8",{fatal:true}).decode(data);
        next.push(admit(parseStrict(decoded)));
      }
      const baseline=next[0],sameTargets=new Set(baseline.targets);
      fail(new Set(next.map(s=>s.run_id)).size===next.length,
        "Repeated original run IDs; mixed source set held");
      for(const source of next.slice(1)) {
        fail(source.scenario_id===baseline.scenario_id,
          "Different source-declared scenario; cannot present one comparison matrix");
        fail(source.targets.length===baseline.targets.length&&
          source.targets.every(t=>sameTargets.has(t)),
          "Different exact declared endpoint set; cannot present one comparison matrix");
      }
      // Only publish after the WHOLE batch has passed strict source admission.
      sources=next;rows=aggregate(next);selected=null;clear($("details"));
      clear($("endpoint"));
      $("endpoint").append(new Option("All declared endpoints",0));
      baseline.targets.forEach((_,i)=>$("endpoint").append(new Option("Endpoint ordinal "+(i+1),i+1)));
      $("workspace").hidden=false;
      $("intro").hidden=true;
      $("sourceCount").textContent=sources.length+" original PRIVATE source files";
      $("sourceSummary").textContent=baseline.targets.length+
        " identical literal declared endpoint slots · "+rows.length+
        " literal capability/check groups · no verification of target, ownership or chronology";
      renderSourceMetrics();renderAttention();refresh();
      message("Local input admitted structurally. Source statements remain unverified. No original data uploaded.");
    } catch(error) {
      message("Entire selection held: "+error.message+
        ". Previously opened selection, if any, was not replaced.",true);
    } finally {
      $("load").disabled=false;$("files").value="";
    }
  }
  $("load").addEventListener("click",importFiles);
  $("forget").addEventListener("click",()=>{
    if(sources.length&&!confirm("Forget ALL locally opened original PRIVATE result data?"))return;
    sources=[];rows=[];visible=[];selected=null;
    clear($("details"));clear($("matrix"));clear($("attention"));clear($("sourceMetrics"));$("query").value="";
    $("workspace").hidden=true;$("intro").hidden=false;
    $("files").value="";message("Private originals discarded from this application state.");
  });
  ["query","severity","endpoint"].forEach(id=>$(id).addEventListener("input",refresh));
  $("exportJSON").addEventListener("click",()=>{
    if(sources.length&&confirm("Download anonymized COUNTS ONLY? Small groups can still be sensitive.")){
      download("lightup-private-declaration-counts.json",
        JSON.stringify(privateExport(),null,2)+"\n","application/json");
    }
  });
  $("exportCSV").addEventListener("click",()=>{
    if(sources.length&&confirm("Download anonymous COUNTS ONLY CSV? This is not a security report.")){
      download("lightup-private-declaration-counts.csv",csv(privateExport()),"text/csv");
    }
  });
  addEventListener("beforeunload",event=>{
    if(sources.length){event.preventDefault();event.returnValue="";}
  });
})();