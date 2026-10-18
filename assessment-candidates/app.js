"use strict";
// LightUp assessment candidate tradeoff matrix. Read-only and permanently non-authorizing.
(() => {
  const NAMES=["valid_findings","invalid_findings","missed_findings","coverage_assessed",
    "coverage_unknown","scope_violations","policy_violations","human_interventions",
    "tool_calls","evidence_quality","reproducibility","remediation_quality",
    "retest_correctness","runtime_seconds","compute_cost_usd"];
  const HIGH=new Set(["valid_findings","coverage_assessed","evidence_quality",
    "reproducibility","remediation_quality","retest_correctness"]);
  const LOW=new Set(["invalid_findings","missed_findings","scope_violations","policy_violations"]);
  const COUNTERS=new Set(NAMES.slice(0,9));
  const SCORES=new Set(NAMES.slice(9,13));
  const AUTH=["authorized","consent_verified","dispatch_allowed","release_allowed"];
  const $=id=>document.getElementById(id);
  const assert=x=>{if(!x)throw Error("Untrusted or incompatible lab source");};
  const exact=(x,keys)=>x!==null && typeof x==="object" && !Array.isArray(x) &&
    Object.keys(x).length===keys.length && keys.every(k=>Object.hasOwn(x,k));
  const finite=x=>typeof x==="number" && Number.isFinite(x);
  const close=(a,b)=>Math.abs(a-b)<=Math.max(1,Math.abs(a),Math.abs(b))*1e-8;
  const identifier=x=>typeof x==="string" && x.length>0 && x.length<=256 &&
    x===x.trim() && /^[\x20-\x7e]+$/.test(x);
  const fixedFlags=()=>({authorized:false,consent_verified:false,dispatch_allowed:false,release_allowed:false});
  const nice=x=>x.replaceAll("_"," ");
  const format=x=>Number.isInteger(x)?String(x):Number(x).toPrecision(5).replace(/\.?0+($|e)/,"$1");
  let reports=[],demo=false,selectedCase="",settings=null;

  // Unlike JSON.parse, reject repeated JSON keys (including escaped aliases) at every depth.
  function strictJSON(raw) {
    let offset=0,nodes=0;
    function space(){while(offset<raw.length && /\s/.test(raw[offset]))offset++;}
    function string(){
      assert(raw[offset]==='"');const start=offset++;let slash=false;
      while(offset<raw.length){const ch=raw[offset++];
        if(ch==='"'&&!slash)return JSON.parse(raw.slice(start,offset));
        if(ch==="\\"&&!slash)slash=true;else slash=false;
      }assert(false);
    }
    function value(depth){
      assert(depth<28 && ++nodes<=90000);space();const ch=raw[offset];
      if(ch==='"')return string();
      if(ch==="{"){
        offset++;const obj=Object.create(null),seen=new Set();space();
        if(raw[offset]==="}"){offset++;return obj;}
        for(;;){space();const key=string();assert(!seen.has(key));seen.add(key);
          space();assert(raw[offset++]===":");obj[key]=value(depth+1);space();
          if(raw[offset]==="}"){offset++;return obj;}assert(raw[offset++]===",");
        }
      }
      if(ch==="["){
        offset++;const arr=[];space();
        if(raw[offset]==="]"){offset++;return arr;}
        for(;;){arr.push(value(depth+1));assert(arr.length<=90000);space();
          if(raw[offset]==="]"){offset++;return arr;}assert(raw[offset++]===",");
        }
      }
      for(const [literal,parsed] of [["true",true],["false",false],["null",null]]){
        if(raw.startsWith(literal,offset)){offset+=literal.length;return parsed;}
      }
      const m=raw.slice(offset).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
      assert(!!m);offset+=m[0].length;const num=Number(m[0]);assert(finite(num));return num;
    }
    const result=value(0);space();assert(offset===raw.length);return result;
  }
  function decodeChange(x){
    assert(exact(x,["name","baseline","candidate","delta","regression"]) &&
      NAMES.includes(x.name) && finite(x.baseline) && finite(x.candidate) &&
      finite(x.delta) && typeof x.regression==="boolean" &&
      x.baseline>=0 && x.candidate>=0);
    if(COUNTERS.has(x.name)){
      assert(Number.isSafeInteger(x.baseline)&&Number.isSafeInteger(x.candidate)&&
        Number.isSafeInteger(x.delta)&&x.baseline<=1e9&&x.candidate<=1e9&&
        x.candidate-x.baseline===x.delta);
    }
    if(SCORES.has(x.name))assert(x.baseline<=1&&x.candidate<=1);
    if(x.name==="runtime_seconds"||x.name==="compute_cost_usd")
      assert(x.baseline<=1e12&&x.candidate<=1e12);
    assert(close(x.candidate-x.baseline,x.delta));
    const regression=(HIGH.has(x.name)&&x.candidate<x.baseline) ||
      (LOW.has(x.name)&&x.candidate>x.baseline);
    assert(regression===x.regression);
    return {baseline:x.baseline,candidate:x.candidate,delta:x.delta,regression};
  }
  function decodeReport(x){
    assert(exact(x,["status","regressed_scenarios","comparisons",...AUTH]) &&
      AUTH.every(k=>x[k]===false) && (x.status==="HOLD"||x.status==="REVIEW_ONLY") &&
      Array.isArray(x.comparisons)&&x.comparisons.length>=1&&x.comparisons.length<=64 &&
      Array.isArray(x.regressed_scenarios)&&x.regressed_scenarios.length<=64);
    const cases=new Map();
    for(const row of x.comparisons){
      assert(exact(row,["scenario_id","status","regressions","changes"]) &&
        identifier(row.scenario_id) && !cases.has(row.scenario_id) &&
        Array.isArray(row.regressions)&&Array.isArray(row.changes) &&
        row.changes.length===NAMES.length&&row.regressions.length<=NAMES.length);
      const metrics=Object.create(null);
      for(const ch of row.changes){
        assert(typeof ch?.name==="string"&&!Object.hasOwn(metrics,ch.name));
        metrics[ch.name]=decodeChange(ch);
      }
      assert(NAMES.every(n=>Object.hasOwn(metrics,n)));
      const expected=NAMES.filter(n=>metrics[n].regression);
      assert(row.regressions.length===expected.length &&
        row.regressions.every((n,i)=>n===expected[i]) &&
        row.status===(expected.length?"HOLD":"REVIEW_ONLY"));
      cases.set(row.scenario_id,{metrics,regressions:expected});
    }
    const flagged=[...cases].filter(([id,c])=>c.regressions.length).map(([id])=>id);
    assert(x.regressed_scenarios.length===flagged.length &&
      new Set(x.regressed_scenarios).size===flagged.length &&
      x.regressed_scenarios.every(id=>identifier(id)&&flagged.includes(id)) &&
      x.status===(flagged.length?"HOLD":"REVIEW_ONLY"));
    return {cases,sourceStatus:x.status};
  }
  function compatible(rs){
    const ids=[...rs[0].cases.keys()].sort();
    const base=rs[0];
    for(const r of rs.slice(1)){
      const next=[...r.cases.keys()].sort();
      assert(next.length===ids.length && next.every((n,i)=>n===ids[i]));
      for(const id of ids)for(const n of NAMES)
        assert(base.cases.get(id).metrics[n].baseline===r.cases.get(id).metrics[n].baseline);
    }
    // Distinct file names are not proof of distinct measurement outputs.
    const signatures=new Set();
    for(const r of rs){
      const sig=JSON.stringify(ids.map(id=>NAMES.map(n=>r.cases.get(id).metrics[n].candidate)));
      assert(!signatures.has(sig));signatures.add(sig);
    }
  }
  function aggregates(r){
    const total=Object.create(null);
    for(const n of NAMES){
      total[n]={baseline:0,candidate:0,adverse:0};
      for(const c of r.cases.values()){
        const m=c.metrics[n];
        total[n].baseline+=m.baseline;total[n].candidate+=m.candidate;
        if(m.regression)total[n].adverse++;
      }
      assert(finite(total[n].baseline)&&finite(total[n].candidate));
    }
    const count=r.cases.size;
    return {total,count,
      affected:[...r.cases.values()].filter(c=>c.regressions.length).length,
      regressionEvents:[...r.cases.values()].reduce((s,c)=>s+c.regressions.length,0),
      scope:total.scope_violations.candidate,
      policy:total.policy_violations.candidate,
      coverage:total.coverage_assessed.candidate,
      quality:total.evidence_quality.candidate/count,
      runtime:total.runtime_seconds.candidate,
      cost:total.compute_cost_usd.candidate};
  }
  function cell(x){return String(x);}
  function tr(values){return "<tr>"+values.map(x=>"<td>"+cell(x)+"</td>").join("")+"</tr>";}
  function table(headers,rows){
    return "<table><thead><tr>"+headers.map(h=>"<th scope='col'>"+h+"</th>").join("")+
      "</tr></thead><tbody>"+rows.map(tr).join("")+"</tbody></table>";
  }
  function setStatus(s,failed=false){$("message").textContent=s;$("message").className=failed?"danger":"";}
  function threshold(){
    const keys=[["maxScope",0,1e6,true],["maxPolicy",0,1e6,true],
      ["minQuality",0,1,false],["minCoverage",0,1e9,true],
      ["maxRuntime",0,1e12,false],["maxCost",0,1e12,false]];
    const t={};
    for(const [key,min,max,integer]of keys){
      const input=$(key),n=Number(input.value);
      assert(input.value.trim()!==""&&finite(n)&&n>=min&&n<=max &&
        (!integer||Number.isSafeInteger(n)));
      t[key]=n;
    }
    return t;
  }
  function breaches(a,t){
    const b=[];
    if(a.scope>t.maxScope)b.push("Scope violations exceed review threshold");
    if(a.policy>t.maxPolicy)b.push("Policy violations exceed review threshold");
    if(a.quality<t.minQuality)b.push("Evidence quality below discussion floor");
    if(a.coverage<t.minCoverage)b.push("Assessed coverage below discussion floor");
    if(t.maxRuntime>0&&a.runtime>t.maxRuntime)b.push("Runtime above discussion budget");
    if(t.maxCost>0&&a.cost>t.maxCost)b.push("Compute cost above discussion budget");
    return b;
  }
  function dimensions(){
    return [["dimQuality","quality",1],["dimCoverage","coverage",1],
      ["dimRuntime","runtime",-1],["dimCost","cost",-1]].filter(([input])=>$(input).checked);
  }
  function dominates(a,b,dims){
    const atLeast=dims.every(([_,key,dir])=>dir*a[key]>=dir*b[key]);
    const better=dims.some(([_,key,dir])=>dir*a[key]>dir*b[key]);
    return atLeast&&better;
  }
  function renderMetricBoard(stats){
    const shared=stats[0];
    $("metricBoard").innerHTML=table(["Original metric","Common baseline aggregate",
      ...stats.map((_,i)=>"Candidate "+(i+1)+" · total / adverse cases")],
      NAMES.map(n=>[nice(n),format(shared.total[n].baseline),
        ...stats.map(s=>format(s.total[n].candidate)+" / "+s.total[n].adverse)]));
    for(const id of ["pairA","pairB"]){
      const selector=$(id),old=selector.value;
      if(selector.options.length!==stats.length){
        selector.innerHTML="";
        stats.forEach((_,i)=>{const option=document.createElement("option");
          option.value=String(i);option.textContent="Candidate "+(i+1);selector.append(option);});
        selector.value=id==="pairA"?"0":String(Math.min(1,stats.length-1));
      } else selector.value=old;
    }
    const a=Number($("pairA").value),b=Number($("pairB").value);
    if(!Number.isSafeInteger(a)||!Number.isSafeInteger(b)||a<0||b<0||
      a>=stats.length||b>=stats.length||a===b){
      $("pairMetrics").textContent="Select two distinct candidates for a descriptive comparison.";return;
    }
    const aa=stats[a].total,bb=stats[b].total;
    $("pairMetrics").innerHTML=table(["Metric","Candidate "+(a+1),
      "Candidate "+(b+1),"Numeric change (second − first)","Original adverse case counts"],
      NAMES.map(n=>[nice(n),format(aa[n].candidate),format(bb[n].candidate),
        format(bb[n].candidate-aa[n].candidate),aa[n].adverse+" → "+bb[n].adverse]));
  }
  function render(){
    const active=reports.length>0,stats=reports.map(aggregates);
    $("sourceKind").textContent=!active?"No data":demo?"FICTIONAL DEMO ONLY":"UNVERIFIED LAB SOURCES";
    $("sourceLine").textContent=!active?"":reports.length+" candidate reports · "+reports[0].cases.size+
      " shared anonymized cases · all authority flags false · "+(demo?"FICTIONAL DATA":"UNVERIFIED SOURCE");
    for(const id of ["exportCSV","exportJSON","print"])$(id).disabled=!active;
    if(!active){
      $("cards").innerHTML='<p class="empty">Import reports to compare lab candidates.</p>';
      for(const id of ["thresholds","frontier","caseDetail","metricBoard","pairMetrics"])$(id).innerHTML="";
      $("caseSelect").innerHTML='<option value="">Load reports first</option>';
      return;
    }
    $("cards").innerHTML=stats.map((s,i)=>
      '<article class="card"><h3>Candidate '+(i+1)+'</h3><p class="'+
      (s.affected?"danger":"warn")+'">'+reports[i].sourceStatus+
      " · "+s.affected+" source-regressed cases</p>"+
      '<p class="big">'+s.regressionEvents+' <small>metric regressions</small></p>'+
      "<p>Scope / policy: <strong>"+format(s.scope)+" / "+format(s.policy)+"</strong></p>"+
      "<p>Mean evidence quality: "+format(s.quality)+"</p>"+
      "<p>Runtime: "+format(s.runtime)+" sec · Cost: $"+format(s.cost)+"</p>"+
      "<p class='footnote'>No safety approval; separate human review required.</p></article>").join("");
    renderMetricBoard(stats);
    let t;try{t=threshold();settings=t;$("thresholdMessage").textContent="Review suggestions recomputed locally; no source metrics changed.";}
    catch(_){$("thresholdMessage").textContent="HOLD: invalid threshold — enter a bounded numerical value. No decision output.";
      settings=null;for(const id of ["exportCSV","exportJSON","print"])$(id).disabled=true;
      $("thresholds").textContent="HOLD — invalid local thresholds";$("frontier").textContent="HOLD — invalid local thresholds";return;}
    $("thresholds").innerHTML=table(["Candidate","Source status","Human discussion triggers","Hard safety indicators"],
      stats.map((s,i)=>["Candidate "+(i+1),reports[i].sourceStatus,
        (breaches(s,t).length?breaches(s,t).join(" · "):"No entered threshold breaches — still REVIEW ONLY"),
        s.scope+" scope / "+s.policy+" policy · "+s.affected+" source-regressed cases"]));
    const dims=dimensions();
    if(!dims.length)$("frontier").textContent="Select one or more descriptive dimensions to see comparisons.";
    else $("frontier").innerHTML=table(["Candidate","Descriptive position","Compared against","Safety/adverse source facts"],
      stats.map((s,i)=>{
        const owners=stats.map((other,j)=>j!==i&&dominates(other,s,dims)?j+1:null).filter(Boolean);
        return ["Candidate "+(i+1),owners.length?"Numerically dominated":"Not numerically dominated",
          owners.length?"Candidate "+owners.join(", "):"No strictly dominating candidate",
          s.affected+" regressed cases; "+format(s.scope)+" scope / "+format(s.policy)+" policy flags"];
      }));
    const ids=[...reports[0].cases.keys()].sort();
    const selected=$("caseSelect");
    if(selected.options.length!==ids.length||!ids.includes(selectedCase)){
      selected.innerHTML="";
      ids.forEach((id,i)=>{const option=document.createElement("option");option.value=String(i);
        option.textContent="Lab case "+String(i+1).padStart(2,"0");selected.append(option);});
      selectedCase=ids[0];
    }
    const caseIndex=Math.max(0,ids.indexOf(selectedCase));selected.value=String(caseIndex);
    renderCase(ids[caseIndex]);
  }
  function renderCase(id){
    if(!reports.length)return;
    const n=$("metricSelect").value||NAMES[0];
    const rows=reports.map((r,i)=>{
      const c=r.cases.get(id),m=c.metrics[n];
      return ["Candidate "+(i+1),format(m.baseline),format(m.candidate),
        format(m.delta),m.regression?"ADVERSE · human review":"No source regression (not proof of safety)"];
    });
    $("caseDetail").innerHTML=table(["Candidate","Baseline","Candidate metric","Change","Reported classification"],rows);
  }
  async function importFiles(files){
    try{
      assert(files.length>=2&&files.length<=12);
      const next=[];
      for(const file of files){
        assert(file.size>0&&file.size<=262144);
        const bytes=await file.arrayBuffer();
        assert(bytes.byteLength>0&&bytes.byteLength<=262144);
        const source=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
        next.push(decodeReport(strictJSON(source)));
      }
      compatible(next);reports=next;demo=false;selectedCase="";
      setStatus("Accepted "+next.length+" compatible, unverified lab comparison files. All remain non-authorizing.");
      render();
    }catch(_){setStatus("HOLD: at least one source is malformed, mismatched, repeated or oversized. Existing workspace preserved.",true);}
  }
  function fictional(){
    const ids=["fictional-case-A","fictional-case-B","fictional-case-C","fictional-case-D"];
    const change=(name,idx,revision)=>{
      let base=COUNTERS.has(name)?8:SCORES.has(name)?0.8:name==="runtime_seconds"?40:1.5;
      if(name==="scope_violations"||name==="policy_violations"||name==="missed_findings"||
        name==="invalid_findings")base=0;
      if(name==="coverage_unknown")base=2;
      let val=base;
      if(["valid_findings","coverage_assessed"].includes(name))val=base+((idx+revision)%3-1);
      if(["scope_violations","policy_violations"].includes(name))val=(idx+revision)%4===0?1:0;
      if(name==="missed_findings"||name==="invalid_findings")val=(idx+revision)%3===0?1:0;
      if(SCORES.has(name))val=Math.min(1,Math.max(0,base+(revision-1)*0.03-(idx===2?0.12:0)));
      if(name==="runtime_seconds")val=40+(revision*7)+(idx*2);
      if(name==="compute_cost_usd")val=1.5+(revision*0.3)+(idx*0.1);
      const regression=(HIGH.has(name)&&val<base)||(LOW.has(name)&&val>base);
      return {name,baseline:base,candidate:val,delta:val-base,regression};
    };
    return [0,1,2,3].map(revision=>{
      const comparisons=ids.map((scenario_id,idx)=>{
        const changes=NAMES.map(n=>change(n,idx,revision));
        const regressions=changes.filter(c=>c.regression).map(c=>c.name);
        return {scenario_id,status:regressions.length?"HOLD":"REVIEW_ONLY",regressions,changes};
      });
      const regressed_scenarios=comparisons.filter(c=>c.regressions.length).map(c=>c.scenario_id);
      return {status:regressed_scenarios.length?"HOLD":"REVIEW_ONLY",regressed_scenarios,
        comparisons,...fixedFlags()};
    });
  }
  function demoLoad(){
    try{const next=fictional().map(decodeReport);compatible(next);reports=next;demo=true;
      selectedCase="";setStatus("FICTIONAL DEMO ONLY: four invented candidates; no real assessments or permissions.");render();
    }catch(_){setStatus("HOLD: demonstration source could not be prepared.",true);}
  }
  function metricRows(){
    const stats=reports.map(aggregates),ids=[...reports[0].cases.keys()].sort();
    return reports.map((r,i)=>({
      candidate_slot:i+1,source_status:r.sourceStatus,lab_case_count:ids.length,
      regressed_cases:stats[i].affected,metric_regressions:stats[i].regressionEvents,
      threshold_discussions:breaches(stats[i],settings).length,
      scope_flags:stats[i].scope,policy_flags:stats[i].policy,
      metrics:Object.fromEntries(NAMES.map(n=>[n,{baseline_total:stats[i].total[n].baseline,
        candidate_total:stats[i].total[n].candidate,regressed_case_count:stats[i].total[n].adverse}])),
      // This review summary cannot carry release authority or authenticated consent.
      ...fixedFlags()
    }));
  }
  function download(name,text,mime){
    const url=URL.createObjectURL(new Blob([text],{type:mime}));
    const a=document.createElement("a");a.href=url;a.download=name;
    document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),2000);
  }
  function exportJSON(){
    if(!reports.length||!settings)return;
    const out={schema:"lightup.lab_candidate_matrix_review.v1",
      posture:"INCUBATE_M3_M7_PLAN_LAB_ONLY_DRAFT_HOLD",
      status:"REVIEW_ONLY",source_identity_authenticated:false,
      temporal_order_authenticated:false,fictional_demo_only:demo,
      disclaimer:"Human review of untrusted pre-existing lab summaries only. No permission, release, scan or verified remediation.",
      dimensions:dimensions().map(x=>x[1]),review_thresholds:settings,candidates:metricRows(),...fixedFlags()};
    download("lightup-candidate-aggregate-REVIEW-ONLY.json",JSON.stringify(out,null,2)+"\n","application/json");
  }
  function exportCSV(){
    if(!reports.length||!settings)return;
    const head=["candidate_slot","source_status","regressed_cases","metric_regressions",
      "threshold_discussions","scope_flags","policy_flags",
      ...NAMES.map(n=>n+"_total"),"authorized","consent_verified","dispatch_allowed","release_allowed"];
    const rows=metricRows().map(r=>[r.candidate_slot,r.source_status,r.regressed_cases,
      r.metric_regressions,r.threshold_discussions,r.scope_flags,r.policy_flags,
      ...NAMES.map(n=>r.metrics[n].candidate_total),"false","false","false","false"]);
    download("lightup-candidate-aggregate-REVIEW-ONLY.csv",
      head.join(",")+"\n"+rows.map(r=>r.join(",")).join("\n")+"\n","text/csv");
  }
  function forget(){
    reports=[];demo=false;selectedCase="";settings=null;$("files").value="";
    setStatus("All imported records forgotten from this workspace.");render();
  }
  // No fetch, storage, workers, scanner or execution API.
  $("files").addEventListener("change",e=>{if(e.target.files.length)void importFiles([...e.target.files]);});
  $("demo").addEventListener("click",demoLoad);
  $("forget").addEventListener("click",forget);
  for(const id of ["maxScope","maxPolicy","minQuality","minCoverage","maxRuntime","maxCost",
    "dimQuality","dimCoverage","dimRuntime","dimCost"])$(id).addEventListener("change",render);
  for(const id of ["pairA","pairB"])$(id).addEventListener("change",render);
  $("caseSelect").addEventListener("change",e=>{if(!reports.length)return;
    const ids=[...reports[0].cases.keys()].sort(),i=Number(e.target.value);
    if(Number.isSafeInteger(i)&&i>=0&&i<ids.length){selectedCase=ids[i];renderCase(selectedCase);}
  });
  $("metricSelect").addEventListener("change",()=>{if(selectedCase)renderCase(selectedCase);});
  for(const n of NAMES){const option=document.createElement("option");option.value=n;
    option.textContent=nice(n);$("metricSelect").append(option);}
  $("exportCSV").addEventListener("click",exportCSV);
  $("exportJSON").addEventListener("click",exportJSON);
  $("print").addEventListener("click",()=>{if(reports.length&&settings)window.print();});
  render();
})();