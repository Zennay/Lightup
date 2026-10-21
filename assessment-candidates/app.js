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
  let reports=[],demo=false,selectedCase="",settings=null,sourceHashes=[],sourceMeta=[];
  const DISCUSSION_STAGES=["needs_review","in_discussion","documented"];
  const DISCUSSION_ROUTES=["unrouted","scope","findings","evidence","operations"];
  const TOPICS={scope:["scope_violations","policy_violations"],
    findings:["valid_findings","invalid_findings","missed_findings","coverage_assessed","coverage_unknown"],
    evidence:["evidence_quality","reproducibility","remediation_quality","retest_correctness"],
    operations:["human_interventions","tool_calls","runtime_seconds","compute_cost_usd"]};
  let discussions=new Map(),queueFocus=0,batchUndo=null;
  let reviewRounds=null; // Two explicit PRIVATE HUMAN drafts; no data leaves the browser.


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
  async function hashBytes(bytes){
    if(!globalThis.crypto?.subtle)return null;
    try{const raw=await crypto.subtle.digest("SHA-256",bytes);
      return Array.from(new Uint8Array(raw),b=>b.toString(16).padStart(2,"0")).join("");}
    catch(_){return null;}
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
        selector.value=old!==""&&Number.isSafeInteger(Number(old))&&
          Number(old)>=0&&Number(old)<stats.length?old:
          id==="pairA"?"0":String(Math.min(1,stats.length-1));
      } else selector.value=old;
    }
    const a=Number($("pairA").value),b=Number($("pairB").value);
    const validPair=Number.isSafeInteger(a)&&Number.isSafeInteger(b)&&a>=0&&b>=0&&
      a<stats.length&&b<stats.length&&a!==b;
    $("exportPairCSV").disabled=!validPair;
    if(!validPair){
      $("pairMetrics").textContent="Select two distinct candidates for a descriptive comparison.";
      $("pairChurn").textContent="";$("pairChurnSummary").textContent="";return;
    }
    const aa=stats[a].total,bb=stats[b].total;
    $("pairMetrics").innerHTML=table(["Metric","Candidate "+(a+1),
      "Candidate "+(b+1),"Numeric change (second − first)","Original adverse case counts"],
      NAMES.map(n=>[nice(n),format(aa[n].candidate),format(bb[n].candidate),
        format(bb[n].candidate-aa[n].candidate),aa[n].adverse+" → "+bb[n].adverse]));
    const churn=pairChurn(a,b);
    $("pairChurn").innerHTML=table(["Original metric","Only in first",
      "Only in second","Adverse in both","Adverse in neither"],
      churn.metrics.map(r=>[nice(r.name),r.only_first,r.only_second,r.both,r.neither]));
    $("pairChurnSummary").textContent="Candidate "+(a+1)+" compared with "+(b+1)+
      ": "+churn.case_count+" shared unverified lab cases · "+
      churn.only_second_cases+" cases with a flag only in second · "+
      churn.only_first_cases+" only in first. No chronology or verified fix.";
  }
  function pairChurn(a,b){
    const first=reports[a],second=reports[b],ids=queueIds();
    const metrics=NAMES.map(name=>{
      let only_first=0,only_second=0,both=0,neither=0;
      for(const id of ids){
        const x=first.cases.get(id).metrics[name].regression;
        const y=second.cases.get(id).metrics[name].regression;
        if(x&&y)both++;else if(x)only_first++;else if(y)only_second++;else neither++;
      }
      return {name,only_first,only_second,both,neither};
    });
    return {first_candidate_slot:a+1,second_candidate_slot:b+1,
      case_count:ids.length,metrics,
      only_first_cases:ids.filter(id=>NAMES.some(n=>
        first.cases.get(id).metrics[n].regression&&!second.cases.get(id).metrics[n].regression)).length,
      only_second_cases:ids.filter(id=>NAMES.some(n=>
        !first.cases.get(id).metrics[n].regression&&second.cases.get(id).metrics[n].regression)).length,
      source_order_authenticated:false,source_identity_authenticated:false,
      status:"REVIEW_ONLY",...fixedFlags()};
  }
  function queueIds(){return reports.length?[...reports[0].cases.keys()].sort():[];}
  function queueAdverse(id,candidate,topic){
    const names=topic==="all"?NAMES:TOPICS[topic];
    return reports.reduce((sum,r,index)=>sum+(candidate==="all"||Number(candidate)===index?
      names.filter(n=>topic==="operations"?
        r.cases.get(id).metrics[n].delta!==0:
        r.cases.get(id).metrics[n].regression).length:0),0);
  }
  function queueSettings(id){
    return discussions.get(id)||{route:"unrouted",stage:"needs_review"};
  }
  function drawQueue(){
    const ids=queueIds(),active=ids.length>0;
    for(const name of ["queueCase","saveQueue","focusQueue","resetQueue"])
      $(name).disabled=!active;
    if(!active){discussions.clear();batchUndo=null;$("applyBulk").disabled=true;
      $("undoBulk").disabled=true;$("queueRows").innerHTML="";
      $("queueSummary").textContent="No lab records imported.";return;}
    if(queueFocus<0||queueFocus>=ids.length)queueFocus=0;
    for(const [node,labels] of [
      ["queueCandidate",["all",...reports.map((_,i)=>String(i))]],
      ["queueCase",ids.map((_,i)=>String(i))]]){
      const select=$(node),before=select.value;
      if(select.options.length!==labels.length){
        select.innerHTML="";
        labels.forEach(label=>{const o=document.createElement("option");o.value=label;
          o.textContent=node==="queueCandidate"?
            label==="all"?"All candidates":"Candidate "+(Number(label)+1):
            "Lab case "+String(Number(label)+1).padStart(2,"0");
          select.append(o);});
        if(labels.includes(before))select.value=before;
      }
    }
    $("queueCase").value=String(queueFocus);
    const focus=queueSettings(ids[queueFocus]);
    $("queueRoute").value=focus.route;$("queueStage").value=focus.stage;
    const cand=$("queueCandidate").value||"all";
    const topic=$("queueFamily").value||"all",filter=$("queueFilter").value||"all";
    const showNeutral=$("queueIncludeNeutral").checked;
    const rows=ids.map((id,i)=>({i,id,count:queueAdverse(id,cand,topic),
      safety:queueAdverse(id,cand,"scope"),review:queueSettings(id)})).filter(r=>
      (filter==="all"||r.review.stage===filter)&&(showNeutral||r.count>0));
    rows.sort((a,b)=>topic==="all"?
      Number(b.safety>0)-Number(a.safety>0)||b.safety-a.safety||
        b.count-a.count||a.i-b.i:
      b.count-a.count||a.i-b.i);
    $("applyBulk").disabled=!rows.length;
    $("undoBulk").disabled=batchUndo===null;
    $("queueSummary").textContent=rows.length+" anonymized cases shown / "+ids.length+
      " total · "+rows.filter(r=>r.count>0).length+
      (topic==="operations"?" with informational source changes":
       " with original source-adverse metrics")+
      " · "+[...discussions.values()].filter(r=>r.stage==="documented").length+
      " locally marked discussion documented (not fixed).";
    $("queueRows").innerHTML=table(["Case ordinal",
      topic==="operations"?"Informational source metric changes":"Original adverse metric instances",
      "Local discussion stage","Generic proposed reviewer group"],
      rows.map(r=>[
        "<button type='button' class='case-link' data-queue-index='"+r.i+
          "' aria-label='Select anonymous case "+(r.i+1)+"'>Lab case "+
          String(r.i+1).padStart(2,"0")+"</button>",
        r.count,r.review.stage.replaceAll("_"," "),r.review.route.replaceAll("_"," ")]));
  }
  function renderSourceManifest(){
    const root=$("sourceManifest");
    root.replaceChildren();
    if(!reports.length||demo||sourceMeta.length!==reports.length){
      root.textContent=demo?"Fictional source snapshots: invented, no original file provenance.":
        "Original source fingerprints and optional private aliases appear after real import.";
      return;
    }
    const table=document.createElement("table"),head=document.createElement("thead");
    const header=document.createElement("tr");
    for(const name of ["Slot","Input size","Local source-byte SHA-256 prefix",
      "Private alias (never in public exports)"]){
      const th=document.createElement("th");th.textContent=name;header.append(th);
    }
    head.append(header);table.append(head);
    const body=document.createElement("tbody");
    sourceMeta.forEach((entry,i)=>{
      const row=document.createElement("tr");
      const parts=[String(i+1),String(entry.bytes)+" bytes",
        entry.sha?entry.sha.slice(0,12)+"… (unsigned)":"Hash unavailable"];
      for(const val of parts){const td=document.createElement("td");
        td.textContent=val;row.append(td);}
      const td=document.createElement("td"),input=document.createElement("input");
      input.type="text";input.maxLength=40;input.value=entry.alias||"";
      input.placeholder="Optional local label";
      input.setAttribute("aria-label","Private alias for unverified source candidate "+(i+1));
      input.addEventListener("change",()=>{
        const value=input.value.trim();
        if(value.length>40||!(/^[\x20-\x7e]*$/.test(value))){
          input.value=entry.alias||"";return;
        }
        entry.alias=value;input.value=value;
        const label=$("cardLabel"+i);
        if(label)label.textContent=value?" · "+value:"";
      });
      td.append(input);row.append(td);body.append(row);
    });
    table.append(body);root.append(table);
    sourceMeta.forEach((entry,i)=>{
      const label=$("cardLabel"+i);
      if(label)label.textContent=entry.alias?" · "+entry.alias:"";
    });
  }
  const AGENDA={
    scope:{title:"Scope and policy",question:"Ask a human scope owner to reconcile lab fixture membership, policy constraints and original scope declarations. No consent is inferred."},
    findings:{title:"Findings and coverage",question:"Ask a lab-detection reviewer for original planted findings and coverage ground truth. Source counts alone cannot verify detection correctness."},
    evidence:{title:"Evidence and scoring",question:"Ask an independent evidence reviewer to reconcile reported rubric, reproducibility and retest interpretation against original lab evidence."},
    operations:{title:"Runtime and operations",question:"Ask a lab operations reviewer to explain source-reported timing, cost and tool-use changes. These are informational, not safety regressions."}
  };
  function agendaCounts(){
    if(!reports.length)return [];
    const ids=queueIds();
    return Object.entries(AGENDA).map(([topic,definition])=>{
      const slots=[],caseIds=new Set();let instances=0;
      for(let i=0;i<reports.length;i++){
        let slotHasSignal=false;
        for(const id of ids){
          const count=queueAdverse(id,String(i),topic);
          if(count){instances+=count;slotHasSignal=true;caseIds.add(id);}
        }
        if(slotHasSignal)slots.push(i+1);
      }
      return {topic,title:definition.title,question:definition.question,
        kind:topic==="operations"?"INFORMATIONAL_CHANGES":"SOURCE_ADVERSE_FLAGS",
        instances,anonymous_case_count:caseIds.size,candidate_slots_with_signal:slots,
        status:"REVIEW_ONLY",...fixedFlags()};
    });
  }
  function renderAgenda(){
    const root=$("agendaCards");root.replaceChildren();
    if(!reports.length){root.textContent="Import previous lab reports to prepare an original-source human discussion agenda.";return;}
    for(const topic of agendaCounts()){
      const card=document.createElement("article");card.className="card";
      const heading=document.createElement("h3");heading.textContent=topic.title;card.append(heading);
      const count=document.createElement("p");count.className="big";
      count.textContent=topic.instances+" "+(topic.kind==="INFORMATIONAL_CHANGES"?
        "informational changes":"adverse flag instances");card.append(count);
      const details=document.createElement("p");
      details.textContent=topic.anonymous_case_count+" anonymous source cases · "+
        topic.candidate_slots_with_signal.length+" candidate slots with any signal. "+
        "No signal does not mean safe or approved.";card.append(details);
      const question=document.createElement("p");question.textContent=topic.question;card.append(question);
      const button=document.createElement("button");button.type="button";button.className="secondary";
      button.textContent="Discuss anonymized "+topic.title.toLowerCase()+" cases";
      button.addEventListener("click",()=>{
        $("queueFamily").value=topic.topic;$("queueFilter").value="all";
        $("queueCandidate").value="all";drawQueue();
        $("casework").scrollIntoView({behavior:"smooth",block:"start"});
      });
      card.append(button);root.append(card);
    }
  }
  function render(){
    displayReviewRounds();
    const active=reports.length>0,stats=reports.map(aggregates);
    $("sourceKind").textContent=!active?"No data":demo?"FICTIONAL DEMO ONLY":"UNVERIFIED LAB SOURCES";
    $("sourceLine").textContent=!active?"":reports.length+" candidate reports · "+reports[0].cases.size+
      " shared anonymized cases · all authority flags false · "+(demo?"FICTIONAL DATA":"UNVERIFIED SOURCE");
    for(const id of ["exportCSV","exportJSON","exportHTML","exportCaseCSV","exportPairCSV","print"])$(id).disabled=!active;
    $("appendFile").disabled=!(active&&!demo&&reports.length<12);
    $("saveDraft").disabled=!(active&&!demo&&sourceHashes.length===reports.length);
    $("draftFile").disabled=$("saveDraft").disabled;
    if(!active){
      renderSourceManifest();
      $("cards").innerHTML='<p class="empty">Import reports to compare lab candidates.</p>';
      drawQueue();renderAgenda();
      for(const id of ["thresholds","frontier","caseDetail","metricBoard","pairMetrics","pairChurn","pairChurnSummary"])$(id).innerHTML="";
      $("caseSelect").innerHTML='<option value="">Load reports first</option>';
      return;
    }
    $("cards").innerHTML=stats.map((s,i)=>
      '<article class="card"><h3>Candidate '+(i+1)+
      '<small id="cardLabel'+i+'"></small></h3><p class="'+
      (s.affected?"danger":"warn")+'">'+reports[i].sourceStatus+
      " · "+s.affected+" source-regressed cases</p>"+
      '<p class="big">'+s.regressionEvents+' <small>metric regressions</small></p>'+
      "<p>Scope / policy: <strong>"+format(s.scope)+" / "+format(s.policy)+"</strong></p>"+
      "<p>Mean evidence quality: "+format(s.quality)+"</p>"+
      "<p>Runtime: "+format(s.runtime)+" sec · Cost: $"+format(s.cost)+"</p>"+
      "<p class='footnote'>No safety approval; separate human review required.</p></article>").join("");
    renderSourceManifest();
    renderMetricBoard(stats);
    drawQueue();renderAgenda();
    let t;try{t=threshold();settings=t;$("thresholdMessage").textContent="Review suggestions recomputed locally; no source metrics changed.";}
    catch(_){$("thresholdMessage").textContent="HOLD: invalid threshold — enter a bounded numerical value. No decision output.";
      settings=null;$("saveDraft").disabled=true;for(const id of ["exportCSV","exportJSON","exportHTML","exportCaseCSV","print"])$(id).disabled=true;
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
      const next=[],hashes=[],meta=[];
      for(const file of files){
        assert(file.size>0&&file.size<=262144);
        const bytes=await file.arrayBuffer();
        assert(bytes.byteLength>0&&bytes.byteLength<=262144);
        const source=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
        const sha=await hashBytes(bytes);hashes.push(sha);
        meta.push({bytes:bytes.byteLength,sha,alias:""});
        next.push(decodeReport(strictJSON(source)));
      }
      compatible(next);clearReviewRounds();discussions.clear();batchUndo=null;queueFocus=0;$("queueMessage").textContent="";
      reports=next;sourceMeta=meta;sourceHashes=hashes.every(h=>typeof h==="string")?hashes:[];demo=false;selectedCase="";
      $("draftMessage").textContent=sourceHashes.length?"Private restore available only for identical source bytes.":"WebCrypto unavailable: private draft save/restore disabled.";
      setStatus("Accepted "+next.length+" compatible, unverified lab comparison files. All remain non-authorizing.");
      render();
    }catch(_){setStatus("HOLD: at least one source is malformed, mismatched, repeated or oversized. Existing workspace preserved.",true);}
  }
  async function appendCandidate(file){
    try{
      assert(reports.length>=2&&reports.length<12&&!demo&&file&&
        file.size>0&&file.size<=262144);
      const bytes=await file.arrayBuffer();
      assert(bytes.byteLength>0&&bytes.byteLength<=262144);
      const source=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
      const candidate=decodeReport(strictJSON(source));
      const newReports=[...reports,candidate];
      compatible(newReports);
      const hash=await hashBytes(bytes);
      const newHashes=sourceHashes.length===reports.length&&hash?
        [...sourceHashes,hash]:[];
      clearReviewRounds();reports=newReports;sourceHashes=newHashes;
      sourceMeta=[...sourceMeta,{bytes:bytes.byteLength,sha:hash,alias:""}];batchUndo=null;
      $("draftMessage").textContent=sourceHashes.length?
        "Source set changed: earlier private drafts no longer bind; save new preferences.":
        "Private draft save disabled: original hashes unavailable.";
      setStatus("One compatible, previously finished unverified lab candidate appended. All source safety flags preserved.");
      render();
    }catch(_){setStatus("HOLD: incompatible, duplicate, malformed or oversized append. Existing workspace preserved.",true);}
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
    try{const next=fictional().map(decodeReport);compatible(next);clearReviewRounds();discussions.clear();batchUndo=null;queueFocus=0;$("queueMessage").textContent="";
      reports=next;sourceMeta=[];sourceHashes=[];demo=true;
      $("draftMessage").textContent="Private source-bound drafts are unavailable for fictional demo.";
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
  function discussionSummary(){
    const ids=queueIds(),stages=Object.fromEntries(DISCUSSION_STAGES.map(s=>[s,0]));
    const routes=Object.fromEntries(DISCUSSION_ROUTES.map(s=>[s,0]));
    for(const id of ids){const d=queueSettings(id);stages[d.stage]++;routes[d.route]++;}
    return {source_case_count:ids.length,locally_recorded:discussions.size,
      stages,routes,source_identity_authenticated:false,...fixedFlags()};
  }
  function download(name,text,mime){
    const url=URL.createObjectURL(new Blob([text],{type:mime}));
    const a=document.createElement("a");a.href=url;a.download=name;
    document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),2000);
  }
  function currentPairChurn(){
    const a=Number($("pairA").value),b=Number($("pairB").value);
    return Number.isSafeInteger(a)&&Number.isSafeInteger(b)&&a>=0&&b>=0&&
      a<reports.length&&b<reports.length&&a!==b?pairChurn(a,b):null;
  }
  function reviewRoundExport(){
    if(!reviewRounds||demo||reports.length<2||
      sourceHashes.length!==reports.length||
      !sourceHashes.every((hash,i)=>hash===reviewRounds.hashes[i]))return null;
    const ids=queueIds();
    const current=[...discussions.entries()].map(([id,row])=>({
      case_ordinal:ids.indexOf(id)+1,proposed_group:row.route,discussion_stage:row.stage
    })).filter(row=>row.case_ordinal>0).sort((a,b)=>a.case_ordinal-b.case_ordinal);
    return {
      schema:"lightup.lab_candidate_human_review_rounds.v1",
      status:"REVIEW_ONLY",round_count:reviewRounds.rounds,
      manually_selected_round_order:true,round_order_authenticated:false,
      source_bytes_bound_to_current_import_locally:true,
      changed_case_count:reviewRounds.diff.length,
      proposal_transition_count:reviewRounds.totalTransitions,
      hypothetical_setting_changes:reviewRounds.settingChanges,
      changed_cases:reviewRounds.diff.map(item=>({
        case_ordinal:item.ordinal,proposal_transitions:item.transitions,
        reverted_to_first:item.before.route===item.after.route&&
          item.before.stage===item.after.stage,
        rounds:reviewRounds.snapshots.map((rows,i)=>({
          round_slot:i+1,proposed_group:rows[item.ordinal-1].route,
          discussion_stage:rows[item.ordinal-1].stage
        }))
      })),
      current_local_discussions:current,
      disclaimer:"Unsigned source-free HUMAN self-reports in manual file order. No reviewer identity, verified chronology, source authenticity, remediation, consent or release is established.",
      source_identity_authenticated:false,...fixedFlags()
    };
  }
  function exportJSON(){
    if(!reports.length||!settings)return;
    const out={schema:"lightup.lab_candidate_matrix_review.v5",
      posture:"INCUBATE_M3_M7_PLAN_LAB_ONLY_DRAFT_HOLD",
      status:"REVIEW_ONLY",source_identity_authenticated:false,
      temporal_order_authenticated:false,fictional_demo_only:demo,
      disclaimer:"Human review of untrusted pre-existing lab summaries only. No permission, release, scan or verified remediation.",
      dimensions:dimensions().map(x=>x[1]),review_thresholds:settings,
      human_discussion_summary:discussionSummary(),
      source_based_discussion_agenda:agendaCounts(),
      selected_pair_flag_crossover:currentPairChurn(),
      human_review_round_history:reviewRoundExport(),
      candidates:metricRows(),...fixedFlags()};
    download("lightup-candidate-aggregate-REVIEW-ONLY.json",JSON.stringify(out,null,2)+"\n","application/json");
  }
  function exportCSV(){
    if(!reports.length||!settings)return;
    const head=["candidate_slot","source_status","regressed_cases","metric_regressions",
      "threshold_discussions","scope_flags","policy_flags","fictional_demo_only","report_status",
      "private_discussions_documented","private_discussions_in_progress",
      ...NAMES.map(n=>n+"_total"),"authorized","consent_verified","dispatch_allowed","release_allowed"];
    const rows=metricRows().map(r=>[r.candidate_slot,r.source_status,r.regressed_cases,
      r.metric_regressions,r.threshold_discussions,r.scope_flags,r.policy_flags,
      demo?"true":"false","REVIEW_ONLY",discussionSummary().stages.documented,
      discussionSummary().stages.in_discussion,...NAMES.map(n=>r.metrics[n].candidate_total),"false","false","false","false"]);
    download("lightup-candidate-aggregate-REVIEW-ONLY.csv",
      head.join(",")+"\n"+rows.map(r=>r.join(",")).join("\n")+"\n","text/csv");
  }
  function exportSelectedPairCSV(){
    if(!reports.length||!settings)return;
    const a=Number($("pairA").value),b=Number($("pairB").value);
    if(!Number.isSafeInteger(a)||!Number.isSafeInteger(b)||a<0||b<0||
      a>=reports.length||b>=reports.length||a===b){
      setStatus("Choose two distinct original candidates before exporting pair metrics.",true);
      return;
    }
    const first=aggregates(reports[a]),second=aggregates(reports[b]),churn=pairChurn(a,b);
    const crossover=new Map(churn.metrics.map(row=>[row.name,row]));
    const head=[
      "first_candidate_slot","second_candidate_slot","shared_case_count","metric",
      "first_baseline_aggregate","second_baseline_aggregate","baseline_delta_second_minus_first",
      "first_candidate_aggregate","second_candidate_aggregate","candidate_delta_second_minus_first",
      "first_original_adverse_cases","second_original_adverse_cases",
      "only_first_original_flags","only_second_original_flags","both_original_flags","neither_original_flags",
      "shared_baseline_matches","fictional_demo_only","report_status",
      "source_order_authenticated","source_identity_authenticated",
      "authorized","consent_verified","dispatch_allowed","release_allowed"
    ];
    const rows=NAMES.map(name=>{
      const x=first.total[name],y=second.total[name],flags=crossover.get(name);
      return [
        a+1,b+1,churn.case_count,name,x.baseline,y.baseline,y.baseline-x.baseline,
        x.candidate,y.candidate,y.candidate-x.candidate,x.adverse,y.adverse,
        flags.only_first,flags.only_second,flags.both,flags.neither,
        String(close(x.baseline,y.baseline)),String(demo),"REVIEW_ONLY",
        "false","false","false","false","false","false"
      ];
    });
    const csvField=value=>"\""+String(value).replace(/"/g,"\"\"")+"\"";
    const csv=[head,...rows].map(row=>row.map(csvField).join(",")).join("\r\n")+"\r\n";
    download("lightup-candidate-pair-metrics-REVIEW-ONLY.csv",csv,"text/csv");
  }

  function exportPrivateCaseCSV(){
    if(!reports.length||!settings)return;
    const a=Number($("pairA").value),b=Number($("pairB").value);
    if(!currentPairChurn()){
      $("queueMessage").textContent="Choose two distinct source candidates before creating the private case register.";
      return;
    }
    const head=["private_anonymous_case_ordinal","first_candidate_slot","second_candidate_slot",
      "original_source_adverse_first","original_source_adverse_second",
      "first_only_original_flags","second_only_original_flags","shared_original_flags",
      "scope_policy_original_flags_any","locally_proposed_generic_group",
      "local_human_discussion_stage","source_chronology_authenticated",
      "source_identity_authenticated","authorized","consent_verified","dispatch_allowed",
      "release_allowed","report_status"];
    const rows=queueIds().map((id,i)=>{
      const first=reports[a].cases.get(id),second=reports[b].cases.get(id);
      const flags=name=>[first.metrics[name].regression,second.metrics[name].regression];
      const onlyA=NAMES.filter(n=>flags(n)[0]&&!flags(n)[1]).length;
      const onlyB=NAMES.filter(n=>!flags(n)[0]&&flags(n)[1]).length;
      const both=NAMES.filter(n=>flags(n)[0]&&flags(n)[1]).length;
      const safety=TOPICS.scope.filter(n=>flags(n)[0]||flags(n)[1]).length;
      const local=queueSettings(id);
      return [i+1,a+1,b+1,first.regressions.length,second.regressions.length,
        onlyA,onlyB,both,safety,local.route,local.stage,"false","false","false",
        "false","false","false","REVIEW_ONLY"];
    });
    download("lightup-PRIVATE-anonymous-case-review-REVIEW-ONLY.csv",
      head.join(",")+"\n"+rows.map(r=>r.join(",")).join("\n")+"\n","text/csv");
    $("queueMessage").textContent="PRIVATE anonymous source-flag conversation CSV exported. Local handling required; no actual authorization or assignments.";
  }
  function exportHTML(){
    if(!reports.length||!settings)return;
    const data=metricRows(),stats=reports.map(aggregates);
    const stylesheet="body{font:15px/1.5 system-ui,sans-serif;max-width:1100px;margin:auto;padding:25px;color:#1a2836}"+
      "table{border-collapse:collapse;width:100%;margin:20px 0}td,th{padding:9px;border:1px solid #aab5bc;text-align:left}"+
      "th{background:#e9f0f3}h1,h2{color:#123047}.warning{border-left:5px solid #bb3737;padding:12px;background:#fff3f3}";
    const source=demo?"FICTIONAL DEMONSTRATION · invented data":"UNVERIFIED PRE-EXISTING LAB SOURCE";
    const advisory=stats.map((a,i)=>{
      const flags=breaches(a,settings);
      return "<h2>Candidate "+(i+1)+"</h2><p>Original source status: "+reports[i].sourceStatus+
        "; regressed lab cases: "+a.affected+"; scope violations: "+format(a.scope)+
        "; policy violations: "+format(a.policy)+"; human discussion flags: "+
        flags.length+". "+(flags.length?flags.join("; "):"No threshold breaches: STILL REVIEW ONLY.")+"</p>";
    }).join("");
    const agendaTable=table(["Human lab discussion topic","Source instances",
      "Anonymous cases","Candidate slots with signal","Evidence to request"],
      agendaCounts().map(x=>[x.title,x.instances,x.anonymous_case_count,
        x.candidate_slots_with_signal.length,x.question]));
    const crossover=currentPairChurn();
    const crossoverTable=crossover?"<h2>Selected two-candidate original source flag crossover</h2>"+
      "<p>Case-level original source regression-flag counts only; no proven order, review, fix or safety.</p>"+
      table(["Original metric","Only first","Only second","Both","Neither"],
        crossover.metrics.map(r=>[nice(r.name),r.only_first,r.only_second,r.both,r.neither])):"";
    const metricTable=table(["Metric",...data.map(r=>"Candidate "+r.candidate_slot+" · total")],
      NAMES.map(n=>[nice(n),...data.map(r=>format(r.metrics[n].candidate_total))]));
    const pairNumericTable=crossover?
      "<h2>Selected two-candidate numeric comparison</h2>"+
      "<p>Second minus first is descriptive only. Shared baselines and original adverse counts are source-reported, not independently verified.</p>"+
      table(["Metric","First baseline aggregate","Second baseline aggregate",
        "First candidate aggregate","Second candidate aggregate","Delta (second − first)",
        "First adverse cases","Second adverse cases"],
        NAMES.map(n=>{
          const first=stats[crossover.first_candidate_slot-1].total[n];
          const second=stats[crossover.second_candidate_slot-1].total[n];
          return [nice(n),format(first.baseline),format(second.baseline),
            format(first.candidate),format(second.candidate),
            format(second.candidate-first.candidate),first.adverse,second.adverse];
        })):"";
    const historyBound=!!reviewRounds&&!demo&&
      sourceHashes.length===reports.length&&
      sourceHashes.every((hash,i)=>hash===reviewRounds.hashes[i]);
    const reviewHistorySection=historyBound?
      "<h2>PRIVATE HUMAN review-round history · manually ordered</h2>"+
      "<p>"+reviewRounds.rounds+" separately selected unsigned HUMAN drafts; "+
      reviewRounds.diff.length+" anonymous cases changed at least once; "+
      reviewRounds.totalTransitions+" local proposal transitions; "+
      reviewRounds.settingChanges+" hypothetical settings/focus changes. "+
      "Chooser order is not verified chronology. No status proves a fix or permission.</p>"+
      (reviewRounds.diff.length?reviewRounds.diff.map(item=>
        "<h3>Lab case "+String(item.ordinal).padStart(2,"0")+
        " · "+item.transitions+" proposal transition(s)</h3>"+
        table(["Manually selected round","Generic HUMAN group","Local discussion stage"],
          reviewRounds.snapshots.map((rows,i)=>[
            "Round "+(i+1),nice(rows[item.ordinal-1].route),
            nice(rows[item.ordinal-1].stage)]))).join("")
        :"<p>No changed local HUMAN proposals. This does not verify any finding, remediation or release.</p>")
      :"";
    const currentDiscussionSection=historyBound&&discussions.size?
      "<h2>Current local HUMAN discussion suggestions</h2>"+
      "<p>Only locally recorded proposals are listed. Unlisted cases have no saved local suggestion; nothing is assigned to a real person.</p>"+
      table(["Anonymous case","Generic proposed group","Local discussion stage"],
        [...discussions.entries()].map(([id,row])=>[
          "Lab case "+String(queueIds().indexOf(id)+1).padStart(2,"0"),
          nice(row.route),nice(row.stage)]))
      :"";
    const html="<!doctype html><html lang='en'><head><meta charset='utf-8'>"+
      "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; script-src 'none'; "+
      "connect-src 'none'; img-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"+
      "<title>LightUp Lab Candidate Discussion · REVIEW ONLY</title><style>"+stylesheet+"</style></head><body>"+
      "<h1>LightUp / private lab candidate discussion</h1><p class='warning'><strong>"+source+
      "</strong>. INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. Never authenticates consent, scope, "+
      "retest, release or security outcomes. Authorized: false. Consent verified: false. "+
      "Dispatch allowed: false. Release allowed: false.</p>"+
      "<p>Original source filenames, source case identifiers, identities and raw source payload "+
      "have been omitted. Untrusted values are only reported as aggregates.</p>"+
      advisory+"<h2>Fixed human discussion questions based on unverified source summaries</h2>"+
      agendaTable+crossoverTable+pairNumericTable+reviewHistorySection+currentDiscussionSection+
      "<h2>Unverified original metric totals</h2>"+metricTable+
      "<p>No recommendation to deploy, grant or scan. Separate authenticated client/operator "+
      "consent with action-time revocation, original security fixes, full required hosted/permanent VPS "+
      "CI, independent security/privacy review and human GO remain mandatory.</p></body></html>";
    download("lightup-human-candidate-brief-REVIEW-ONLY.html",html,"text/html");
  }
  const DRAFT_SCHEMA_V1="lightup.lab_candidate_private_preferences.v1";
  const DRAFT_SCHEMA_V2="lightup.lab_candidate_private_preferences.v2";
  const DRAFT_SCHEMA="lightup.lab_candidate_private_preferences.v3";
  const PREF_KEYS=["maxScope","maxPolicy","minQuality","minCoverage","maxRuntime","maxCost"];
  const DIM_KEYS=["dimQuality","dimCoverage","dimRuntime","dimCost"];
  function checkDraft(x){
    assert(!demo&&reports.length>=2&&sourceHashes.length===reports.length);
    const v3=x?.schema===DRAFT_SCHEMA,v2=x?.schema===DRAFT_SCHEMA_V2;
    const withDiscussions=v2||v3;
    assert((withDiscussions||x?.schema===DRAFT_SCHEMA_V1)&&
      exact(x,["schema","private_unsigned","source_sha256","thresholds",
        "dimensions","focus",...(withDiscussions?["discussions"]:[]),
        ...(v3?["source_aliases"]:[]),...AUTH])&&
      x.private_unsigned===true&&AUTH.every(k=>x[k]===false));
    assert(Array.isArray(x.source_sha256)&&x.source_sha256.length===sourceHashes.length&&
      x.source_sha256.every((h,i)=>typeof h==="string"&&
      /^[a-f0-9]{64}$/.test(h)&&h===sourceHashes[i]));
    assert(exact(x.thresholds,PREF_KEYS)&&exact(x.dimensions,DIM_KEYS)&&
      DIM_KEYS.every(k=>typeof x.dimensions[k]==="boolean")&&
      exact(x.focus,["pairA","pairB","caseIndex","metric"]));
    const t=x.thresholds;
    for(const k of PREF_KEYS)assert(finite(t[k])&&t[k]>=0);
    assert(Number.isSafeInteger(t.maxScope)&&t.maxScope<=1e6&&
      Number.isSafeInteger(t.maxPolicy)&&t.maxPolicy<=1e6&&
      t.minQuality<=1&&Number.isSafeInteger(t.minCoverage)&&t.minCoverage<=1e9&&
      t.maxRuntime<=1e12&&t.maxCost<=1e12);
    const f=x.focus;
    assert(Number.isSafeInteger(f.pairA)&&Number.isSafeInteger(f.pairB)&&
      f.pairA>=0&&f.pairB>=0&&f.pairA<reports.length&&f.pairB<reports.length&&
      f.pairA!==f.pairB&&Number.isSafeInteger(f.caseIndex)&&
      f.caseIndex>=0&&f.caseIndex<reports[0].cases.size&&NAMES.includes(f.metric));
    if(withDiscussions){
      assert(Array.isArray(x.discussions)&&x.discussions.length<=reports[0].cases.size);
      const ordinals=new Set();
      for(const row of x.discussions){
        assert(exact(row,["ordinal","route","stage"])&&
          Number.isSafeInteger(row.ordinal)&&row.ordinal>=1&&
          row.ordinal<=reports[0].cases.size&&!ordinals.has(row.ordinal)&&
          DISCUSSION_ROUTES.includes(row.route)&&DISCUSSION_STAGES.includes(row.stage)&&
          (row.route!=="unrouted"||row.stage!=="needs_review"));
        ordinals.add(row.ordinal);
      }
    }
    if(v3)assert(Array.isArray(x.source_aliases)&&
      x.source_aliases.length===sourceHashes.length&&
      x.source_aliases.every(label=>typeof label==="string"&&label.length<=40&&
        label===label.trim()&&/^[\x20-\x7e]*$/.test(label)));
    return x;
  }
  function saveDraft(){
    if(demo||sourceHashes.length!==reports.length||!settings)return;
    const ids=[...reports[0].cases.keys()].sort();
    const obj={schema:DRAFT_SCHEMA,private_unsigned:true,source_sha256:[...sourceHashes],
      source_aliases:sourceMeta.map(e=>e.alias||""),thresholds:{...settings},
      dimensions:Object.fromEntries(DIM_KEYS.map(k=>[k,$(k).checked])),
      focus:{pairA:Number($("pairA").value),pairB:Number($("pairB").value),
        caseIndex:Math.max(0,ids.indexOf(selectedCase)),metric:$("metricSelect").value},
      discussions:[...discussions].map(([id,value])=>({
        ordinal:ids.indexOf(id)+1,route:value.route,stage:value.stage
      })).sort((a,b)=>a.ordinal-b.ordinal),...fixedFlags()};
    try{checkDraft(obj);
      download("lightup-PRIVATE-local-review-preferences.json",
        JSON.stringify(obj,null,2)+"\n","application/json");
      $("draftMessage").textContent="Private unsigned source-bound preferences saved. This does not authenticate provenance or consent.";
    }catch(_){$("draftMessage").textContent="HOLD: invalid local review selection, private draft not saved.";}
  }
  async function restoreDraft(file){
    try{
      assert(file&&file.size>0&&file.size<=32768);
      const source=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
      const x=checkDraft(strictJSON(source));
      // Atomic validation already completed before changing live review state.
      const ids=queueIds(),next=new Map();
      for(const row of x.discussions||[])next.set(ids[row.ordinal-1],
        {route:row.route,stage:row.stage});
      clearReviewRounds();discussions=next;batchUndo=null;queueFocus=x.focus.caseIndex;
      sourceMeta.forEach((entry,i)=>entry.alias=x.source_aliases?.[i]||"");
      PREF_KEYS.forEach(k=>$(k).value=String(x.thresholds[k]));
      DIM_KEYS.forEach(k=>$(k).checked=x.dimensions[k]);
      $("pairA").value=String(x.focus.pairA);
      $("pairB").value=String(x.focus.pairB);
      selectedCase=[...reports[0].cases.keys()].sort()[x.focus.caseIndex];
      $("metricSelect").value=x.focus.metric;
      render();
      $("draftMessage").textContent="PRIVATE source-bound settings and discussion state restored. No grant, consent or permission created.";
    }catch(_){$("draftMessage").textContent="HOLD: changed, malformed or incompatible PRIVATE draft. Workspace unchanged.";}
  }

  // Offline, separately chosen, unsigned HUMAN discussion rounds from identical
  // original source bytes. No timestamp, reviewer identity or order is inferred.
  function clearReviewRounds(){
    reviewRounds=null;
    $("draftRounds").value="";
    $("roundsMessage").textContent="";
    $("roundsSummary").textContent="";
    $("roundsTable").textContent="";
    $("exportRoundsCSV").disabled=true;
    $("exportRoundsHTML").disabled=true;
    $("adoptRound").disabled=true;
    $("adoptSelected").disabled=true;
    $("selectVisibleRounds").disabled=true;
    $("clearSelectedRounds").disabled=true;
    $("selectedRoundsCount").textContent="";
    $("roundDetail").textContent="";
  }
  function roundRows(draft){
    const n=queueIds().length,rows=Array.from({length:n},()=>({
      route:"unrouted",stage:"needs_review"
    }));
    for(const row of draft.discussions||[])
      rows[row.ordinal-1]={route:row.route,stage:row.stage};
    return rows;
  }
  function roundSettingsDiff(first,second){
    let changed=0;
    for(const key of PREF_KEYS)if(first.thresholds[key]!==second.thresholds[key])changed++;
    for(const key of DIM_KEYS)if(first.dimensions[key]!==second.dimensions[key])changed++;
    for(const key of ["pairA","pairB","caseIndex","metric"])
      if(first.focus[key]!==second.focus[key])changed++;
    return changed;
  }
  function displayReviewRounds(){
    const valid=!!reviewRounds&&reports.length>=2&&!demo&&
      sourceHashes.length===reports.length&&
      sourceHashes.every((hash,i)=>hash===reviewRounds.hashes[i]);
    $("draftRounds").disabled=!(reports.length>=2&&!demo&&sourceHashes.length===reports.length);
    $("exportRoundsCSV").disabled=!valid;
    $("exportRoundsHTML").disabled=!valid;
    $("adoptRound").disabled=!valid;
    $("selectVisibleRounds").disabled=!valid;
    $("clearSelectedRounds").disabled=!valid;
    $("adoptSelected").disabled=!valid||!reviewRounds?.selected.size;
    $("selectedRoundsCount").textContent=valid?
      reviewRounds.selected.size+" case suggestions selected for optional LOCAL carry-forward.":"";
    if(!valid){
      $("adoptSelected").disabled=true;
      $("roundsSummary").textContent="";
      $("roundsTable").textContent="";
      return;
    }
    const diffs=reviewRounds.diff;
    const filtered=diffs.filter(d=>{
      const mode=$("roundFilter").value;
      return mode==="all"||(mode==="repeated"&&d.transitions>=2)||
        (mode==="reverted"&&d.before.route===d.after.route&&
          d.before.stage===d.after.stage);
    });
    $("roundsSummary").textContent=reviewRounds.rounds+" separately chosen local HUMAN rounds · "+
      diffs.length+" of "+queueIds().length+
      " anonymous cases changed across at least one adjacent round ("+
      reviewRounds.totalTransitions+" changes). "+
      reviewRounds.settingChanges+" hypothetical setting/focus changes across round boundaries. "+

      "File order is a manual selection, not verified chronology. Zero changes cannot prove remediation.";
    $("roundsTable").innerHTML=table(
      ["Select","Anonymous case","First HUMAN stage","Last HUMAN stage",
       "First proposed group","Last proposed group","Proposal transitions"],
      filtered.map(d=>[
        '<input type="checkbox" aria-label="Select local HUMAN case '+d.ordinal+
          '" data-round-select="'+d.ordinal+'" '+(reviewRounds.selected.has(d.ordinal)?"checked":"")+'>',
        '<button type="button" class="secondary" data-round-focus="'+d.ordinal+
          '">Lab case '+String(d.ordinal).padStart(2,"0")+'</button>',
        nice(d.before.stage),nice(d.after.stage),nice(d.before.route),
        nice(d.after.route),d.transitions])
    );
    if(!filtered.length)$("roundsTable").textContent="No HUMAN changes for this view; original source findings remain unverified.";
    if(reviewRounds.focused)showRoundTimeline(reviewRounds.focused);
    else $("roundDetail").textContent="";
  }
  function shownRoundDiffs(){
    if(!reviewRounds)return [];
    const mode=$("roundFilter").value;
    return reviewRounds.diff.filter(d=>mode==="all"||
      (mode==="repeated"&&d.transitions>=2)||
      (mode==="reverted"&&d.before.route===d.after.route&&
       d.before.stage===d.after.stage));
  }
  function showRoundTimeline(ordinal){
    if(!reviewRounds||!Number.isSafeInteger(ordinal)||ordinal<1||
      ordinal>queueIds().length)return;
    reviewRounds.focused=ordinal;
    $("roundDetail").innerHTML='<h4>Lab case '+String(ordinal).padStart(2,"0")+
      ' · local proposal history only</h4>'+table(
      ["Manually supplied round","Proposed HUMAN group","Local discussion stage"],
      reviewRounds.snapshots.map((rows,i)=>[
        "HUMAN draft "+(i+1),nice(rows[ordinal-1].route),
        nice(rows[ordinal-1].stage)]));
  }
  async function compareReviewRounds(files){
    try{
      assert(files.length>=2&&files.length<=8&&!demo&&reports.length>=2&&
        sourceHashes.length===reports.length);
      const drafts=[];
      for(const file of files){
        assert(file&&file.size>0&&file.size<=32768);
        const bytes=await file.arrayBuffer();
        assert(bytes.byteLength>0&&bytes.byteLength<=32768);
        const raw=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
        const draft=checkDraft(strictJSON(raw));
        // Earlier settings-only v1 drafts have no HUMAN queue to compare.
        assert(draft.schema===DRAFT_SCHEMA_V2||draft.schema===DRAFT_SCHEMA);
        drafts.push(draft);
      }
      const snapshots=drafts.map(roundRows),before=snapshots[0],
        after=snapshots[snapshots.length-1],diff=[];
      let totalTransitions=0,settingChanges=0;
      for(let j=1;j<drafts.length;j++)
        settingChanges+=roundSettingsDiff(drafts[j-1],drafts[j]);
      for(let i=0;i<before.length;i++){
        let transitions=0;
        for(let j=1;j<snapshots.length;j++)
          if(snapshots[j][i].route!==snapshots[j-1][i].route||
            snapshots[j][i].stage!==snapshots[j-1][i].stage)transitions++;
        totalTransitions+=transitions;
        if(transitions)diff.push({ordinal:i+1,before:before[i],after:after[i],
          transitions});
      }
      // All admission and source binding above must succeed before replacing view.
      reviewRounds={hashes:[...sourceHashes],before,after,diff,
        snapshots,selected:new Set(),focused:0,
        rounds:drafts.length,totalTransitions,settingChanges};
      $("roundFilter").value="all";
      $("roundsMessage").textContent=drafts.length+" PRIVATE source-byte-bound HUMAN drafts admitted. "+
        "Only ordinal discussion changes shown. No identity, consent or reviewer chronology verified.";
      displayReviewRounds();
    }catch(_){
      $("roundsMessage").textContent="HOLD: original source bytes, HUMAN schema or size mismatch. "+
        "Prior local comparison and workspace are unchanged.";
    }
  }
  function exportReviewRoundsCSV(){
    if(!reviewRounds||demo||reports.length<2||
      sourceHashes.length!==reports.length||
      !sourceHashes.every((h,i)=>h===reviewRounds.hashes[i]))return;
    const header=["case_ordinal","manually_selected_round_slot","round_count",
      "proposed_group","discussion_stage","changed_from_previous_round",
      "returned_to_first_proposal","case_transition_count","local_human_discussion_only",
      "source_identity_authenticated","round_order_authenticated","authorized",
      "consent_verified","dispatch_allowed","release_allowed","status"];
    const lines=[];
    for(const item of reviewRounds.diff){
      const snapshots=reviewRounds.snapshots.map(rows=>rows[item.ordinal-1]);
      snapshots.forEach((row,i)=>{
        const previous=i?snapshots[i-1]:null;
        const changed=!!previous&&(row.route!==previous.route||row.stage!==previous.stage);
        const returned=!!previous&&changed&&row.route===snapshots[0].route&&
          row.stage===snapshots[0].stage;
        lines.push([item.ordinal,i+1,reviewRounds.rounds,row.route,row.stage,
          changed?"true":"false",returned?"true":"false",item.transitions,
          "true","false","false","false","false","false","false","REVIEW_ONLY"]);
      });
    }
    const csvField=value=>'"'+String(value).replace(/"/g,'""')+'"';
    download("lightup-PRIVATE-HUMAN-review-round-history.csv",
      [header,...lines].map(row=>row.map(csvField).join(",")).join("\r\n")+"\r\n",
      "text/csv");
    $("roundsMessage").textContent="PRIVATE changed-only HUMAN proposals saved locally. "+
      "Missing changes never imply a security fix or approval.";
  }
  function exportReviewRoundsHTML(){
    if(!reviewRounds||demo||reports.length<2||
      sourceHashes.length!==reports.length||
      !sourceHashes.every((hash,i)=>hash===reviewRounds.hashes[i]))return;
    // Values entering HTML are constrained to bounded integer ordinals or
    // hard-coded enum stage/group labels by original private draft admission.
    const css="body{font:15px system-ui,sans-serif;max-width:1000px;margin:2rem auto;"+
      "padding:0 1rem;color:#182336}table{border-collapse:collapse;width:100%;"+
      "margin:1rem 0 2rem}th,td{border:1px solid #9da9b6;padding:.45rem;text-align:left}"+
      "th{background:#e9edf2}.hold{border:2px solid #a54a22;padding:1rem}"+
      "h2{page-break-after:avoid}table{break-inside:avoid}"+
      "@media print{body{margin:0;max-width:none}}";
    const header="<!doctype html><html lang='en'><head><meta charset='utf-8'>"+
      "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "+
      "script-src 'none'; connect-src 'none'; img-src 'none'; object-src 'none'; "+
      "frame-src 'none'; base-uri 'none'; form-action 'none'; style-src 'unsafe-inline'\">"+
      "<title>LightUp PRIVATE HUMAN lab review history · REVIEW ONLY</title><style>"+css+
      "</style></head><body><h1>LightUp · PRIVATE HUMAN lab review history</h1>"+
      "<div class='hold'><strong>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD</strong>"+
      "<p>Unauthenticated local HUMAN proposals from separately chosen unsigned source-byte-matched drafts. "+
      "No established file chronology, reviewer identity, client consent, remediation, authorization, "+
      "release, scanner instruction, security finding verification or dispatch. "+
      "authorized=false · consent_verified=false · dispatch_allowed=false · release_allowed=false</p></div>";
    const summary="<h2>Source-free discussion summary</h2><p>"+
      reviewRounds.rounds+" manually ordered private drafts; "+queueIds().length+
      " anonymous lab cases; "+reviewRounds.diff.length+
      " case suggestions changed at least once; "+reviewRounds.totalTransitions+
      " local proposal changes. "+reviewRounds.settingChanges+
      " hypothetical setting/focus changes are counted separately and never treated as policy.</p>";
    let body="";
    for(const item of reviewRounds.diff){
      body+="<h2>Anonymous lab case "+String(item.ordinal).padStart(2,"0")+
        " · "+item.transitions+" HUMAN proposal transition(s)</h2>"+
        table(["Manually supplied round","Generic HUMAN review group","Local discussion stage"],
          reviewRounds.snapshots.map((rows,i)=>["Round "+(i+1),
            nice(rows[item.ordinal-1].route),nice(rows[item.ordinal-1].stage)]));
    }
    if(!reviewRounds.diff.length)body="<p>No changes in the local HUMAN proposals; "+
      "this cannot verify a finding, resolution or release.</p>";
    const footer="<p>Source case IDs, source fingerprints, aliases, filenames, "+
      "targets, raw original metrics, human identities and notes are intentionally absent. "+
      "Separate original security/privacy reviews, authentic current client and operator consent, "+
      "action-time revocation, exact-head CI and HUMAN GO remain mandatory.</p></body></html>";
    download("lightup-PRIVATE-HUMAN-review-history-REVIEW-ONLY.html",
      header+summary+body+footer,"text/html");
    $("roundsMessage").textContent="PRIVATE script-free HUMAN timeline briefing saved locally. "+
      "No source IDs, people, findings or permission claims included.";
  }
  function adoptReviewRound(){
    if(!reviewRounds||demo||reports.length<2||
      sourceHashes.length!==reports.length||
      !sourceHashes.every((h,i)=>h===reviewRounds.hashes[i]))return;
    if(!window.confirm("Replace current LOCAL anonymous HUMAN discussion suggestions "+
      "with all suggestions from the LAST manually selected PRIVATE draft? "+
      "This does not alter original lab data, evidence, consent or security findings."))return;
    const ids=queueIds(),next=new Map();
    reviewRounds.after.forEach((row,i)=>{
      if(row.route!=="unrouted"||row.stage!=="needs_review")
        next.set(ids[i],{route:row.route,stage:row.stage});
    });
    batchUndo=new Map(discussions);discussions=next;
    $("roundsMessage").textContent="Last PRIVATE HUMAN discussion round copied "+
      "to local queue. Hypothetical thresholds and original findings unchanged.";
    render();
  }
  function adoptSelectedReviewRows(){
    if(!reviewRounds||!reviewRounds.selected.size||demo||
      sourceHashes.length!==reports.length||
      !sourceHashes.every((hash,i)=>hash===reviewRounds.hashes[i]))return;
    const count=reviewRounds.selected.size;
    if(!window.confirm("Apply last-round LOCAL HUMAN proposals to exactly "+count+
      " selected anonymous cases and preserve other local discussion states? "+
      "No real assignments, security findings or consent are changed."))return;
    const ids=queueIds(),next=new Map(discussions);
    for(const ordinal of reviewRounds.selected){
      if(!Number.isSafeInteger(ordinal)||ordinal<1||ordinal>ids.length)return;
      const row=reviewRounds.after[ordinal-1],id=ids[ordinal-1];
      if(row.route==="unrouted"&&row.stage==="needs_review")next.delete(id);
      else next.set(id,{route:row.route,stage:row.stage});
    }
    batchUndo=new Map(discussions);discussions=next;
    $("roundsMessage").textContent="Copied "+count+
      " selected LOCAL HUMAN suggestions. Other discussions and original lab sources unchanged; one-step undo is available in the Human queue.";
    render();
  }
  function forget(){
    clearReviewRounds();
    reports=[];sourceMeta=[];sourceHashes=[];demo=false;selectedCase="";settings=null;
    discussions.clear();batchUndo=null;queueFocus=0;$("queueMessage").textContent="";
    $("draftFile").value="";$("draftMessage").textContent="";
    const defaults={maxScope:0,maxPolicy:0,minQuality:0.75,minCoverage:0,
      maxRuntime:0,maxCost:0};
    Object.entries(defaults).forEach(([k,v])=>$(k).value=String(v));
    for(const k of ["dimQuality","dimCoverage","dimRuntime","dimCost"])$(k).checked=true;
    $("thresholdMessage").textContent="";$("files").value="";
    setStatus("All imported records forgotten from this workspace.");render();
  }
  // Accessible local workspace navigation; no route changes, external links or telemetry.
  const sectionLinks=[...document.querySelectorAll(".quicknav a")];
  function markNav(hash){
    for(const link of sectionLinks){
      if(link.getAttribute("href")===hash)link.setAttribute("aria-current","location");
      else link.removeAttribute("aria-current");
    }
  }
  if("IntersectionObserver" in window){
    const navigator=new IntersectionObserver(entries=>{
      const visible=entries.filter(e=>e.isIntersecting)
        .sort((a,b)=>b.intersectionRatio-a.intersectionRatio);
      if(visible.length)markNav("#"+visible[0].target.id);
    },{rootMargin:"-70px 0px -60% 0px",threshold:[0,0.15,0.4]});
    for(const link of sectionLinks){
      const target=document.querySelector(link.getAttribute("href"));
      if(target)navigator.observe(target);
      link.addEventListener("click",()=>markNav(link.getAttribute("href")));
    }
  }else{
    for(const link of sectionLinks)
      link.addEventListener("click",()=>markNav(link.getAttribute("href")));
  }
  // No fetch, storage, workers, scanner or execution API.
  $("queueIncludeNeutral").addEventListener("change",drawQueue);
  $("queueRows").addEventListener("click",e=>{
    const button=e.target.closest("button[data-queue-index]");
    if(!button)return;
    const ordinal=Number(button.dataset.queueIndex);
    if(!Number.isSafeInteger(ordinal)||ordinal<0||ordinal>=queueIds().length)return;
    queueFocus=ordinal;drawQueue();
    $("queueCase").focus();
  });
  $("applyBulk").addEventListener("click",()=>{
    if(!reports.length)return;
    const route=$("bulkRoute").value,stage=$("bulkStage").value;
    if(!(route==="unchanged"||DISCUSSION_ROUTES.includes(route))||
       !(stage==="unchanged"||DISCUSSION_STAGES.includes(stage))||
       (route==="unchanged"&&stage==="unchanged")){
      $("queueMessage").textContent="Select a valid generic group or human discussion stage first.";
      return;
    }
    const candidate=$("queueCandidate").value,topic=$("queueFamily").value,
      filter=$("queueFilter").value,neutral=$("queueIncludeNeutral").checked;
    const visible=queueIds().filter(id=>
      (neutral||queueAdverse(id,candidate,topic)>0)&&
      (filter==="all"||queueSettings(id).stage===filter));
    if(!visible.length)return;
    if(!window.confirm("Update only "+visible.length+
       " visible anonymized lab case discussions? No real assignment or authorization."))return;
    const previous=new Map(discussions);
    for(const id of visible){
      const current=queueSettings(id);
      const next={route:route==="unchanged"?current.route:route,
        stage:stage==="unchanged"?current.stage:stage};
      if(next.route==="unrouted"&&next.stage==="needs_review")discussions.delete(id);
      else discussions.set(id,next);
    }
    batchUndo=previous;
    $("queueMessage").textContent="Updated "+visible.length+
      " local anonymous human discussion suggestions. One-step undo available.";
    drawQueue();
  });
  $("undoBulk").addEventListener("click",()=>{
    if(batchUndo===null)return;
    discussions=batchUndo;batchUndo=null;
    $("queueMessage").textContent="Last local batch reversed. No source findings changed.";
    drawQueue();
  });
  $("queueCase").addEventListener("change",e=>{
    const i=Number(e.target.value);
    if(Number.isSafeInteger(i)&&i>=0&&i<queueIds().length){queueFocus=i;drawQueue();}
  });
  for(const id of ["queueCandidate","queueFamily","queueFilter"])
    $(id).addEventListener("change",drawQueue);
  $("saveQueue").addEventListener("click",()=>{
    const id=queueIds()[queueFocus];if(!id)return;
    const route=$("queueRoute").value,stage=$("queueStage").value;
    if(!DISCUSSION_ROUTES.includes(route)||!DISCUSSION_STAGES.includes(stage))return;
    batchUndo=null;
    if(route==="unrouted"&&stage==="needs_review")discussions.delete(id);
    else discussions.set(id,{route,stage});
    $("queueMessage").textContent="Local anonymous human discussion updated. Nothing assigned, scanned or authorized.";
    drawQueue();
  });
  $("focusQueue").addEventListener("click",()=>{
    const id=queueIds()[queueFocus];if(!id)return;
    selectedCase=id;const select=$("caseSelect");
    select.value=String(queueFocus);renderCase(id);select.scrollIntoView({behavior:"smooth",block:"center"});
  });
  $("resetQueue").addEventListener("click",()=>{
    if(!discussions.size)return;
    if(!window.confirm("Discard all local human discussion stages and proposed groups?"))return;
    discussions.clear();batchUndo=null;$("queueMessage").textContent="Local human discussion suggestions forgotten.";
    drawQueue();
  });
  $("exportRoundsCSV").addEventListener("click",exportReviewRoundsCSV);
  $("exportRoundsHTML").addEventListener("click",exportReviewRoundsHTML);
  $("adoptRound").addEventListener("click",adoptReviewRound);
  $("saveDraft").addEventListener("click",saveDraft);
  $("roundFilter").addEventListener("change",displayReviewRounds);
  $("roundsTable").addEventListener("click",e=>{
    const b=e.target.closest("button[data-round-focus]");
    if(!b||!reviewRounds)return;
    showRoundTimeline(Number(b.dataset.roundFocus));
  });
  $("roundsTable").addEventListener("change",e=>{
    const input=e.target.closest("input[data-round-select]");
    if(!input||!reviewRounds)return;
    const ordinal=Number(input.dataset.roundSelect);
    if(!reviewRounds.diff.some(d=>d.ordinal===ordinal))return;
    if(input.checked)reviewRounds.selected.add(ordinal);
    else reviewRounds.selected.delete(ordinal);
    $("adoptSelected").disabled=!reviewRounds.selected.size;
    $("selectedRoundsCount").textContent=reviewRounds.selected.size+
      " case suggestions selected for optional LOCAL carry-forward.";
  });
  $("selectVisibleRounds").addEventListener("click",()=>{
    if(!reviewRounds)return;
    for(const row of shownRoundDiffs())reviewRounds.selected.add(row.ordinal);
    displayReviewRounds();
  });
  $("clearSelectedRounds").addEventListener("click",()=>{
    if(!reviewRounds)return;
    reviewRounds.selected.clear();displayReviewRounds();
  });
  $("adoptSelected").addEventListener("click",adoptSelectedReviewRows);
  $("draftRounds").addEventListener("change",e=>{
    if(e.target.files.length)void compareReviewRounds([...e.target.files]);
    e.target.value="";
  });
  $("draftFile").addEventListener("change",e=>{
    if(e.target.files.length)void restoreDraft(e.target.files[0]);
    e.target.value="";
  });
  $("files").addEventListener("change",e=>{
    if(e.target.files.length)void importFiles([...e.target.files]);
    e.target.value="";
  });
  $("appendFile").addEventListener("change",e=>{
    if(e.target.files.length)void appendCandidate(e.target.files[0]);
    e.target.value="";
  });
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
  $("exportHTML").addEventListener("click",exportHTML);
  $("exportCaseCSV").addEventListener("click",exportPrivateCaseCSV);
  $("exportPairCSV").addEventListener("click",exportSelectedPairCSV);
  $("print").addEventListener("click",()=>{if(reports.length&&settings)window.print();});
  render();
})();