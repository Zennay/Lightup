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
  const MAX_FILE=262144,MAX_PRIVATE_BUNDLE=2097152;
  const MAX_ENCRYPTED_BUNDLE=2809856;
  const ENVELOPE_SCHEMA="lightup.assessment_trends_encrypted_private_session.v1";
  const CRYPTO_ITERATIONS=310000;
  const PRIVATE_AAD=new TextEncoder().encode(ENVELOPE_SCHEMA);

  // Digests compare local imported bytes only. Never export to anonymous outputs.
  let sourceFingerprints=[];
  async function sourceDigest(bytes){
    if(!globalThis.crypto||!crypto.subtle||typeof crypto.subtle.digest!=="function")return null;
    try{
      const hash=new Uint8Array(await crypto.subtle.digest("SHA-256",bytes));
      return [...hash].map(n=>n.toString(16).padStart(2,"0")).join("");
    }catch(_){return null;}
  }
  function canResume(){
    return snapshots.length>=3&&!fictional&&sourceFingerprints.length===snapshots.length&&
      sourceFingerprints.every(v=>typeof v==="string"&&/^[0-9a-f]{64}$/.test(v));
  }
  function renderSessionControls(){
    const ready=canResume();
    $("exportPrivateSession").disabled=!ready||!hasSessionCrypto();
    $("importPrivateSession").disabled=!ready;
    $("privateSessionFile").disabled=!ready;
    $("sessionAvailability").textContent=ready?
      "Exact source-byte comparison available for this local cohort. Digest values are PRIVATE, not source authentication.":
      snapshots.length?
        "PRIVATE restore requires 3–12 original imported snapshots and browser SHA-256 support; fictional demo or unsupported browser cannot restore.":
        "Import original snapshots to enable source-byte-bound PRIVATE save and resume.";
  }

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

  function toBase64(bytes){
    let binary="";
    for(let i=0;i<bytes.length;i+=16384)
      binary+=String.fromCharCode(...bytes.subarray(i,i+16384));
    return btoa(binary);
  }
  function fromBase64(value,limit){
    admit(typeof value==="string"&&value.length>=4&&value.length<=Math.ceil(limit/3)*4+4&&
      value.length%4===0&&/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value));
    const decoded=atob(value);admit(decoded.length>0&&decoded.length<=limit);
    const out=new Uint8Array(decoded.length);
    for(let i=0;i<decoded.length;i++)out[i]=decoded.charCodeAt(i);
    admit(toBase64(out)===value);return out;
  }
  function hasSessionCrypto(){
    return !!(globalThis.crypto&&crypto.subtle&&crypto.getRandomValues&&
      typeof crypto.subtle.importKey==="function"&&
      typeof crypto.subtle.deriveKey==="function"&&
      typeof crypto.subtle.encrypt==="function"&&typeof crypto.subtle.decrypt==="function");
  }
  async function sessionKey(passphrase,salt,usages){
    admit(hasSessionCrypto()&&typeof passphrase==="string"&&passphrase.length>=14&&passphrase.length<=256);
    const material=await crypto.subtle.importKey("raw",new TextEncoder().encode(passphrase),
      "PBKDF2",false,["deriveKey"]);
    return crypto.subtle.deriveKey(
      {name:"PBKDF2",hash:"SHA-256",iterations:CRYPTO_ITERATIONS,salt},
      material,{name:"AES-GCM",length:256},false,usages);
  }
  async function encryptPrivatePayload(cleartext,passphrase){
    admit(hasSessionCrypto()&&typeof cleartext==="string");
    const bytes=new TextEncoder().encode(cleartext);
    admit(bytes.length>0&&bytes.length<=MAX_PRIVATE_BUNDLE);
    const salt=crypto.getRandomValues(new Uint8Array(16));
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const key=await sessionKey(passphrase,salt,["encrypt"]);
    const encrypted=new Uint8Array(await crypto.subtle.encrypt(
      {name:"AES-GCM",iv,additionalData:PRIVATE_AAD,tagLength:128},key,bytes));
    admit(encrypted.length===bytes.length+16);
    return {schema:ENVELOPE_SCHEMA,private_encrypted:true,
      cipher:"AES-256-GCM",kdf:"PBKDF2-HMAC-SHA256",
      iterations:CRYPTO_ITERATIONS,salt_b64:toBase64(salt),
      iv_b64:toBase64(iv),ciphertext_b64:toBase64(encrypted)};
  }
  async function decryptPrivatePayload(envelope,passphrase){
    admit(exact(envelope,["schema","private_encrypted","cipher","kdf","iterations",
      "salt_b64","iv_b64","ciphertext_b64"])&&
      envelope.schema===ENVELOPE_SCHEMA&&envelope.private_encrypted===true&&
      envelope.cipher==="AES-256-GCM"&&envelope.kdf==="PBKDF2-HMAC-SHA256"&&
      envelope.iterations===CRYPTO_ITERATIONS);
    const salt=fromBase64(envelope.salt_b64,16),iv=fromBase64(envelope.iv_b64,12),
      encrypted=fromBase64(envelope.ciphertext_b64,MAX_PRIVATE_BUNDLE+16);
    admit(salt.length===16&&iv.length===12&&encrypted.length>16);
    const key=await sessionKey(passphrase,salt,["decrypt"]);
    const bytes=await crypto.subtle.decrypt(
      {name:"AES-GCM",iv,additionalData:PRIVATE_AAD,tagLength:128},key,encrypted);
    admit(bytes.byteLength>0&&bytes.byteLength<=MAX_PRIVATE_BUNDLE);
    return new TextDecoder("utf-8",{fatal:true}).decode(bytes);
  }
  async function openPrivateSessionJson(file,passphrase){
    admit(file&&file.size>0&&file.size<=MAX_ENCRYPTED_BUNDLE);
    const bytes=await file.arrayBuffer();
    admit(bytes.byteLength>0&&bytes.byteLength<=MAX_ENCRYPTED_BUNDLE);
    const raw=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
    admit(!raw.startsWith("\uFEFF"));
    const parsed=strictJSON(raw);
    if(parsed&&parsed.schema===ENVELOPE_SCHEMA){
      const cleartext=await decryptPrivatePayload(parsed,passphrase);
      admit(!cleartext.startsWith("\uFEFF"));
      return strictJSON(cleartext);
    }
    // Older v1 PRIVATE plaintext files are read-only compatible; new exports are encrypted.
    admit(bytes.byteLength<=MAX_PRIVATE_BUNDLE);
    return parsed;
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
  const humanReviewStages=new Map();
  const HUMAN_STAGES=["UNREVIEWED","NEEDS_INPUT","FOLLOW_UP","HUMAN_NOTED"];
  function humanStageKey(e){return JSON.stringify([e.id,e.metric,e.snapshotSlot]);}
  function humanStage(e){return humanReviewStages.get(humanStageKey(e))||"UNREVIEWED";}
  function humanStageSummary(){
    const all=buildReviewEvents(),assigned=all.filter(e=>humanStage(e)!=="UNREVIEWED");
    return {total:all.length,assigned:assigned.length,
      needs:assigned.filter(e=>humanStage(e)==="NEEDS_INPUT").length,
      followup:assigned.filter(e=>humanStage(e)==="FOLLOW_UP").length,
      noted:assigned.filter(e=>humanStage(e)==="HUMAN_NOTED").length};
  }

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
      chosenSlot=$("reviewSlot").value,chosenStage=$("reviewStage").value;
    return buildReviewEvents().filter(e=>(kind==="all"||kind===e.kind)&&
      (group==="all"||group===e.group)&&
      (chosenSlot==="all"||Number(chosenSlot)===e.snapshotSlot)&&
      (chosenStage==="all"||humanStage(e)===chosenStage));
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
    for(const id of ["reviewExportStages","reviewExportStageCsv","reviewExportStageBrief"])
      $(id).disabled=humanReviewStages.size===0;
    const h=humanStageSummary();
    $("reviewHumanSummary").textContent=h.total?
      "Local HUMAN-only marks: "+h.assigned+" of "+h.total+
      " events · "+h.needs+" NEEDS_INPUT · "+h.followup+" FOLLOW_UP · "+
      h.noted+" HUMAN_NOTED. These are not review approvals or evidence.":
      "No source-flag events admitted or marked.";
    $("reviewPrev").disabled=reviewOffset===0;
    $("reviewNext").disabled=reviewOffset+REVIEW_PAGE>=rows.length;
    $("reviewCount").textContent=rows.length?
      "Displaying "+(reviewOffset+1)+"–"+Math.min(rows.length,reviewOffset+REVIEW_PAGE)+" of "+
      rows.length+" anonymous source-flag events. Manual order only; no fix or permission inferred.":
      snapshots.length?"No source-flag transitions match these filters.":"Import snapshots to see local source-flag transitions.";
    if(!rows.length)return;
    const table=document.createElement("table"),head=document.createElement("thead"),tr=document.createElement("tr");
    for(const name of ["Manual slot","Anonymous case","Metric","Review group","Source-reported change",
      "Candidate","Δ","Source status","Human stage · self-report only","Human follow-up"]){
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
      const stageCell=document.createElement("td"),stageSelect=document.createElement("select");
      stageSelect.setAttribute("aria-label","Human stage for scenario "+event.scenarioSlot+" "+event.metric+" slot "+event.snapshotSlot);
      for(const stage of HUMAN_STAGES){
        const option=document.createElement("option");option.value=stage;option.textContent=stage;stageSelect.append(option);
      }
      stageSelect.value=humanStage(event);
      stageSelect.addEventListener("change",()=>{
        const key=humanStageKey(event);
        if(stageSelect.value==="UNREVIEWED")humanReviewStages.delete(key);
        else humanReviewStages.set(key,stageSelect.value);
        renderReviewQueue();
      });
      stageCell.append(stageSelect);line.append(stageCell);
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
  function exportHumanStages(format){
    admit(["json","csv","html"].includes(format));
    if(!snapshots.length||!humanReviewStages.size)return;
    if(!window.confirm("Export HUMAN-only local review stages as a separate PRIVATE, UNSIGNED file? Manual scenario/slot ordinals cannot authenticate source files or be safely imported against another cohort."))return;
    const rows=buildReviewEvents().filter(e=>humanStage(e)!=="UNREVIEWED");
    const exported=rows.map(e=>({snapshot_slot:e.snapshotSlot,scenario_slot:e.scenarioSlot,
      metric:e.metric,source_flag_event:e.kind,human_self_report_stage:humanStage(e)}));
    if(format==="csv"){
      const headers=["snapshot_slot","scenario_slot","metric","source_flag_event",
        "human_self_report_stage","private_unsigned","chronology_authenticated",
        "source_identity_authenticated",...FLAGS];
      const values=[headers,...exported.map(e=>[e.snapshot_slot,e.scenario_slot,e.metric,
        e.source_flag_event,e.human_self_report_stage,true,false,false,false,false,false,false])];
      download("assessment-trends-PRIVATE-human-stage-register.csv",
        values.map(v=>v.map(csvField).join(",")).join("\r\n")+"\r\n","text/csv");
    }else if(format==="html"){
      const columns=["Manual slot","Anonymous scenario","Metric","Source-flag event",
        "HUMAN self-reported stage"];
      const values=exported.map(e=>[e.snapshot_slot,e.scenario_slot,e.metric,
        REVIEW_KINDS[e.source_flag_event],e.human_self_report_stage]);
      const table="<table><thead><tr>"+columns.map(k=>"<th>"+esc(k)+"</th>").join("")+
        "</tr></thead><tbody>"+values.map(row=>"<tr>"+row.map(value=>"<td>"+esc(value)+"</td>").join("")+
        "</tr>").join("")+"</tbody></table>";
      const html="<!doctype html><html lang='en'><head><meta charset='utf-8'>"+
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; connect-src 'none'; script-src 'none'; img-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'; style-src 'unsafe-inline'\">"+
        "<title>PRIVATE HUMAN follow-up · unsigned</title><style>body{font:15px system-ui,sans-serif;max-width:1100px;margin:2rem auto;color:#162334;padding:0 1rem}table{border-collapse:collapse;width:100%}td,th{padding:.5rem;border:1px solid #aab6c5;text-align:left}th{background:#eaf0f6}.hold{border:2px solid #9a5b18;padding:1rem}</style></head><body>"+
        "<h1>LightUp PRIVATE HUMAN follow-up · UNSIGNED</h1><div class='hold'><strong>"+
        (fictional?"FICTIONAL DEMO ONLY · ":"")+
        "INCUBATE M3/M7 · PLAN/LAB ONLY · REVIEW_ONLY / HOLD</strong><p>"+
        exported.length+" human self-reported local stages from manually ordered untrusted source reports.</p>"+
        "<p>Source identity and chronology unauthenticated. Missing source flag is NOT fix proof. This worksheet is NOT evidence, consent or approval.</p>"+
        "<p>authorized=false · consent_verified=false · dispatch_allowed=false · release_allowed=false</p></div>"+
        table+"<p>PRIVATE · UNSIGNED · Original source IDs, filenames, raw evidence, uploaded hashes and HUMAN notes are excluded. No portable stage import or security authority.</p></body></html>";
      download("assessment-trends-PRIVATE-human-followup-REVIEW-ONLY.html",html,"text/html");
    }else{
    const out={schema:"lightup.assessment_trends_private_human_stage.v1",
      status:"PRIVATE_UNSIGNED",private_unsigned:true,fictional_demo_only:fictional,
      manually_selected_order:true,chronology_authenticated:false,
      source_identity_authenticated:false,stage_count:rows.length,
      stages:exported,
      disclaimer:"PRIVATE local self-report only; no source binding or authenticated identity. Do not re-apply ordinal-only stages to another imported source. Not verification, remediation or release permission.",
      ...Object.fromEntries(FLAGS.map(k=>[k,false]))};
    download("assessment-trends-PRIVATE-human-stage-register.json",
      JSON.stringify(out,null,2)+"\n","application/json");
    }
    $("reviewHumanSummary").textContent="PRIVATE unsigned HUMAN follow-up "+format.toUpperCase()+
      " downloaded separately. No source IDs, uploaded hashes or note text.";
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
      $("reviewPrev").disabled=true;$("reviewNext").disabled=true;
      for(const id of ["reviewExportStages","reviewExportStageCsv","reviewExportStageBrief"])
        $(id).disabled=true;
      $("reviewHumanSummary").textContent="No local HUMAN stages.";}
    renderNotePanel();
    renderSessionControls();
    for(const id of ["revisionEarlierFile","revisionLaterFile","revisionCompare","timelineFiles","timelineImport"])
      $(id).disabled=!canResume();
  }
  async function importFiles(list){
    const files=[...list];
    try{
      admit(files.length>=3&&files.length<=12);
      const next=[],nextFingerprints=[];
      for(const file of files){
        admit(file&&file.size>0&&file.size<=MAX_FILE);
        const bytes=await file.arrayBuffer();admit(bytes.byteLength>0&&bytes.byteLength<=MAX_FILE);
        const raw=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
        admit(!raw.startsWith("\uFEFF"));
        next.push(parseReport(strictJSON(raw)));
        nextFingerprints.push(await sourceDigest(bytes));
      }
      const ids=harmonize(next);
      snapshots=next;scenarioIds=ids;selectedScenario=ids[0];selectedMetric=METRICS[0];
      sourceFingerprints=nextFingerprints.every(v=>v!==null)?nextFingerprints:[];
      $("privateSessionFile").value="";
      reviewOffset=0;humanReviewStages.clear();resetReviewFilters();
      notes.clear();scratch.clear();fictional=false;resetRevisionComparison();resetHumanTimeline();
      render();$("sessionMessage").textContent="New snapshot batch admitted; previous HUMAN session cannot be carried across datasets.";
      $("message").textContent="Accepted "+snapshots.length+
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
    sourceFingerprints=[];$("privateSessionFile").value="";
    reviewOffset=0;humanReviewStages.clear();resetReviewFilters();resetRevisionComparison();resetHumanTimeline();render();
    $("message").textContent="FICTIONAL DEMO ONLY: invented data in memory; no source measurements or permissions.";
  }
  function forget(){
    snapshots=[];scenarioIds=[];selectedScenario="";notes.clear();scratch.clear();fictional=false;
    sourceFingerprints=[];$("privateSessionFile").value="";
    reviewOffset=0;humanReviewStages.clear();resetReviewFilters();resetRevisionComparison();resetHumanTimeline();
    $("files").value="";$("message").textContent="All imported source data and local commentary forgotten from this workspace.";
    $("sessionMessage").textContent="PRIVATE session and all local source digests forgotten.";render();
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


  function privateSessionData(){
    const events=buildReviewEvents();
    const stages=events.filter(e=>humanStage(e)!=="UNREVIEWED")
      .map(e=>[e.snapshotSlot,e.scenarioSlot,e.metric,humanStage(e)]);
    const savedNotes=[...notes].map(([key,value])=>{
      const [id,metric]=JSON.parse(key);return [slot(id),metric,value];
    }).filter(e=>e[0]>0).sort((a,b)=>a[0]-b[0]||METRICS.indexOf(a[1])-METRICS.indexOf(b[1]));
    return {schema:"lightup.assessment_trends_source_bound_private_session.v1",
      status:"PRIVATE_UNSIGNED",private_unsigned:true,
      fictional_demo_only:false,manually_selected_order:true,
      chronology_authenticated:false,source_identity_authenticated:false,
      snapshot_sha256_by_manual_slot:[...sourceFingerprints],
      scenario_count:scenarioIds.length,stages,notes:savedNotes,
      disclaimer:"Byte equality against the SAME manually ordered source files only. This unsigned local recovery file may disclose HUMAN notes and source fingerprints. Digests do NOT prove source authenticity, finding accuracy, remediation, identity, consent or release.",
      ...Object.fromEntries(FLAGS.map(k=>[k,false]))};
  }
  async function savePrivateSession(){
    const passphrase=$("sessionSavePassphrase").value;
    const confirm=$("sessionSaveConfirm").value;
    try{
      if(!canResume()||!hasSessionCrypto())throw Error("crypto unavailable");
      if(passphrase.length<14||passphrase.length>256||passphrase!==confirm){
        $("sessionMessage").textContent="HOLD: enter and confirm the same recovery passphrase (14–256 characters).";return;
      }
      if(!window.confirm("Download an ENCRYPTED, PRIVATE, UNSIGNED HUMAN review session? AES-256-GCM with a random salt and nonce protects local source fingerprints, self-reported stages and saved HUMAN notes. Losing your passphrase makes recovery unavailable. No source authentication or consent is established."))return;
      const contents=JSON.stringify(privateSessionData())+"\n";
      const envelope=await encryptPrivatePayload(contents,passphrase);
      const output=JSON.stringify(envelope,null,2)+"\n";
      admit(new Blob([output]).size<=MAX_ENCRYPTED_BUNDLE);
      download("assessment-trends-PRIVATE-ENCRYPTED-review-session.json",output,"application/json");
      $("sessionMessage").textContent="Encrypted PRIVATE session downloaded. Keep the passphrase separately and retain the original source snapshots in the same manual order. No password recovery or source authentication.";
    }catch(_){
      $("sessionMessage").textContent="HOLD: encrypted PRIVATE export unavailable. Existing HUMAN notes and stages remain in memory. No plaintext file downloaded.";
    }finally{
      $("sessionSavePassphrase").value="";$("sessionSaveConfirm").value="";
    }
  }
  async function admitPrivateSessionFile(file,passphrase){
    admit(canResume());
      const data=await openPrivateSessionJson(file,passphrase);
      admit(exact(data,["schema","status","private_unsigned","fictional_demo_only",
        "manually_selected_order","chronology_authenticated","source_identity_authenticated",
        "snapshot_sha256_by_manual_slot","scenario_count","stages","notes","disclaimer",...FLAGS]));
      admit(data.schema==="lightup.assessment_trends_source_bound_private_session.v1"&&
        data.status==="PRIVATE_UNSIGNED"&&data.private_unsigned===true&&
        data.fictional_demo_only===false&&data.manually_selected_order===true&&
        data.chronology_authenticated===false&&data.source_identity_authenticated===false&&
        typeof data.disclaimer==="string"&&data.disclaimer.length>0&&data.disclaimer.length<=1000&&flags(data)&&
        Number.isSafeInteger(data.scenario_count)&&data.scenario_count===scenarioIds.length);
      admit(Array.isArray(data.snapshot_sha256_by_manual_slot)&&
        data.snapshot_sha256_by_manual_slot.length===sourceFingerprints.length&&
        data.snapshot_sha256_by_manual_slot.every((digest,i)=>
          typeof digest==="string"&&/^[0-9a-f]{64}$/.test(digest)&&digest===sourceFingerprints[i]));
      admit(Array.isArray(data.stages)&&data.stages.length<=11520&&
        Array.isArray(data.notes)&&data.notes.length<=960);
      const eventSet=new Set(buildReviewEvents().map(e=>
        JSON.stringify([e.snapshotSlot,e.scenarioSlot,e.metric])));
      const newStages=new Map(),newNotes=new Map(),seenStages=new Set(),seenNotes=new Set();
      for(const row of data.stages){
        admit(Array.isArray(row)&&row.length===4);
        const [snapshotSlot,scenarioSlot,metric,stage]=row;
        admit(Number.isSafeInteger(snapshotSlot)&&snapshotSlot>=1&&snapshotSlot<=snapshots.length&&
          Number.isSafeInteger(scenarioSlot)&&scenarioSlot>=1&&scenarioSlot<=scenarioIds.length&&
          METRICS.includes(metric)&&HUMAN_STAGES.includes(stage)&&stage!=="UNREVIEWED");
        const idKey=JSON.stringify([snapshotSlot,scenarioSlot,metric]);
        admit(eventSet.has(idKey)&&!seenStages.has(idKey));seenStages.add(idKey);
        newStages.set(JSON.stringify([scenarioIds[scenarioSlot-1],metric,snapshotSlot]),stage);
      }
      for(const row of data.notes){
        admit(Array.isArray(row)&&row.length===3);
        const [scenarioSlot,metric,note]=row;
        admit(Number.isSafeInteger(scenarioSlot)&&scenarioSlot>=1&&scenarioSlot<=scenarioIds.length&&
          METRICS.includes(metric)&&typeof note==="string"&&
          note.length>=1&&note.length<=500&&note.trim().length>0);
        const idKey=JSON.stringify([scenarioSlot,metric]);
        admit(!seenNotes.has(idKey));seenNotes.add(idKey);
        newNotes.set(noteKey(scenarioIds[scenarioSlot-1],metric),note);
      }
    return {newStages,newNotes};
  }

  async function restorePrivateSession(){
    const file=$("privateSessionFile").files[0];
    if(!file||!canResume()){
      $("sessionMessage").textContent="HOLD: admit the original source cohort first, then choose one PRIVATE recovery file.";return;
    }
    try{
      const {newStages,newNotes}=await admitPrivateSessionFile(file,$("sessionUnlockPassphrase").value);
      // Never mutate existing work on failure. Consent to replace comes AFTER full validation.
      if(!window.confirm("Exact ordered source bytes matched. Replace the CURRENT local HUMAN marks and saved notes with this PRIVATE unsigned file? Unsaved scratch text will be discarded. Matching bytes are not proof of source authenticity.")){
        $("sessionMessage").textContent="PRIVATE restore cancelled. Existing HUMAN work left unchanged.";return;
      }
      humanReviewStages.clear();for(const [key,value] of newStages)humanReviewStages.set(key,value);
      notes.clear();for(const [key,value] of newNotes)notes.set(key,value);
      scratch.clear();reviewOffset=0;render();
      $("sessionMessage").textContent="PRIVATE HUMAN session restored for identical local source bytes and manual order: "+
        newStages.size+" stages, "+newNotes.size+" saved notes. UNSIGNED and non-authorizing.";
    }catch(_){
      $("sessionMessage").textContent="HOLD: PRIVATE recovery rejected (invalid, tampered, duplicate, oversized, or not bound to the exact currently admitted original files/order). Existing HUMAN stages and notes untouched.";
    }finally{
      $("privateSessionFile").value="";
      $("sessionUnlockPassphrase").value="";
    }
  }


  let privateRevisionComparison=null;
  function revisionChanges(before,after){
    const records=[];
    const events=new Map(buildReviewEvents().map(e=>[humanStageKey(e),e]));
    const stageKeys=new Set([...before.newStages.keys(),...after.newStages.keys()]);
    for(const key of stageKeys){
      const left=before.newStages.get(key)||"UNREVIEWED",right=after.newStages.get(key)||"UNREVIEWED";
      if(left===right)continue;
      const event=events.get(key);admit(!!event);
      records.push({kind:"HUMAN_STAGE",snapshot_slot:event.snapshotSlot,
        scenario_slot:event.scenarioSlot,metric:event.metric,source_flag_event:event.kind,
        before:left,after:right});
    }
    const noteKeys=new Set([...before.newNotes.keys(),...after.newNotes.keys()]);
    for(const key of noteKeys){
      const a=before.newNotes.get(key),b=after.newNotes.get(key);
      if(a===b)continue;
      const [id,metric]=JSON.parse(key),scenarioSlot=slot(id);
      admit(scenarioSlot>=1&&METRICS.includes(metric));
      const type=a===undefined?"ADDED":b===undefined?"REMOVED":"EDITED";
      records.push({kind:"HUMAN_NOTE_CHANGE",snapshot_slot:null,
        scenario_slot:scenarioSlot,metric,source_flag_event:null,
        before:type==="ADDED"?"ABSENT":"PRESENT",after:type==="REMOVED"?"ABSENT":"PRESENT"});
    }
    records.sort((a,b)=>a.scenario_slot-b.scenario_slot||
      METRICS.indexOf(a.metric)-METRICS.indexOf(b.metric)||
      (a.snapshot_slot||0)-(b.snapshot_slot||0)||a.kind.localeCompare(b.kind));
    return records;
  }
  function revisionTable(){
    const root=$("revisionCompareTable");root.replaceChildren();
    if(!privateRevisionComparison)return;
    const changes=privateRevisionComparison.changes;
    $("revisionCompareSummary").textContent=
      "Two PRIVATE unsigned sessions bound to identical local source bytes and manual order · "+
      changes.filter(v=>v.kind==="HUMAN_STAGE").length+" HUMAN stage changes · "+
      changes.filter(v=>v.kind==="HUMAN_NOTE_CHANGE").length+
      " note presence/content changes. Only a self-reported comparison, not remediation proof.";
    for(const id of ["revisionExportJson","revisionExportCsv","revisionExportBrief"])
      $(id).disabled=false;
    const rows=changes.slice(0,150);
    drawTable("revisionCompareTable",
      ["Change","Manual slot","Anonymous scenario","Metric","Source flag event","Earlier HUMAN","Later HUMAN"],
      rows.map(e=>[e.kind,e.snapshot_slot===null?"—":e.snapshot_slot,
        "Scenario "+String(e.scenario_slot).padStart(2,"0"),e.metric,
        e.source_flag_event||"PRIVATE note only",e.before,e.after]));
    $("revisionCompareCount").textContent=changes.length>150?
      "Showing 150 of "+changes.length+" PRIVATE changes. Explicit exports include all admitted changes.":
      "All "+changes.length+" PRIVATE changes shown. No original IDs or HUMAN note text.";
  }
  function resetRevisionComparison(){
    privateRevisionComparison=null;
    for(const id of ["revisionExportJson","revisionExportCsv","revisionExportBrief"])
      $(id).disabled=true;
    $("revisionCompareTable").replaceChildren();
    $("revisionCompareSummary").textContent="Choose two source-bound PRIVATE sessions after admitting their original snapshots.";
    $("revisionCompareCount").textContent="";
    $("revisionEarlierFile").value="";$("revisionLaterFile").value="";
  }
  async function comparePrivateRevisions(){
    const earlier=$("revisionEarlierFile").files[0],later=$("revisionLaterFile").files[0];
    if(!canResume()||!earlier||!later){
      $("revisionCompareSummary").textContent="HOLD: original cohort and both PRIVATE source-bound session files required.";return;
    }
    try{
      // Admit both complete files before changing the displayed comparison.
      const before=await admitPrivateSessionFile(earlier,$("revisionUnlockPassphrase").value);
      const after=await admitPrivateSessionFile(later,$("revisionUnlockPassphrase").value);
      const changes=revisionChanges(before,after);
      privateRevisionComparison={changes,beforeCount:before.newStages.size,
        afterCount:after.newStages.size,earlierNotes:before.newNotes.size,
        laterNotes:after.newNotes.size};
      revisionTable();
    }catch(_){
      $("revisionCompareSummary").textContent="HOLD: one or both PRIVATE sessions failed decryption or did not match exact sources, schema, order or HUMAN event scope. Existing comparison and current HUMAN work left unchanged.";
    }finally{$("revisionUnlockPassphrase").value="";}
  }
  function revisionPayload(){
    admit(!!privateRevisionComparison);
    return {schema:"lightup.assessment_trends_private_revision_diff.v1",
      status:"PRIVATE_UNSIGNED",private_unsigned:true,fictional_demo_only:false,
      manually_selected_order:true,chronology_authenticated:false,source_identity_authenticated:false,
      earlier_stages:privateRevisionComparison.beforeCount,
      later_stages:privateRevisionComparison.afterCount,
      earlier_saved_notes:privateRevisionComparison.earlierNotes,
      later_saved_notes:privateRevisionComparison.laterNotes,
      changed_record_count:privateRevisionComparison.changes.length,
      changes:privateRevisionComparison.changes.map(e=>({...e})),
      disclaimer:"Two independently admitted PRIVATE HUMAN self-reports tied only by original source-byte equality. Manual order is not chronology; note changes contain no note text. Not authenticated review, consent, remediation or release.",
      ...Object.fromEntries(FLAGS.map(k=>[k,false]))};
  }
  function exportRevision(format){
    if(!privateRevisionComparison)return;
    if(!window.confirm("Export PRIVATE UNSIGNED HUMAN revision differences? Includes self-reported stage changes, anonymous scenario and metric ordinals but no original IDs or note text."))return;
    const data=revisionPayload();
    if(format==="json"){
      download("assessment-trends-PRIVATE-human-revisions.json",
        JSON.stringify(data,null,2)+"\n","application/json");
    }else if(format==="csv"){
      const cols=["change_kind","manual_snapshot_slot","anonymous_scenario_slot","metric",
        "source_flag_event","earlier_human_stage_or_note_presence",
        "later_human_stage_or_note_presence","private_unsigned","authorized",
        "consent_verified","dispatch_allowed","release_allowed"];
      const rows=[cols,...data.changes.map(e=>[e.kind,e.snapshot_slot===null?"":e.snapshot_slot,
        e.scenario_slot,e.metric,e.source_flag_event||"",e.before,e.after,
        true,false,false,false,false])];
      download("assessment-trends-PRIVATE-human-revisions.csv",
        rows.map(row=>row.map(csvField).join(",")).join("\r\n")+"\r\n","text/csv");
    }else if(format==="html"){
      const columns=["Change type","Manual source slot","Anonymous scenario","Metric",
        "Source-reported flag event","Earlier HUMAN state","Later HUMAN state"];
      const values=data.changes.map(e=>[e.kind,e.snapshot_slot===null?"—":e.snapshot_slot,
        "Scenario "+String(e.scenario_slot).padStart(2,"0"),e.metric,
        e.source_flag_event||"Saved HUMAN note (contents withheld)",e.before,e.after]);
      const table="<table><thead><tr>"+columns.map(v=>"<th scope='col'>"+esc(v)+"</th>").join("")+
        "</tr></thead><tbody>"+values.map(row=>"<tr>"+
        row.map(v=>"<td>"+esc(v)+"</td>").join("")+"</tr>").join("")+"</tbody></table>";
      const style="body{margin:2rem auto;padding:0 1rem;max-width:1280px;color:#192435;"+
        "font:15px/1.5 system-ui,sans-serif}h1{font-size:1.9rem}"+
        ".hold{border:2px solid #9a5b18;padding:1rem;background:#fff7ed}"+
        ".tablewrap{max-width:100%;overflow-x:auto}table{width:100%;border-collapse:collapse}"+
        "th,td{border:1px solid #b6bec9;padding:.45rem;text-align:left}th{background:#eaf0f6}"+
        "tbody tr:nth-child(even){background:#f6f8fa}"+
        "@media print{body{margin:0;max-width:none}.hold{background:white}"+
        "thead{display:table-header-group}tr{break-inside:avoid}}";
      const html="<!doctype html><html lang='en'><head><meta charset='utf-8'>"+
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"+
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"+
        " script-src 'none'; connect-src 'none'; img-src 'none'; object-src 'none';"+
        " frame-src 'none'; form-action 'none'; base-uri 'none'; style-src 'unsafe-inline'\">"+
        "<title>LightUp PRIVATE HUMAN revision differences</title><style>"+style+"</style></head><body>"+
        "<h1>LightUp · PRIVATE HUMAN review revisions</h1>"+
        "<div class='hold'><strong>PRIVATE / UNSIGNED / REVIEW_ONLY · INCUBATE M3/M7 PLAN/LAB ONLY</strong>"+
        "<p>Two separate human-selected PRIVATE sessions re-admitted against identical source bytes."+
        " This comparison is NOT authenticated chronology, proof, consent, grant, verified remediation or release.</p>"+
        "<p>authorized=false · consent_verified=false · dispatch_allowed=false · release_allowed=false</p></div>"+
        "<h2>Local HUMAN self-report differences</h2>"+
        "<p>"+data.changed_record_count+" anonymous changes; "+
        data.changes.filter(e=>e.kind==="HUMAN_STAGE").length+" stage changes and "+
        data.changes.filter(e=>e.kind==="HUMAN_NOTE_CHANGE").length+
        " saved note content/presence changes. Note text intentionally withheld.</p>"+
        "<div class='tablewrap'>"+table+"</div>"+
        "<p>Output includes only fixed non-authorizing labels, anonymous scenario ordinals and metric names."+
        " No original source IDs, hashes, filenames or private note text. Missing a source flag is NOT evidence of a fix.</p>"+
        "</body></html>";
      if(new Blob([html]).size>4194304){
        $("revisionCompareCount").textContent="HOLD: PRIVATE printable report exceeds 4 MiB; use JSON or CSV.";return;
      }
      download("assessment-trends-PRIVATE-human-revision-brief-REVIEW-ONLY.html",html,"text/html");
    }
    $("revisionCompareCount").textContent="PRIVATE "+format.toUpperCase()+
      " comparison downloaded. No HUMAN note text or original source ID included.";
  }



  function humanRoundMetrics(revisions){
    const metrics=METRICS.map(name=>({metric:name,review_priority_group:family(name),
      needs_input_by_round:revisions.map(()=>0),follow_up_by_round:revisions.map(()=>0),
      human_noted_by_round:revisions.map(()=>0)}));
    revisions.forEach((revision,i)=>{
      for(const [key,stage] of revision.newStages){
        const [_id,metric]=JSON.parse(key),index=METRICS.indexOf(metric);
        admit(index>=0);
        const row=metrics[index];
        if(stage==="NEEDS_INPUT")row.needs_input_by_round[i]++;
        else if(stage==="FOLLOW_UP")row.follow_up_by_round[i]++;
        else if(stage==="HUMAN_NOTED")row.human_noted_by_round[i]++;
        else admit(false);
      }
    });
    return metrics;
  }
  function renderHumanRoundMetrics(){
    const table=$("timelineMetricTable");
    if(!privateTimeline){table.replaceChildren();return;}
    const k=privateTimeline.summary.length;
    drawTable("timelineMetricTable",
      ["Fixed metric","Static review group",...Array.from({length:k},(_,i)=>
        "HUMAN round "+(i+1)+" · needs/follow-up/noted")],
      privateTimeline.metric_matrix.map(v=>[v.metric,v.review_priority_group,
        ...Array.from({length:k},(_,i)=>
          "N:"+v.needs_input_by_round[i]+" · F:"+v.follow_up_by_round[i]+
          " · H:"+v.human_noted_by_round[i])]));
  }

  let privateTimeline=null;
  function timelineStageCounts(stages){
    const all=[...stages.values()];
    return {needs_input:all.filter(x=>x==="NEEDS_INPUT").length,
      follow_up:all.filter(x=>x==="FOLLOW_UP").length,
      human_noted:all.filter(x=>x==="HUMAN_NOTED").length};
  }
  function resetHumanTimeline(){
    privateTimeline=null;
    $("timelineFiles").value="";
    $("timelineSummary").textContent="Select 2–8 source-bound PRIVATE HUMAN revisions to compare manual slots.";
    $("timelineTable").replaceChildren();$("timelineMetricTable").replaceChildren();
    for(const id of ["timelineExportJson","timelineExportCsv","timelineExportBrief","timelineExportMetrics"])
      $(id).disabled=true;
  }
  async function importHumanTimeline(){
    const files=[...$("timelineFiles").files];
    if(!canResume()||files.length<2||files.length>8){
      $("timelineSummary").textContent="HOLD: 2–8 PRIVATE session JSON files plus original source snapshots required.";return;
    }
    try{
      const revisions=[];
      for(const file of files)revisions.push(await admitPrivateSessionFile(file,$("timelineUnlockPassphrase").value));
      const summary=[];
      revisions.forEach((r,i)=>{
        const stageCounts=timelineStageCounts(r.newStages);
        const changes=i?revisionChanges(revisions[i-1],r):[];
        summary.push({human_round_slot:i+1,saved_stage_count:r.newStages.size,
          ...stageCounts,saved_human_note_count:r.newNotes.size,
          changed_stage_count:changes.filter(x=>x.kind==="HUMAN_STAGE").length,
          changed_note_count:changes.filter(x=>x.kind==="HUMAN_NOTE_CHANGE").length});
      });
      // Only aggregate counters survive; do not retain source digests, ids or note text.
      privateTimeline={summary,metric_matrix:humanRoundMetrics(revisions)};
      renderHumanRoundMetrics();
      drawTable("timelineTable",["Manually selected HUMAN round","Saved HUMAN stages",
        "NEEDS_INPUT","FOLLOW_UP","HUMAN_NOTED","Saved notes",
        "Changed stages vs previous","Changed note presence/content vs previous"],
        summary.map(v=>[v.human_round_slot,v.saved_stage_count,v.needs_input,
          v.follow_up,v.human_noted,v.saved_human_note_count,
          v.human_round_slot===1?"—":v.changed_stage_count,
          v.human_round_slot===1?"—":v.changed_note_count]));
      for(const id of ["timelineExportJson","timelineExportCsv","timelineExportBrief","timelineExportMetrics"])
        $(id).disabled=false;
      $("timelineSummary").textContent=summary.length+
        " manually selected PRIVATE HUMAN revision files admitted for identical original cohort bytes/order. Unauthenticated selection order, no current HUMAN work modified.";
      $("timelineFiles").value="";
    }catch(_){
      $("timelineSummary").textContent="HOLD: PRIVATE HUMAN session could not be decrypted or did not match the exact original source bytes/order. Previous comparison and current HUMAN work unchanged.";
    }finally{$("timelineUnlockPassphrase").value="";}
  }
  function humanTimelinePayload(){
    admit(!!privateTimeline);
    return {schema:"lightup.assessment_trends_private_human_rounds.v1",
      status:"PRIVATE_UNSIGNED",private_unsigned:true,fictional_demo_only:false,
      manually_selected_order:true,chronology_authenticated:false,source_identity_authenticated:false,
      summary:privateTimeline.summary.map(v=>({...v})),
      metric_matrix:privateTimeline.metric_matrix.map(v=>({
        metric:v.metric,review_priority_group:v.review_priority_group,
        needs_input_by_round:[...v.needs_input_by_round],
        follow_up_by_round:[...v.follow_up_by_round],
        human_noted_by_round:[...v.human_noted_by_round]})),
      disclaimer:"Human-chosen round order is unauthenticated. Counts only: no original source IDs, file names, hashes, private note text or proof of remediation. Source byte equality was verified only at local admission, not authenticated origin.",
      ...Object.fromEntries(FLAGS.map(k=>[k,false]))};
  }
  function exportHumanTimeline(format){
    if(!privateTimeline)return;
    if(!window.confirm("Export PRIVATE unsigned HUMAN round counts only? Source identity and chronology are not authenticated; no original file names, hashes, notes or findings are included."))return;
    const data=humanTimelinePayload();
    if(format==="json"){
      download("assessment-trends-PRIVATE-human-rounds.json",
        JSON.stringify(data,null,2)+"\n","application/json");
    }else if(format==="csv"){
      const columns=["human_round_slot","saved_stage_count","needs_input","follow_up",
        "human_noted","saved_human_note_count","changed_stage_count_vs_previous",
        "changed_note_count_vs_previous","private_unsigned","authorized",
        "consent_verified","dispatch_allowed","release_allowed"];
      const rows=[columns,...data.summary.map(v=>[v.human_round_slot,v.saved_stage_count,
        v.needs_input,v.follow_up,v.human_noted,v.saved_human_note_count,
        v.human_round_slot===1?"":v.changed_stage_count,
        v.human_round_slot===1?"":v.changed_note_count,true,false,false,false,false])];
      download("assessment-trends-PRIVATE-human-rounds.csv",
        rows.map(line=>line.map(csvField).join(",")).join("\r\n")+"\r\n","text/csv");
    }else if(format==="metric_csv"){
      const columns=["human_round_slot","metric","review_priority_group","needs_input",
        "follow_up","human_noted","private_unsigned","authorized","consent_verified",
        "dispatch_allowed","release_allowed"];
      const rows=[columns];
      data.metric_matrix.forEach(v=>v.needs_input_by_round.forEach((_,i)=>rows.push([
        i+1,v.metric,v.review_priority_group,v.needs_input_by_round[i],
        v.follow_up_by_round[i],v.human_noted_by_round[i],
        true,false,false,false,false
      ])));
      download("assessment-trends-PRIVATE-human-rounds-metrics.csv",
        rows.map(line=>line.map(csvField).join(",")).join("\r\n")+"\r\n","text/csv");
    }else if(format==="html"){
      const cols=["Human round · manual","Saved stages","NEEDS_INPUT","FOLLOW_UP",
        "HUMAN_NOTED","Saved notes","Stage changes vs prior","Note changes vs prior"];
      const values=data.summary.map(v=>[v.human_round_slot,v.saved_stage_count,
        v.needs_input,v.follow_up,v.human_noted,v.saved_human_note_count,
        v.human_round_slot===1?"—":v.changed_stage_count,
        v.human_round_slot===1?"—":v.changed_note_count]);
      const table="<table><thead><tr>"+cols.map(x=>"<th scope='col'>"+esc(x)+"</th>").join("")+
        "</tr></thead><tbody>"+values.map(row=>"<tr>"+row.map(x=>"<td>"+esc(x)+"</td>").join("")+
        "</tr>").join("")+"</tbody></table>";
      const metricColumns=["Fixed metric","Static review group",
        ...data.summary.map(v=>"Round "+v.human_round_slot+" · N/F/H")];
      const metricValues=data.metric_matrix.map(v=>[v.metric,v.review_priority_group,
        ...v.needs_input_by_round.map((_,i)=>
          v.needs_input_by_round[i]+"/"+v.follow_up_by_round[i]+"/"+v.human_noted_by_round[i])]);
      const metricTable="<table><thead><tr>"+metricColumns.map(x=>"<th scope='col'>"+esc(x)+"</th>").join("")+
        "</tr></thead><tbody>"+metricValues.map(row=>"<tr>"+
        row.map(x=>"<td>"+esc(x)+"</td>").join("")+"</tr>").join("")+"</tbody></table>";
      const style="body{margin:2rem auto;padding:0 1rem;max-width:1100px;font:16px/1.5 system-ui,sans-serif;color:#182333}"+
        "table{width:100%;border-collapse:collapse}th,td{border:1px solid #b5c0cf;padding:.5rem;text-align:left}"+
        "th{background:#eaf0f6}.hold{border:2px solid #9a5b18;background:#fff7ed;padding:1rem}"+
        "@media print{body{margin:0}.hold{background:white}thead{display:table-header-group}}";
      const html="<!doctype html><html lang='en'><head><meta charset='utf-8'>"+
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"+
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; connect-src 'none';"+
        " script-src 'none'; img-src 'none'; object-src 'none'; frame-src 'none';"+
        " form-action 'none'; base-uri 'none'; style-src 'unsafe-inline'\">"+
        "<title>LightUp PRIVATE HUMAN rounds</title><style>"+style+"</style></head><body>"+
        "<h1>LightUp · PRIVATE HUMAN round overview</h1>"+
        "<div class='hold'><strong>PRIVATE / UNSIGNED / REVIEW_ONLY · INCUBATE M3/M7 PLAN/LAB ONLY</strong>"+
        "<p>"+data.summary.length+" human-selected rounds. Order is not authenticated chronology."+
        " Changed HUMAN declarations do not establish actual remediation, consent, scan or release approval.</p>"+
        "<p>authorized=false · consent_verified=false · dispatch_allowed=false · release_allowed=false</p></div>"+
        "<h2>HUMAN review workload by fixed metric and manually selected round</h2>"+
        "<p>N=NEEDS_INPUT, F=FOLLOW_UP, H=HUMAN_NOTED. These are only HUMAN self-reported marks, not severity scores.</p>"+
        metricTable+
        table+"<p>Only local HUMAN aggregate counts. No original source ID, file name,"+
        " SHA-256, HUMAN note text or verified security findings are disclosed."+
        " Original source byte equality is not independent provenance.</p></body></html>";
      download("assessment-trends-PRIVATE-human-rounds-REVIEW-ONLY.html",html,"text/html");
    }
    $("timelineSummary").textContent="PRIVATE HUMAN rounds "+format.toUpperCase()+
      " exported. No note text or original hashes included.";
  }

  function resetReviewFilters(){
    $("reviewKind").value="all";$("reviewStage").value="all";
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
  for(const filter of ["reviewKind","reviewGroup","reviewSlot","reviewStage"]){
    $(filter).addEventListener("change",()=>{reviewOffset=0;renderReviewQueue();});
  }
  $("reviewPrev").addEventListener("click",()=>{reviewOffset=Math.max(0,reviewOffset-REVIEW_PAGE);renderReviewQueue();});
  $("reviewNext").addEventListener("click",()=>{reviewOffset+=REVIEW_PAGE;renderReviewQueue();});
  $("reviewExportCsv").addEventListener("click",()=>exportReviewQueue("csv"));
  $("reviewExportJson").addEventListener("click",()=>exportReviewQueue("json"));
  $("reviewExportStages").addEventListener("click",()=>exportHumanStages("json"));
  $("reviewExportStageCsv").addEventListener("click",()=>exportHumanStages("csv"));
  $("reviewExportStageBrief").addEventListener("click",()=>exportHumanStages("html"));
  resetReviewFilters();
  $("timelineImport").addEventListener("click",()=>{void importHumanTimeline();});
  $("timelineExportJson").addEventListener("click",()=>exportHumanTimeline("json"));
  $("timelineExportCsv").addEventListener("click",()=>exportHumanTimeline("csv"));
  $("timelineExportBrief").addEventListener("click",()=>exportHumanTimeline("html"));
  $("timelineExportMetrics").addEventListener("click",()=>exportHumanTimeline("metric_csv"));
  $("revisionCompare").addEventListener("click",()=>{void comparePrivateRevisions();});
  $("revisionExportJson").addEventListener("click",()=>exportRevision("json"));
  $("revisionExportCsv").addEventListener("click",()=>exportRevision("csv"));
  $("revisionExportBrief").addEventListener("click",()=>exportRevision("html"));
  $("exportPrivateSession").addEventListener("click",()=>{void savePrivateSession();});
  $("importPrivateSession").addEventListener("click",()=>{void restorePrivateSession();});
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
