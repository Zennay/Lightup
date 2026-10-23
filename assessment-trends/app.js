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
    $("rotateSourceFile").disabled=!ready;
    $("rotateSubmit").disabled=!ready||!hasSessionCrypto();
    $("sessionAvailability").textContent=ready?
      "Exact source-byte comparison available for this local cohort. Digest values are PRIVATE, not source authentication.":
      snapshots.length?
        "PRIVATE restore requires 3–12 original imported snapshots and browser SHA-256 support; fictional demo or unsupported browser cannot restore.":
        "Import original snapshots to enable source-byte-bound PRIVATE save and resume.";
  }

  let snapshots=[],scenarioIds=[],selectedScenario="",selectedMetric=METRICS[0],notes=new Map(),scratch=new Map(),fictional=false;
  const NOTE_HISTORY_LIMIT=20;
  let noteUndoHistory=[],noteRedoHistory=[];

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
  // Note snapshots are local-only and cannot cross a change of original source cohort.
  function noteSnapshot(){return {dataset:snapshots,sha:[...sourceFingerprints],ids:[...scenarioIds],
    notes:new Map(notes),scratch:new Map(scratch)};}
  function noteSnapshotCurrent(entry){
    return !!entry&&entry.dataset===snapshots&&entry.sha.length===sourceFingerprints.length&&
      entry.sha.every((v,i)=>v===sourceFingerprints[i])&&entry.ids.length===scenarioIds.length&&
      entry.ids.every((v,i)=>v===scenarioIds[i]);
  }
  function renderNoteHistory(){
    const undo=$("undoNote"),redo=$("redoNote"),msg=$("noteHistoryStatus");
    if(!undo||!redo||!msg)return;
    const count=stack=>{
      let n=0;for(let i=stack.length-1;i>=0;i--){if(!noteSnapshotCurrent(stack[i]))break;n++;}return n;
    };
    const u=count(noteUndoHistory),r=count(noteRedoHistory);
    undo.disabled=u===0;redo.disabled=r===0;
    $("clearAllNotes").disabled=notes.size===0&&scratch.size===0;
    undo.textContent=u?"Undo commentary ("+u+")":"Undo commentary";
    redo.textContent=r?"Redo commentary ("+r+")":"Redo commentary";
    msg.textContent="Undo "+u+" · Redo "+r+" · up to "+NOTE_HISTORY_LIMIT+
      " saved HUMAN note edits retained in this tab only. Imports and Forget clear history.";
  }
  function rememberNoteEdit(){
    if(!snapshots.length)return;
    noteUndoHistory.push(noteSnapshot());
    if(noteUndoHistory.length>NOTE_HISTORY_LIMIT)noteUndoHistory.shift();
    noteRedoHistory=[];renderNoteHistory();
  }
  function resetNoteHistory(){noteUndoHistory=[];noteRedoHistory=[];renderNoteHistory();}
  function changeNoteHistory(from,to,label){
    if(!snapshots.length||!from.length)return;
    if(!noteSnapshotCurrent(from[from.length-1])){resetNoteHistory();return;}
    if(scratch.size&&!window.confirm(label+" commentary? Unsaved local drafts may be replaced."))return;
    const next=from.pop();
    to.push(noteSnapshot());if(to.length>NOTE_HISTORY_LIMIT)to.shift();
    notes=new Map(next.notes);scratch=new Map(next.scratch);
    renderNotePanel();renderNotePacketControls();
    $("noteMessage").textContent=label+" restored only local HUMAN commentary; assessment sources and HUMAN stages did not change.";
  }
  function currentId(){return scenarioIds.includes(selectedScenario)?selectedScenario:scenarioIds[0];}
  function slot(id){return scenarioIds.indexOf(id)+1;}
  function fmt(n){return Number(n).toLocaleString("en-US",{maximumFractionDigits:6});}
  function csvField(v){
    const raw=String(v).replace(/[\r\n]/g," ");
    // Keep actual numeric cells numeric; guard only string cells that spreadsheets
    // could interpret as formulas, including values preceded by whitespace.
    const safe=typeof v==="string"&&/^[\s\uFEFF]*[=+\-@]/.test(raw)?"'"+raw:raw;
    return '"'+safe.replace(/"/g,'""')+'"';
  }
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
  function reappearanceCount(values){
    let seen=false,previous=false,count=0;
    for(const value of values){
      if(value&&seen&&!previous)count++;
      if(value)seen=true;
      previous=value;
    }
    return count;
  }
  function metricStats(name){
    const counts=snapshots.map(report=>scenarioIds.filter(id=>report.cases.get(id).metrics.get(name).regression).length);
    let ever=0,persistent=0,maxStreak=0,reappeared=0,reappearanceEvents=0;
    for(const id of scenarioIds){
      const values=snapshots.map(report=>report.cases.get(id).metrics.get(name).regression);
      if(values.some(Boolean))ever++;
      const best=streak(values),returns=reappearanceCount(values);
      if(best>=2)persistent++;
      if(returns>0)reappeared++;
      reappearanceEvents+=returns;
      maxStreak=Math.max(maxStreak,best);
    }
    return {counts,ever,persistent,maxStreak,reappeared,reappearanceEvents};
  }
  function scenarioStats(id){
    const counts=snapshots.map(report=>report.cases.get(id).adverse.length);
    let persistent=0,reappearedMetrics=0,reappearanceEvents=0,longestMetricStreak=0;
    for(const name of METRICS){
      const values=snapshots.map(report=>report.cases.get(id).metrics.get(name).regression);
      const best=streak(values),returns=reappearanceCount(values);
      if(best>=2)persistent++;
      if(returns>0)reappearedMetrics++;
      reappearanceEvents+=returns;
      longestMetricStreak=Math.max(longestMetricStreak,best);
    }
    const flaggedSlots=counts.flatMap((count,index)=>count>0?[index+1]:[]);
    return {counts,persistent,reappearedMetrics,reappearanceEvents,longestMetricStreak,
      firstFlaggedSlot:flaggedSlots.length?flaggedSlots[0]:null,
      lastFlaggedSlot:flaggedSlots.length?flaggedSlots[flaggedSlots.length-1]:null,
      status:counts.some(Boolean)?"HOLD":"REVIEW_ONLY"};
  }
  function summary(){
    const instances=snapshots.reduce((n,report)=>n+report.regressionInstances,0);
    const held=snapshots.filter(report=>report.status==="HOLD").length;
    const metrics=METRICS.map(metricStats);
    const persistent=metrics.reduce((n,item)=>n+item.persistent,0);
    const reappearedPairs=metrics.reduce((n,item)=>n+item.reappeared,0);
    const reappearanceEvents=metrics.reduce((n,item)=>n+item.reappearanceEvents,0);
    return {instances,held,persistent,reappearedPairs,reappearanceEvents,
      status:held||instances?"HOLD":"REVIEW_ONLY"};
  }
  function renderSummary(){
    const s=summary(),cards=[
      ["Selected snapshots",snapshots.length],
      ["Anonymous scenarios",scenarioIds.length],
      ["Source-reported regression instances",s.instances],
      ["Persistent scenario/metric trajectories",s.persistent],
      ["Reappearing scenario/metric pairs",s.reappearedPairs]
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
      "Ever flagged cases","Persistent cases","Longest consecutive slots",
      "Cases with reappearing flags","Reappearance events"];
    const rows=METRICS.map(name=>{const s=metricStats(name);return [name,family(name),
      ...s.counts.map(n=>cell(n,n?"cell-adverse":"cell-neutral")),
      s.ever,s.persistent,s.maxStreak,s.reappeared,s.reappearanceEvents];});
    drawTable("metricHeatmap",headers,rows);
  }
  function median(values){
    const sorted=[...values].sort((a,b)=>a-b),middle=Math.floor(sorted.length/2);
    return sorted.length%2?sorted[middle]:(sorted[middle-1]+sorted[middle])/2;
  }
  // Linear interpolation at (n - 1) * p defines quartiles for every cohort size.
  function quantile(sorted,p){
    const position=(sorted.length-1)*p,lower=Math.floor(position),upper=Math.ceil(position);
    return sorted[lower]+(sorted[upper]-sorted[lower])*(position-lower);
  }
  function metricDistributionRows(){
    const chosen=$("metricDistributionGroup").value,flagFilter=$("metricDistributionFlagFilter").value,rows=[];
    if(!snapshots.length||!scenarioIds.length)return rows;
    const reference=new Map(METRICS.map(name=>{
      const values=scenarioIds.map(id=>snapshots[0].cases.get(id).metrics.get(name));
      return [name,{candidate:median(values.map(v=>v.candidate)),delta:median(values.map(v=>v.delta))}];
    }));
    snapshots.forEach((report,index)=>METRICS.forEach(name=>{
      const group=family(name);if(chosen!=="all"&&chosen!==group)return;
      const values=scenarioIds.map(id=>report.cases.get(id).metrics.get(name));
      const flagged=values.filter(v=>v.regression).length;
      if(flagFilter==="flagged"&&flagged===0)return;
      if(flagFilter==="clear"&&flagged!==0)return;
      const candidates=values.map(v=>v.candidate).sort((a,b)=>a-b);
      const deltas=values.map(v=>v.delta).sort((a,b)=>a-b);
      const cq1=quantile(candidates,.25),cq3=quantile(candidates,.75);
      const dq1=quantile(deltas,.25),dq3=quantile(deltas,.75);
      const mc=median(candidates),md=median(deltas),base=reference.get(name);
      rows.push({manual_slot:index+1,metric:name,review_group:group,scenario_count:values.length,
        flagged_scenarios:flagged,median_candidate:mc,
        q1_candidate:cq1,q3_candidate:cq3,candidate_iqr:cq3-cq1,
        min_candidate:candidates[0],max_candidate:candidates[candidates.length-1],
        median_delta:md,q1_delta:dq1,q3_delta:dq3,delta_iqr:dq3-dq1,
        median_candidate_shift_from_slot_01:mc-base.candidate,
        median_delta_shift_from_slot_01:md-base.delta,source_snapshot_status:report.status});
    }));
    return rows;
  }
  function renderMetricDistribution(){
    const rows=metricDistributionRows();
    drawTable("metricDistribution",
      ["Manual slot","Metric","Static review group","Scenarios","Flagged scenarios",
       "Median candidate","Candidate Q1","Candidate Q3","Candidate IQR","Candidate min","Candidate max",
       "Median Δ","Δ Q1","Δ Q3","Δ IQR","Median candidate shift vs slot 01","Median Δ shift vs slot 01","Source status"],
      rows.map(r=>[r.manual_slot,r.metric,r.review_group,r.scenario_count,
        cell(r.flagged_scenarios,r.flagged_scenarios?"cell-adverse":"cell-neutral"),
        fmt(r.median_candidate),fmt(r.q1_candidate),fmt(r.q3_candidate),fmt(r.candidate_iqr),
        fmt(r.min_candidate),fmt(r.max_candidate),fmt(r.median_delta),fmt(r.q1_delta),
        fmt(r.q3_delta),fmt(r.delta_iqr),fmt(r.median_candidate_shift_from_slot_01),
        fmt(r.median_delta_shift_from_slot_01),r.source_snapshot_status]));
    $("metricDistributionSummary").textContent=rows.length?
      "Showing "+rows.length+" aggregate metric/slot rows across "+scenarioIds.length+
      " anonymous scenarios. Quartiles use linear interpolation at (n−1)×p; IQR is Q3−Q1. Median shifts compare against manual slot 01 only. These summaries are descriptive; order is not chronology.":
      snapshots.length?"No metrics match the selected review-group and source-flag filters.":
      "Import snapshots to summarize numeric metric distributions.";
    $("metricDistributionCsv").disabled=!rows.length;
    $("metricDistributionJson").disabled=!rows.length;
    $("metricDistributionBrief").disabled=!rows.length;
  }
  function metricTrendSummaryRows(){
    const groupFilter=$("metricDistributionGroup").value,flagFilter=$("metricTrendFlagFilter").value,rows=[];
    if(!snapshots.length||!scenarioIds.length)return rows;
    for(const name of METRICS){
      const group=family(name);if(groupFilter!=="all"&&groupFilter!==group)continue;
      const slots=snapshots.map((report,index)=>{
        const values=scenarioIds.map(id=>report.cases.get(id).metrics.get(name));
        return {slot:index+1,medianCandidate:median(values.map(v=>v.candidate)),
          medianDelta:median(values.map(v=>v.delta)),flagged:values.filter(v=>v.regression).length};
      });
      const flaggedSlots=slots.filter(slot=>slot.flagged>0).length;
      if(flagFilter==="flagged"&&flaggedSlots===0)continue;
      if(flagFilter==="clear"&&flaggedSlots!==0)continue;
      const first=slots[0],last=slots[slots.length-1];
      let peakCandidate={slot:first.slot,shift:0},peakDelta={slot:first.slot,shift:0};
      for(const slot of slots){
        const cs=slot.medianCandidate-first.medianCandidate,ds=slot.medianDelta-first.medianDelta;
        if(Math.abs(cs)>Math.abs(peakCandidate.shift))peakCandidate={slot:slot.slot,shift:cs};
        if(Math.abs(ds)>Math.abs(peakDelta.shift))peakDelta={slot:slot.slot,shift:ds};
      }
      const maxFlagged=Math.max(...slots.map(slot=>slot.flagged));
      rows.push({metric:name,review_group:group,scenario_count:scenarioIds.length,
        first_manual_slot:first.slot,last_manual_slot:last.slot,
        first_median_candidate:first.medianCandidate,last_median_candidate:last.medianCandidate,
        net_median_candidate_shift:last.medianCandidate-first.medianCandidate,
        max_abs_median_candidate_shift:Math.abs(peakCandidate.shift),
        peak_median_candidate_shift:peakCandidate.shift,max_candidate_shift_slot:peakCandidate.slot,
        first_median_delta:first.medianDelta,last_median_delta:last.medianDelta,
        net_median_delta_shift:last.medianDelta-first.medianDelta,
        max_abs_median_delta_shift:Math.abs(peakDelta.shift),
        peak_median_delta_shift:peakDelta.shift,max_delta_shift_slot:peakDelta.slot,
        max_flagged_scenarios:maxFlagged,max_flagged_percent:maxFlagged/scenarioIds.length*100,
        slots_with_flagged_scenarios:flaggedSlots,
        flagged_scenario_slot_observations:slots.reduce((sum,slot)=>sum+slot.flagged,0)});
    }
    const sort = $("metricTrendSort").value;
    const metricOrder = new Map(METRICS.map((name, index) => [name, index]));
    const compareNumber = (a, b, key) => (b[key] - a[key]) || (metricOrder.get(a.metric) - metricOrder.get(b.metric));
    if (sort === "flagged_percent") rows.sort((a,b)=>compareNumber(a,b,"max_flagged_percent"));
    else if (sort === "flagged_observations") rows.sort((a,b)=>compareNumber(a,b,"flagged_scenario_slot_observations"));
    else if (sort === "candidate_shift") rows.sort((a,b)=>compareNumber(a,b,"max_abs_median_candidate_shift"));
    else if (sort === "delta_shift") rows.sort((a,b)=>compareNumber(a,b,"max_abs_median_delta_shift"));
    else if (sort === "flagged_slots") rows.sort((a,b)=>compareNumber(a,b,"slots_with_flagged_scenarios"));
    else rows.sort((a,b)=>metricOrder.get(a.metric)-metricOrder.get(b.metric));
    return rows;
  }
  // Coverage uncertainty is deliberately tracked separately from regression labels.
  // Slot order is selected by the operator and is never treated as chronology.
  function coverageUnknownTrajectoryRows(){
    if(!snapshots.length||!scenarioIds.length)return [];
    const firstValues=scenarioIds.map(id=>snapshots[0].cases.get(id).metrics.get("coverage_unknown").candidate);
    const firstTotal=firstValues.reduce((sum,value)=>sum+value,0);
    let previousTotal=null;
    return snapshots.map((report,index)=>{
      const values=scenarioIds.map(id=>report.cases.get(id).metrics.get("coverage_unknown").candidate);
      const total=values.reduce((sum,value)=>sum+value,0);
      let increased=0,decreased=0,unchanged=0;
      values.forEach((value,i)=>{
        if(value>firstValues[i])increased++;
        else if(value<firstValues[i])decreased++;
        else unchanged++;
      });
      const row={manual_slot:index+1,scenario_count:scenarioIds.length,
        total_unknown_coverage:total,median_unknown_coverage:median(values),
        scenarios_with_unknown_coverage:values.filter(value=>value>0).length,
        scenarios_increased_vs_slot_01:increased,scenarios_decreased_vs_slot_01:decreased,
        scenarios_unchanged_vs_slot_01:unchanged,
        net_total_change_from_slot_01:total-firstTotal,
        total_change_from_previous_slot:previousTotal===null?null:total-previousTotal};
      previousTotal=total;
      return row;
    });
  }
  function renderMetricTrendSummary(){
    const rows=metricTrendSummaryRows();
    drawTable("metricTrendSummary",
      ["Metric","Static review group","Scenarios","First median candidate","Last median candidate",
       "Net median candidate shift","Peak candidate shift (signed)","Peak candidate shift magnitude","Peak slot",
       "First median Δ","Last median Δ","Net median Δ shift","Peak Δ shift (signed)","Peak Δ shift magnitude","Peak slot",
       "Max flagged scenarios","Max flagged %","Slots with any flags","Flagged scenario-slot observations"],
      rows.map(r=>[r.metric,r.review_group,r.scenario_count,fmt(r.first_median_candidate),
        fmt(r.last_median_candidate),fmt(r.net_median_candidate_shift),fmt(r.peak_median_candidate_shift),
        fmt(r.max_abs_median_candidate_shift),r.max_candidate_shift_slot,fmt(r.first_median_delta),fmt(r.last_median_delta),
        fmt(r.net_median_delta_shift),fmt(r.peak_median_delta_shift),fmt(r.max_abs_median_delta_shift),r.max_delta_shift_slot,
        r.max_flagged_scenarios,fmt(r.max_flagged_percent)+"%",r.slots_with_flagged_scenarios,
        r.flagged_scenario_slot_observations]));
    const sortLabel = ({
      fixed:"fixed metric order", flagged_percent:"highest maximum flag prevalence",
      flagged_observations:"most flagged scenario-slot observations",
      candidate_shift:"largest absolute median candidate shift",
      delta_shift:"largest absolute median delta shift",
      flagged_slots:"most slots containing flags"
    })[$("metricTrendSort").value] || "fixed metric order";
    $("metricTrendSummaryText").textContent=rows.length?
      "Showing "+rows.length+" metric-level summaries across "+snapshots.length+
      " manual slots and "+scenarioIds.length+" anonymous scenarios; sorted by "+sortLabel+
      ". Endpoint and peak shifts are descriptive only; no slot chronology or remediation is authenticated.":
      snapshots.length?"No metrics match the selected group/flag filters.":"Import snapshots to summarize median shifts and source-flag prevalence.";
    $("metricTrendSummaryCsv").disabled=!rows.length;
    $("metricTrendSummaryJson").disabled=!rows.length;
    $("metricTrendSummaryBrief").disabled=!rows.length;
  }
  function renderCoverageUnknownTrajectory(){
    const rows=coverageUnknownTrajectoryRows();
    drawTable("coverageUnknownTrajectory",
      ["Manual slot","Anonymous scenarios","Total unknown coverage","Median unknown coverage",
       "Scenarios with unknown coverage","Higher than slot 01","Lower than slot 01",
       "Unchanged vs slot 01","Total change vs slot 01","Total change vs previous slot"],
      rows.map(r=>[r.manual_slot,r.scenario_count,r.total_unknown_coverage,
        fmt(r.median_unknown_coverage),r.scenarios_with_unknown_coverage,
        r.scenarios_increased_vs_slot_01,r.scenarios_decreased_vs_slot_01,
        r.scenarios_unchanged_vs_slot_01,fmt(r.net_total_change_from_slot_01),
        r.total_change_from_previous_slot===null?"—":fmt(r.total_change_from_previous_slot)]));
    $("coverageUnknownSummary").textContent=rows.length?
      "Unknown coverage is shown separately from source regression flags. Across "+rows.length+
      " manually selected slots, totals and scenario counts are descriptive only; increasing unknown coverage is not reclassified as a regression, and slot order is not authenticated chronology.":
      "Import snapshots to compare declared unknown coverage separately from regression flags.";
    for(const id of ["coverageUnknownCsv","coverageUnknownJson","coverageUnknownBrief"])
      $(id).disabled=!rows.length;
  }
  function metricTrendSummaryPayload(){
    return {schema:"lightup.assessment_trends_metric_trend_summary.v2",status:summary().status,
      fictional_demo_only:fictional,manual_slot_order:true,manual_slot_count:snapshots.length,
      authenticated_chronology:false,source_metrics_independently_verified:false,
      remediation_verified:false,authorized:false,consent_verified:false,dispatch_allowed:false,
      release_allowed:false,selected_group_filter:$("metricDistributionGroup").value,
      selected_flag_filter:$("metricTrendFlagFilter").value,selected_sort:$("metricTrendSort").value,rows:metricTrendSummaryRows()};
  }
  function coverageUnknownTrajectoryPayload(){
    return {schema:"lightup.assessment_trends_unknown_coverage_trajectory.v1",
      status:summary().status,fictional_demo_only:fictional,
      interpretation:"Unknown coverage is an uncertainty signal, not a source-reported regression label or verified finding. Slot order is manual and does not establish chronology or remediation.",
      manual_slot_order:true,manual_slot_count:snapshots.length,scenario_count:scenarioIds.length,
      authenticated_chronology:false,source_metrics_independently_verified:false,
      remediation_verified:false,authorized:false,consent_verified:false,dispatch_allowed:false,
      release_allowed:false,rows:coverageUnknownTrajectoryRows()};
  }
  function exportCoverageUnknownTrajectory(kind){
    const payload=coverageUnknownTrajectoryPayload();
    if(!payload.rows.length)return;
    if(kind==="json"){
      download("lightup-unknown-coverage-trajectory-REVIEW-ONLY.json",
        JSON.stringify(payload,null,2)+"\n","application/json");
      return;
    }
    const headers=["manual_slot","scenario_count","total_unknown_coverage",
      "median_unknown_coverage","scenarios_with_unknown_coverage",
      "scenarios_increased_vs_slot_01","scenarios_decreased_vs_slot_01",
      "scenarios_unchanged_vs_slot_01","net_total_change_from_slot_01",
      "total_change_from_previous_slot","fictional_demo_only","status",
      "authenticated_chronology","source_metrics_independently_verified",
      "remediation_verified","authorized","consent_verified","dispatch_allowed","release_allowed"];
    const values=payload.rows.map(r=>[r.manual_slot,r.scenario_count,r.total_unknown_coverage,
      r.median_unknown_coverage,r.scenarios_with_unknown_coverage,r.scenarios_increased_vs_slot_01,
      r.scenarios_decreased_vs_slot_01,r.scenarios_unchanged_vs_slot_01,
      r.net_total_change_from_slot_01,r.total_change_from_previous_slot,
      payload.fictional_demo_only,payload.status,false,false,false,false,false,false,false]);
    if(kind==="csv"){
      download("lightup-unknown-coverage-trajectory-REVIEW-ONLY.csv",
        [headers,...values].map(row=>row.map(csvField).join(",")).join("\r\n")+"\r\n","text/csv");
      return;
    }
    const table="<table><thead><tr>"+headers.slice(0,10).map(v=>"<th scope='col'>"+esc(v)+"</th>").join("")+
      "</tr></thead><tbody>"+payload.rows.map(r=>"<tr>"+[
        r.manual_slot,r.scenario_count,r.total_unknown_coverage,r.median_unknown_coverage,
        r.scenarios_with_unknown_coverage,r.scenarios_increased_vs_slot_01,
        r.scenarios_decreased_vs_slot_01,r.scenarios_unchanged_vs_slot_01,
        r.net_total_change_from_slot_01,r.total_change_from_previous_slot===null?"—":r.total_change_from_previous_slot
      ].map(v=>"<td>"+esc(v)+"</td>").join("")+"</tr>").join("")+"</tbody></table>";
    const html="<!doctype html><html lang='en'><head><meta charset='utf-8'>"+
      "<meta name='viewport' content='width=device-width,initial-scale=1'>"+
      "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none'; object-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'; style-src 'unsafe-inline'\">"+
      "<title>LightUp · Unknown coverage trajectory · REVIEW ONLY</title><style>"+
      "body{font:14px/1.5 system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#17212f}"+
      "table{border-collapse:collapse;width:100%;font-size:12px}th,td{border:1px solid #b7c1cb;padding:.45rem;text-align:left}"+
      "th{background:#edf1f5}.hold{border:1px solid #a77b35;padding:1rem;margin:1rem 0}"+
      "@media print{body{margin:0}tr{break-inside:avoid}}</style></head><body>"+
      "<h1>LightUp · Unknown coverage trajectory</h1><div class='hold'><strong>"+
      esc((payload.fictional_demo_only?"FICTIONAL DEMO ONLY · ":"")+payload.status+" · REVIEW ONLY / HOLD")+
      "</strong><p>"+esc(payload.interpretation)+"</p><p>fictional_demo_only="+payload.fictional_demo_only+
      " · authenticated_chronology=false · source_metrics_independently_verified=false · remediation_verified=false"+
      " · authorized=false · consent_verified=false · dispatch_allowed=false · release_allowed=false</p></div>"+
      "<p>Selected manual slots: "+payload.manual_slot_count+" · anonymous scenarios: "+payload.scenario_count+
      ". This aggregate handoff excludes scenario identifiers, source names and target metadata.</p>"+table+
      "</body></html>";
    download("lightup-unknown-coverage-trajectory-REVIEW-ONLY.html",html,"text/html");
  }
  function exportMetricTrendSummaryHtml(payload){
    const headers=["Metric","Review group","Scenarios","First median candidate","Last median candidate",
      "Net candidate shift","Peak candidate shift (signed)","Peak candidate shift magnitude","Peak slot",
      "First median delta","Last median delta","Net delta shift","Peak delta shift (signed)",
      "Peak delta shift magnitude","Peak slot","Max flagged scenarios","Max flagged %",
      "Slots with flags","Flagged scenario-slot observations"];
    const values=payload.rows.map(r=>[r.metric,r.review_group,r.scenario_count,r.first_median_candidate,
      r.last_median_candidate,r.net_median_candidate_shift,r.peak_median_candidate_shift,
      r.max_abs_median_candidate_shift,r.max_candidate_shift_slot,r.first_median_delta,r.last_median_delta,r.net_median_delta_shift,
      r.peak_median_delta_shift,r.max_abs_median_delta_shift,r.max_delta_shift_slot,r.max_flagged_scenarios,
      r.max_flagged_percent.toFixed(4)+"%",r.slots_with_flagged_scenarios,r.flagged_scenario_slot_observations]);
    const table="<table><thead><tr>"+headers.map(v=>"<th scope='col'>"+esc(v)+"</th>").join("")+
      "</tr></thead><tbody>"+values.map(row=>"<tr>"+row.map(v=>"<td>"+esc(v)+"</td>").join("")+
      "</tr>").join("")+"</tbody></table>";
    const html="<!doctype html><html lang='en'><head><meta charset='utf-8'>"+
      "<meta name='viewport' content='width=device-width,initial-scale=1'>"+
      `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none'; object-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'; style-src 'unsafe-inline'">`+
      "<title>LightUp · Anonymous metric trend summary</title><style>"+
      "body{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#17202a}h1{font-size:1.6rem}"+
      ".hold{border:1px solid #8a6d3b;padding:1rem;margin:1rem 0}table{border-collapse:collapse;width:100%;font-size:12px}"+
      "th,td{border:1px solid #bbb;padding:.4rem;text-align:left;vertical-align:top}th{background:#eee}"+
      "@media print{body{margin:0}table{font-size:9px}tr{break-inside:avoid}}"+
      "</style></head><body><h1>LightUp · Anonymous metric trend summary</h1>"+
      "<p>Aggregate summaries of already-completed source reports. Selected slot order is manual, not authenticated chronology. Shifts do not prove remediation.</p>"+
      "<p>Selected static group: "+esc(payload.selected_group_filter)+" · Flag filter: "+
      esc(payload.selected_flag_filter)+" · Sort: "+esc(payload.selected_sort)+
      " · Manual slots: "+payload.manual_slot_count+"</p>"+
      "<div class='hold'><strong>"+esc((payload.fictional_demo_only?"FICTIONAL DEMO ONLY · ":"")+payload.status+" · REVIEW ONLY / HOLD")+"</strong><p>"+
      "fictional_demo_only="+payload.fictional_demo_only+" · authorized=false · consent_verified=false · dispatch_allowed=false · release_allowed=false · "+
      "authenticated_chronology=false · source_metrics_independently_verified=false · remediation_verified=false</p></div>"+
      table+"<p>No original scenario IDs, filenames, source hashes or HUMAN notes are included.</p></body></html>";
    if(new Blob([html]).size>4*1024*1024)return;
    download("assessment-trends-anonymous-metric-trend-summary-REVIEW-ONLY.html",html,"text/html");
  }
  function exportMetricTrendSummary(format){
    const payload=metricTrendSummaryPayload();if(!payload.rows.length)return;
    if(format==="html"){exportMetricTrendSummaryHtml(payload);return;}
    if(format==="json"){
      download("assessment-trends-anonymous-metric-trend-summary.json",
        JSON.stringify(payload,null,2)+"\n","application/json");return;
    }
    const columns=["schema","selected_group_filter","selected_flag_filter","manual_slot_order","manual_slot_count",
      "metric","review_group","scenario_count","first_manual_slot","last_manual_slot",
      "first_median_candidate","last_median_candidate","net_median_candidate_shift","peak_median_candidate_shift",
      "max_abs_median_candidate_shift","max_candidate_shift_slot","first_median_delta","last_median_delta",
      "net_median_delta_shift","peak_median_delta_shift","max_abs_median_delta_shift","max_delta_shift_slot","max_flagged_scenarios",
      "max_flagged_percent","slots_with_flagged_scenarios","flagged_scenario_slot_observations",
      "overall_status","fictional_demo_only","authenticated_chronology","source_metrics_independently_verified",
      "remediation_verified",...FLAGS];
    const lines=[columns.map(csvField).join(","),...payload.rows.map(row=>columns.map(key=>
      csvField(key==="overall_status"?payload.status:
        Object.prototype.hasOwnProperty.call(row,key)?row[key]:
        Object.prototype.hasOwnProperty.call(payload,key)?payload[key]:false)).join(","))];
    download("assessment-trends-anonymous-metric-trend-summary.csv",lines.join("\n")+"\n","text/csv;charset=utf-8");
  }
  function metricDistributionPayload(){
    return {schema:"lightup.assessment_trends_metric_distribution.v1",status:summary().status,
      fictional_demo_only:fictional,manual_slot_order:true,authenticated_chronology:false,
      source_metrics_independently_verified:false,remediation_verified:false,
      authorized:false,consent_verified:false,dispatch_allowed:false,release_allowed:false,
      selected_group_filter:$("metricDistributionGroup").value,
      selected_flag_filter:$("metricDistributionFlagFilter").value,rows:metricDistributionRows()};
  }
  function exportMetricDistributionHtml(payload){
    const headers=["Manual slot","Metric","Review group","Scenarios","Flagged scenarios",
      "Median candidate","Candidate Q1","Candidate Q3","Candidate IQR","Candidate min","Candidate max",
      "Median delta","Delta Q1","Delta Q3","Delta IQR","Median candidate shift vs slot 01",
      "Median delta shift vs slot 01","Source status"];
    const values=payload.rows.map(r=>[r.manual_slot,r.metric,r.review_group,r.scenario_count,r.flagged_scenarios,
      r.median_candidate,r.q1_candidate,r.q3_candidate,r.candidate_iqr,r.min_candidate,r.max_candidate,
      r.median_delta,r.q1_delta,r.q3_delta,r.delta_iqr,r.median_candidate_shift_from_slot_01,
      r.median_delta_shift_from_slot_01,r.source_snapshot_status]);
    const table="<table><thead><tr>"+headers.map(v=>"<th scope='col'>"+esc(v)+"</th>").join("")+
      "</tr></thead><tbody>"+values.map(row=>"<tr>"+row.map(v=>"<td>"+esc(v)+"</td>").join("")+
      "</tr>").join("")+"</tbody></table>";
    const html="<!doctype html><html lang='en'><head><meta charset='utf-8'>"+
      "<meta name='viewport' content='width=device-width,initial-scale=1'>"+
      `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none'; object-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'; style-src 'unsafe-inline'">`+
      "<title>LightUp · Anonymous metric distribution</title><style>"+
      "body{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#17202a}h1{font-size:1.6rem}"+
      ".hold{border:1px solid #8a6d3b;padding:1rem;margin:1rem 0}table{border-collapse:collapse;width:100%;font-size:11px}"+
      "th,td{border:1px solid #bbb;padding:.35rem;text-align:left;vertical-align:top}th{background:#eee}"+
      "@media print{body{margin:0}table{font-size:8px}tr{break-inside:avoid}}"+
      "</style></head><body><h1>LightUp · Anonymous metric distribution</h1>"+
      "<p>Aggregate summaries of already-completed source reports. Quartiles use linear interpolation at (n−1)×p. Median shifts compare with manual slot 01, not authenticated chronology.</p>"+
      "<p>Selected static group: "+esc(payload.selected_group_filter)+" · Flag filter: "+
      esc(payload.selected_flag_filter)+" · Manual slots: "+snapshots.length+"</p>"+
      "<div class='hold'><strong>"+esc((payload.fictional_demo_only?"FICTIONAL DEMO ONLY · ":"")+payload.status+" · REVIEW ONLY / HOLD")+"</strong><p>"+
      "fictional_demo_only="+payload.fictional_demo_only+" · authorized=false · consent_verified=false · dispatch_allowed=false · release_allowed=false · "+
      "authenticated_chronology=false · source_metrics_independently_verified=false · remediation_verified=false</p></div>"+
      table+"<p>No original scenario IDs, filenames, source hashes or HUMAN notes are included.</p></body></html>";
    if(new Blob([html]).size>4*1024*1024)return;
    download("assessment-trends-anonymous-metric-distribution-REVIEW-ONLY.html",html,"text/html");
  }
  function exportMetricDistribution(format){
    const payload=metricDistributionPayload();if(!payload.rows.length)return;
    if(format==="html"){exportMetricDistributionHtml(payload);return;}
    if(format==="json"){
      download("assessment-trends-anonymous-metric-distribution.json",
        JSON.stringify(payload,null,2)+"\n","application/json");return;
    }
    const columns=["schema","selected_group_filter","selected_flag_filter","manual_slot_order","manual_slot","metric","review_group",
      "scenario_count","flagged_scenarios","median_candidate","q1_candidate","q3_candidate","candidate_iqr",
      "min_candidate","max_candidate","median_delta","q1_delta","q3_delta","delta_iqr",
      "median_candidate_shift_from_slot_01","median_delta_shift_from_slot_01","min_delta","max_delta",
      "source_snapshot_status","overall_status","fictional_demo_only","authenticated_chronology",
      "source_metrics_independently_verified","remediation_verified",...FLAGS];
    const lines=[columns.map(csvField).join(","),...payload.rows.map(row=>columns.map(key=>
      csvField(key==="overall_status"?payload.status:
        Object.prototype.hasOwnProperty.call(row,key)?row[key]:
        Object.prototype.hasOwnProperty.call(payload,key)?payload[key]:false)).join(","))];
    download("assessment-trends-anonymous-metric-distribution.csv",lines.join("\n")+"\n","text/csv;charset=utf-8");
  }

  function metricTransitionRows(){
    const chosenGroup=$("metricDistributionGroup").value;
    const chosenTransition=$("metricTransitionFilter").value;
    const chosenScope=$("metricTransitionScope").value;
    const rows=[];
    if(snapshots.length<2||!scenarioIds.length)return rows;
    const pairs=[];
    if(chosenScope==="all_pairs"){
      for(let previous=1;previous<snapshots.length;previous++)
        for(let current=previous+1;current<=snapshots.length;current++)pairs.push([previous,current]);
    }else{
      for(let current=2;current<=snapshots.length;current++)pairs.push([current-1,current]);
    }
    for(const [previousSlot,currentSlot] of pairs){
      const previous=snapshots[previousSlot-1],current=snapshots[currentSlot-1];
      for(const name of METRICS){
        const group=family(name);
        if(chosenGroup!=="all"&&chosenGroup!==group)continue;
        let clearToFlagged=0,flaggedToClear=0,flaggedBoth=0,clearBoth=0;
        for(const id of scenarioIds){
          const before=previous.cases.get(id).metrics.get(name).regression;
          const after=current.cases.get(id).metrics.get(name).regression;
          if(!before&&after)clearToFlagged++;
          else if(before&&!after)flaggedToClear++;
          else if(before&&after)flaggedBoth++;
          else clearBoth++;
        }
        const changed=clearToFlagged+flaggedToClear;
        const matches={
          all:true,
          changed:changed>0,
          clear_to_flagged:clearToFlagged>0,
          flagged_to_clear:flaggedToClear>0,
          flagged_both:flaggedBoth>0,
          clear_both:clearBoth>0
        };
        if(!matches[chosenTransition])continue;
        rows.push({
          previous_manual_slot:previousSlot,current_manual_slot:currentSlot,
          metric:name,review_group:group,scenario_count:scenarioIds.length,
          previous_flagged_scenarios:flaggedToClear+flaggedBoth,
          current_flagged_scenarios:clearToFlagged+flaggedBoth,
          clear_to_flagged_scenarios:clearToFlagged,
          flagged_to_clear_scenarios:flaggedToClear,
          flagged_in_both_slots_scenarios:flaggedBoth,
          clear_in_both_slots_scenarios:clearBoth,
          changed_scenarios:changed,
          net_flag_change:clearToFlagged-flaggedToClear,
          previous_source_status:previous.status,current_source_status:current.status
        });
      }
    }
    return rows;
  }
  function renderMetricTransitions(){
    syncTransitionDrilldownControls();
    const rows=metricTransitionRows();
    drawTable("metricTransitionTable",
      ["Previous manual slot","Current manual slot","Metric","Static review group","Scenarios",
       "Flagged before","Flagged after","Clear → flagged","Flagged → clear · NOT a verified fix",
       "Flagged in both","Clear in both","Changed scenarios","Net flag-count change",
       "Previous source status","Current source status"],
      rows.map(r=>[r.previous_manual_slot,r.current_manual_slot,r.metric,r.review_group,r.scenario_count,
        r.previous_flagged_scenarios,r.current_flagged_scenarios,
        cell(r.clear_to_flagged_scenarios,r.clear_to_flagged_scenarios?"cell-adverse":"cell-neutral"),
        cell(r.flagged_to_clear_scenarios,r.flagged_to_clear_scenarios?"cell-adverse":"cell-neutral"),
        r.flagged_in_both_slots_scenarios,r.clear_in_both_slots_scenarios,r.changed_scenarios,
        r.net_flag_change,r.previous_source_status,r.current_source_status]));
    const scope=$("metricTransitionScope").value;
    const pairCount=scope==="all_pairs"?snapshots.length*(snapshots.length-1)/2:snapshots.length-1;
    $("metricTransitionSummary").textContent=rows.length?
      "Showing "+rows.length+" metric/pair rows within a scope of "+pairCount+
      (scope==="all_pairs"?" possible distinct manual-slot pairs (including non-adjacent comparisons)":" adjacent manual-slot pairs")+
      " and "+scenarioIds.length+
      " anonymous scenarios. Each scenario contributes to exactly one flag-state category. A flag absent in a later-selected slot is not a verified fix; slot order is not authenticated chronology.":
      snapshots.length>1?"No metric/slot-pair rows match the selected group and transition filters.":
      "Import at least two snapshots to summarize flag-state changes.";
    for(const id of ["metricTransitionCsv","metricTransitionJson","metricTransitionBrief"])
      $(id).disabled=!rows.length;
    renderMetricTransitionCases();
  }
  function syncTransitionDrilldownControls(){
    const metric=$("metricTransitionMetric"),oldMetric=metric.value;
    metric.replaceChildren();
    for(const name of METRICS){
      const option=document.createElement("option");
      option.value=name;option.textContent=name;metric.append(option);
    }
    metric.value=METRICS.includes(oldMetric)?oldMetric:METRICS[0];
    const pair=$("metricTransitionPair"),oldPair=pair.value;
    pair.replaceChildren();
    const pairMatch=/^([1-9][0-9]*):([1-9][0-9]*)$/.exec(oldPair);
    const validPair=!!pairMatch&&Number(pairMatch[1])<Number(pairMatch[2])&&
      Number(pairMatch[2])<=snapshots.length;
    for(let previous=1;previous<snapshots.length;previous++){
      for(let current=previous+1;current<=snapshots.length;current++){
        const option=document.createElement("option");
        option.value=previous+":"+current;
        option.textContent="Slot "+String(previous).padStart(2,"0")+" → slot "+
          String(current).padStart(2,"0")+
          (current===previous+1?" · adjacent":" · direct pairwise comparison");
        pair.append(option);
      }
    }
    pair.value=validPair?oldPair:"1:2";
    const active=snapshots.length>=2;
    metric.disabled=!active;pair.disabled=!active;
    $("metricTransitionCaseFilter").disabled=!active;
  }
  function transitionDrilldownRows(){
    if(snapshots.length<2||!scenarioIds.length)return [];
    const metric=$("metricTransitionMetric").value;
    const pairMatch=/^([1-9][0-9]*):([1-9][0-9]*)$/.exec($("metricTransitionPair").value);
    if(!pairMatch)return [];
    const previousSlot=Number(pairMatch[1]),currentSlot=Number(pairMatch[2]);
    const previous=snapshots[previousSlot-1],current=snapshots[currentSlot-1];
    if(!previous||!current||previousSlot>=currentSlot||!METRICS.includes(metric))return [];
    const filter=$("metricTransitionCaseFilter").value;
    const rows=[];
    scenarioIds.forEach((id,index)=>{
      const before=previous.cases.get(id).metrics.get(metric);
      const after=current.cases.get(id).metrics.get(metric);
      const state=!before.regression&&after.regression?"clear_to_flagged":
        before.regression&&!after.regression?"flagged_to_clear":
        before.regression&&after.regression?"flagged_both":"clear_both";
      const changed=state==="clear_to_flagged"||state==="flagged_to_clear";
      if(filter==="changed"&&!changed)return;
      if(filter!=="changed"&&filter!==state)return;
      rows.push({id,ordinal:index+1,state,previousCandidate:before.candidate,
        currentCandidate:after.candidate,previousDelta:before.delta,currentDelta:after.delta,
        previousFlag:before.regression,currentFlag:after.regression,
        previousStatus:previous.status,currentStatus:current.status});
    });
    return rows;
  }
  function renderMetricTransitionCases(){
    const root=$("metricTransitionCases"),rows=transitionDrilldownRows();
    root.replaceChildren();
    if(snapshots.length<2){
      $("metricTransitionCasesSummary").textContent="Import at least two snapshots to inspect the scenarios behind a flag-state transition.";
      for(const id of ["metricTransitionCasesCsv","metricTransitionCasesJson","metricTransitionCasesBrief"])$(id).disabled=true;
      return;
    }
    $("metricTransitionCasesSummary").textContent=rows.length?
      "Showing "+rows.length+" anonymous scenarios for "+$("metricTransitionMetric").value+
      " · "+$("metricTransitionPair").selectedOptions[0].textContent+
      " · "+$("metricTransitionCaseFilter").selectedOptions[0].textContent+
      ". Original scenario IDs remain hidden. Opening a row changes only the local scenario selection.":
      "No scenarios match this metric, manual-slot pair and flag-state category.";
    for(const id of ["metricTransitionCasesCsv","metricTransitionCasesJson","metricTransitionCasesBrief"])
      $(id).disabled=!rows.length;
    const table=document.createElement("table"),head=document.createElement("thead"),header=document.createElement("tr");
    for(const label of ["Anonymous scenario","Flag state","Previous candidate","Current candidate",
      "Previous Δ","Current Δ","Previous source status","Current source status","Inspect"]){
      const th=document.createElement("th");th.scope="col";th.textContent=label;header.append(th);
    }
    head.append(header);table.append(head);
    const body=document.createElement("tbody");
    for(const row of rows){
      const tr=document.createElement("tr");
      const values=["Scenario "+String(row.ordinal).padStart(2,"0"),
        row.state==="clear_to_flagged"?"CLEAR → FLAGGED":
          row.state==="flagged_to_clear"?"FLAGGED → CLEAR · NOT A VERIFIED FIX":
          row.state==="flagged_both"?"FLAGGED IN BOTH SLOTS":"CLEAR IN BOTH SLOTS",
        fmt(row.previousCandidate),fmt(row.currentCandidate),fmt(row.previousDelta),fmt(row.currentDelta),
        row.previousStatus,row.currentStatus];
      for(const value of values){const td=document.createElement("td");td.textContent=String(value);tr.append(td);}
      const action=document.createElement("td"),button=document.createElement("button");
      button.type="button";button.textContent="Open trajectory";
      button.setAttribute("aria-label","Open anonymous scenario "+row.ordinal+" trajectory");
      button.addEventListener("click",()=>{
        selectedScenario=row.id;$("scenarioSelect").value=row.id;
        renderScenarioDetail();renderNotePanel();renderNotePacketControls();
        $("scenarioSelect").focus();
      });
      action.append(button);tr.append(action);body.append(tr);
    }
    table.append(body);root.append(table);
  }
  function transitionCasePayload(){
    const metric=$("metricTransitionMetric").value;
    const pairMatch=/^([1-9][0-9]*):([1-9][0-9]*)$/.exec($("metricTransitionPair").value);
    admit(!!pairMatch);
    const previousSlot=Number(pairMatch[1]),currentSlot=Number(pairMatch[2]);
    const filter=$("metricTransitionCaseFilter").value;
    const selectedRows=transitionDrilldownRows().map(row=>({
      anonymous_scenario_ordinal:row.ordinal,
      metric,
      review_group:family(metric),
      previous_manual_slot:previousSlot,
      current_manual_slot:currentSlot,
      state:row.state,
      previous_flag:row.previousFlag,
      current_flag:row.currentFlag,
      previous_candidate:row.previousCandidate,
      current_candidate:row.currentCandidate,
      previous_delta:row.previousDelta,
      current_delta:row.currentDelta,
      previous_source_status:row.previousStatus,
      current_source_status:row.currentStatus
    }));
    const adjacent=currentSlot===previousSlot+1;
    return {schema:"lightup.assessment_trends_transition_case_handoff.v2",
      status:summary().status,fictional_demo_only:fictional,
      manual_slot_order:true,manual_slot_count:snapshots.length,
      previous_manual_slot:previousSlot,current_manual_slot:currentSlot,
      selected_pair_adjacent:adjacent,
      selected_pair_mode:adjacent?"adjacent":"non_adjacent_pairwise",
      selected_metric:metric,selected_state_filter:filter,
      authenticated_chronology:false,source_metrics_independently_verified:false,
      remediation_verified:false,...Object.fromEntries(FLAGS.map(name=>[name,false])),
      rows:selectedRows};
  }
  function exportTransitionCasesHtml(payload){
    const headers=["Anonymous scenario ordinal","Metric","Static review group","Previous slot","Current slot",
      "Flag state","Previous flag","Current flag","Previous candidate","Current candidate",
      "Previous Δ","Current Δ","Previous source status","Current source status"];
    const values=payload.rows.map(r=>[r.anonymous_scenario_ordinal,r.metric,r.review_group,
      r.previous_manual_slot,r.current_manual_slot,r.state,r.previous_flag,r.current_flag,
      r.previous_candidate,r.current_candidate,r.previous_delta,r.current_delta,
      r.previous_source_status,r.current_source_status]);
    const table="<table><thead><tr>"+headers.map(v=>"<th scope='col'>"+esc(v)+"</th>").join("")+
      "</tr></thead><tbody>"+values.map(row=>"<tr>"+row.map(v=>"<td>"+esc(v)+"</td>").join("")+
      "</tr>").join("")+"</tbody></table>";
    const html="<!doctype html><html lang='en'><head><meta charset='utf-8'>"+
      "<meta name='viewport' content='width=device-width,initial-scale=1'>"+
      "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none'; object-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'; style-src 'unsafe-inline'\">"+
      "<title>LightUp · Anonymous transition cases</title><style>"+
      "body{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#17202a}h1{font-size:1.6rem}"+
      ".hold{border:1px solid #8a6d3b;padding:1rem;margin:1rem 0}table{border-collapse:collapse;width:100%;font-size:11px}"+
      "th,td{border:1px solid #bbb;padding:.35rem;text-align:left;vertical-align:top}th{background:#eee}"+
      "@media print{body{margin:0}table{font-size:8px}tr{break-inside:avoid}}"+
      "</style></head><body><h1>LightUp · Anonymous transition cases</h1>"+
      "<p>These are local ordinal references only, not original scenario IDs. The manually selected slot order is not authenticated chronology; a flag absent from the current slot is not a verified fix.</p>"+
      "<p>Metric: "+esc(payload.selected_metric)+" · Group: "+esc(family(payload.selected_metric))+
      " · State filter: "+esc(payload.selected_state_filter)+" · Pair mode: "+
      esc(payload.selected_pair_mode)+" · Slots: "+
      payload.previous_manual_slot+" → "+payload.current_manual_slot+"</p>"+
      "<div class='hold'><strong>"+esc((payload.fictional_demo_only?"FICTIONAL DEMO ONLY · ":"")+
      payload.status+" · REVIEW ONLY / HOLD")+"</strong><p>fictional_demo_only="+payload.fictional_demo_only+
      " · authenticated_chronology=false · source_metrics_independently_verified=false · remediation_verified=false · "+
      "authorized=false · consent_verified=false · dispatch_allowed=false · release_allowed=false</p></div>"+
      table+"<p>No original scenario IDs, filenames, source hashes or HUMAN notes are included. "+
      "This export does not establish a verified finding, remediation or release decision.</p></body></html>";
    if(new Blob([html]).size>4*1024*1024)return;
    download("assessment-trends-anonymous-transition-cases-REVIEW-ONLY.html",html,"text/html");
  }
  function exportTransitionCases(format){
    const payload=transitionCasePayload();
    if(!payload.rows.length)return;
    if(format==="html"){exportTransitionCasesHtml(payload);return;}
    if(format==="json"){
      download("assessment-trends-anonymous-transition-cases.json",
        JSON.stringify(payload,null,2)+"\n","application/json");return;
    }
    const columns=["schema","overall_status","fictional_demo_only","manual_slot_order","manual_slot_count",
      "previous_manual_slot","current_manual_slot","selected_pair_adjacent","selected_pair_mode",
      "selected_metric","selected_state_filter",
      "authenticated_chronology","source_metrics_independently_verified","remediation_verified",...FLAGS,
      "anonymous_scenario_ordinal","metric","review_group","state","previous_flag","current_flag",
      "previous_candidate","current_candidate","previous_delta","current_delta",
      "previous_source_status","current_source_status"];
    const lines=[columns.map(csvField).join(","),...payload.rows.map(row=>columns.map(key=>
      csvField(key==="overall_status"?payload.status:
        Object.prototype.hasOwnProperty.call(row,key)?row[key]:
        Object.prototype.hasOwnProperty.call(payload,key)?payload[key]:false)).join(","))];
    download("assessment-trends-anonymous-transition-cases.csv",
      lines.join("\n")+"\n","text/csv;charset=utf-8");
  }
  function metricTransitionPayload(){
    const selectedPairScope=$("metricTransitionScope").value;
    const allPairs=snapshots.length*(snapshots.length-1)/2;
    return {schema:"lightup.assessment_trends_flag_transition_matrix.v2",
      status:summary().status,fictional_demo_only:fictional,
      manual_slot_order:true,manual_slot_count:snapshots.length,
      adjacent_manual_slot_pairs:Math.max(0,snapshots.length-1),
      all_manual_slot_pairs:Math.max(0,allPairs),
      selected_pair_scope:selectedPairScope,
      selected_pair_count:selectedPairScope==="all_pairs"?allPairs:Math.max(0,snapshots.length-1),
      authenticated_chronology:false,source_metrics_independently_verified:false,
      remediation_verified:false,...Object.fromEntries(FLAGS.map(name=>[name,false])),
      selected_group_filter:$("metricDistributionGroup").value,
      selected_transition_filter:$("metricTransitionFilter").value,
      rows:metricTransitionRows()};
  }
  function exportMetricTransitionHtml(payload){
    const headers=["Previous slot","Current slot","Metric","Review group","Scenarios",
      "Flagged before","Flagged after","Clear to flagged","Flagged to clear · NOT a verified fix",
      "Flagged in both","Clear in both","Changed scenarios","Net flag-count change",
      "Previous source status","Current source status"];
    const values=payload.rows.map(r=>[r.previous_manual_slot,r.current_manual_slot,r.metric,r.review_group,
      r.scenario_count,r.previous_flagged_scenarios,r.current_flagged_scenarios,
      r.clear_to_flagged_scenarios,r.flagged_to_clear_scenarios,r.flagged_in_both_slots_scenarios,
      r.clear_in_both_slots_scenarios,r.changed_scenarios,r.net_flag_change,
      r.previous_source_status,r.current_source_status]);
    const table="<table><thead><tr>"+headers.map(v=>"<th scope='col'>"+esc(v)+"</th>").join("")+
      "</tr></thead><tbody>"+values.map(row=>"<tr>"+row.map(v=>"<td>"+esc(v)+"</td>").join("")+
      "</tr>").join("")+"</tbody></table>";
    const html="<!doctype html><html lang='en'><head><meta charset='utf-8'>"+
      "<meta name='viewport' content='width=device-width,initial-scale=1'>"+
      "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none'; object-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'; style-src 'unsafe-inline'\">"+
      "<title>LightUp · Anonymous flag-state transitions</title><style>"+
      "body{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#17202a}h1{font-size:1.6rem}"+
      ".hold{border:1px solid #8a6d3b;padding:1rem;margin:1rem 0}table{border-collapse:collapse;width:100%;font-size:11px}"+
      "th,td{border:1px solid #bbb;padding:.35rem;text-align:left;vertical-align:top}th{background:#eee}"+
      "@media print{body{margin:0}table{font-size:8px}tr{break-inside:avoid}}"+
      "</style></head><body><h1>LightUp · Anonymous flag-state transitions</h1>"+
      "<p>"+(payload.selected_pair_scope==="all_pairs"?
        "Counts compare every distinct pair of manually ordered snapshots, including non-adjacent slots.":
        "Counts compare adjacent manually ordered snapshots only.")+
        " The selected order is not authenticated chronology; a missing flag is not a verified fix.</p>"+
      "<p>Static review group: "+esc(payload.selected_group_filter)+" · Transition filter: "+
      esc(payload.selected_transition_filter)+" · Pair scope: "+esc(payload.selected_pair_scope)+
      " ("+payload.selected_pair_count+" pairs) · Manual slots: "+payload.manual_slot_count+"</p>"+
      "<div class='hold'><strong>"+esc((payload.fictional_demo_only?"FICTIONAL DEMO ONLY · ":"")+
      payload.status+" · REVIEW ONLY / HOLD")+"</strong><p>fictional_demo_only="+payload.fictional_demo_only+
      " · authenticated_chronology=false · source_metrics_independently_verified=false · remediation_verified=false · "+
      "authorized=false · consent_verified=false · dispatch_allowed=false · release_allowed=false</p></div>"+
      table+"<p>Every scenario is counted in exactly one category per metric and "+
      (payload.selected_pair_scope==="all_pairs"?"selected manual-slot pair. ":"adjacent slot pair. ")+
      "No original scenario IDs, filenames, source hashes or HUMAN notes are included.</p></body></html>";
    if(new Blob([html]).size>4*1024*1024)return;
    download("assessment-trends-anonymous-flag-transitions-REVIEW-ONLY.html",html,"text/html");
  }
  function exportMetricTransitions(format){
    const payload=metricTransitionPayload();
    if(!payload.rows.length)return;
    if(format==="html"){exportMetricTransitionHtml(payload);return;}
    if(format==="json"){
      download("assessment-trends-anonymous-flag-transitions.json",
        JSON.stringify(payload,null,2)+"\n","application/json");return;
    }
    const columns=["schema","selected_group_filter","selected_transition_filter","manual_slot_order",
      "manual_slot_count","adjacent_manual_slot_pairs","all_manual_slot_pairs","selected_pair_scope",
      "selected_pair_count","previous_manual_slot","current_manual_slot",
      "metric","review_group","scenario_count","previous_flagged_scenarios","current_flagged_scenarios",
      "clear_to_flagged_scenarios","flagged_to_clear_scenarios","flagged_in_both_slots_scenarios",
      "clear_in_both_slots_scenarios","changed_scenarios","net_flag_change","previous_source_status",
      "current_source_status","overall_status","fictional_demo_only","authenticated_chronology",
      "source_metrics_independently_verified","remediation_verified",...FLAGS];
    const lines=[columns.map(csvField).join(","),...payload.rows.map(row=>columns.map(key=>
      csvField(key==="overall_status"?payload.status:
        Object.prototype.hasOwnProperty.call(row,key)?row[key]:
        Object.prototype.hasOwnProperty.call(payload,key)?payload[key]:false)).join(","))];
    download("assessment-trends-anonymous-flag-transitions.csv",lines.join("\n")+"\n","text/csv;charset=utf-8");
  }

  const SCENARIO_PAGE=100;
  let scenarioOffset=0;
  function scenarioBoardRows(){
    const filter=$("scenarioViewFilter").value;
    const raw=$("scenarioSearch").value.trim();
    const exactOrdinal=/^\d{1,4}$/.test(raw)?Number(raw):null;
    const query=raw.toLowerCase();
    return scenarioIds.map((id,index)=>({id,ordinal:index+1,stats:scenarioStats(id)})).filter(item=>{
      const label="Scenario "+String(item.ordinal).padStart(2,"0");
      const matchesFilter=filter==="all"||
        (filter==="hold"&&item.stats.status==="HOLD")||
        (filter==="persistent"&&item.stats.persistent>0)||
        (filter==="reappeared"&&item.stats.reappearedMetrics>0);
      const matchesSearch=!raw||(exactOrdinal!==null?item.ordinal===exactOrdinal:label.toLowerCase().includes(query));
      return matchesFilter&&matchesSearch;
    });
  }
  function renderScenarioBoard(){
    const all=snapshots.length?scenarioBoardRows():[];
    const maxOffset=Math.max(0,Math.floor((all.length-1)/SCENARIO_PAGE)*SCENARIO_PAGE);
    scenarioOffset=Math.min(scenarioOffset,maxOffset);
    const page=all.slice(scenarioOffset,scenarioOffset+SCENARIO_PAGE);
    const headers=["Anonymous scenario",...snapshots.map((_,i)=>"Slot "+String(i+1).padStart(2,"0")+" flagged metrics"),
      "First flagged slot","Last flagged slot","Persistent metrics","Reappearing metrics",
      "Reappearance events","Longest metric streak","Overall source status"];
    const rows=page.map(({ordinal,stats})=>[
      "Scenario "+String(ordinal).padStart(2,"0"),
      ...stats.counts.map(n=>cell(n,n?"cell-adverse":"cell-neutral")),
      stats.firstFlaggedSlot??"—",stats.lastFlaggedSlot??"—",stats.persistent,stats.reappearedMetrics,
      stats.reappearanceEvents,stats.longestMetricStreak,stats.status
    ]);
    drawTable("scenarioHeatmap",headers,rows);
    $("scenarioPrev").disabled=scenarioOffset===0;
    $("scenarioNext").disabled=scenarioOffset+SCENARIO_PAGE>=all.length;
    $("scenarioPageSummary").textContent=all.length?
      "Showing "+(scenarioOffset+1)+"–"+Math.min(all.length,scenarioOffset+SCENARIO_PAGE)+
        " of "+all.length+" anonymous scenarios matching the filter. Source order only; no missing flag is a verified fix.":
      snapshots.length?"No anonymous scenarios match the selected filter.":
        "Import snapshots to see anonymous scenario trajectories.";
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
  // A bounded HUMAN-only visible-page edit; neither a source verdict nor approval.
  let stageBatchUndo=null,stageSelectionDataset=null,stageSelectionContext="";
  const selectedStageEvents=new Set();
  function syncStageSelectionContext(){
    const context=[reviewOffset,$("reviewKind").value,$("reviewGroup").value,
      $("reviewSlot").value,$("reviewStage").value].join("|");
    if(stageSelectionDataset!==snapshots||stageSelectionContext!==context)
      selectedStageEvents.clear();
    stageSelectionDataset=snapshots;stageSelectionContext=context;
  }
  function sameStageMap(left,right){
    return left.size===right.size&&[...left].every(([key,value])=>right.get(key)===value);
  }
  function visibleReviewRows(){
    return snapshots.length?reviewSelection().slice(reviewOffset,reviewOffset+REVIEW_PAGE):[];
  }
  function updateStageBatchControls(){
    const chosen=$("reviewBulkStage").value,rows=visibleReviewRows();
    const selected=rows.filter(event=>selectedStageEvents.has(humanStageKey(event)));
    const changed=HUMAN_STAGES.includes(chosen)?
      selected.filter(event=>humanStage(event)!==chosen).length:0;
    $("reviewBulkSelectAll").disabled=!rows.length;
    $("reviewBulkSelectAll").checked=!!rows.length&&selected.length===rows.length;
    $("reviewBulkSelectAll").indeterminate=selected.length>0&&selected.length<rows.length;
    $("reviewBulkApply").disabled=changed===0;
    const canUndo=!!stageBatchUndo&&stageBatchUndo.dataset===snapshots&&
      sameStageMap(stageBatchUndo.after,humanReviewStages);
    $("reviewBulkUndo").disabled=!canUndo;
    if(stageBatchUndo&&!canUndo)stageBatchUndo=null;
    if(changed)
      $("reviewBulkStatus").textContent=changed+" of "+selected.length+
        " selected events on this visible page would change to "+chosen+
        ". Nothing has changed yet; unselected events and other pages are excluded.";
    else if(rows.length)
      $("reviewBulkStatus").textContent="Visible page: "+rows.length+
        " events, "+selected.length+" selected. Select row checkboxes and a different HUMAN stage.";
    else
      $("reviewBulkStatus").textContent="No visible events to change; existing HUMAN marks stay untouched.";
  }
  function applyStageBatch(){
    const stage=$("reviewBulkStage").value,rows=visibleReviewRows().filter(
      event=>selectedStageEvents.has(humanStageKey(event)));
    if(!HUMAN_STAGES.includes(stage)||!rows.length)return;
    const changes=rows.filter(event=>humanStage(event)!==stage);
    if(!changes.length)return;
    if(!window.confirm("Apply HUMAN-only self-report "+stage+" to "+changes.length+
      " changed selected events on this visible page (of "+rows.length+" selected)? Unselected events and other pages"+
      " are untouched. This does NOT verify any finding, remediation, consent or approval."))return;
    const before=new Map(humanReviewStages),dataset=snapshots;
    for(const event of changes){
      const key=humanStageKey(event);
      if(stage==="UNREVIEWED")humanReviewStages.delete(key);
      else humanReviewStages.set(key,stage);
    }
    stageBatchUndo={dataset,before,after:new Map(humanReviewStages)};
    selectedStageEvents.clear();
    renderReviewQueue();renderHumanWorkPlan();
    $("reviewBulkStatus").textContent="Applied "+changes.length+
      " local HUMAN marks. Undo is available until another stage edit or source replacement.";
  }
  function undoStageBatch(){
    if(!stageBatchUndo||stageBatchUndo.dataset!==snapshots||
      !sameStageMap(stageBatchUndo.after,humanReviewStages))return;
    const previous=stageBatchUndo.before;
    stageBatchUndo=null;
    humanReviewStages.clear();
    for(const [key,value] of previous)humanReviewStages.set(key,value);
    renderReviewQueue();renderHumanWorkPlan();
    $("reviewBulkStatus").textContent="Last visible-page batch reverted. Source data and HUMAN notes unchanged.";
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
    syncStageSelectionContext();
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
    updateStageBatchControls();
    if(!rows.length)return;
    const table=document.createElement("table"),head=document.createElement("thead"),tr=document.createElement("tr");
    for(const name of ["Select","Manual slot","Anonymous case","Metric","Review group","Source-reported change",
      "Candidate","Δ","Source status","Human stage · self-report only","Human follow-up"]){
      const th=document.createElement("th");th.scope="col";th.textContent=name;tr.append(th);
    }
    head.append(tr);table.append(head);
    const body=document.createElement("tbody");
    for(const event of rows.slice(reviewOffset,reviewOffset+REVIEW_PAGE)){
      const line=document.createElement("tr");
      const selectCell=document.createElement("td"),checkbox=document.createElement("input");
      checkbox.type="checkbox";
      checkbox.checked=selectedStageEvents.has(humanStageKey(event));
      checkbox.setAttribute("aria-label","Select HUMAN batch event scenario "+
        event.scenarioSlot+" metric "+event.metric+" manual slot "+event.snapshotSlot);
      checkbox.addEventListener("change",()=>{
        const key=humanStageKey(event);
        if(checkbox.checked)selectedStageEvents.add(key);
        else selectedStageEvents.delete(key);
        updateStageBatchControls();
      });
      selectCell.append(checkbox);line.append(selectCell);
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
        selectedStageEvents.clear();
        const key=humanStageKey(event);
        stageBatchUndo=null;
        if(stageSelect.value==="UNREVIEWED")humanReviewStages.delete(key);
        else humanReviewStages.set(key,stageSelect.value);
        renderReviewQueue();renderHumanWorkPlan();
      });
      stageCell.append(stageSelect);line.append(stageCell);
      const action=document.createElement("td"),button=document.createElement("button");
      button.type="button";button.className="secondary";button.textContent="Open commentary";
      button.setAttribute("aria-label","Review scenario "+event.scenarioSlot+" "+event.metric);
      button.addEventListener("click",()=>{
        selectedScenario=event.id;selectedMetric=event.metric;
        $("scenarioSelect").value=selectedScenario;$("noteMetric").value=selectedMetric;
        renderScenarioDetail();renderNotePanel();renderNotePacketControls();$("noteInput").focus();
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


  // HUMAN-only follow-up organizer. It never creates a finding, grant, due date,
  // review approval or security severity; group order is a fixed UI convention.
  let workPlanOffset=0;
  const WORK_PLAN_PAGE=100;
  function humanPlanAction(stage){
    return stage==="NEEDS_INPUT"?
      "Ask a HUMAN reviewer for missing context (not verified evidence).":
      "HUMAN follow-up needed; check the source with an authorized owner.";
  }
  function actionableRows(){
    const rank=group=>group.startsWith("P1")?1:group.startsWith("P2")?2:
      group.startsWith("P3")?3:group.startsWith("P4")?4:5;
    const rankFlag=kind=>kind==="reappeared"?0:kind==="consecutive"?1:
      kind==="first"?2:kind==="initial"?3:4;
    return buildReviewEvents().filter(event=>
      ["NEEDS_INPUT","FOLLOW_UP"].includes(humanStage(event))).sort((a,b)=>{
      const stageRank=e=>humanStage(e)==="NEEDS_INPUT"?0:1;
      return stageRank(a)-stageRank(b)||rank(a.group)-rank(b.group)||
        rankFlag(a.kind)-rankFlag(b.kind)||a.snapshotSlot-b.snapshotSlot||
        a.scenarioSlot-b.scenarioSlot||METRICS.indexOf(a.metric)-METRICS.indexOf(b.metric);
    });
  }
  function openHumanCommentary(event){
    selectedScenario=event.id;selectedMetric=event.metric;
    $("scenarioSelect").value=selectedScenario;$("noteMetric").value=selectedMetric;
    renderScenarioDetail();renderNotePanel();renderNotePacketControls();$("noteInput").focus();
    $("commentary").scrollIntoView({block:"start",behavior:"smooth"});
  }
  function selectedHumanPlanRows(){
    const group=$("workPlanGroup").value,stage=$("workPlanStage").value;
    return actionableRows().filter(e=>(group==="all"||e.group===group)&&
      (stage==="all"||humanStage(e)===stage));
  }
  function renderHumanWorkPlan(){
    const all=snapshots.length?actionableRows():[];
    const actions=snapshots.length?selectedHumanPlanRows():[];
    workPlanOffset=Math.min(workPlanOffset,
      Math.max(0,Math.floor((actions.length-1)/WORK_PLAN_PAGE)*WORK_PLAN_PAGE));
    const awaiting=all.filter(e=>humanStage(e)==="NEEDS_INPUT").length,
      following=all.length-awaiting;
    $("workPlanSummary").textContent=snapshots.length?
      awaiting+" HUMAN NEEDS_INPUT · "+following+" HUMAN FOLLOW_UP · "+
      all.length+" total HUMAN self-reported next actions; "+actions.length+
      " match the selected PRIVATE handoff filters. Fixed grouping is not authenticated severity or chronology.":
      "Import snapshots and mark HUMAN stages to assemble a local follow-up plan.";
    for(const id of ["workPlanExportCsv","workPlanExportJson","workPlanExportBrief"])
      $(id).disabled=actions.length===0;
    $("workPlanPrev").disabled=workPlanOffset===0;
    $("workPlanNext").disabled=workPlanOffset+WORK_PLAN_PAGE>=actions.length;
    $("workPlanRange").textContent=actions.length?
      "Displaying "+(workPlanOffset+1)+"–"+
        Math.min(actions.length,workPlanOffset+WORK_PLAN_PAGE)+
        " of "+actions.length+" local proposed HUMAN actions.":
      "No outstanding self-reported NEEDS_INPUT or FOLLOW_UP stages.";
    const root=$("workPlanTable");root.replaceChildren();
    if(!actions.length)return;
    const table=document.createElement("table"),head=document.createElement("thead"),
      header=document.createElement("tr"),body=document.createElement("tbody");
    for(const label of ["HUMAN stage","Static review grouping","Manual source slot",
      "Anonymous scenario","Fixed metric","Unverified source event","Proposed HUMAN action","Open local note"]){
      const th=document.createElement("th");th.scope="col";th.textContent=label;header.append(th);
    }
    head.append(header);table.append(head);
    for(const event of actions.slice(workPlanOffset,workPlanOffset+WORK_PLAN_PAGE)){
      const row=document.createElement("tr");
      for(const value of [humanStage(event),event.group,event.snapshotSlot,
        "Scenario "+String(event.scenarioSlot).padStart(2,"0"),event.metric,
        REVIEW_KINDS[event.kind],humanPlanAction(humanStage(event))]){
        const td=document.createElement("td");td.textContent=String(value);row.append(td);
      }
      const td=document.createElement("td"),btn=document.createElement("button");
      btn.type="button";btn.className="secondary";btn.textContent="Open";
      btn.setAttribute("aria-label","Open HUMAN note for scenario "+event.scenarioSlot+
        " metric "+event.metric);
      btn.addEventListener("click",()=>openHumanCommentary(event));
      td.append(btn);row.append(td);body.append(row);
    }
    table.append(body);root.append(table);
  }
  function humanPlanPayload(){
    const actions=selectedHumanPlanRows();
    return {schema:"lightup.assessment_trends_private_human_plan.v1",
      status:"PRIVATE_UNSIGNED",private_unsigned:true,fictional_demo_only:fictional,
      manually_selected_order:true,chronology_authenticated:false,
      source_identity_authenticated:false,action_count:actions.length,
      chosen_static_review_group:$("workPlanGroup").value,
      chosen_human_stage:$("workPlanStage").value,
      proposed_human_actions:actions.map(e=>({
        human_self_report_stage:humanStage(e),static_review_group:e.group,
        snapshot_slot:e.snapshotSlot,scenario_slot:e.scenarioSlot,
        metric:e.metric,unverified_source_flag_event:e.kind,
        human_next_step:humanPlanAction(humanStage(e))})),
      disclaimer:"HUMAN-only proposed review workload. Not authenticated severity, source validity, chronology, identity, verified remediation, consent, scan authorization or release. No original identifiers, hashes, filenames or note text.",
      ...Object.fromEntries(FLAGS.map(k=>[k,false]))};
  }
  function exportHumanPlan(format){
    if(!snapshots.length||!selectedHumanPlanRows().length)return;
    if(!window.confirm("Export a PRIVATE UNSIGNED HUMAN follow-up plan? Contains anonymous scenario and metric ordinals, self-reported stages and generic questions, but NO original IDs, source hashes or note text."))return;
    const payload=humanPlanPayload();
    if(format==="json"){
      download("assessment-trends-PRIVATE-human-plan.json",
        JSON.stringify(payload,null,2)+"\n","application/json");
    }else if(format==="csv"){
      const header=["human_self_report_stage","static_review_group",
        "manual_snapshot_slot","anonymous_scenario_slot","metric",
        "unverified_source_flag_event","proposed_human_action","private_unsigned",
        "chronology_authenticated","source_identity_authenticated",...FLAGS];
      const rows=[header,...payload.proposed_human_actions.map(e=>[
        e.human_self_report_stage,e.static_review_group,e.snapshot_slot,
        e.scenario_slot,e.metric,e.unverified_source_flag_event,e.human_next_step,
        true,false,false,false,false,false,false
      ])];
      download("assessment-trends-PRIVATE-human-plan.csv",
        rows.map(row=>row.map(csvField).join(",")).join("\r\n")+"\r\n","text/csv");
    }else if(format==="html"){
      const cols=["HUMAN self-reported stage","Static review group","Manual source slot",
        "Anonymous scenario","Fixed metric","Source-reported event","Generic HUMAN follow-up"];
      const rows=payload.proposed_human_actions.map(e=>[
        e.human_self_report_stage,e.static_review_group,e.snapshot_slot,
        "Scenario "+String(e.scenario_slot).padStart(2,"0"),e.metric,
        REVIEW_KINDS[e.unverified_source_flag_event],e.human_next_step]);
      const table="<table><thead><tr>"+cols.map(label=>
        "<th scope='col'>"+esc(label)+"</th>").join("")+"</tr></thead><tbody>"+
        rows.map(row=>"<tr>"+row.map(value=>"<td>"+esc(value)+"</td>").join("")+"</tr>").join("")+
        "</tbody></table>";
      const n=payload.proposed_human_actions.filter(e=>
        e.human_self_report_stage==="NEEDS_INPUT").length;
      const css="body{margin:2rem auto;padding:0 1rem;max-width:1280px;"+
        "font:15px/1.5 system-ui,sans-serif;color:#182436}"+
        "h1{font-size:1.9rem}.hold{border:2px solid #9a5b18;padding:1rem;background:#fff7ed}"+
        ".wrap{overflow-x:auto}table{width:100%;border-collapse:collapse}"+
        "th,td{border:1px solid #aeb9c7;padding:.4rem;text-align:left}"+
        "thead th{background:#edf2f7}tbody tr:nth-child(even){background:#f8fafc}"+
        "@media print{body{margin:0;max-width:none}.hold{background:white}"+
        "thead{display:table-header-group}tr{break-inside:avoid}}";
      const html="<!doctype html><html lang='en'><head><meta charset='utf-8'>"+
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"+
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"+
        " script-src 'none'; connect-src 'none'; img-src 'none'; object-src 'none';"+
        " frame-src 'none'; form-action 'none'; base-uri 'none'; style-src 'unsafe-inline'\">"+
        "<title>LightUp PRIVATE HUMAN follow-up plan</title><style>"+css+"</style></head><body>"+
        "<h1>LightUp · PRIVATE HUMAN follow-up plan</h1>"+
        "<div class='hold'><strong>PRIVATE / UNSIGNED / REVIEW_ONLY · INCUBATE M3/M7 PLAN/LAB ONLY</strong>"+
        "<p>"+payload.action_count+" self-reported HUMAN actions: "+n+" NEEDS_INPUT, "+
        (payload.action_count-n)+" FOLLOW_UP. Static grouping is not measured severity; "+
        "manually selected snapshots and HUMAN status are not authenticated chronology or proof.</p>"+
        "<p>authorized=false · consent_verified=false · dispatch_allowed=false · release_allowed=false</p></div>"+
        "<p>Questions below are generic HUMAN follow-ups, not conclusions, assessments, permissions or verified remediation. "+
        "A flag no longer present in a later source is not a verified fix.</p>"+
        "<div class='wrap'>"+table+"</div>"+
        "<p>No original source IDs, filenames, hashes, evidence bytes, client identities or saved HUMAN note text are disclosed. "+
        "This PRIVATE file is UNSIGNED and must be reviewed by its original authorized HUMAN owners.</p></body></html>";
      if(new Blob([html]).size>4194304){
        $("workPlanRange").textContent="HOLD: PRIVATE printable plan exceeds 4 MiB; use JSON or CSV.";return;
      }
      download("assessment-trends-PRIVATE-human-followup-plan-REVIEW-ONLY.html",html,"text/html");
    }
    $("workPlanRange").textContent="Downloaded PRIVATE unsigned "+format.toUpperCase()+
      " with "+payload.action_count+" generic HUMAN follow-up actions and no note text.";
  }


  // In-memory PRIVATE saved-note navigation. Never put note text in a listing,
  // printed anonymous report, exported aggregate, browser storage or URL.
  let savedNoteOffset=0;
  const SAVED_NOTE_PAGE=80;
  function sortedSavedNotes(){
    const filter=$("savedNoteGroup").value;
    return [...notes].map(([key,content])=>{
      const [id,metric]=JSON.parse(key);
      return {id,metric,scenarioSlot:slot(id),group:family(metric),
        characterCount:content.length};
    }).filter(row=>row.scenarioSlot>0&&(filter==="all"||row.group===filter))
      .sort((a,b)=>a.scenarioSlot-b.scenarioSlot||
        METRICS.indexOf(a.metric)-METRICS.indexOf(b.metric));
  }
  function renderSavedNoteIndex(){
    const rows=sortedSavedNotes();
    savedNoteOffset=Math.min(savedNoteOffset,
      Math.max(0,Math.floor((rows.length-1)/SAVED_NOTE_PAGE)*SAVED_NOTE_PAGE));
    $("savedNoteCount").textContent=notes.size?
      notes.size+" saved PRIVATE HUMAN note(s) in this tab; "+rows.length+
      " match the selected static group. Note contents are only shown in the selected editor.":
      "No HUMAN notes saved locally. Imported source-bound note packets appear here after confirmed merge.";
    $("savedNotePrev").disabled=savedNoteOffset===0;
    $("savedNoteNext").disabled=savedNoteOffset+SAVED_NOTE_PAGE>=rows.length;
    const root=$("savedNoteTable");root.replaceChildren();
    if(!rows.length)return;
    const table=document.createElement("table"),head=document.createElement("thead"),
      title=document.createElement("tr"),body=document.createElement("tbody");
    for(const label of ["Anonymous scenario","Fixed metric","Static group","Saved characters","View PRIVATE note"]){
      const th=document.createElement("th");th.scope="col";th.textContent=label;title.append(th);
    }
    head.append(title);table.append(head);
    for(const row of rows.slice(savedNoteOffset,savedNoteOffset+SAVED_NOTE_PAGE)){
      const tr=document.createElement("tr");
      for(const val of ["Scenario "+String(row.scenarioSlot).padStart(2,"0"),
        row.metric,row.group,row.characterCount]){
        const td=document.createElement("td");td.textContent=String(val);tr.append(td);
      }
      const td=document.createElement("td"),button=document.createElement("button");
      button.type="button";button.className="secondary";button.textContent="Open";
      button.setAttribute("aria-label","Open locally saved PRIVATE HUMAN note for scenario "+
        row.scenarioSlot+" metric "+row.metric);
      button.addEventListener("click",()=>{
        selectedScenario=row.id;selectedMetric=row.metric;
        $("scenarioSelect").value=selectedScenario;$("noteMetric").value=selectedMetric;
        renderScenarioDetail();renderNotePanel();renderNotePacketControls();
        $("noteInput").focus();$("commentary").scrollIntoView({block:"start",behavior:"smooth"});
      });
      td.append(button);tr.append(td);body.append(tr);
    }
    table.append(body);root.append(table);
  }

  function renderNotePanel(){
    const id=currentId(),metric=$("noteMetric").value||METRICS[0];
    const key=id?noteKey(id,metric):"";
    $("noteInput").disabled=!id;$("saveNote").disabled=!id;$("clearNote").disabled=!id;
    $("exportNotes").disabled=notes.size===0||!fictional;
    $("noteInput").value=key?(scratch.has(key)?scratch.get(key):(notes.get(key)||"")):"";
    $("noteMessage").textContent=id?"Scenario "+String(slot(id)).padStart(2,"0")+" · "+metric+
      ". Notes are local to this tab and are never included in anonymous exports.":"";
    renderSavedNoteIndex();
    renderNoteHistory();
  }

  // Minimum-necessary encrypted HUMAN note handoff; no HUMAN stage or source
  // evidence is included. Imported self-reports are never approvals or findings.
  const PRIVATE_NOTES_SCHEMA="lightup.assessment_trends_source_bound_private_notes.v1";
  const PRIVATE_NOTES_DISCLAIMER="PRIVATE unsigned HUMAN commentary only. Original source byte fingerprints compare identical local inputs but do not authenticate provenance, reviewer identity, finding validity, consent, remediation or release. Notes never authorize an assessment.";
  function notePacketEntries(){
    const onlySelected=$("notePacketScope").value==="current",
      selectedKey=noteKey(currentId(),$("noteMetric").value||METRICS[0]);
    const entries=[...notes].filter(([key])=>!onlySelected||key===selectedKey);
    return entries.map(([key,value])=>{
      const [id,metric]=JSON.parse(key);
      return [slot(id),metric,value];
    }).filter(row=>row[0]>0).sort((a,b)=>
      a[0]-b[0]||METRICS.indexOf(a[1])-METRICS.indexOf(b[1]));
  }
  function renderNotePacketControls(){
    const capable=canResume()&&hasSessionCrypto();
    $("notePacketFile").disabled=!capable;
    $("notePacketImport").disabled=!capable;
    $("notePacketExport").disabled=!capable||notePacketEntries().length===0;
    $("notePacketCount").textContent=capable?
      notePacketEntries().length+" saved HUMAN note(s) selected for a PRIVATE, source-bound encrypted handoff.":
      "Import 3–12 original source snapshots with browser Web Crypto to use encrypted HUMAN note handoffs.";
  }
  async function exportEncryptedNotes(){
    const sourceTicket=sourceAdmissionTicket;
    const password=$("notePacketSecret").value,
      confirmed=$("notePacketConfirm").value;
    try{
      if(!canResume()||!hasSessionCrypto()||password.length<14||password.length>256||password!==confirmed){
        $("notePacketMessage").textContent="HOLD: original source cohort, available browser crypto and matching 14–256-character note passphrase required.";return;
      }
      const entries=notePacketEntries();
      admit(entries.length>=1&&entries.length<=960);
      if(!window.confirm("Create a PRIVATE ENCRYPTED, UNSIGNED note-only handoff? Only explicitly selected saved HUMAN notes, anonymous slot numbers and exact original source byte fingerprints will be inside the AES-GCM ciphertext. No other HUMAN stages, targets, client identity or original findings will be shared."))return;
      const packet={schema:PRIVATE_NOTES_SCHEMA,status:"PRIVATE_UNSIGNED",
        private_unsigned:true,fictional_demo_only:false,manually_selected_order:true,
        chronology_authenticated:false,source_identity_authenticated:false,
        snapshot_sha256_by_manual_slot:[...sourceFingerprints],
        scenario_count:scenarioIds.length,notes:entries,disclaimer:PRIVATE_NOTES_DISCLAIMER,
        ...Object.fromEntries(FLAGS.map(k=>[k,false]))};
      const envelope=await encryptPrivatePayload(JSON.stringify(packet)+"\n",password);
      admit(sourceTicket===sourceAdmissionTicket&&canResume());
      const output=JSON.stringify(envelope,null,2)+"\n";
      admit(new Blob([output]).size<=MAX_ENCRYPTED_BUNDLE);
      download("assessment-trends-PRIVATE-ENCRYPTED-human-notes.json",output,"application/json");
      $("notePacketMessage").textContent="PRIVATE encrypted note-only handoff downloaded. No HUMAN stages or original source identifiers included.";
    }catch(_){
      $("notePacketMessage").textContent="HOLD: note-only encryption could not finish. No plaintext notes were downloaded and current HUMAN work is unchanged.";
    }finally{
      $("notePacketSecret").value="";$("notePacketConfirm").value="";
    }
  }
  async function importEncryptedNotes(){
    const sourceTicket=sourceAdmissionTicket;
    const file=$("notePacketFile").files[0],
      password=$("notePacketUnlock").value;
    try{
      admit(file&&canResume()&&hasSessionCrypto()&&
        file.size>0&&file.size<=MAX_ENCRYPTED_BUNDLE);
      const content=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
      admit(!content.startsWith("\uFEFF"));
      const envelope=strictJSON(content);
      admit(envelope&&envelope.schema===ENVELOPE_SCHEMA);
      const decrypted=await decryptPrivatePayload(envelope,password);
      admit(!decrypted.startsWith("\uFEFF"));
      const data=strictJSON(decrypted);
      admit(exact(data,["schema","status","private_unsigned","fictional_demo_only",
        "manually_selected_order","chronology_authenticated","source_identity_authenticated",
        "snapshot_sha256_by_manual_slot","scenario_count","notes","disclaimer",...FLAGS])&&
        data.schema===PRIVATE_NOTES_SCHEMA&&data.status==="PRIVATE_UNSIGNED"&&
        data.private_unsigned===true&&data.fictional_demo_only===false&&
        data.manually_selected_order===true&&data.chronology_authenticated===false&&
        data.source_identity_authenticated===false&&
        data.disclaimer===PRIVATE_NOTES_DISCLAIMER&&flags(data)&&
        data.scenario_count===scenarioIds.length);
      admit(Array.isArray(data.snapshot_sha256_by_manual_slot)&&
        data.snapshot_sha256_by_manual_slot.length===sourceFingerprints.length&&
        data.snapshot_sha256_by_manual_slot.every((digest,i)=>
          typeof digest==="string"&&digest===sourceFingerprints[i]));
      admit(Array.isArray(data.notes)&&data.notes.length>=1&&data.notes.length<=960);
      const additions=new Map();
      for(const row of data.notes){
        admit(Array.isArray(row)&&row.length===3);
        const [scenarioSlot,metric,note]=row;
        admit(Number.isSafeInteger(scenarioSlot)&&scenarioSlot>=1&&
          scenarioSlot<=scenarioIds.length&&METRICS.includes(metric)&&
          typeof note==="string"&&note.length>=1&&note.length<=500&&note.trim().length>0);
        const key=noteKey(scenarioIds[scenarioSlot-1],metric);
        admit(!additions.has(key));additions.set(key,note);
      }
      admit(sourceTicket===sourceAdmissionTicket&&canResume());
      const replacing=[...additions.keys()].filter(key=>notes.has(key)&&notes.get(key)!==additions.get(key)).length;
      if(!window.confirm("The encrypted PRIVATE note packet matches exact local source bytes and manual order. Merge "+additions.size+" HUMAN note(s) into THIS local review, replacing "+replacing+" existing saved note(s) after explicit confirmation? No HUMAN stages, original source files or other notes are changed. Self-reports are not verified.")){
        $("notePacketMessage").textContent="PRIVATE note merge cancelled. Current HUMAN work remains unchanged.";return;
      }
      for(const [key,note] of additions){
        notes.set(key,note);scratch.delete(key);
      }
      renderNotePanel();renderNotePacketControls();
      resetNoteHistory();
       $("notePacketMessage").textContent="Merged "+additions.size+
        " PRIVATE HUMAN note(s), including "+replacing+" changed saved notes, for the exact original byte-bound cohort. Current stages unchanged.";
    }catch(_){
      $("notePacketMessage").textContent="HOLD: encrypted note packet rejected (password, schema, source bytes/order, size or HUMAN note membership). Current HUMAN notes and stages unchanged.";
    }finally{
      $("notePacketFile").value="";$("notePacketUnlock").value="";
    }
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
    for(const id of ["forget","exportJson","exportCsv","exportScenarioCsv","exportScenarioJson","exportScenarioBrief","exportBrief","print","reviewExportCsv","reviewExportJson","metricDistributionCsv","metricDistributionJson","metricDistributionBrief",
      "metricTrendSummaryCsv","metricTrendSummaryJson","metricTrendSummaryBrief",
      "coverageUnknownCsv","coverageUnknownJson","coverageUnknownBrief",
      "metricTransitionCsv","metricTransitionJson","metricTransitionBrief",
      "metricTransitionCasesCsv","metricTransitionCasesJson","metricTransitionCasesBrief"])$(id).disabled=!active;
    $("scenarioSelect").disabled=!active;$("noteMetric").disabled=!active;
    $("noteMetric").replaceChildren();
    METRICS.forEach(name=>{const option=document.createElement("option");option.value=name;option.textContent=name;$("noteMetric").append(option);});
    $("noteMetric").value=selectedMetric;
    $("scenarioSelect").replaceChildren();
    scenarioIds.forEach((id,i)=>{const option=document.createElement("option");option.value=id;
      option.textContent="Scenario "+String(i+1).padStart(2,"0");$("scenarioSelect").append(option);});
    if(active){selectedScenario=scenarioIds.includes(selectedScenario)?selectedScenario:scenarioIds[0];$("scenarioSelect").value=selectedScenario;
      renderSummary();renderMetricBoard();renderMetricDistribution();renderMetricTrendSummary();
      renderCoverageUnknownTrajectory();renderMetricTransitions();renderScenarioBoard();renderScenarioDetail();
      renderReviewQueue();renderHumanWorkPlan();renderPrintBrief();}
    else{
      $("statusBanner").className="status hold";$("statusBanner").textContent="INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. No sources loaded.";
      $("summaryCards").innerHTML='<p class="empty">Import snapshots to build the trend view.</p>';
      $("summaryText").textContent="";
      ["metricHeatmap","metricDistribution","metricTrendSummary","coverageUnknownTrajectory","metricTransitionTable","metricTransitionCases","scenarioHeatmap","trajectoryTable","reviewTable","reviewSummary","workPlanTable","printBrief"].forEach(id=>$(id).replaceChildren());
      $("metricDistributionSummary").textContent="Import snapshots to summarize numeric metric distributions.";
      $("metricTrendSummaryText").textContent="Import snapshots to summarize median shifts and source-flag prevalence.";
      $("coverageUnknownSummary").textContent="Import snapshots to compare declared unknown coverage separately from regression flags.";
      $("metricTransitionSummary").textContent="Import at least two snapshots to summarize flag-state changes.";
      $("metricTransitionCasesSummary").textContent="Import at least two snapshots to inspect the scenarios behind a flag-state transition.";
      $("metricTransitionMetric").disabled=$("metricTransitionPair").disabled=$("metricTransitionCaseFilter").disabled=true;
      $("metricDistributionCsv").disabled=$("metricDistributionJson").disabled=$("metricDistributionBrief").disabled=true;
      $("metricTrendSummaryCsv").disabled=$("metricTrendSummaryJson").disabled=$("metricTrendSummaryBrief").disabled=true;
      $("coverageUnknownCsv").disabled=$("coverageUnknownJson").disabled=$("coverageUnknownBrief").disabled=true;
      $("metricTransitionCsv").disabled=$("metricTransitionJson").disabled=$("metricTransitionBrief").disabled=true;
      $("metricTransitionCasesCsv").disabled=$("metricTransitionCasesJson").disabled=$("metricTransitionCasesBrief").disabled=true;
      renderHumanWorkPlan();
    }
    if(!active){updateStageBatchControls();$("reviewCount").textContent="Import snapshots to see local source-flag transitions.";
      $("reviewPrev").disabled=true;$("reviewNext").disabled=true;
      for(const id of ["reviewExportStages","reviewExportStageCsv","reviewExportStageBrief"])
        $(id).disabled=true;
      $("reviewHumanSummary").textContent="No local HUMAN stages.";}
    renderNotePanel();renderNotePacketControls();
    renderSessionControls();
    for(const id of ["revisionEarlierFile","revisionLaterFile","revisionCompare","timelineFiles","timelineImport"])
      $(id).disabled=!canResume();
  }

  // The browser's FileList order is not an operator-selected chronology. Keep an
  // explicit local reorderable selection; none of these filenames enter exports.
  let pendingSources=[],sourceAdmissionTicket=0,sourceAdmissionBusy=false;
  function renderPendingSources(){
    const root=$("pendingSourceList");root.replaceChildren();
    const valid=pendingSources.length>=3&&pendingSources.length<=12;
    $("import").disabled=!valid||sourceAdmissionBusy;
    $("pendingSourceStatus").textContent=pendingSources.length?
      pendingSources.length+" local input file(s) in your explicit display order. "+
        (valid?"Use Up/Down to set manual order before admitting.":"Choose between 3 and 12 files.")+
        " Filenames are shown only on this local screen and never exported.":
      "No pending input files. Choose 3–12 source reports.";
    pendingSources.forEach((file,i)=>{
      const item=document.createElement("li"),label=document.createElement("span"),
        controls=document.createElement("span");
      label.textContent="Slot "+String(i+1).padStart(2,"0")+" · "+file.name+
        " · "+file.size.toLocaleString("en-US")+" bytes";
      label.className="pending-file-name";
      for(const [direction,textLabel] of [[-1,"Move up"],[1,"Move down"]]){
        const button=document.createElement("button");
        button.type="button";button.className="secondary";button.textContent=textLabel;
        button.disabled=i+direction<0||i+direction>=pendingSources.length;
        button.setAttribute("aria-label",textLabel+" source slot "+(i+1)+" (not chronology)");
        button.addEventListener("click",()=>{
          ++sourceAdmissionTicket;sourceAdmissionBusy=false;
          [pendingSources[i],pendingSources[i+direction]]=
            [pendingSources[i+direction],pendingSources[i]];
          renderPendingSources();
          $("message").textContent="Pending local display order changed. Import atomically to apply. Current admitted HUMAN work is unchanged.";
        });
        controls.append(button);
      }
      controls.className="controls pending-file-actions";
      item.append(label,controls);root.append(item);
    });
  }
  function setPendingSources(files){
    ++sourceAdmissionTicket;sourceAdmissionBusy=false;
    pendingSources=[...files];renderPendingSources();
    $("message").textContent=pendingSources.length?
      "Pending batch ready for explicit manual slot ordering; current admitted sources and HUMAN work remain unchanged.":
      "No pending sources selected. Current admitted workspace remains unchanged.";
  }

  function confirmWorkspaceReplacement(action,force){
    const staged=[...scratch].filter(([key,value])=>
      typeof value==="string"&&value.trim()&&notes.get(key)!==value).length;
    const marked=humanReviewStages.size,saved=notes.size;
    if(!force&&!marked&&!saved&&!staged)return true;
    return window.confirm("PRIVATE HUMAN work replacement: "+action+"?\n\n"+
      marked+" local HUMAN stage mark(s), "+saved+" saved HUMAN note(s) and "+
      staged+" unsaved note draft(s) would be forgotten.\n"+
      "This operation cannot be undone. Download an encrypted PRIVATE session first "+
      "if you need continuity. No assessment, consent or approval is implied.");
  }
  async function importFiles(list){
    const files=[...list],ticket=++sourceAdmissionTicket;
    sourceAdmissionBusy=true;renderPendingSources();
    $("message").textContent="Reading local source files. No network or assessment execution.";
    try{
      admit(files.length>=3&&files.length<=12);
      const next=[],nextFingerprints=[];
      for(const file of files){
        admit(file&&file.size>0&&file.size<=MAX_FILE);
        const bytes=await file.arrayBuffer();
        if(ticket!==sourceAdmissionTicket)return;
        admit(bytes.byteLength>0&&bytes.byteLength<=MAX_FILE);
        const raw=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
        admit(!raw.startsWith("\uFEFF"));
        next.push(parseReport(strictJSON(raw)));
        nextFingerprints.push(await sourceDigest(bytes));
        if(ticket!==sourceAdmissionTicket)return;
      }
      const ids=harmonize(next);
      if(ticket!==sourceAdmissionTicket)return;
      if(!confirmWorkspaceReplacement("replace the current original source cohort",false)){
        $("message").textContent="Replacement cancelled. Current HUMAN work and source snapshots remain intact.";
        return;
      }
      if(ticket!==sourceAdmissionTicket)return;
      snapshots=next;scenarioIds=ids;selectedScenario=ids[0];selectedMetric=METRICS[0];
      sourceFingerprints=nextFingerprints.every(v=>v!==null)?nextFingerprints:[];
      $("privateSessionFile").value="";
      reviewOffset=0;workPlanOffset=0;
      $("workPlanGroup").value="all";$("workPlanStage").value="all";
      humanReviewStages.clear();resetReviewFilters();
      notes.clear();scratch.clear();fictional=false;resetNoteHistory();
      savedNoteOffset=0;$("savedNoteGroup").value="all";
      resetRevisionComparison();resetHumanTimeline();
      render();$("sessionMessage").textContent="New snapshot batch admitted; previous HUMAN session cannot be carried across datasets.";
      $("message").textContent="Accepted "+snapshots.length+
        " compatible source snapshots with "+scenarioIds.length+
        " matching anonymous scenarios and identical original baselines. No chronology authenticated.";
    }catch(_){
      if(ticket===sourceAdmissionTicket)
        $("message").textContent="HOLD: invalid, duplicated, oversized, mismatched or baseline-inconsistent batch. Previous workspace unchanged.";
    }finally{
      if(ticket===sourceAdmissionTicket){sourceAdmissionBusy=false;renderPendingSources();}
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
    if(!confirmWorkspaceReplacement("load fictional demo sources",false))return;
    ++sourceAdmissionTicket;sourceAdmissionBusy=false;
    snapshots=[buildDemoReport(1),buildDemoReport(2),buildDemoReport(3)];
    scenarioIds=[...snapshots[0].cases.keys()].sort();selectedScenario=scenarioIds[0];
    selectedMetric=METRICS[0];notes.clear();scratch.clear();resetNoteHistory();fictional=true;
    savedNoteOffset=0;$("savedNoteGroup").value="all";
    sourceFingerprints=[];$("privateSessionFile").value="";
    reviewOffset=0;workPlanOffset=0;scenarioOffset=0;
    $("scenarioViewFilter").value="all";$("scenarioSearch").value="";
    $("workPlanGroup").value="all";$("workPlanStage").value="all";
    humanReviewStages.clear();resetReviewFilters();resetRevisionComparison();resetHumanTimeline();render();renderPendingSources();
    $("message").textContent="FICTIONAL DEMO ONLY: invented data in memory; no source measurements or permissions.";
  }
  function forget(){
    if(!confirmWorkspaceReplacement("forget all local sources and work",true))return;
    ++sourceAdmissionTicket;sourceAdmissionBusy=false;
    pendingSources=[];$("files").value="";
    snapshots=[];scenarioIds=[];selectedScenario="";notes.clear();scratch.clear();fictional=false;resetNoteHistory();
    savedNoteOffset=0;$("savedNoteGroup").value="all";
    sourceFingerprints=[];$("privateSessionFile").value="";
    reviewOffset=0;workPlanOffset=0;scenarioOffset=0;
    $("scenarioViewFilter").value="all";$("scenarioSearch").value="";
    $("workPlanGroup").value="all";$("workPlanStage").value="all";
    humanReviewStages.clear();resetReviewFilters();resetRevisionComparison();resetHumanTimeline();
    $("files").value="";$("message").textContent="All imported source data and local commentary forgotten from this workspace.";
    $("sessionMessage").textContent="PRIVATE session and all local source digests forgotten.";render();renderPendingSources();
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
        ever_flagged_cases:st.ever,persistent_cases:st.persistent,longest_consecutive_slots:st.maxStreak,
        cases_with_reappearing_flags:st.reappeared,reappearance_events:st.reappearanceEvents};}),
      scenario_trajectories:scenarioIds.map((id,i)=>{const st=scenarioStats(id);return {
        scenario_slot:i+1,source_reported_regressed_metric_count_by_snapshot:st.counts,
        persistent_metric_count:st.persistent,first_flagged_manual_slot:st.firstFlaggedSlot,
        last_flagged_manual_slot:st.lastFlaggedSlot,reappearing_metric_count:st.reappearedMetrics,
        reappearance_event_count:st.reappearanceEvents,longest_metric_flag_streak:st.longestMetricStreak,
        overall_source_status:st.status};}),
      disclaimer:"Already-completed untrusted source comparisons only. Snapshot order is a human display preference, not authenticated chronology. No remediation, ground truth, consent, authorization, dispatch or release is established.",
      ...Object.fromEntries(FLAGS.map(k=>[k,false]))};
    download("assessment-trends-anonymous-aggregate.json",JSON.stringify(out,null,2)+"\n","application/json");
    $("message").textContent="Anonymous aggregate JSON downloaded. No source IDs, filenames, hashes or commentary.";
  }
  function exportCsv(){
    if(!snapshots.length)return;
    const header=["snapshot_slot","scenario_slot","metric","review_priority_group","baseline","candidate",
      "delta","source_reported_regression","metric_reappearance_events","metric_longest_consecutive_flag_slots",
      "source_snapshot_status","fictional_demo_only","source_identity_authenticated","chronology_authenticated",
      "authorized","consent_verified","dispatch_allowed","release_allowed","status"];
    const rows=[header];
    snapshots.forEach((report,i)=>scenarioIds.forEach((id,j)=>METRICS.forEach(name=>{
      const m=report.cases.get(id).metrics.get(name);
      const flagsBySlot=snapshots.map(item=>item.cases.get(id).metrics.get(name).regression);
      rows.push([i+1,j+1,name,family(name),m.baseline,m.candidate,m.delta,m.regression,
        reappearanceCount(flagsBySlot),streak(flagsBySlot),report.status,fictional?"true":"false",
        "false","false","false","false","false","false","REVIEW_ONLY"]);
    })));
    download("assessment-trends-anonymous-trajectories.csv",
      rows.map(row=>row.map(csvField).join(",")).join("\r\n")+"\r\n","text/csv");
    $("message").textContent="Anonymous trajectory CSV downloaded. Only ordinals, metric names and source-reported numbers/flags.";
  }

  // Minimum-necessary local handoff for one selected anonymous scenario.
  // It intentionally excludes original IDs, source bytes, filenames and HUMAN notes.
  function selectedScenarioRows(){
    const id=currentId();
    if(!id||!snapshots.length)return [];
    const scenarioSlot=scenarioIds.indexOf(id)+1;
    if(scenarioSlot<1)return [];
    const history=scenarioStats(id);
    return snapshots.flatMap((report,i)=>METRICS.map(metric=>{
      const m=report.cases.get(id).metrics.get(metric);
      const flagsBySlot=snapshots.map(item=>item.cases.get(id).metrics.get(metric).regression);
      return {
        snapshot_slot:i+1,scenario_slot:scenarioSlot,metric,review_priority_group:family(metric),
        baseline:m.baseline,candidate:m.candidate,delta:m.delta,
        source_reported_regression:m.regression,
        metric_reappearance_events:reappearanceCount(flagsBySlot),
        metric_longest_consecutive_flag_slots:streak(flagsBySlot),
        scenario_first_flagged_manual_slot:history.firstFlaggedSlot??"",
        scenario_last_flagged_manual_slot:history.lastFlaggedSlot??"",
        scenario_persistent_metric_count:history.persistent,
        scenario_reappearing_metric_count:history.reappearedMetrics,
        scenario_reappearance_event_count:history.reappearanceEvents,
        scenario_longest_metric_flag_streak:history.longestMetricStreak,
        source_snapshot_status:report.status,fictional_demo_only:fictional,
        source_identity_authenticated:false,chronology_authenticated:false,
        authorized:false,consent_verified:false,dispatch_allowed:false,release_allowed:false,status:"REVIEW_ONLY"
      };
    }));
  }
  function exportScenarioCsv(){
    const rows=selectedScenarioRows();if(!rows.length)return;
    const header=["snapshot_slot","scenario_slot","metric","review_priority_group","baseline","candidate",
      "delta","source_reported_regression","metric_reappearance_events","metric_longest_consecutive_flag_slots",
      "scenario_first_flagged_manual_slot","scenario_last_flagged_manual_slot",
      "scenario_persistent_metric_count","scenario_reappearing_metric_count",
      "scenario_reappearance_event_count","scenario_longest_metric_flag_streak",
      "source_snapshot_status","fictional_demo_only","source_identity_authenticated","chronology_authenticated",
      "authorized","consent_verified","dispatch_allowed","release_allowed","status"];
    download("assessment-trends-scenario-"+String(rows[0].scenario_slot).padStart(2,"0")+"-trajectory.csv",
      [header,...rows.map(row=>header.map(key=>row[key]))]
        .map(row=>row.map(csvField).join(",")).join("\r\n")+"\r\n","text/csv");
    $("message").textContent="Selected anonymous scenario CSV downloaded. It contains only this scenario's source-reported metric trajectory; no original IDs, filenames, hashes or HUMAN notes.";
  }
  function exportScenarioJson(){
    const rows=selectedScenarioRows();if(!rows.length)return;
    const scenarioSlot=rows[0].scenario_slot;
    const out={
      schema:"lightup.assessment_trends_selected_scenario_trajectory.v1",
      status:"REVIEW_ONLY",scenario_slot:scenarioSlot,
      snapshot_count:snapshots.length,manually_selected_order:true,
      chronology_authenticated:false,source_identity_authenticated:false,
      fictional_demo_only:fictional,authorized:false,consent_verified:false,
      dispatch_allowed:false,release_allowed:false,
      trajectory_summary:(()=>{const h=scenarioStats(currentId());return {
        first_flagged_manual_slot:h.firstFlaggedSlot,last_flagged_manual_slot:h.lastFlaggedSlot,
        persistent_metric_count:h.persistent,reappearing_metric_count:h.reappearedMetrics,
        reappearance_event_count:h.reappearanceEvents,longest_metric_flag_streak:h.longestMetricStreak
      };})(),
      trajectories:METRICS.map(metric=>{
        const subset=rows.filter(row=>row.metric===metric);
        return {metric,review_priority_group:family(metric),baseline:subset[0].baseline,
          reappearance_event_count:subset[0].metric_reappearance_events,
          longest_consecutive_flag_slots:subset[0].metric_longest_consecutive_flag_slots,
          slots:subset.map(row=>({snapshot_slot:row.snapshot_slot,candidate:row.candidate,delta:row.delta,
            source_reported_regression:row.source_reported_regression,source_snapshot_status:row.source_snapshot_status}))};
      }),
      disclaimer:"One selected anonymous scenario from already-completed untrusted comparison reports. Slot order is manually selected, not authenticated chronology. Source flags are not verified findings or remediation. This export does not grant authorization or release approval."
    };
    download("assessment-trends-scenario-"+String(scenarioSlot).padStart(2,"0")+"-trajectory.json",
      JSON.stringify(out,null,2)+"\n","application/json");
    $("message").textContent="Selected anonymous scenario JSON downloaded. Original IDs, filenames, hashes and HUMAN notes are excluded; status remains REVIEW_ONLY.";
  }


  function exportScenarioBrief(){
    const rows=selectedScenarioRows();if(!rows.length)return;
    const scenarioSlot=rows[0].scenario_slot;
    const headers=["Metric","Review-priority group","Original baseline",
      ...snapshots.map((_,i)=>"Slot "+String(i+1).padStart(2,"0")+" · candidate / Δ / source flag")];
    const bodyRows=METRICS.map(metric=>{
      const subset=rows.filter(row=>row.metric===metric);
      return [metric,family(metric),fmt(subset[0].baseline),
        ...subset.map(row=>fmt(row.candidate)+" / "+fmt(row.delta)+" / "+
          (row.source_reported_regression?"HOLD":"—"))];
    });
    const table="<table><thead><tr>"+headers.map(v=>"<th>"+esc(v)+"</th>").join("")+
      "</tr></thead><tbody>"+bodyRows.map(row=>"<tr>"+row.map(v=>"<td>"+esc(v)+"</td>").join("")+
      "</tr>").join("")+"</tbody></table>";
    const history=scenarioStats(currentId());
    const historyRows=[
      ["First flagged manual slot",history.firstFlaggedSlot??"None"],
      ["Last flagged manual slot",history.lastFlaggedSlot??"None"],
      ["Persistent metrics",history.persistent],
      ["Metrics with reappearing flags",history.reappearedMetrics],
      ["Reappearance events",history.reappearanceEvents],
      ["Longest consecutive metric flag streak",history.longestMetricStreak]
    ];
    const historyTable="<table><thead><tr><th>Selected-scenario flag history</th><th>Source-reported count / slot</th></tr></thead><tbody>"+
      historyRows.map(row=>"<tr>"+row.map(value=>"<td>"+esc(value)+"</td>").join("")+"</tr>").join("")+"</tbody></table>";
    const cssText="body{font:15px/1.5 system-ui,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem;color:#17212f}"+
      "h1{font-size:1.8rem}.hold{border:2px solid #9a5b18;padding:.8rem;background:#fff7ed}"+
      "table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #aab6c5;padding:.4rem;text-align:left}"+
      "th{background:#eef2f6}td{white-space:nowrap}.note{font-size:.9rem;color:#475569}"+
      "@media print{body{margin:0;max-width:none}table{font-size:9pt}th,td{white-space:normal;padding:.25rem}}";
    const doc="<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"+
      "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"+
      "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; style-src 'unsafe-inline'\">"+
      "<title>LightUp · Anonymous scenario trajectory</title><style>"+cssText+"</style></head><body>"+
      "<p class=\"eyebrow\">LIGHTUP / ASSESSMENT RUNTIME</p><h1>Anonymous scenario trajectory</h1>"+
      "<p class=\"hold\"><strong>REVIEW_ONLY · INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD</strong></p>"+
      "<p>Selected anonymous scenario: "+esc(String(scenarioSlot).padStart(2,"0"))+
      " · Snapshot slots: "+esc(String(snapshots.length))+".</p>"+historyTable+table+
      "<p class=\"note\">Slot order is manually selected, not authenticated chronology. Values and regression flags are source-reported from already-completed, untrusted comparison documents. A missing flag is not a verified fix. This brief contains no original scenario IDs, filenames, source hashes or HUMAN notes and grants no authorization, consent, dispatch or release approval.</p>"+
      "</body></html>";
    download("assessment-trends-scenario-"+String(scenarioSlot).padStart(2,"0")+"-brief.html",doc,"text/html");
    $("message").textContent="Script-free printable HTML brief downloaded for the selected anonymous scenario. It contains no original IDs, filenames, hashes or HUMAN notes.";
  }

  function esc(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");}
  function exportBrief(){
    if(!snapshots.length)return;
    const s=summary();
    const css="body{font:15px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#182336}"+
      "table{border-collapse:collapse;width:100%;margin:1rem 0 2rem}th,td{border:1px solid #aab6c5;padding:.4rem;text-align:left}"+
      "th{background:#eef2f6}.hold{border:2px solid #9a5b18;padding:1rem}";
    const rows=METRICS.map(name=>{const st=metricStats(name);return [name,family(name),...st.counts,
      st.ever,st.persistent,st.maxStreak,st.reappeared,st.reappearanceEvents];});
    const headers=["Metric","Review-priority group",...snapshots.map((_,i)=>"Slot "+String(i+1).padStart(2,"0")),
      "Ever flagged cases","Persistent cases","Longest run","Cases with reappearing flags","Reappearance events"];
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
      " anonymous scenarios · "+s.instances+" source-reported regression instances · "+
      s.reappearedPairs+" scenario/metric pairs with reappearing flags ("+s.reappearanceEvents+
      " reappearance events). Order is not authenticated chronology.</p>"+
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
    if(!notes.size||!snapshots.length||!fictional)return;
    if(!window.confirm("FICTIONAL DEMO ONLY: export saved invented commentary to a separate PRIVATE file? It contains your notes, but no original IDs, filenames or hashes."))return;
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
      stageBatchUndo=null;selectedStageEvents.clear();
      humanReviewStages.clear();for(const [key,value] of newStages)humanReviewStages.set(key,value);
      notes.clear();for(const [key,value] of newNotes)notes.set(key,value);
      scratch.clear();resetNoteHistory();reviewOffset=0;render();
      $("sessionMessage").textContent="PRIVATE HUMAN session restored for identical local source bytes and manual order: "+
        newStages.size+" stages, "+newNotes.size+" saved notes. UNSIGNED and non-authorizing.";
    }catch(_){
      $("sessionMessage").textContent="HOLD: PRIVATE recovery rejected (invalid, tampered, duplicate, oversized, or not bound to the exact currently admitted original files/order). Existing HUMAN stages and notes untouched.";
    }finally{
      $("privateSessionFile").value="";
      $("sessionUnlockPassphrase").value="";
    }
  }



  // Local, source-bound migration/rotation. Never writes to original source or
  // replaces current HUMAN work; the operator must handle legacy plaintext files.
  async function rotatePrivateSession(){
    const file=$("rotateSourceFile").files[0],
      oldSecret=$("rotateOldSecret").value,
      newSecret=$("rotateNewSecret").value,
      confirmSecret=$("rotateConfirmSecret").value;
    const sourceTicket=sourceAdmissionTicket;
    try{
      if(!file||!canResume()||!hasSessionCrypto()){
        $("rotateMessage").textContent="HOLD: admit the original source cohort and choose a legacy or encrypted PRIVATE review session.";return;
      }
      if(newSecret.length<14||newSecret.length>256||newSecret!==confirmSecret){
        $("rotateMessage").textContent="HOLD: new encryption passphrase and confirmation must match (14–256 characters).";return;
      }
      // Full existing strict source-byte/event/HUMAN admission before any export.
      const {newStages,newNotes}=await admitPrivateSessionFile(file,oldSecret);
      admit(sourceTicket===sourceAdmissionTicket&&canResume());
      const stages=buildReviewEvents().filter(e=>
        newStages.has(humanStageKey(e))).map(e=>[
          e.snapshotSlot,e.scenarioSlot,e.metric,newStages.get(humanStageKey(e))]);
      admit(stages.length===newStages.size);
      const savedNotes=[...newNotes].map(([key,note])=>{
        const [id,metric]=JSON.parse(key);
        return [slot(id),metric,note];
      }).sort((a,b)=>a[0]-b[0]||METRICS.indexOf(a[1])-METRICS.indexOf(b[1]));
      admit(savedNotes.length===newNotes.size&&savedNotes.every(row=>row[0]>0));
      const next={...privateSessionData(),stages,notes:savedNotes};
      const cleartext=JSON.stringify(next)+"\n";
      admit(new Blob([cleartext]).size<=MAX_PRIVATE_BUNDLE);
      if(!window.confirm("Create a NEW passphrase-encrypted PRIVATE recovery file from this exact-source HUMAN session? Original input and current HUMAN work are never modified. Old plaintext/encrypted copies remain on your device and must be handled separately. No source authenticity or consent is proven.")){
        $("rotateMessage").textContent="Rotation cancelled; nothing changed.";return;
      }
      const envelope=await encryptPrivatePayload(cleartext,newSecret);
      admit(sourceTicket===sourceAdmissionTicket);
      const output=JSON.stringify(envelope,null,2)+"\n";
      admit(new Blob([output]).size<=MAX_ENCRYPTED_BUNDLE);
      download("assessment-trends-PRIVATE-ENCRYPTED-rotated-session.json",output,"application/json");
      $("rotateMessage").textContent="New encrypted PRIVATE session downloaded using fresh random salt and IV. Original file and current HUMAN work remain unchanged. Preserve the new passphrase; handle any old plaintext copies separately.";
    }catch(_){
      $("rotateMessage").textContent="HOLD: original file/password, exact source bytes, HUMAN membership or encryption did not match. No new file published; current HUMAN work unchanged.";
    }finally{
      $("rotateSourceFile").value="";
      $("rotateOldSecret").value="";$("rotateNewSecret").value="";
      $("rotateConfirmSecret").value="";
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
  $("metricDistributionGroup").addEventListener("change",()=>{
    renderMetricDistribution();renderMetricTrendSummary();renderMetricTransitions();
  });
  $("metricDistributionFlagFilter").addEventListener("change",renderMetricDistribution);
  $("metricTrendFlagFilter").addEventListener("change",renderMetricTrendSummary);
  $("metricTrendSort").addEventListener("change",renderMetricTrendSummary);
  $("metricTransitionFilter").addEventListener("change",renderMetricTransitions);
  $("metricTransitionScope").addEventListener("change",renderMetricTransitions);
  for(const id of ["metricTransitionMetric","metricTransitionPair","metricTransitionCaseFilter"])
    $(id).addEventListener("change",renderMetricTransitionCases);
  $("metricTransitionCasesCsv").addEventListener("click",()=>exportTransitionCases("csv"));
  $("metricTransitionCasesJson").addEventListener("click",()=>exportTransitionCases("json"));
  $("metricTransitionCasesBrief").addEventListener("click",()=>exportTransitionCases("html"));
  $("metricTransitionCsv").addEventListener("click",()=>exportMetricTransitions("csv"));
  $("metricTransitionJson").addEventListener("click",()=>exportMetricTransitions("json"));
  $("metricTransitionBrief").addEventListener("click",()=>exportMetricTransitions("html"));
  $("metricTrendSummaryCsv").addEventListener("click",()=>exportMetricTrendSummary("csv"));
  $("metricTrendSummaryJson").addEventListener("click",()=>exportMetricTrendSummary("json"));
  $("metricTrendSummaryBrief").addEventListener("click",()=>exportMetricTrendSummary("html"));
  $("coverageUnknownCsv").addEventListener("click",()=>exportCoverageUnknownTrajectory("csv"));
  $("coverageUnknownJson").addEventListener("click",()=>exportCoverageUnknownTrajectory("json"));
  $("coverageUnknownBrief").addEventListener("click",()=>exportCoverageUnknownTrajectory("html"));
  $("metricDistributionCsv").addEventListener("click",()=>exportMetricDistribution("csv"));
  $("metricDistributionJson").addEventListener("click",()=>exportMetricDistribution("json"));
  $("metricDistributionBrief").addEventListener("click",()=>exportMetricDistribution("html"));
  for(const filter of ["reviewKind","reviewGroup","reviewSlot","reviewStage"]){
    $(filter).addEventListener("change",()=>{reviewOffset=0;renderReviewQueue();});
  }
  $("reviewPrev").addEventListener("click",()=>{reviewOffset=Math.max(0,reviewOffset-REVIEW_PAGE);renderReviewQueue();});
  $("reviewNext").addEventListener("click",()=>{reviewOffset+=REVIEW_PAGE;renderReviewQueue();});
  $("reviewExportCsv").addEventListener("click",()=>exportReviewQueue("csv"));
  $("reviewExportJson").addEventListener("click",()=>exportReviewQueue("json"));
  const planGroup=$("workPlanGroup");planGroup.replaceChildren();
  for(const name of ["all",...new Set(METRICS.map(family))]){
    const option=document.createElement("option");
    option.value=name;option.textContent=name==="all"?"All static review groups":name;
    planGroup.append(option);
  }
  for(const id of ["workPlanGroup","workPlanStage"]){
    $(id).addEventListener("change",()=>{workPlanOffset=0;renderHumanWorkPlan();});
  }
  $("workPlanPrev").addEventListener("click",()=>{
    workPlanOffset=Math.max(0,workPlanOffset-WORK_PLAN_PAGE);renderHumanWorkPlan();
  });
  $("workPlanNext").addEventListener("click",()=>{
    workPlanOffset+=WORK_PLAN_PAGE;renderHumanWorkPlan();
  });
  $("workPlanExportJson").addEventListener("click",()=>exportHumanPlan("json"));
  $("workPlanExportCsv").addEventListener("click",()=>exportHumanPlan("csv"));
  $("workPlanExportBrief").addEventListener("click",()=>exportHumanPlan("html"));
  $("reviewExportStages").addEventListener("click",()=>exportHumanStages("json"));
  $("reviewExportStageCsv").addEventListener("click",()=>exportHumanStages("csv"));
  $("reviewExportStageBrief").addEventListener("click",()=>exportHumanStages("html"));
  $("reviewBulkSelectAll").addEventListener("change",()=>{
    const rows=visibleReviewRows();
    for(const event of rows){
      const key=humanStageKey(event);
      if($("reviewBulkSelectAll").checked)selectedStageEvents.add(key);
      else selectedStageEvents.delete(key);
    }
    renderReviewQueue();
  });
  $("reviewBulkStage").addEventListener("change",updateStageBatchControls);
  $("reviewBulkApply").addEventListener("click",applyStageBatch);
  $("reviewBulkUndo").addEventListener("click",undoStageBatch);
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
  $("rotateSubmit").addEventListener("click",()=>{void rotatePrivateSession();});
  $("importPrivateSession").addEventListener("click",()=>{void restorePrivateSession();});
  $("files").addEventListener("change",()=>setPendingSources($("files").files));
  $("import").addEventListener("click",()=>{
    if(pendingSources.length>=3&&pendingSources.length<=12&&!sourceAdmissionBusy)
      void importFiles(pendingSources);
    else $("message").textContent="Choose and order 3–12 original cohort JSON files before import.";
  });
  $("scenarioViewFilter").addEventListener("change",()=>{scenarioOffset=0;renderScenarioBoard();});
  $("scenarioSearch").addEventListener("input",()=>{scenarioOffset=0;renderScenarioBoard();});
  $("scenarioPrev").addEventListener("click",()=>{scenarioOffset=Math.max(0,scenarioOffset-SCENARIO_PAGE);renderScenarioBoard();});
  $("scenarioNext").addEventListener("click",()=>{scenarioOffset+=SCENARIO_PAGE;renderScenarioBoard();});
  $("scenarioSelect").addEventListener("change",()=>{
    selectedScenario=$("scenarioSelect").value;renderScenarioDetail();renderNotePanel();
    renderNotePacketControls();
  });
  $("noteMetric").addEventListener("change",()=>{
    selectedMetric=$("noteMetric").value;renderNotePanel();renderNotePacketControls();
  });
  $("noteInput").addEventListener("input",()=>{const id=currentId();if(id)scratch.set(noteKey(id,$("noteMetric").value),$("noteInput").value);});
  $("saveNote").addEventListener("click",()=>{
    const id=currentId();if(!id)return;
    const key=noteKey(id,$("noteMetric").value);
    const value=scratch.has(key)?scratch.get(key):(notes.get(key)||"");
    if(value.length>500){$("noteMessage").textContent="HOLD: commentary exceeds 500 characters.";return;}
    const next=value.trim()?value:null;
    if((notes.get(key)??null)!==next||scratch.has(key))rememberNoteEdit();
    if(next===null)notes.delete(key);else notes.set(key,next);
    scratch.delete(key);
    renderNotePanel();renderNotePacketControls();
    $("noteMessage").textContent="Commentary saved in tab memory only. Not included in anonymous exports.";
  });
  $("clearNote").addEventListener("click",()=>{
    const id=currentId();if(!id)return;
    const key=noteKey(id,$("noteMetric").value);
    if(notes.has(key)||scratch.has(key))rememberNoteEdit();
    notes.delete(key);scratch.delete(key);renderNotePanel();renderNotePacketControls();
    $("noteMessage").textContent="Selected commentary cleared from this tab.";
  });
  $("clearAllNotes").addEventListener("click",()=>{
    if(!snapshots.length||(!notes.size&&!scratch.size))return;
    if(!window.confirm("Clear "+notes.size+" saved HUMAN note(s) and "+scratch.size+
      " draft(s) for this local cohort? This can be undone while this source cohort remains open. "+
      "Use Forget to erase the whole source cohort and history."))return;
    rememberNoteEdit();
    notes.clear();scratch.clear();renderNotePanel();renderNotePacketControls();
    $("noteMessage").textContent="HUMAN notes and drafts cleared; Undo can restore them until history is cleared or tab closes.";
  });
  $("undoNote").addEventListener("click",()=>changeNoteHistory(noteUndoHistory,noteRedoHistory,"Undo"));
  $("redoNote").addEventListener("click",()=>changeNoteHistory(noteRedoHistory,noteUndoHistory,"Redo"));
  document.addEventListener("keydown",event=>{
    if(!(event.ctrlKey||event.metaKey)||event.altKey)return;
    const target=event.target;
    if(target&&(/^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName)||target.isContentEditable))return;
    const key=event.key.toLowerCase();
    if(key==="z"){event.preventDefault();
      if(event.shiftKey)changeNoteHistory(noteRedoHistory,noteUndoHistory,"Redo");
      else changeNoteHistory(noteUndoHistory,noteRedoHistory,"Undo");}
    else if(key==="y"){event.preventDefault();changeNoteHistory(noteRedoHistory,noteUndoHistory,"Redo");}
  });
  const noteIndexGroup=$("savedNoteGroup");noteIndexGroup.replaceChildren();
  for(const group of ["all",...new Set(METRICS.map(family))]){
    const option=document.createElement("option");option.value=group;
    option.textContent=group==="all"?"All saved HUMAN note groups":group;
    noteIndexGroup.append(option);
  }
  $("savedNoteGroup").addEventListener("change",()=>{
    savedNoteOffset=0;renderSavedNoteIndex();
  });
  $("savedNotePrev").addEventListener("click",()=>{
    savedNoteOffset=Math.max(0,savedNoteOffset-SAVED_NOTE_PAGE);renderSavedNoteIndex();
  });
  $("savedNoteNext").addEventListener("click",()=>{
    savedNoteOffset+=SAVED_NOTE_PAGE;renderSavedNoteIndex();
  });
  $("notePacketScope").addEventListener("change",renderNotePacketControls);
  $("notePacketExport").addEventListener("click",()=>{void exportEncryptedNotes();});
  $("notePacketImport").addEventListener("click",()=>{void importEncryptedNotes();});
  $("exportNotes").addEventListener("click",exportPrivateNotes);
  $("exportJson").addEventListener("click",exportJson);
  $("exportCsv").addEventListener("click",exportCsv);
  $("exportScenarioCsv").addEventListener("click",exportScenarioCsv);
  $("exportScenarioJson").addEventListener("click",exportScenarioJson);
  $("exportScenarioBrief").addEventListener("click",exportScenarioBrief);
  $("exportBrief").addEventListener("click",exportBrief);
  $("print").addEventListener("click",()=>{if(snapshots.length)window.print();});
  $("forget").addEventListener("click",()=>{if(window.confirm("Forget all admitted source data and local commentary from this tab?"))forget();});
  $("demo").addEventListener("click",()=>{if(snapshots.length&&!window.confirm("Replace current sources with fictional demo data?"))return;demoLoad();});
  $("noteMetric").replaceChildren();
  METRICS.forEach(name=>{const o=document.createElement("option");o.value=name;o.textContent=name;$("noteMetric").append(o);});
  renderPendingSources();
  render();
})();
