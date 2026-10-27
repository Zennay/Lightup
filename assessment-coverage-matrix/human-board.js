"use strict";
/* PRIVATE local HUMAN routing, never assessment authority or remediation evidence.
   Consumes only previously admitted original source data from the parent offline app. */
function createHumanBoard(api) {
  const { $, node, clear, fail, shape, obj, int, text, parseStrict,
    download, message, onFocus, getRows, getDigests, FLAGS } = api;
  const STAGES = ["needs_review","queued","discussing","documented","blocked"];
  const ROUTES = ["unassigned","scope","findings","evidence","remediation","privacy"];
  const ACTIONS = ["none","clarify_source","review_scope_policy",
    "request_evidence_review","discuss_declared_difference",
    "prepare_private_human_brief","request_independent_human_review"];
  const DEFAULT = Object.freeze({stage:"needs_review",route:"unassigned",action:"none"});
  const KINDS = ["stage","route","action"];
  const MAX_PRIVATE_BYTES = 3 * 1024 * 1024;
  const MAX_ENCRYPTED_BYTES = 5 * 1024 * 1024;
  const privatePlanCrypto=createPrivatePlanCrypto();
  const PLAN_KEYS = ["ordinal","stage","route","action"];
  const FILE_KEYS = ["kind","version","disposition","authorized","consent_verified",
    "dispatch_allowed","release_allowed","source_sha256","ordered_row_count",
    "row_plans","interpretation"];
  let plans = [], page = 0, changed = false, lastBulk = null;
  let history = null, historyPage = 0, historyResolutions = new Map();
  const fresh = () => ({...DEFAULT});
  const isDefault = p => KINDS.every(k=>p[k]===DEFAULT[k]);
  const strictDigest = s => typeof s==="string"&&/^[0-9a-f]{64}$/.test(s);
  const exactSet = (a,b) => a.length===b.length&&a.every((item,i)=>item===b[i]);
  const safeDigests = () => {
    const d=getDigests();
    return d.length>=2&&d.length<=8&&d.every(strictDigest);
  };
  const counts = () => {
    const metrics = Object.fromEntries(KINDS.map(k=>[k,Object.create(null)]));
    for(const kind of KINDS){
      const allowed=kind==="stage"?STAGES:kind==="route"?ROUTES:ACTIONS;
      allowed.forEach(value=>{metrics[kind][value]=0;});
      plans.forEach(p=>{metrics[kind][p[kind]]++;});
    }
    return metrics;
  };
  function summarize() {
    const area=$("humanSummary");clear(area);
    if(!plans.length){area.textContent="No source-bound HUMAN rows loaded.";return;}
    const total=plans.filter(p=>!isDefault(p)).length;
    area.append(node("strong",total+" of "+plans.length+" local literal check groups have human planning decisions."));
    const c=counts();
    area.append(node("p",STAGES.map(s=>s.replaceAll("_"," ")+": "+c.stage[s]).join(" · ")));
    const validity=node("p",safeDigests()
      ? "PRIVATE resume is available only against this exact original source-byte selection, including its order."
      : "Source fingerprints are unavailable in this browser context. PRIVATE save and restore are disabled; local HUMAN planning and source-free count briefing remain available.");
    validity.className="hint";area.append(validity);
    $("humanSave").disabled=!safeDigests();
    $("humanSaveEncrypted").disabled=!safeDigests()||!privatePlanCrypto.supported();
    $("humanResumeButton").disabled=!safeDigests();
    $("humanBrief").disabled=false;
    $("humanHandoff").disabled=false;
  }
  function optionList(select,values,current){
    for(const value of values) {
      const option=node("option",value.replaceAll("_"," "));
      option.value=value;option.selected=value===current;select.append(option);
    }
  }
  function matching() {
    const phrase=$("humanSearch").value.trim().toLocaleLowerCase();
    const stage=$("humanStage").value;
    return getRows().map((row,i)=>({row,i})).filter(({row,i})=>
      (stage==="all"||plans[i]?.stage===stage)&&
      (row.capability+" "+row.check).toLocaleLowerCase().includes(phrase));
  }
  function render() {
    const candidates=matching();
    const pages=Math.max(1,Math.ceil(candidates.length/64));
    page=Math.max(0,Math.min(page,pages-1));
    $("humanPages").textContent="Page "+(page+1)+" of "+pages+" · "+candidates.length+
      " selected source-declared check groups";
    $("humanPrev").disabled=page===0;
    $("humanNext").disabled=page+1>=pages;
    const table=$("humanTable");clear(table);
    const header=node("tr");
    for(const label of ["Source row","HUMAN stage","Review group","Next HUMAN question","Inspect"])header.append(node("th",label));
    const head=node("thead");head.append(header);table.append(head);
    const body=node("tbody");
    candidates.slice(page*64,(page+1)*64).forEach(({row,i})=>{
      const tr=node("tr"),identity=node("td");
      identity.append(node("strong","#"+(i+1)+" · "+(row.capability||"(no capability)")));
      identity.append(node("small",row.check||"(no check)"));tr.append(identity);
      for(const [kind,choices] of [["stage",STAGES],["route",ROUTES],["action",ACTIONS]]){
        const td=node("td"),select=node("select");
        select.setAttribute("aria-label","Row "+(i+1)+" HUMAN "+kind);
        optionList(select,choices,plans[i][kind]);
        select.addEventListener("change",()=>{
          plans[i]={...plans[i],[kind]:select.value};changed=true;lastBulk=null;historyResolutions.clear();
          $("humanUndo").disabled=true;
          summarize();if(history)renderHistory();
          if($("humanStage").value!=="all")render();
        });
        td.append(select);tr.append(td);
      }
      const inspect=node("td"),button=node("button","Open source declaration","secondary");
      button.type="button";button.addEventListener("click",()=>onFocus(row));
      inspect.append(button);tr.append(inspect);body.append(tr);
    });
    table.append(body);summarize();
  }
  function initialize() {
    plans=getRows().map(fresh);page=0;changed=false;lastBulk=null;
    $("humanUndo").disabled=true;
    clearHistory();
    $("humanSearch").value="";$("humanStage").value="all";
    render();
  }
  function clearAll() {
    plans=[];page=0;changed=false;lastBulk=null;
    $("humanUndo").disabled=true;
    clearHistory();
    clear($("humanTable"));clear($("humanSummary"));
    $("humanPages").textContent="No HUMAN work loaded.";
    for(const id of ["humanSave","humanSaveEncrypted","humanResumeButton","humanBrief","humanHandoff","humanPrev","humanNext"])$(id).disabled=true;
    $("humanResume").value="";
    $("humanEncryptPass").value="";$("humanResumePass").value="";
  }
  function privatePlan() {
    fail(safeDigests(),"Browser cannot bind PRIVATE HUMAN plan to original bytes");
    const rowPlans=plans.flatMap((value,i)=>
      isDefault(value)?[]:[{ordinal:i+1,...value}]);
    return {
      kind:"lightup.private_original_lab_human_matrix_plan",
      version:1,disposition:"REVIEW_ONLY_DRAFT_HOLD",...FLAGS,
      source_sha256:getDigests().slice(),ordered_row_count:plans.length,
      row_plans:rowPlans,
      interpretation:"Source hashes bind local bytes only. Unsigned PRIVATE human plans are not authenticated client/operator identity, authorization, verified findings, or successful remediation."
    };
  }
  function admitPrivatePlan(source, expectedRows=getRows(), expectedDigests=getDigests()) {
    fail(shape(source,FILE_KEYS),"Incompatible PRIVATE HUMAN plan envelope");
    fail(source.kind==="lightup.private_original_lab_human_matrix_plan"&&
      source.version===1&&source.disposition==="REVIEW_ONLY_DRAFT_HOLD");
    for(const key of Object.keys(FLAGS))fail(source[key]===false);
    fail(Array.isArray(source.source_sha256)&&
      source.source_sha256.length===expectedDigests.length&&
      source.source_sha256.every(strictDigest));
    fail(exactSet(source.source_sha256,expectedDigests),
      "Different or reordered original source bytes; saved plan cannot be applied");
    fail(int(source.ordered_row_count,16384)&&
      source.ordered_row_count===expectedRows.length);
    fail(Array.isArray(source.row_plans)&&source.row_plans.length<=source.ordered_row_count);
    fail(text(source.interpretation,1024));
    const next=expectedRows.map(fresh);
    let previous=0;
    for(const row of source.row_plans) {
      fail(shape(row,PLAN_KEYS)&&int(row.ordinal,source.ordered_row_count)&&row.ordinal>previous);
      fail(STAGES.includes(row.stage)&&ROUTES.includes(row.route)&&ACTIONS.includes(row.action));
      fail(!isDefault(row),"Default entries are not valid in sparse PRIVATE plan");
      next[row.ordinal-1]={stage:row.stage,route:row.route,action:row.action};
      previous=row.ordinal;
    }
    return next;
  }
  function humanBrief() {
    const c=counts();
    const lines=[
      "LIGHTUP · HUMAN DECLARATION DISCUSSION · COUNTS ONLY",
      "REVIEW_ONLY / DRAFT_HOLD · unsigned offline operator selection",
      "Source-group count: "+plans.length,
      "HUMAN decisions recorded: "+plans.filter(p=>!isDefault(p)).length,
      "",
      "STAGE COUNTS"
    ];
    for(const name of STAGES)lines.push(name+": "+c.stage[name]);
    lines.push("","HUMAN REVIEW GROUP COUNTS");
    for(const name of ROUTES)lines.push(name+": "+c.route[name]);
    lines.push("","HUMAN QUESTION COUNTS");
    for(const name of ACTIONS)lines.push(name+": "+c.action[name]);
    lines.push("","No original identifiers, addresses, source text, hashes, finding IDs, run IDs or consent data.",
      "These are HUMAN planning counts, not unique incidents, risk reduction, verified fixes or authorization.",
      "Small aggregates may be sensitive. Do not disclose without separate approval.",
      "No original sources were modified. No scanner, grant, dispatch or live action.");
    return lines.join("\n")+"\n";
  }
  // Read-only PRIVATE HTML, deliberately containing original source-declared check labels.
  // Source bytes, targets, evidence IDs/summaries and original run/tenant IDs are NEVER embedded.
  function escaped(value) {
    return String(value).replace(/[&<>"']/g, ch=>({
      "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
    }[ch]));
  }
  function privateHumanHandoff() {
    const selected=matching().filter(({i})=>!isDefault(plans[i]));
    fail(selected.length>0&&selected.length<=512,
      "Select 1–512 HUMAN-planned groups with current search/stage filter");
    const serializedRows=selected.map(({row,i})=>{
      const p=plans[i];
      return "<tr><td>"+(i+1)+"</td><td>"+escaped(row.capability)+"</td><td>"+
        escaped(row.check)+"</td><td>"+escaped(p.stage)+"</td><td>"+
        escaped(p.route)+"</td><td>"+escaped(p.action)+"</td></tr>";
    }).join("\n");
    return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'none'; style-src 'none'; connect-src 'none'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>LightUp PRIVATE HUMAN source-declaration handoff</title></head><body>
<h1>PRIVATE HUMAN source-declaration follow-up</h1>
<p><strong>REVIEW ONLY / DRAFT HOLD — NO SCAN, AUTHORIZATION, CLIENT CONSENT OR VERIFIED FINDINGS</strong></p>
<p>Original-source capability/check labels below are PRIVATE unverified declarations. Do not distribute without separate HUMAN approval. Source labels may reveal confidential details. This standalone scriptless handoff has no externally loaded resources and is NOT a source-authenticated or byte-bound return. It does not include targets, original source bytes, evidence, provider data or scan credentials.</p>
<p>Selected HUMAN routing rows: ${selected.length}. Local row ordinals refer only to the operator's current selected originals, not verified case identities.</p>
<table border="1" cellpadding="8" cellspacing="0">
<thead><tr><th>Local ordinal</th><th>Original capability label</th><th>Original check label</th><th>HUMAN stage</th><th>Proposed group</th><th>Next HUMAN question</th></tr></thead>
<tbody>${serializedRows}</tbody></table>
<p>Signed identity, authorization, consent, independent ground truth, remediation and subsequent scan results have NOT been established. Missing declarations never imply safe or fixed.</p>
</body></html>\n`;
  }

  // The two user-selected PRIVATE snapshots are plans, NOT attested events or chronology.
  // Strict admission always reuses the original byte-bound private-plan contract.
  async function parsePrivateJSONFile(file,password) {
    fail(file&&file.size>0&&file.size<=MAX_ENCRYPTED_BYTES,
      "PRIVATE HUMAN plan exceeds its bounded import size");
    const raw=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
    const envelope=parseStrict(raw);
    if(privatePlanCrypto.isEncrypted(envelope)) {
      const plain=await privatePlanCrypto.decrypt(envelope,password);
      return parseStrict(plain);
    }
    fail(file.size<=MAX_PRIVATE_BYTES,"Unencrypted PRIVATE HUMAN plan exceeds 3 MiB");
    return envelope;
  }
  async function readHistoryFile(file,password) {
    return admitPrivatePlan(await parsePrivateJSONFile(file,password));
  }
  function historyChanges(earlier,later) {
    const results=[];
    for(let i=0;i<earlier.length;i++) {
      const fields=KINDS.filter(kind=>earlier[i][kind]!==later[i][kind]);
      if(fields.length)results.push({ordinal:i+1,fields,before:earlier[i],after:later[i]});
    }
    return results;
  }
  function historyDisposition(change) {
    let needs=0,already=0,conflicts=0,resolvedKeep=0,resolvedUse=0;
    for(const kind of change.fields) {
      const current=plans[change.ordinal-1][kind];
      if(current===change.before[kind])needs++;
      else if(current===change.after[kind])already++;
      else {
        const resolution=historyResolutions.get(change.ordinal)?.[kind];
        if(resolution==="keep")resolvedKeep++;
        else if(resolution==="later")resolvedUse++;
        else conflicts++;
      }
    }
    return {needs,already,conflicts,resolvedKeep,resolvedUse,
      label:conflicts?"UNRESOLVED / HOLD":
        needs||resolvedUse?"HUMAN APPLY PROPOSED":
        resolvedKeep?"HUMAN CHOICE: KEEP CURRENT":"ALREADY MATCHES LATER"};
  }
  function historyStats() {
    if(!history)return {changed:0,needs:0,already:0,conflicts:0,resolvedKeep:0,resolvedUse:0};
    const stats={changed:history.changes.length,needs:0,already:0,conflicts:0,
      resolvedKeep:0,resolvedUse:0};
    for(const item of history.changes) {
      const d=historyDisposition(item);
      stats.needs+=d.needs;stats.already+=d.already;stats.conflicts+=d.conflicts;
      stats.resolvedKeep+=d.resolvedKeep;stats.resolvedUse+=d.resolvedUse;
    }
    return stats;
  }
  function clearHistory() {
    history=null;historyPage=0;historyResolutions.clear();
    clear($("historyTable"));
    $("historySummary").textContent="No PRIVATE source-bound snapshots loaded.";
    $("historyPagination").textContent="No snapshots loaded.";
    for(const key of ["historyPrev","historyNext","historyApply","historyCounts","historyPrivate"])
      $(key).disabled=true;
    $("historyEarlier").value="";$("historyLater").value="";
    $("historyPassEarlier").value="";$("historyPassLater").value="";
    $("historySearch").value="";$("historyState").value="all";
  }
  function renderHistory() {
    if(!history){clearHistory();return;}
    const all=history.changes;
    const phrase=$("historySearch").value.trim().toLocaleLowerCase();
    const status=$("historyState").value;
    const results=all.filter(item=>{
      const d=historyDisposition(item);
      const row=getRows()[item.ordinal-1];
      return (status==="all"||(status==="conflict"&&d.conflicts>0)||
        (status==="pending"&&d.needs>0&&!d.conflicts)||
        (status==="matched"&&!d.needs&&!d.conflicts))&&
        (row.capability+" "+row.check).toLocaleLowerCase().includes(phrase);
    });
    const pages=Math.max(1,Math.ceil(results.length/60));
    historyPage=Math.max(0,Math.min(historyPage,pages-1));
    $("historyPagination").textContent="Page "+(historyPage+1)+" / "+pages+
      " · "+results.length+" selected HUMAN-only changed groups";
    $("historyPrev").disabled=historyPage===0;
    $("historyNext").disabled=historyPage+1>=pages;
    const table=$("historyTable");clear(table);
    const headings=node("tr");
    ["Original local group","Changed HUMAN fields","Earlier declared choices","Later declared choices","Current local reconciliation"].forEach(v=>headings.append(node("th",v)));
    const head=node("thead");head.append(headings);table.append(head);
    const body=node("tbody");
    results.slice(historyPage*60,(historyPage+1)*60).forEach(item=>{
      const row=getRows()[item.ordinal-1],tr=node("tr");
      const identity=node("td");identity.append(node("strong","#"+item.ordinal+" · "+(row.capability||"(blank label)")));
      identity.append(node("small",row.check||"(blank check)"));tr.append(identity);
      tr.append(node("td",item.fields.join(" · ")));
      const oldText=item.fields.map(k=>k+": "+item.before[k]).join("\n");
      const newText=item.fields.map(k=>k+": "+item.after[k]).join("\n");
      tr.append(node("td",oldText),node("td",newText));
      const state=historyDisposition(item);
      const td=node("td",state.label+(state.conflicts?" ("+state.conflicts+" unresolved field(s))":""),
        state.conflicts?"metric-alert":"");
      for(const kind of item.fields) {
        const current=plans[item.ordinal-1][kind];
        if(current===item.before[kind]||current===item.after[kind])continue;
        const caption=node("label","Conflict in "+kind+" (current "+current+")");
        const choice=node("select");
        choice.setAttribute("aria-label","Original row "+item.ordinal+" HUMAN conflict "+kind);
        for(const [value,label] of [["","Hold — choose explicitly"],
          ["keep","Keep current HUMAN value"],["later","Use later HUMAN proposal"]]) {
          const option=node("option",label);
          option.value=value;option.selected=(historyResolutions.get(item.ordinal)?.[kind]||"")===value;
          choice.append(option);
        }
        choice.addEventListener("change",()=>{
          const existing=historyResolutions.get(item.ordinal)||{};
          const updated={...existing,[kind]:choice.value};
          historyResolutions.set(item.ordinal,updated);
          renderHistory();
        });
        caption.append(choice);td.append(caption);
      }
      tr.append(td);body.append(tr);
    });
    table.append(body);
    const stats=historyStats();
    clear($("historySummary"));
    $("historySummary").append(node("strong",stats.changed+
      " changed HUMAN rows across the two manually ordered PRIVATE plans."));
    $("historySummary").append(node("p",stats.needs+" directly compatible field proposals · "+
      stats.already+" already matching · "+stats.conflicts+" unresolved HOLD conflicts · "+
      stats.resolvedKeep+" explicit keep-current choices · "+
      stats.resolvedUse+" explicit use-later choices."));
    $("historySummary").append(node("p","Selection order is not a verified time series. A later HUMAN stage is not evidence of a resolved security finding.","hint"));
    $("historyApply").disabled=!(stats.needs+stats.resolvedUse)||stats.conflicts>0;
    $("historyCounts").disabled=false;
    $("historyPrivate").disabled=results.length===0||results.length>512;
  }
  function historyCountRows() {
    const stats=historyStats(),transitions=Object.create(null);
    const dimensions=[];
    for(const kind of KINDS) {
      const options=kind==="stage"?STAGES:kind==="route"?ROUTES:ACTIONS;
      for(const before of options)for(const after of options) {
        if(before===after)continue;
        const count=history.changes.filter(item=>
          item.fields.includes(kind)&&item.before[kind]===before&&item.after[kind]===after).length;
        if(count)dimensions.push({dimension:kind,earlier:before,later:after,source_declared_human_row_appearances:count});
      }
    }
    return {kind:"lightup.offline_private_human_matrix_numeric_history",
      version:1,disposition:"REVIEW_ONLY_DRAFT_HOLD",
      ...FLAGS,original_local_row_slots:plans.length,changed_human_rows:stats.changed,
      pending_human_field_proposals:stats.needs,already_matching_fields:stats.already,
      unresolved_human_conflicts:stats.conflicts,explicit_keep_current:stats.resolvedKeep,
      explicit_use_later:stats.resolvedUse,transitions:dimensions,
      interpretation:"Unsigned unverified manual earlier/later order. HUMAN choices only: never a verified remediation, authentic date, vulnerability, client consent, permission, or scan."};
  }
  function historyCSV(result) {
    const lines=[["dimension","earlier_choice","later_choice","HUMAN_row_appearances"]];
    for(const row of result.transitions)lines.push([row.dimension,row.earlier,row.later,row.source_declared_human_row_appearances]);
    return lines.map(row=>row.join(",")).join("\r\n")+"\r\n";
  }
  function historyPrivateHTML(items) {
    fail(items.length>0&&items.length<=512,"PRIVATE handoff requires 1–512 selected HUMAN changes");
    const rows=items.map(item=>{
      const source=getRows()[item.ordinal-1],state=historyDisposition(item);
      return "<tr><td>"+item.ordinal+"</td><td>"+escaped(source.capability)+"</td><td>"+
        escaped(source.check)+"</td><td>"+escaped(item.fields.join(" / "))+"</td><td>"+
        escaped(item.fields.map(k=>k+"="+item.before[k]).join(" / "))+"</td><td>"+
        escaped(item.fields.map(k=>k+"="+item.after[k]).join(" / "))+"</td><td>"+
        escaped(state.label)+"</td></tr>";
    }).join("\n");
    return '<!doctype html><html lang="en"><head><meta charset="utf-8">'+
      '<meta name="viewport" content="width=device-width,initial-scale=1">'+
      '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; script-src &#39;none&#39;; style-src &#39;none&#39;; connect-src &#39;none&#39;; img-src &#39;none&#39;; object-src &#39;none&#39;; base-uri &#39;none&#39;">'+
      '<title>LightUp PRIVATE HUMAN snapshot differences</title></head><body>'+
      '<h1>PRIVATE HUMAN-only snapshot differences</h1>'+
      '<p>REVIEW_ONLY / DRAFT_HOLD. Manually ordered original BYTE-bound private plans are NOT authenticated chronology. These are local HUMAN planning changes, NEVER verified vulnerabilities, fixes, risk reduction, consent, permission or source authorization. Source labels are confidential.</p>'+
      '<table border="1" cellpadding="7"><thead><tr><th>Local row</th><th>Original capability</th><th>Original check</th><th>HUMAN fields</th><th>Earlier</th><th>Later</th><th>Current reconciliation</th></tr></thead><tbody>'+
      rows+'</tbody></table><p>PRIVATE unverified labels may identify clients or systems. Separate protected HUMAN distribution only; original source bytes, targets, evidence, private plan source hashes and run IDs are excluded. No network, scripts or grants.</p></body></html>\n';
  }
  async function loadHistory() {
    const earlier=$("historyEarlier").files[0],later=$("historyLater").files[0];
    if(!safeDigests()||!plans.length) {
      message("Open the original PRIVATE lab batch with WebCrypto before loading its HUMAN snapshot history.",true);return;
    }
    $("historyOpen").disabled=true;
    try {
      fail(earlier&&later,"Choose an earlier and a later PRIVATE saved plan explicitly");
      const oldPlan=await readHistoryFile(earlier,$("historyPassEarlier").value);
      const newPlan=await readHistoryFile(later,$("historyPassLater").value);
      const next={earlier:oldPlan,later:newPlan,changes:historyChanges(oldPlan,newPlan)};
      // Entire two-file source-byte admission completed BEFORE any active comparison changes.
      history=next;historyPage=0;historyResolutions.clear();
      $("historySearch").value="";$("historyState").value="all";
      renderHistory();
      message("Both PRIVATE snapshots admitted against exact current original bytes. Chronology and reviewer authenticity remain unverified.");
    } catch(error) {
      message("Entire PRIVATE HUMAN history HOLD: "+error.message+
        ". Existing in-memory HUMAN plan and previous comparison remain unchanged.",true);
    } finally {
      $("historyOpen").disabled=false;
      $("historyEarlier").value="";$("historyLater").value="";
      $("historyPassEarlier").value="";$("historyPassLater").value="";
    }
  }
  function applyHistory() {
    if(!history)return;
    const stats=historyStats();
    if(stats.conflicts) {
      message("HUMAN history merge HOLD: "+stats.conflicts+" field conflicts. Current plan unchanged.",true);return;
    }
    if(!(stats.needs+stats.resolvedUse))return;
    if(!confirm("Apply "+(stats.needs+stats.resolvedUse)+
      " explicitly compatible or human-chosen use-later categorical proposals; preserve "+
      stats.resolvedKeep+" human-confirmed keep-current decisions? This is only a HUMAN plan edit, never a finding, grant, consent, authorization or scan."))return;
    // Reassess every field and refuse all changes if any concurrent HUMAN decision conflicts.
    if(historyStats().conflicts)return;
    const next=plans.map(p=>({...p}));
    for(const item of history.changes)for(const kind of item.fields) {
      const current=next[item.ordinal-1][kind];
      if(current===item.before[kind])next[item.ordinal-1][kind]=item.after[kind];
      else if(current===item.after[kind])continue;
      else if(historyResolutions.get(item.ordinal)?.[kind]==="later")
        next[item.ordinal-1][kind]=item.after[kind];
      else if(historyResolutions.get(item.ordinal)?.[kind]==="keep")continue;
      else {
        message("A HUMAN conflict changed before application; entire merge held.",true);
        return;
      }
    }
    plans=next;changed=true;lastBulk=null;historyResolutions.clear();
    $("humanUndo").disabled=true;
    page=0;render();renderHistory();
    message("Applied only nonconflicting HUMAN categorical proposals. No original finding or authorization was changed.");
  }

  function wire() {
    $("historyOpen").addEventListener("click",loadHistory);
    $("historyApply").addEventListener("click",applyHistory);
    $("historyForget").addEventListener("click",()=>{
      if(history&&!confirm("Forget only the two PRIVATE HUMAN comparison snapshots? Current HUMAN plan stays as is."))return;
      clearHistory();message("Private HUMAN comparison discarded; current local HUMAN choices retained.");
    });
    $("historySearch").addEventListener("input",()=>{historyPage=0;if(history)renderHistory();});
    $("historyState").addEventListener("change",()=>{historyPage=0;if(history)renderHistory();});
    $("historyPrev").addEventListener("click",()=>{if(history&&historyPage>0){historyPage--;renderHistory();}});
    $("historyNext").addEventListener("click",()=>{if(history){historyPage++;renderHistory();}});
    $("historyCounts").addEventListener("click",()=>{
      if(!history)return;
      if(!confirm("Download anonymous HUMAN change COUNTS only? Small numeric groups can remain sensitive."))return;
      const report=historyCountRows();
      download("lightup-human-change-counts.csv",historyCSV(report),"text/csv");
      download("lightup-human-change-counts.json",JSON.stringify(report,null,2)+"\n","application/json");
    });
    $("historyPrivate").addEventListener("click",()=>{
      if(!history)return;
      try {
        const phrase=$("historySearch").value.trim().toLocaleLowerCase();
        const state=$("historyState").value;
        const chosen=history.changes.filter(item=>{
          const d=historyDisposition(item),row=getRows()[item.ordinal-1];
          return (state==="all"||(state==="conflict"&&d.conflicts>0)||
            (state==="pending"&&d.needs>0&&!d.conflicts)||
            (state==="matched"&&!d.needs&&!d.conflicts))&&
            (row.capability+" "+row.check).toLocaleLowerCase().includes(phrase);
        });
        const pageHTML=historyPrivateHTML(chosen);
        fail(new Blob([pageHTML]).size<=MAX_PRIVATE_BYTES,"PRIVATE HTML comparison exceeds output limit");
        if(!confirm("Download PRIVATE HUMAN change handoff with ORIGINAL capability/check labels? Independent protected sharing approval is required."))return;
        download("lightup-PRIVATE-human-changes.html",pageHTML,"text/html");
      } catch(error){message("PRIVATE HUMAN comparison HOLD: "+error.message,true);}
    });
    $("humanSearch").addEventListener("input",()=>{page=0;render();});
    $("humanStage").addEventListener("change",()=>{page=0;render();});
    $("humanPrev").addEventListener("click",()=>{if(page>0){page--;render();}});
    $("humanNext").addEventListener("click",()=>{page++;render();});
    $("humanBulk").addEventListener("click",()=>{
      if(!plans.length)return;
      const rows=matching();
      if(!rows.length){message("No HUMAN rows match the current local search and stage filter.",true);return;}
      if(rows.length>512){
        message("Bulk HUMAN change HOLD: narrow the selection to at most 512 literal groups; nothing changed.",true);return;
      }
      const modifications={stage:$("humanBulkStage").value,
        route:$("humanBulkRoute").value,action:$("humanBulkAction").value};
      if(Object.values(modifications).every(v=>v==="keep")){
        message("Choose at least one HUMAN planning field for the bulk edit.",true);return;
      }
      const proposal=rows.filter(({i})=>Object.entries(modifications).some(([kind,value])=>
        value!=="keep"&&plans[i][kind]!==value));
      if(!proposal.length){message("No matching HUMAN planning values need changing.");return;}
      if(!confirm("Change "+proposal.length+" matching local HUMAN planning rows? This changes no original finding, scanner state, grant or remediation. You may undo this one bulk edit."))return;
      lastBulk=proposal.map(({i})=>({i,before:{...plans[i]}}));
      proposal.forEach(({i})=>{
        const current={...plans[i]};
        for(const kind of KINDS)if(modifications[kind]!=="keep")current[kind]=modifications[kind];
        plans[i]=current;
      });
      changed=true;historyResolutions.clear();$("humanUndo").disabled=false;page=0;render();if(history)renderHistory();
      message("Changed "+proposal.length+" HUMAN planning rows only; last bulk edit is undoable.");
    });
    $("humanUndo").addEventListener("click",()=>{
      if(!lastBulk)return;
      const snapshot=lastBulk;lastBulk=null;
      snapshot.forEach(({i,before})=>{plans[i]={...before};});
      changed=true;historyResolutions.clear();$("humanUndo").disabled=true;render();if(history)renderHistory();
      message("Restored "+snapshot.length+" HUMAN planning rows from last bulk edit; original sources unchanged.");
    });
    $("humanReset").addEventListener("click",()=>{
      if(!plans.length)return;
      if(!confirm("Reset ALL local HUMAN planning choices? No original source file changes."))return;
      plans=getRows().map(fresh);changed=true;lastBulk=null;historyResolutions.clear();
      $("humanUndo").disabled=true;page=0;render();if(history)renderHistory();message("Local HUMAN routing reset; source declarations unchanged.");
    });
    $("humanSave").addEventListener("click",()=>{
      if(!plans.length||!safeDigests())return;
      if(!confirm("Download PRIVATE source-byte-bound HUMAN plan? It contains unsalted source SHA-256 digests and should not be publicly shared."))return;
      const plan=privatePlan();
      const serialized=JSON.stringify(plan,null,2)+"\n";
      if(new Blob([serialized]).size>MAX_PRIVATE_BYTES){
        message("HUMAN plan is too large for private bounded handoff.",true);return;
      }
      download("lightup-PRIVATE-human-matrix-plan.json",serialized,"application/json");
      changed=false;
      message("PRIVATE source-bound HUMAN plan downloaded. Unsigned hash binding is not identity authentication.");
    });
    $("humanSaveEncrypted").addEventListener("click",async()=>{
      if(!plans.length||!safeDigests()||!privatePlanCrypto.supported())return;
      const password=$("humanEncryptPass").value;
      try {
        if(!confirm("Encrypt and download a PRIVATE HUMAN plan locally with your passphrase? If you lose this passphrase, the contents cannot be recovered. No password or file is sent anywhere."))return;
        const original=JSON.stringify(privatePlan(),null,2)+"\n";
        fail(new Blob([original]).size<=MAX_PRIVATE_BYTES,
          "HUMAN plan exceeds local encryption size limit");
        const encrypted=await privatePlanCrypto.encrypt(original,password);
        const output=JSON.stringify(encrypted,null,2)+"\n";
        fail(new Blob([output]).size<=MAX_ENCRYPTED_BYTES,
          "Encrypted PRIVATE output is too large");
        download("lightup-PRIVATE-human-plan-ENCRYPTED.json",output,"application/json");
        changed=false;
        message("AES-GCM encrypted PRIVATE HUMAN plan downloaded. The passphrase has not been saved or shared. Original source-byte binding remains mandatory after decryption.");
      } catch(error){
        message("Encrypted PRIVATE HUMAN save HOLD: "+error.message,true);
      } finally {$("humanEncryptPass").value="";}
    });
    $("humanResumeButton").addEventListener("click",async()=>{
      const file=$("humanResume").files[0];
      if(!safeDigests()||!file){message("Open the original source files, then choose one PRIVATE saved plan.",true);return;}
      try {
        const candidate=admitPrivatePlan(
          await parsePrivateJSONFile(file,$("humanResumePass").value));
        if(!confirm("Replace ALL local HUMAN notes with this PRIVATE exact-byte-bound plan?"))return;
        plans=candidate;changed=true;lastBulk=null;historyResolutions.clear();
        $("humanUndo").disabled=true;page=0;render();if(history)renderHistory();
        message("Source-byte-bound PRIVATE HUMAN plan restored after whole-document admission. No findings or authority changed.");
      } catch(error) {
        message("PRIVATE HUMAN plan HOLD: "+error.message+"; current notes unchanged.",true);
      } finally {$("humanResume").value="";$("humanResumePass").value="";}
    });
    $("humanHandoff").addEventListener("click",()=>{
      if(!plans.length)return;
      try {
        const prepared=privateHumanHandoff();
        if(new Blob([prepared]).size>MAX_PRIVATE_BYTES){
          message("PRIVATE HUMAN brief exceeds the bounded local handoff size.",true);return;
        }
        if(!confirm("Download PRIVATE read-only HUMAN handoff containing ORIGINAL check/capability LABELS? Explicit separate protected distribution is required."))return;
        download("lightup-PRIVATE-human-followup.html",prepared,"text/html");
        message("Scriptless PRIVATE HUMAN brief downloaded. It is NOT a source-authenticated authorization or evidence record.");
      } catch(error){message("PRIVATE HANDOFF HOLD: "+error.message,true);}
    });
    $("humanBrief").addEventListener("click",()=>{
      if(!plans.length||!confirm("Download counts-only HUMAN follow-up brief? Small numeric groups can be sensitive."))return;
      download("lightup-human-counts-brief.txt",humanBrief(),"text/plain");
    });
  }
  wire();clearAll();
  return {initialize,clearAll,render,
    exportVaultPlan:()=>privatePlan(),
    validateVaultPlan:(candidate,rows,digests)=>admitPrivatePlan(candidate,rows,digests),
    commitVaultPlan:(prepared)=>{
      fail(Array.isArray(prepared)&&prepared.length===getRows().length,
        "Prepared PRIVATE workspace notes not bound to active local source rows");
      plans=prepared.map(note=>({...note}));changed=false;lastBulk=null;
      historyResolutions.clear();clearHistory();page=0;render();
    },
    hasEdits:()=>changed&&plans.some(p=>!isDefault(p)),
    stageTotals:()=>plans.length?{...counts().stage}:null};
}
