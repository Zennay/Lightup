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
  const PLAN_KEYS = ["ordinal","stage","route","action"];
  const FILE_KEYS = ["kind","version","disposition","authorized","consent_verified",
    "dispatch_allowed","release_allowed","source_sha256","ordered_row_count",
    "row_plans","interpretation"];
  let plans = [], page = 0, changed = false, lastBulk = null;
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
    $("humanResumeButton").disabled=!safeDigests();
    $("humanBrief").disabled=false;
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
          plans[i]={...plans[i],[kind]:select.value};changed=true;lastBulk=null;
          $("humanUndo").disabled=true;
          summarize();
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
    $("humanSearch").value="";$("humanStage").value="all";
    render();
  }
  function clearAll() {
    plans=[];page=0;changed=false;lastBulk=null;
    $("humanUndo").disabled=true;
    clear($("humanTable"));clear($("humanSummary"));
    $("humanPages").textContent="No HUMAN work loaded.";
    for(const id of ["humanSave","humanResumeButton","humanBrief","humanPrev","humanNext"])$(id).disabled=true;
    $("humanResume").value="";
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
  function admitPrivatePlan(source) {
    fail(shape(source,FILE_KEYS),"Incompatible PRIVATE HUMAN plan envelope");
    fail(source.kind==="lightup.private_original_lab_human_matrix_plan"&&
      source.version===1&&source.disposition==="REVIEW_ONLY_DRAFT_HOLD");
    for(const key of Object.keys(FLAGS))fail(source[key]===false);
    fail(Array.isArray(source.source_sha256)&&
      source.source_sha256.length===getDigests().length&&
      source.source_sha256.every(strictDigest));
    fail(exactSet(source.source_sha256,getDigests()),
      "Different or reordered original source bytes; saved plan cannot be applied");
    fail(int(source.ordered_row_count,16384)&&
      source.ordered_row_count===getRows().length);
    fail(Array.isArray(source.row_plans)&&source.row_plans.length<=source.ordered_row_count);
    fail(text(source.interpretation,1024));
    const next=getRows().map(fresh);
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
  function wire() {
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
      changed=true;$("humanUndo").disabled=false;page=0;render();
      message("Changed "+proposal.length+" HUMAN planning rows only; last bulk edit is undoable.");
    });
    $("humanUndo").addEventListener("click",()=>{
      if(!lastBulk)return;
      const snapshot=lastBulk;lastBulk=null;
      snapshot.forEach(({i,before})=>{plans[i]={...before};});
      changed=true;$("humanUndo").disabled=true;render();
      message("Restored "+snapshot.length+" HUMAN planning rows from last bulk edit; original sources unchanged.");
    });
    $("humanReset").addEventListener("click",()=>{
      if(!plans.length)return;
      if(!confirm("Reset ALL local HUMAN planning choices? No original source file changes."))return;
      plans=getRows().map(fresh);changed=true;lastBulk=null;
      $("humanUndo").disabled=true;page=0;render();message("Local HUMAN routing reset; source declarations unchanged.");
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
    $("humanResumeButton").addEventListener("click",async()=>{
      const file=$("humanResume").files[0];
      if(!safeDigests()||!file){message("Open the original source files, then choose one PRIVATE saved plan.",true);return;}
      try {
        fail(file.size>0&&file.size<=MAX_PRIVATE_BYTES,"PRIVATE plan exceeds bounded import size");
        const raw=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
        const candidate=admitPrivatePlan(parseStrict(raw));
        if(!confirm("Replace ALL local HUMAN notes with this PRIVATE exact-byte-bound plan?"))return;
        plans=candidate;changed=true;lastBulk=null;
        $("humanUndo").disabled=true;page=0;render();
        message("Source-byte-bound PRIVATE HUMAN plan restored after whole-document admission. No findings or authority changed.");
      } catch(error) {
        message("PRIVATE HUMAN plan HOLD: "+error.message+"; current notes unchanged.",true);
      } finally {$("humanResume").value="";}
    });
    $("humanBrief").addEventListener("click",()=>{
      if(!plans.length||!confirm("Download counts-only HUMAN follow-up brief? Small numeric groups can be sensitive."))return;
      download("lightup-human-counts-brief.txt",humanBrief(),"text/plain");
    });
  }
  wire();clearAll();
  return {initialize,clearAll,render,
    hasEdits:()=>changed&&plans.some(p=>!isDefault(p)),
    stageTotals:()=>plans.length?{...counts().stage}:null};
}
