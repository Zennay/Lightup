"use strict";
/* PRIVATE offline LightUp HUMAN ordinal worksheet editor.
 * No source finding details, target calls, network or browser persistence.
 * Outputs remain non-authorizing, PRIVATE, source-bound only by original CLI.
 */
(() => {
  const HEAD = ["original_ordinal","source_reported_severity","evidence_reference_count",
                "human_stage","human_owner_group","human_next_action","human_blocker"];
  const SEVERITIES = ["critical","high","medium","low","info"];
  const STAGES = ["","needs_review","discussing","blocked","documented"];
  const MAX_BYTES = 1024*1024, MAX_ROWS = 2048, PAGE = 40;
  const $ = (id) => document.getElementById(id);
  const txt = (v) => String(v ?? "");
  let rows = [], originalName = "", sourceSize = 0, page = 0, dirty = false;
  let sourceFileSha = "", selectionFilter = "", lastBulk = null;
  const headById = Object.fromEntries(HEAD.map((x,i)=>[x,i]));
  const control = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;

  function need(valid) {
    if (!valid) throw Error("PRIVATE source/worksheet format not admitted (HOLD).");
  }
  function message(s, bad=false) {
    $("message").textContent = s; $("message").dataset.error = String(bad);
  }
  function quote(s) {
    s = txt(s);
    return /[",\r\n]/.test(s) ? '"' + s.replaceAll('"','""') + '"' : s;
  }
  function parseCSV(raw) {
    need(raw.length < 1100000 && !raw.includes("\0"));
    const result = [];
    let current = [], value = "", quoted = false, closed = false, start = true;
    let tokens = 0, cells = 0;
    function pushValue(){
      need(++cells <= 15000);
      current.push(value); value = ""; start = true; closed = false;
      need(current.length <= HEAD.length);
    }
    function pushRow(){
      pushValue();
      need(current.length === HEAD.length);
      result.push(current);
      need(result.length <= MAX_ROWS+1);
      current = [];
    }
    for (let i=0; i<raw.length; i++) {
      const ch=raw[i];
      need(++tokens < 1100000 && value.length <= 5000);
      if (quoted) {
        if (ch === '"') {
          if (raw[i+1] === '"') {value+='"'; i++;}
          else {quoted=false; closed=true;}
        } else value+=ch;
      } else if (ch === ',' ) pushValue();
      else if (ch === '\r' || ch === '\n') {
        if (ch==='\r') {need(raw[i+1]==='\n'); i++;}
        pushRow();
      } else if (ch === '"' && start) {quoted=true; start=false;}
      else {need(ch!=='"' && !closed); value += ch; start=false;}
    }
    need(!quoted);
    if (current.length || value || closed || !start) pushRow();
    need(result.length >= 1);
    return result;
  }
  function safeHuman(s) {
    const norm = s.normalize("NFKC")
      .replace(/^[\u0009\u0020\u00a0\u2000-\u200f\u202a-\u202e\u2060-\u206f\ufeff]+/gu,"");
    // Reject formula-shaped cells before spreadsheets interpret them.
    // This is deliberately strict rather than silently changing HUMAN text.
    return !/^[=+\-@\t\r\n]/u.test(norm);
  }
  function admit(parsed) {
    need(parsed.length>=1 && JSON.stringify(parsed[0])===JSON.stringify(HEAD));
    const next=[];
    let prior=0;
    for (const row of parsed.slice(1)) {
      need(row.length===7);
      const ordinal=Number(row[0]), evidence=Number(row[2]);
      need(Number.isSafeInteger(ordinal) && ordinal===prior+1 && ordinal<=MAX_ROWS);
      need(SEVERITIES.includes(row[1]));
      need(/^(0|[1-9][0-9]?)$/.test(row[2]) && evidence <=64);
      need(STAGES.includes(row[3]));
      need(row[4].length<=120 && row[5].length<=600 && row[6].length<=600);
      need(row.every(field=>!control.test(field)));
      need(row.slice(3).every(safeHuman));
      next.push({ordinal, severity:row[1], evidence,
                 stage:row[3],group:row[4],action:row[5],blocker:row[6]});
      prior=ordinal;
    }
    need(next.length<=MAX_ROWS);
    return next;
  }
  async function importFile(file) {
    need(file && file.size>0 && file.size<=MAX_BYTES);
    const decode = new TextDecoder("utf-8", {fatal:true});
    const raw = decode.decode(await file.arrayBuffer()).replace(/^\uFEFF/,"");
    const admitted=admit(parseCSV(raw));
    if (dirty && !confirm("Replace your unsaved PRIVATE HUMAN edits? Download before replacing.")) return;
    rows=admitted;originalName=file.name;sourceSize=file.size;
    page=0;dirty=false;lastBulk=null;sourceFileSha="";
    $("severityFilter").value="all";$("stageFilter").value="all";
    $("query").value="";$("groupFilter").value="all";
    $("workroom").hidden=false;
    $("sourceName").textContent=file.name;
    $("sourceStatus").textContent=rows.length+" anonymous original ordinals. Original target, title, run, evidence and authentication are NOT supplied to this editor.";
    render();
    message("PRIVATE worksheet admitted in memory only. No source authenticity or HUMAN identity proved.");
  }
  function visibleRows() {
    const sev=$("severityFilter").value, stage=$("stageFilter").value;
    const group=$("groupFilter").value;
    const query=$("query").value.trim().toLocaleLowerCase();
    return rows.filter(x=>(sev==="all" || x.severity===sev) &&
      (stage==="all" || (x.stage||"needs_review")===stage) &&
      (group==="all" || (group==="unassigned"?x.group==="":x.group===group)) &&
      (!query || [String(x.ordinal),x.group,x.action,x.blocker].some(v=>v.toLocaleLowerCase().includes(query))));
  }
  function counts() {
    const severity=Object.fromEntries(SEVERITIES.map(s=>[s,0]));
    const stage=Object.fromEntries(STAGES.slice(1).map(s=>[s,0]));
    const group=Object.create(null);
    let blockers=0, actions=0, ownerMissing=0;
    rows.forEach(r=>{
      severity[r.severity]++;
      stage[r.stage||"needs_review"]++;
      group[r.group||"unassigned"]=(group[r.group||"unassigned"]||0)+1;
      blockers+=Number(!!r.blocker.trim());actions+=Number(!!r.action.trim());
      ownerMissing+=Number(!r.group.trim());
    });
    return {severity,stage,group,blockers,actions,ownerMissing};
  }
  function drawSummary() {
    const data=counts();
    const pct = rows.length?Math.round(100*(rows.length-data.stage.needs_review)/rows.length):0;
    $("summary").replaceChildren();
    const cards=[
      ["Original ordinals",rows.length],["Human stages progressed",pct+"%"],
      ["Source high / critical",data.severity.high+data.severity.critical],
      ["Human blockers",data.blockers],["Owner/group missing",data.ownerMissing],
      ["Actions proposed",data.actions]
    ];
    cards.forEach(([label,value])=>{
      const item=document.createElement("div");item.className="stat";
      const l=document.createElement("small");l.textContent=label;
      const v=document.createElement("strong");v.textContent=String(value);
      item.append(l,v);$("summary").append(item);
    });
    $("completionFill").style.width=pct+"%";
    const groups=Object.keys(data.group).sort();
    const old=$("groupFilter").value;
    $("groupFilter").replaceChildren();
    [["all","All groups"],["unassigned","Unassigned"],...groups
      .filter(s=>s!=="unassigned").map(s=>[s,s])].forEach(([v,label])=>{
      const opt=new Option(label,v);$("groupFilter").add(opt);
    });
    $("groupFilter").value=groups.includes(old)||old==="all"||old==="unassigned"?old:"all";
    $("dirtyStatus").textContent=dirty?"Unsaved HUMAN changes · PRIVATE":"In-memory PRIVATE worksheet · no pending edits";
  }
  function td(text,tag="td") {
    const c=document.createElement(tag);c.textContent=txt(text);return c;
  }
  function changeRow(row,key,value,field) {
    value=txt(value);
    if ((key==="group"&&value.length>120) ||
        ((key==="action"||key==="blocker")&&value.length>600) ||
        control.test(value) || !safeHuman(value) ||
        (key==="stage"&&!STAGES.includes(value))) {
      field.value=row[key];message("Unsafe or overlong PRIVATE HUMAN field rejected. No export mutation.",true);return;
    }
    row[key]=value;lastBulk=null;dirty=true;render();
    message("Edited local HUMAN proposal only. Download PRIVATE CSV to retain this change.");
  }
  function inputCell(row,key,textarea=false) {
    const c=document.createElement("td"), field=document.createElement(textarea?"textarea":"input");
    if (key==="stage") {
      const select=document.createElement("select");
      STAGES.forEach(s=>select.add(new Option(s||"needs_review (blank)",s)));
      select.value=row.stage;select.setAttribute("aria-label","Stage for ordinal "+row.ordinal);
      select.addEventListener("change",()=>changeRow(row,"stage",select.value,select));
      c.append(select);return c;
    }
    field.value=row[key];
    field.maxLength=key==="group"?120:600;
    field.setAttribute("aria-label",key+" for ordinal "+row.ordinal);
    if (!textarea) field.placeholder="group (human only)";
    else {field.rows=2;field.placeholder=key==="action"?"Human next action":"Human uncertainty / blocker";}
    field.addEventListener("change",()=>changeRow(row,key,field.value,field));
    c.append(field);return c;
  }
  function render() {
    drawSummary();
    const visible=visibleRows(), pages=Math.max(1,Math.ceil(visible.length/PAGE));
    page=Math.min(Math.max(0,page),pages-1);
    $("displayCount").textContent=visible.length+" of "+rows.length+" original anonymous ordinals";
    $("pageLabel").textContent="Page "+(page+1)+" / "+pages;
    const body=$("tableBody");body.replaceChildren();
    visible.slice(page*PAGE,(page+1)*PAGE).forEach(row=>{
      const tr=document.createElement("tr");tr.id="original-"+row.ordinal;
      tr.append(td("#"+row.ordinal,"th"),td(row.severity),td(row.evidence),
                inputCell(row,"stage"),inputCell(row,"group"),
                inputCell(row,"action",true),inputCell(row,"blocker",true));
      body.append(tr);
    });
    if (!visible.length) {
      const tr=document.createElement("tr"),cell=td("No matching PRIVATE HUMAN rows. Adjust local filters.");
      cell.colSpan=7;tr.append(cell);body.append(tr);
    }
    $("prev").disabled=page===0;$("next").disabled=page>=pages-1;
    $("undoBulk").disabled=!lastBulk;
    $("saveCsv").disabled=rows.length===0;
    $("saveCounts").disabled=rows.length===0;
  }
  function batch() {
    const stage=$("bulkStage").value, group=$("bulkGroup").value;
    const selected=visibleRows();
    if (!selected.length) {message("No filtered rows to update.",true);return;}
    if (stage==="unchanged"&&group==="unchanged") {message("Select a HUMAN change first.",true);return;}
    if (group!=="unchanged"&&(group.length>120||control.test(group)||!safeHuman(group))) {
      message("Unsafe HUMAN group name (HOLD).",true);return;
    }
    if (!confirm("Apply HUMAN-only proposals to "+selected.length+" visible rows? Original source, evidence and permissions remain untouched."))return;
    const snapshot=selected.map(r=>({ordinal:r.ordinal,stage:r.stage,group:r.group}));
    selected.forEach(r=>{
      if (stage!=="unchanged")r.stage=stage;
      if (group!=="unchanged")r.group=group;
    });
    lastBulk=snapshot;dirty=true;page=0;render();
    message("Batch HUMAN change applied locally to "+selected.length+" filtered original ordinals. Single-step Undo available.");
  }
  function undoBulk() {
    if (!lastBulk) return;
    const index=new Map(rows.map(r=>[r.ordinal,r]));
    lastBulk.forEach(old=>{
      const row=index.get(old.ordinal);
      if (row){row.stage=old.stage;row.group=old.group;}
    });
    lastBulk=null;dirty=true;render();message("Last HUMAN batch edit reverted in memory.");
  }
  function download(name,content,type) {
    const blob=new Blob([content],{type});const url=URL.createObjectURL(blob);
    const a=document.createElement("a");a.href=url;a.download=name;
    document.body.appendChild(a);a.click();a.remove();
    setTimeout(()=>URL.revokeObjectURL(url),2500);
  }
  function csvOut() {
    return HEAD.join(",")+"\r\n"+rows.map(r=>[
      String(r.ordinal),r.severity,String(r.evidence),r.stage,r.group,r.action,r.blocker
    ].map(quote).join(",")).join("\r\n")+(rows.length?"\r\n":"");
  }
  function exportCsv() {
    if (!rows.length)return;
    const serial=csvOut();
    if (new TextEncoder().encode(serial).length>MAX_BYTES) {
      message("Export exceeds original PRIVATE 1 MiB human CSV limit (HOLD).",true);return;
    }
    if (!confirm("Save PRIVATE human notes + immutable original row ordinals? Do not share publicly; this is NOT authorization."))return;
    download("lightup-private-human-followup.csv",serial,"text/csv;charset=utf-8");
    dirty=false;render();message("PRIVATE HUMAN CSV prepared. Re-import through original human_return.py with unchanged original source + manifest.");
  }
  function exportCounts() {
    const data=counts();
    const summary={schema:"lightup.private_human_ordinal_counts.v1",
      status:"REVIEW_ONLY",scope:"unverified_original_ordinal_worksheet",
      declared_original_ordinal_count:rows.length,
      source_reported_severity_counts:data.severity,
      human_self_reported_stage_counts:data.stage,
      human_self_reported_group_counts:Object.values(data.group).reduce((a,v)=>a+v,0),
      human_blocker_count:data.blockers, human_next_action_count:data.actions,
      human_group_missing_count:data.ownerMissing,
      original_source_verified:false,human_identity_authenticated:false,
      client_consent_verified:false,operator_consent_verified:false,
      authorization_granted:false,dispatch_allowed:false,release_allowed:false};
    if (!confirm("Export numeric-only HUMAN totals? Aggregates may still be sensitive."))return;
    download("lightup-private-human-counts.json",JSON.stringify(summary,null,2)+"\n","application/json");
    message("PRIVATE numeric-only HUMAN counts exported; no original names/targets/notes/hashes included.");
  }
  function forget() {
    if ((dirty||rows.length) && !confirm("Forget all local PRIVATE worksheet data? Downloaded files are unaffected.")) return;
    rows=[];dirty=false;lastBulk=null;sourceSize=0;originalName="";sourceFileSha="";
    $("fileInput").value="";$("workroom").hidden=true;
    $("tableBody").replaceChildren();message("Private workroom cleared from application memory (best effort). Downloaded files remain on disk.");
  }
  $("load").addEventListener("click",async()=>{
    try{await importFile($("fileInput").files[0]);}
    catch(_){message("PRIVATE worksheet rejected (HOLD); existing in-memory work retained.",true);}
  });
  ["severityFilter","stageFilter","groupFilter","query"].forEach(id=>{
    $(id).addEventListener(id==="query"?"input":"change",()=>{page=0;render();});
  });
  $("prev").addEventListener("click",()=>{page--;render();});
  $("next").addEventListener("click",()=>{page++;render();});
  $("applyBulk").addEventListener("click",batch);
  $("undoBulk").addEventListener("click",undoBulk);
  $("saveCsv").addEventListener("click",exportCsv);
  $("saveCounts").addEventListener("click",exportCounts);
  $("forget").addEventListener("click",forget);
  addEventListener("beforeunload",e=>{if (dirty){e.preventDefault();e.returnValue="";}});
  message("Load an existing PRIVATE original ordinal worksheet. Nothing is uploaded or stored by this application.");
})();