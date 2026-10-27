"use strict";
/* LightUp PRIVATE HUMAN browser studio: memory-only, no fetch, no local storage. */
(() => {
  const MAX = 12, LIMIT = 16384;
  const FLAGS = ["authenticated","tenant_verified","source_authorized",
    "assessment_authorized","grant","client_consent","operator_consent",
    "execution","scan","audit_verdict","retest_verified","release"];
  const STAGES = ["unassigned","assigned","waiting_human","locally_answered"];
  const INBOX = ["kind","schema_version","disposition",
    "source_free_workrooms_not_unique_cases",
    "local_pending_human_questions_not_fixes","warning",...FLAGS];
  const PLAN = ["kind","schema_version","disposition","slots_not_unique_cases",
    "local_stage_totals","pending_local_human_attention_slots",
    "due_slots_with_local_dates","warning",...FLAGS];
  const WORKROOM = ["kind","schema_version","disposition","source_free_inbox",
    "local_human_planning","warning",...FLAGS];
  const $ = id => document.getElementById(id);
  let entries = [];
  let earlier = null; // Source-free NUMERIC aggregate snapshot only, never raw inputs.

  const SESSION_KIND="lightup.private_human_browser_numeric_session";
  const SESSION_DISPOSITION="LOCAL_BROWSER_ONLY_NO_ORIGINAL_SOURCE_ATTESTATION";
  const SESSION_WARNING="Self-declared private HUMAN counts only; does not authenticate original source, consent, findings, fixes, grants, or users.";
  const SESSION_FIELDS=["kind","schema_version","disposition","packets",
    "earlier_numeric_aggregate","warning",...FLAGS];
  const PACKET_FIELDS=["type","slots","questions","plan"];
  const SUMMARY_FIELDS=["packets","slots","questions","attention","dated","planned",
    "possible_same_numeric_shape_appearances","stages"];
  const SAVED_PLAN_FIELDS=["attention","dated","stages"];
  let resumedFromNumericFile=false;
  let humanActions=[];
  const BOARD_KIND="lightup.private_human_anonymous_followup_board";
  const BOARD_DISPOSITION="LOCAL_HUMAN_FOLLOWUP_ONLY_NO_SOURCE_AUTHORITY";
  const BOARD_WARNING="Anonymous local HUMAN routing choices only. Not unique cases, original source authentication, verified security findings, consent, grant, remediation or action permission.";
  const BOARD_ACTIONS=[
    ["none","No next step selected"],
    ["request_fresh_source_export","Request fresh original-source counts"],
    ["discuss_open_questions","Discuss open HUMAN questions"],
    ["clarify_human_assignment","Clarify anonymous HUMAN assignment"],
    ["reconcile_anonymous_coverage","Reconcile anonymous coverage"],
    ["request_original_human_review","Request original HUMAN review"]
  ];
  const BOARD_STATES=[
    ["not_triaged","Not yet triaged"],
    ["needs_human_followup","Needs HUMAN follow-up"],
    ["waiting_original_owner","Waiting for original HUMAN source owner"],
    ["locally_discussed","Locally discussed (not verified fix)"]
  ];
  const BOARD_FIELDS=["kind","schema_version","disposition","numeric_packets",
    "assignments","warning",...FLAGS];
  const BOARD_ASSIGNMENT_FIELDS=["ordinal","action","state"];
  let timelineMoments=[]; // Distinct temporary numeric session previews, NOT original evidence.

  const ensure = ok => { if (!ok) throw Error("HOLD"); };
  const integer = (v,min,max) => Number.isSafeInteger(v) && v >= min && v <= max;
  const keys = (o,expected) => o !== null && typeof o === "object" &&
    !Array.isArray(o) && Object.keys(o).length === expected.length &&
    expected.every(k => Object.prototype.hasOwnProperty.call(o,k));
  const header = (o,fields,kind,disposition) => {
    ensure(keys(o,fields) && o.kind === kind &&
      o.schema_version === 1 && o.disposition === disposition &&
      typeof o.warning === "string" && o.warning.length >= 10 &&
      o.warning.length <= 4096 && FLAGS.every(k => o[k] === false));
  };
  const inbox = o => {
    header(o,INBOX,"lightup.anonymous_human_inbox_counts_only",
      "PRIVATE_HUMAN_COUNTS_ONLY_NO_AUTHORITY");
    ensure(integer(o.source_free_workrooms_not_unique_cases,1,12) &&
      integer(o.local_pending_human_questions_not_fixes,0,1000000));
    return {type:"inbox", slots:o.source_free_workrooms_not_unique_cases,
      questions:o.local_pending_human_questions_not_fixes,plan:null};
  };
  const plan = (o,slots) => {
    header(o,PLAN,"lightup.private_anonymous_human_slot_workload",
      "UNVERIFIED_HUMAN_PLANNING_COUNTS_ONLY");
    ensure(o.slots_not_unique_cases === slots && keys(o.local_stage_totals,STAGES));
    const stages = STAGES.map(k => o.local_stage_totals[k]);
    ensure(stages.every(n => integer(n,0,slots)) &&
      stages.reduce((a,b)=>a+b,0) === slots &&
      integer(o.pending_local_human_attention_slots,0,slots) &&
      o.pending_local_human_attention_slots ===
         slots - o.local_stage_totals.locally_answered &&
      integer(o.due_slots_with_local_dates,0,slots));
    return {attention:o.pending_local_human_attention_slots,
      dated:o.due_slots_with_local_dates,stages:o.local_stage_totals};
  };
  const admit = o => {
    ensure(o && typeof o === "object" && !Array.isArray(o));
    if (o.kind === "lightup.anonymous_human_inbox_counts_only") return inbox(o);
    header(o,WORKROOM,"lightup.private_human_workroom_anonymous_counts",
      "COUNTS_ONLY_NO_AUTHORITY");
    const packet = inbox(o.source_free_inbox);
    return {...packet,type:"workroom",plan:plan(o.local_human_planning,packet.slots)};
  };


  const savedPlan = (data,slots) => {
    ensure(keys(data,SAVED_PLAN_FIELDS) &&
      integer(data.attention,0,slots) && integer(data.dated,0,slots) &&
      keys(data.stages,STAGES));
    const counts=STAGES.map(stage=>data.stages[stage]);
    ensure(counts.every(n=>integer(n,0,slots)) &&
      counts.reduce((a,b)=>a+b,0)===slots &&
      data.attention===slots-data.stages.locally_answered);
    return {attention:data.attention,dated:data.dated,stages:{...data.stages}};
  };
  const savedAggregate=(obj)=>{
    ensure(keys(obj,SUMMARY_FIELDS) &&
      integer(obj.packets,1,MAX) &&
      integer(obj.slots,obj.packets,MAX*12) &&
      integer(obj.questions,0,MAX*1000000) &&
      integer(obj.planned,0,obj.packets) &&
      integer(obj.attention,0,obj.slots) &&
      integer(obj.dated,0,obj.slots) &&
      integer(obj.possible_same_numeric_shape_appearances,0,obj.packets) &&
      keys(obj.stages,STAGES));
    const stages=STAGES.map(key=>obj.stages[key]);
    ensure(stages.every(value=>integer(value,0,obj.slots)) &&
      stages.reduce((a,b)=>a+b,0)<=obj.slots &&
      (obj.planned!==0 || (obj.attention===0 && obj.dated===0 &&
        stages.every(n=>n===0))));
    return {...obj,stages:{...obj.stages}};
  };
  const savedSession=(obj)=>{
    header(obj,SESSION_FIELDS,SESSION_KIND,SESSION_DISPOSITION);
    ensure(obj.warning===SESSION_WARNING &&
      Array.isArray(obj.packets) && obj.packets.length>=1 &&
      obj.packets.length<=MAX);
    const files=obj.packets.map(data=>{
      ensure(keys(data,PACKET_FIELDS) &&
        (data.type==="inbox" || data.type==="workroom") &&
        integer(data.slots,1,12) && integer(data.questions,0,1000000));
      if(data.type==="inbox"){ensure(data.plan===null);}
      const plan=data.type==="inbox"?null:savedPlan(data.plan,data.slots);
      return {type:data.type,slots:data.slots,questions:data.questions,plan};
    });
    if(obj.earlier_numeric_aggregate!==null)
      savedAggregate(obj.earlier_numeric_aggregate);
    return {packets:files,earlier:obj.earlier_numeric_aggregate===null?null:
      savedAggregate(obj.earlier_numeric_aggregate)};
  };
  const exportableSession=()=>{
    ensure(entries.length>0 && entries.length<=MAX);
    const snapshot={
      kind:SESSION_KIND,schema_version:1,disposition:SESSION_DISPOSITION,
      packets:entries.map(x=>({
        type:x.type,slots:x.slots,questions:x.questions,
        plan:x.plan===null?null:{attention:x.plan.attention,dated:x.plan.dated,
          stages:{...x.plan.stages}}
      })),
      earlier_numeric_aggregate:earlier===null?null:{...earlier,
        stages:{...earlier.stages}},
      warning:SESSION_WARNING,
      ...Object.fromEntries(FLAGS.map(key=>[key,false]))
    };
    savedSession(snapshot);
    return JSON.stringify(snapshot,null,2)+"\n";
  };

  /* JSON scanner rejects duplicates at every nesting level BEFORE JSON.parse.
     Bound raw inputs, nodes, nesting and numeric lexical form; no regex-only parsing. */
  const strictJSON = source => {
    let p=0, nodes=0;
    const fail = () => { throw Error("HOLD"); };
    const ws = () => { while (p < source.length && " \n\r\t".includes(source[p])) p++; };
    const str = () => {
      const start=p;
      if(source[p++] !== '"') fail();
      while (p < source.length) {
        const c=source[p++];
        if(c === '"') return JSON.parse(source.slice(start,p));
        if(c === "\\") {
          const e=source[p++];
          if(!e || !'"\\/bfnrtu'.includes(e)) fail();
          if(e === "u") {
            if(!/^[0-9a-fA-F]{4}$/.test(source.slice(p,p+4))) fail();
            p+=4;
          }
        } else if (c.charCodeAt(0) < 32) fail();
      }
      fail();
    };
    const value = depth => {
      ws();
      if(++nodes > 2048 || depth > 14) fail();
      const ch=source[p];
      if(ch === '"') { str(); return; }
      if(ch === "{") {
        p++; ws();
        const observed=new Set();
        if(source[p] === "}") { p++; return; }
        while(p<source.length){
          ws();
          const key=str();
          if(observed.has(key)) fail();
          observed.add(key); ws();
          if(source[p++] !== ":") fail();
          value(depth+1); ws();
          if(source[p] === "}") { p++; return; }
          if(source[p++] !== ",") fail();
        }
        fail();
      }
      if(ch === "[") {
        p++; ws();
        if(source[p] === "]") { p++; return; }
        while(p<source.length){
          value(depth+1); ws();
          if(source[p] === "]") { p++; return; }
          if(source[p++] !== ",") fail();
        }
        fail();
      }
      const rest=source.slice(p);
      const m=/^(?:true|false|null|(?:0|[1-9]\d*))/.exec(rest);
      if(!m) fail();
      p+=m[0].length;
    };
    value(0); ws();
    if(p !== source.length) fail();
    return JSON.parse(source);
  };
  const showStatus = (message,bad=false) => {
    $("status").textContent=message;
    $("status").dataset.state=bad?"hold":"ready";
  };
  const td=(row,text,tag="td")=>{
    const cell=document.createElement(tag);cell.textContent=String(text);
    row.appendChild(cell);
  };
  const summary = data => {
    const totals={packets:data.length,slots:0,questions:0,attention:0,dated:0,planned:0,
      possible_same_numeric_shape_appearances:0,
      stages:{unassigned:0,assigned:0,waiting_human:0,locally_answered:0}};
    for(const item of data){
      totals.slots+=item.slots;totals.questions+=item.questions;
      if(item.plan){totals.planned++;totals.attention+=item.plan.attention;
        totals.dated+=item.plan.dated;
        for(const stage of STAGES)totals.stages[stage]+=item.plan.stages[stage];}
    }
    const shapes=new Map();
    for(const item of data){
      const profile=JSON.stringify([item.type,item.slots,item.questions,
        item.plan?[item.plan.attention,item.plan.dated,
          ...STAGES.map(stage=>item.plan.stages[stage])]:null]);
      shapes.set(profile,(shapes.get(profile)??0)+1);
    }
    totals.possible_same_numeric_shape_appearances=
      Array.from(shapes.values()).filter(n=>n>1).reduce((a,b)=>a+b,0);
    return totals;
  };
  const queue = data => data.map((item,i)=>({...item,ordinal:i+1}))
    .sort((a,b)=>b.questions-a.questions ||
      (b.plan?.attention??0)-(a.plan?.attention??0)||a.ordinal-b.ordinal);
  const render=()=>{
    const total=summary(entries);
    for(const key of ["packets","slots","questions","attention","dated"])
      $(key).textContent=String(total[key]);
    const body=$("rows");body.replaceChildren();
    for(const packet of queue(entries)){
      const tr=document.createElement("tr");
      td(tr,packet.ordinal,"th");td(tr,packet.type);
      td(tr,packet.slots);td(tr,packet.questions);
      td(tr,packet.plan?.attention??"Not provided");
      td(tr,packet.plan?.dated??"Not provided");
      const actions=document.createElement("td");
      const button=document.createElement("button");
      button.type="button";button.textContent="Remove packet";
      button.addEventListener("click",()=>{
        entries=entries.filter((_,i)=>i!==packet.ordinal-1);
        humanActions.splice(packet.ordinal-1,1);
        render();showStatus("One anonymous packet and its local HUMAN routing choice removed from memory.");
      });
      actions.appendChild(button);tr.appendChild(actions);body.appendChild(tr);
    }
    $("export").disabled=entries.length===0;
    $("clear").disabled=entries.length===0;
    $("freeze").disabled=entries.length===0;
    $("forgetEarlier").disabled=earlier===null;
    $("exportDelta").disabled=earlier===null || entries.length===0;
    $("exportBrief").disabled=entries.length===0;
    $("exportJson").disabled=entries.length===0;
    $("saveBoard").disabled=entries.length===0;
    $("boardCSV").disabled=entries.length===0;
    $("boardBrief").disabled=entries.length===0;
    $("resetBoard").disabled=entries.length===0;
    $("saveSession").disabled=entries.length===0;
    $("sourceStatus").textContent=resumedFromNumericFile?
      "Resumed numeric browser summary (NOT freshly source-checked)":
      "Native-shaped count exports declared by their files (NOT independently authenticated)";
    $("missing").textContent=String(total.packets-total.planned);
    renderBoard();
    $("overlap").textContent=String(total.possible_same_numeric_shape_appearances);
    for(const stage of STAGES)$("stage_"+stage).textContent=
      String(total.stages[stage])+" recorded slot appearances";
    const former=earlier;
    $("earlierLabel").textContent=former===null?"None saved in memory":"Earlier numeric counters held in memory";
    const baselineCells=[["packets","deltaPackets"],["slots","deltaSlots"],
      ["questions","deltaQuestions"],["attention","deltaAttention"],["dated","deltaDated"]];
    for(const [key,id] of baselineCells){
      const difference=former===null?"No baseline":
         String(total[key]-former[key]);
      $(id).textContent=difference;
    }
  };


  const browserPacket=x=>({
    type:x.type,slots:x.slots,questions:x.questions,
    plan:x.plan===null?null:{attention:x.plan.attention,dated:x.plan.dated,
      stages:{...x.plan.stages}}
  });
  const assignmentDefaults=()=>({action:"none",state:"not_triaged"});
  const boardPayload=()=>{
    ensure(entries.length>0 && entries.length<=MAX &&
      humanActions.length===entries.length);
    const data={
      kind:BOARD_KIND,schema_version:1,disposition:BOARD_DISPOSITION,
      numeric_packets:entries.map(browserPacket),
      assignments:humanActions.map((entry,i)=>({
        ordinal:i+1,action:entry.action,state:entry.state
      })),
      warning:BOARD_WARNING,
      ...Object.fromEntries(FLAGS.map(name=>[name,false]))
    };
    admitBoard(data);
    return data;
  };
  const admitBoard=data=>{
    header(data,BOARD_FIELDS,BOARD_KIND,BOARD_DISPOSITION);
    ensure(data.warning===BOARD_WARNING &&
      Array.isArray(data.numeric_packets) &&
      data.numeric_packets.length===entries.length &&
      Array.isArray(data.assignments) &&
      data.assignments.length===entries.length &&
      entries.length>0);
    const current=entries.map(browserPacket);
    // Numeric full packet equality is only local binding to the exact browser
    // selection. Matching numbers cannot authenticate any original case.
    for(const [i,row] of data.numeric_packets.entries()){
      ensure(keys(row,PACKET_FIELDS) && JSON.stringify(row)===JSON.stringify(current[i]));
    }
    for(const [index,row] of data.assignments.entries()){
      ensure(keys(row,BOARD_ASSIGNMENT_FIELDS) &&
        row.ordinal===index+1 &&
        BOARD_ACTIONS.some(entry=>entry[0]===row.action) &&
        BOARD_STATES.some(entry=>entry[0]===row.state));
    }
    return data.assignments.map(x=>({action:x.action,state:x.state}));
  };
  const renderBoard=()=>{
    const body=$("boardRows");body.replaceChildren();
    while(humanActions.length<entries.length)
      humanActions.push(assignmentDefaults());
    if(humanActions.length>entries.length)
      humanActions.length=entries.length;
    const selectedState=$("boardFilter").value;
    for(const [index,packet] of entries.entries()){
      if(selectedState!=="all" && humanActions[index].state!==selectedState)continue;
      const row=document.createElement("tr");
      td(row,String(index+1),"th");
      td(row,packet.questions);
      const first=document.createElement("td");
      const action=document.createElement("select");
      action.setAttribute("aria-label","Local HUMAN next step for anonymous packet "+(index+1));
      for(const [code,label] of BOARD_ACTIONS){
        const option=document.createElement("option");option.value=code;
        option.textContent=label;action.appendChild(option);
      }
      action.value=humanActions[index].action;
      action.addEventListener("change",()=>{
        humanActions[index].action=action.value;
        $("boardStatus").textContent="Local HUMAN routing choice changed in memory; no original workroom modified.";
      });
      first.appendChild(action);row.appendChild(first);
      const second=document.createElement("td");
      const state=document.createElement("select");
      state.setAttribute("aria-label","Local HUMAN routing state for anonymous packet "+(index+1));
      for(const [code,label] of BOARD_STATES){
        const option=document.createElement("option");option.value=code;
        option.textContent=label;state.appendChild(option);
      }
      state.value=humanActions[index].state;
      state.addEventListener("change",()=>{
        humanActions[index].state=state.value;
        renderBoard();
        $("boardStatus").textContent="Local HUMAN state changed in memory; not a verified fix or authorization.";
      });
      second.appendChild(state);row.appendChild(second);
      body.appendChild(row);
    }
    $("boardVisible").textContent=String(body.childElementCount);
    for(const [name] of BOARD_STATES)
      $("count_"+name).textContent=String(
        humanActions.filter(item=>item.state===name).length);
  };
  $("boardFilter").addEventListener("change",()=>{renderBoard();});
  $("resetBoard").addEventListener("click",()=>{
    if(!entries.length || !window.confirm("Reset ALL local HUMAN follow-up choices? No original source, verified fix or grant will change."))return;
    humanActions=entries.map(assignmentDefaults);
    renderBoard();$("boardStatus").textContent="Local HUMAN routing choices reset to untriaged.";
  });
  $("boardBrief").addEventListener("click",()=>{
    if(!entries.length)return;
    const lines=[
      "LIGHTUP PRIVATE HUMAN FOLLOW-UP ACTION DESK / NO AUTHORITY",
      BOARD_WARNING,"",
      "Original source/identity not authenticated. Ordinals are local appearances.",
      ""
    ];
    for(const [i,record] of humanActions.entries()){
      const p=entries[i];
      const action=BOARD_ACTIONS.find(([code])=>code===record.action)?.[1]??"Unknown";
      const state=BOARD_STATES.find(([code])=>code===record.state)?.[1]??"Unknown";
      lines.push("ANONYMOUS PACKET "+(i+1)+" / "+p.questions+" HUMAN QUESTIONS",
        "HUMAN NEXT STEP: "+action,"LOCAL ROUTING STATUS: "+state,
        "No original case identifier, consent, verified fix or release.","");
    }
    download("lightup-private-human-action-brief.txt","text/plain",
      lines.join("\n")+"\n");
    $("boardStatus").textContent="HUMAN-only private routing brief saved; no original workroom changed.";
  });
  $("saveBoard").addEventListener("click",()=>{
    if(!entries.length)return;
    try{
      download("lightup-private-human-followup-board.json","application/json",
        JSON.stringify(boardPayload(),null,2)+"\n");
      $("boardStatus").textContent="Local anonymous HUMAN follow-up JSON saved. Pair with numeric browser session when using action_board.py.";
    }catch(_){$("boardStatus").textContent="HOLD: could not save HUMAN routing board.";}
  });
  $("boardCSV").addEventListener("click",()=>{
    if(!entries.length)return;
    try{
      boardPayload();
      const lines=["packet_ordinal_not_original_case,source_type,slot_appearances,open_human_questions,local_human_action,local_routing_state"];
      for(const [i,entry] of humanActions.entries()){
        const packet=entries[i];
        lines.push([i+1,packet.type,packet.slots,packet.questions,
          entry.action,entry.state].join(","));
      }
      download("lightup-private-human-followup-board.csv","text/csv",
        lines.join("\r\n")+"\r\n");
      $("boardStatus").textContent="PRIVATE HUMAN routing CSV saved; original evidence untouched.";
    }catch(_){$("boardStatus").textContent="HOLD: could not save HUMAN routing CSV.";}
  });
  $("restoreBoard").addEventListener("change",async event=>{
    const files=Array.from(event.target.files??[]);event.target.value="";
    try{
      ensure(entries.length>0 && files.length===1 &&
        files[0].size>0 && files[0].size<=LIMIT);
      const raw=new TextDecoder("utf-8",{fatal:true}).decode(
        await files[0].arrayBuffer());
      ensure(new TextEncoder().encode(raw).length<=LIMIT);
      const proposed=admitBoard(strictJSON(raw));
      if(!window.confirm("Replace current local HUMAN routing choices for EXACT matching numeric packet ordinals? This does NOT verify original source or consent."))return;
      humanActions=proposed;renderBoard();
      $("boardStatus").textContent="Self-declared HUMAN routing choices restored. No source authenticity or permissions verified.";
    }catch(_){
      $("boardStatus").textContent="HOLD: invalid or nonmatching HUMAN board; existing choices unchanged.";
    }
  });

  const numericTrendRows=()=>{
    const rows=[];
    for(const [index,now] of timelineMoments.entries()){
      const old=index?timelineMoments[index-1]:null;
      rows.push({...now,ordinal:index+1,
        packet_count_changed:old!==null && old.packets!==now.packets,
        questions_difference:old===null?null:now.questions-old.questions});
    }
    return rows;
  };
  const renderTimeline=()=>{
    const rows=numericTrendRows();
    const table=$("momentRows");table.replaceChildren();
    for(const moment of rows){
      const tr=document.createElement("tr");
      td(tr,"Moment "+moment.ordinal,"th");
      td(tr,moment.packets);td(tr,moment.slots);td(tr,moment.questions);
      td(tr,moment.attention);
      td(tr,moment.questions_difference===null?"First selection":
        (moment.questions_difference>=0?"+":"")+moment.questions_difference);
      td(tr,moment.packet_count_changed?"Declared packet coverage changed":
        "Case coverage STILL unverified");
      const actions=document.createElement("td");
      for(const [label,offset] of [["Earlier",-1],["Later",1]]){
        const button=document.createElement("button");
        button.type="button";button.textContent=label;
        button.disabled=moment.ordinal+offset<1 ||
          moment.ordinal+offset>timelineMoments.length;
        button.setAttribute("aria-label","Move numeric moment "+moment.ordinal+
          " "+label.toLowerCase()+" in self-selected order");
        button.addEventListener("click",()=>{
          const position=moment.ordinal-1,other=position+offset;
          if(other<0 || other>=timelineMoments.length)return;
          [timelineMoments[position],timelineMoments[other]]=
            [timelineMoments[other],timelineMoments[position]];
          renderTimeline();
          $("momentStatus").textContent="Human-selected numeric moment order updated; ordinals are NOT verified dates.";
        });
        actions.appendChild(button);
      }
      tr.appendChild(actions);table.appendChild(tr);
    }
    $("momentExportCSV").disabled=rows.length<2;
    $("momentExportJSON").disabled=rows.length<2;
    $("momentClear").disabled=rows.length===0;
    $("momentCount").textContent=String(rows.length);
    const svg=$("momentPlot");
    svg.replaceChildren();
    svg.setAttribute("viewBox","0 0 820 240");
    if(!rows.length){
      svg.setAttribute("aria-label","No saved HUMAN moment selections loaded.");
      return;
    }
    svg.setAttribute("aria-label","Numbered HUMAN pending-question packet appearances: "+
      rows.map(x=>x.questions).join(", "));
    const ns="http://www.w3.org/2000/svg";
    const top=Math.max(1,...rows.map(x=>x.questions));
    const points=rows.map((x,i)=>[
      50+Math.round(i*700/Math.max(1,rows.length-1)),
      20+Math.round((1-x.questions/top)*150)
    ]);
    const line=document.createElementNS(ns,"polyline");
    line.setAttribute("points",points.map(p=>p.join(",")).join(" "));
    line.setAttribute("fill","none");line.setAttribute("stroke","#a6f1d1");
    line.setAttribute("stroke-width","3");svg.appendChild(line);
    for(const [i,p] of points.entries()){
      const dot=document.createElementNS(ns,"circle");
      dot.setAttribute("cx",String(p[0]));dot.setAttribute("cy",String(p[1]));
      dot.setAttribute("r","5");dot.setAttribute("fill","#a6f1d1");
      svg.appendChild(dot);
      const text=document.createElementNS(ns,"text");
      text.setAttribute("x",String(p[0]));text.setAttribute("y","215");
      text.setAttribute("fill","#d4e8f5");text.setAttribute("text-anchor","middle");
      text.textContent=String(i+1);svg.appendChild(text);
    }
  };
  $("momentPick").addEventListener("change",async event=>{
    const files=Array.from(event.target.files??[]);
    event.target.value="";
    try{
      ensure(files.length>=2 && files.length<=MAX);
      const staged=[], seen=new Set();
      for(const file of files){
        ensure(file.size>0 && file.size<=LIMIT);
        const raw=new TextDecoder("utf-8",{fatal:true}).decode(
          await file.arrayBuffer());
        ensure(new TextEncoder().encode(raw).length<=LIMIT);
        ensure(!seen.has(raw));seen.add(raw);
        const state=savedSession(strictJSON(raw));
        staged.push(summary(state.packets)); // Only numeric counters survive.
      }
      if(timelineMoments.length &&
          !window.confirm("Replace the current private numbered moments with this new source-free selection?"))return;
      timelineMoments=staged;renderTimeline();
      $("momentStatus").textContent=files.length+" self-declared browser numeric sessions admitted. Input order is NOT verified calendar order.";
    }catch(_){
      $("momentStatus").textContent="HOLD: invalid session selection. Previous numbered moments remain unchanged.";
    }
  });
  $("momentClear").addEventListener("click",()=>{
    timelineMoments=[];renderTimeline();
    $("momentStatus").textContent="Private numbered moment counters cleared from memory.";
  });
  $("momentExportCSV").addEventListener("click",()=>{
    if(timelineMoments.length<2)return;
    const lines=["human_selected_ordinal_not_date,packets,slot_appearances,pending_human_questions_not_fixes,planned_human_attention,packet_count_changed"];
    for(const moment of numericTrendRows()){
      lines.push([moment.ordinal,moment.packets,moment.slots,moment.questions,
        moment.attention,moment.packet_count_changed?"1":"0"].join(","));
    }
    download("lightup-private-human-numbered-moments.csv","text/csv",
      lines.join("\r\n")+"\r\n");
    $("momentStatus").textContent="Source-free numbered moment CSV saved; no fixes or dates verified.";
  });
  $("momentExportJSON").addEventListener("click",()=>{
    if(timelineMoments.length<2)return;
    const data={
      kind:"lightup.private_human_browser_numbered_moments",
      schema_version:1,
      disposition:"UNVERIFIED_BROWSER_NUMERIC_SEQUENCE_NOT_ORIGINAL_EVIDENCE",
      snapshots:numericTrendRows(),
      warning:"Human-chosen numeric sequence only. No original timestamps, matching clients, verified fixes, source authenticity, consent, or target authority.",
      ...Object.fromEntries(FLAGS.map(k=>[k,false]))
    };
    download("lightup-private-human-numbered-moments.json","application/json",
      JSON.stringify(data,null,2)+"\n");
    $("momentStatus").textContent="Source-free numeric sequence saved as separate unverified browser JSON.";
  });

  const download=(name,mime,text)=>{
    const blob=new Blob([text],{type:mime});
    const url=URL.createObjectURL(blob);
    const anchor=document.createElement("a");
    anchor.download=name;anchor.href=url;anchor.textContent="Save "+name;
    document.body.appendChild(anchor);anchor.click();anchor.remove();
    setTimeout(()=>URL.revokeObjectURL(url),1000);
  };
  $("pick").addEventListener("change",async event=>{
    const files=Array.from(event.target.files??[]);
    event.target.value="";
    try{
      ensure(files.length>0 && entries.length+files.length<=MAX);
      const staged=[];
      for(const f of files){
        ensure(f.size>0 && f.size<=LIMIT);
        const raw=new TextDecoder("utf-8",{fatal:true}).decode(await f.arrayBuffer());
        ensure(new TextEncoder().encode(raw).length<=LIMIT);
        staged.push(admit(strictJSON(raw)));
      }
      entries=[...entries,...staged];
      humanActions.push(...staged.map(()=>({action:"none",state:"not_triaged"})));
      render();
      showStatus(files.length+" PRIVATE HUMAN count packet(s) admitted in memory.");
    }catch(_){
      showStatus("HOLD: selection rejected atomically; no files added.",true);
    }
  });
  $("clear").addEventListener("click",()=>{
    entries=[];humanActions=[];resumedFromNumericFile=false;render();showStatus("Current anonymous imports cleared. Earlier aggregate remains until forgotten.");
  });
  $("freeze").addEventListener("click",()=>{
    if(!entries.length)return;
    earlier=Object.freeze({...summary(entries)});
    render();showStatus("Earlier numeric counters frozen in memory. Clear current imports, then add later packets.");
  });
  $("forgetEarlier").addEventListener("click",()=>{
    earlier=null;render();showStatus("Earlier numeric snapshot forgotten.");
  });
  const brief = () => {
    const t=summary(entries);
    const lines=[
      "LIGHTUP | PRIVATE HUMAN FOLLOW-UP BRIEF",
      "Incubate M3/M7 PLAN-LAB ONLY / DRAFT HOLD",
      "Source-free anonymous packet appearances; NOT matched cases.",
      "No original source identity, evidence, consent, verified fix, or authority.",
      "",
      "Packet appearances: "+t.packets,
      "Source-free slot appearances: "+t.slots,
      "Pending HUMAN questions (not fixes): "+t.questions,
      "Planning-stage packets: "+t.planned,
      "Indistinguishable numeric profile appearances (not duplicates): "+t.possible_same_numeric_shape_appearances,
      "Attention slot appearances (only planning packets): "+t.attention,
      "Locally dated slot appearances (only planning packets): "+t.dated,
      "",
      "HUMAN FOLLOW-UP"
    ];
    if(t.questions)lines.push("Ask original HUMAN source-owners to review outstanding questions locally.");
    if(t.stages.unassigned)lines.push("Discuss assignment of unassigned slots in original PRIVATE workrooms.");
    if(t.stages.waiting_human)lines.push("Review waiting_human stages in original PRIVATE workrooms.");
    if(t.dated)lines.push("Review date-bearing slots only in original PRIVATE plans; exact dates are not imported.");
    if(t.packets!==t.planned)lines.push("Some packets lack HUMAN planning states; missing means NOT PROVIDED.");
    if(t.possible_same_numeric_shape_appearances)lines.push("Several packets share identical anonymous numeric profiles; this is NOT proof of duplicate source work.");
    lines.push("Confirm source overlap privately; packet appearance changes are NOT remediation.",
      "Counts may identify people in small populations; human disclosure approval required.",
      "");
    return lines.join("\n");
  };

  $("saveSession").addEventListener("click",()=>{
    if(!entries.length)return;
    try{
      download("lightup-private-human-browser-session.json","application/json",
        exportableSession());
      showStatus("Private source-free numeric session saved; it is NOT an original authenticated export.");
    }catch(_){showStatus("HOLD: session could not be exported.",true);}
  });
  $("resumeSession").addEventListener("change",async event=>{
    const files=Array.from(event.target.files??[]);
    event.target.value="";
    try{
      ensure(files.length===1 && files[0].size>0 && files[0].size<=LIMIT);
      const raw=new TextDecoder("utf-8",{fatal:true}).decode(
        await files[0].arrayBuffer());
      ensure(new TextEncoder().encode(raw).length<=LIMIT);
      const loaded=savedSession(strictJSON(raw));
      // The new complete numeric state is accepted before any existing
      // private current state is replaced. No partial import or coercion.
      if((entries.length>0 || earlier!==null) &&
          !window.confirm("Replace current in-memory HUMAN counts and earlier numeric baseline with this UNVERIFIED saved browser session?"))return;
      entries=loaded.packets;humanActions=loaded.packets.map(()=>
        ({action:"none",state:"not_triaged"}));earlier=loaded.earlier;
      resumedFromNumericFile=true;render();
      showStatus("Source-free HUMAN numeric browser session restored. No original source, key, or authority was checked.");
    }catch(_){
      showStatus("HOLD: saved browser session rejected. Existing selections unchanged.",true);
    }
  });

  $("exportJson").addEventListener("click",()=>{
    if(!entries.length)return;
    const totals=summary(entries);
    const payload={
      kind:"lightup.private_human_studio_numeric_snapshot",
      schema_version:1,
      disposition:"LOCAL_BROWSER_SOURCE_FREE_COUNTERS_NOT_ORIGINAL_ATTESTATION",
      packet_count:totals.packets,
      source_free_slot_appearances_not_unique:totals.slots,
      pending_human_questions_not_fixes:totals.questions,
      planning_packet_count:totals.planned,
      possible_same_numeric_shape_appearances_not_proven_duplicates:totals.possible_same_numeric_shape_appearances,
      human_attention_slot_appearances:totals.attention,
      locally_dated_slot_appearances:totals.dated,
      local_planning_stages:totals.stages,
      packets_in_original_local_selection_order:entries.map((x,i)=>({
        packet:i+1,source_type:x.type,slot_appearances:x.slots,
        pending_human_questions_not_fixes:x.questions,
        human_attention_slot_appearances:x.plan?.attention??null
      })),
      warning:"Self-reported source-free packet appearances only. No unique cases, authenticated source, verified findings/fixes, consent, grant or authority.",
      ...Object.fromEntries(FLAGS.map(key=>[key,false]))
    };
    download("lightup-human-browser-numeric-snapshot.json","application/json",
      JSON.stringify(payload,null,2)+"\n");
    showStatus("One source-free browser snapshot downloaded, not an original verified export.");
  });
  $("exportBrief").addEventListener("click",()=>{
    if(!entries.length)return;
    download("lightup-private-human-followup.txt","text/plain",brief());
    showStatus("Local PRIVATE HUMAN brief saved; no original evidence or identity included.");
  });
  $("exportDelta").addEventListener("click",()=>{
    if(earlier===null || entries.length===0)return;
    const now=summary(entries);
    const keys=["packets","slots","questions","attention","dated","planned"];
    const lines=["metric,earlier,later,change_in_packet_appearances"];
    for(const key of keys)lines.push([key,earlier[key],now[key],
      now[key]-earlier[key]].join(","));
    download("lightup-human-two-snapshot-counts.csv","text/csv",
      lines.join("\r\n")+"\r\n");
    showStatus("Local numeric delta saved. No matching cases or verified progress inferred.");
  });
  $("export").addEventListener("click",()=>{
    if(!entries.length)return;
    const rows=queue(entries);
    const values=["volume_rank,packet,questions_not_fixes,local_human_attention,slot_appearances,ordering"];
    for(const [i,r] of rows.entries())
      values.push([i+1,r.ordinal,r.questions,r.plan?.attention??"",r.slots,
        "human_question_volume_only"].join(","));
    download("lightup-human-volume-queue.csv","text/csv",
      values.join("\r\n")+"\r\n");
    showStatus("Local volume-only CSV saved. No source/authenticity verified.");
  });
  render();renderTimeline();
  showStatus("Offline studio ready. Select native counts-only exports to begin.");
})();
