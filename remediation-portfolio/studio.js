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
        render();showStatus("One anonymous packet removed from memory.");
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
    $("missing").textContent=String(total.packets-total.planned);
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
      entries=[...entries,...staged];render();
      showStatus(files.length+" PRIVATE HUMAN count packet(s) admitted in memory.");
    }catch(_){
      showStatus("HOLD: selection rejected atomically; no files added.",true);
    }
  });
  $("clear").addEventListener("click",()=>{
    entries=[];render();showStatus("Current anonymous imports cleared. Earlier aggregate remains until forgotten.");
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
  render();
  showStatus("Offline studio ready. Select native counts-only exports to begin.");
})();
