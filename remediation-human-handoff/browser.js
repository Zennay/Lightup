"use strict";
(() => {
  const FLAGS=["authenticated","tenant_verified","source_authorized","assessment_authorized",
    "grant","client_consent","operator_consent","execution","scan","audit_verdict",
    "retest_verified","release"];
  const STAGES=["unassigned","assigned","waiting_human","locally_answered"];
  const ACTIONS={
    none:"No next action",
    request_fresh_source_export:"Ask original owner for fresh source export",
    discuss_open_questions:"Discuss unanswered HUMAN questions",
    clarify_human_assignment:"Discuss HUMAN assignment",
    reconcile_anonymous_coverage:"Clarify possible anonymous coverage overlap",
    request_original_human_review:"Request authentic HUMAN review"
  };
  const STATES={
    not_triaged:"Not triaged locally",
    needs_human_followup:"Needs HUMAN follow-up",
    waiting_original_owner:"Waiting for original HUMAN owner",
    locally_discussed:"Locally discussed — NOT a verified fix"
  };
  const SESS_FIELDS=["kind","schema_version","disposition","packets","earlier_numeric_aggregate","warning",...FLAGS];
  const BOARD_FIELDS=["kind","schema_version","disposition","numeric_packets","assignments","warning",...FLAGS];
  const PACKET_FIELDS=["type","slots","questions","plan"];
  const PLAN_FIELDS=["attention","dated","stages"];
  const AGG_FIELDS=["packets","slots","questions","attention","dated","planned","possible_same_numeric_shape_appearances","stages"];
  const SESS_WARN="Self-declared private HUMAN counts only; does not authenticate original source, consent, findings, fixes, grants, or users.";
  const BOARD_WARN="Anonymous local HUMAN routing choices only. Not unique cases, original source authentication, verified security findings, consent, grant, remediation or action permission.";
  const HANDOFF_WARN="LOCAL SOURCE-FREE HUMAN PLANNING ONLY. Anonymous numeric packet ordinals do not identify original clients, findings, security issues, fixes or consent. All states are self-declared; there is no scan, grant, authenticated evidence or actual delivery.";
  const $=id=>document.getElementById(id);
  let session=null, original=null, draft=null, peer=null;
  const fail=()=>{throw Error("HOLD");};
  const ensure=value=>{if(!value)fail();};
  const number=(x,lo,hi)=>Number.isSafeInteger(x)&&x>=lo&&x<=hi;
  const exact=(obj,fields)=>obj!==null&&typeof obj==="object"&&!Array.isArray(obj)
    &&Object.keys(obj).length===fields.length&&fields.every(f=>Object.prototype.hasOwnProperty.call(obj,f));
  const header=(v,fields,kind,disposition,warning)=>{
    ensure(exact(v,fields)&&v.kind===kind&&v.schema_version===1
      &&v.disposition===disposition&&v.warning===warning
      &&FLAGS.every(f=>v[f]===false));
  };
  const clone=v=>JSON.parse(JSON.stringify(v));
  const flags=()=>Object.fromEntries(FLAGS.map(f=>[f,false]));
  const same=(a,b)=>{
    if(a===b)return true;
    if(typeof a!==typeof b||a===null||b===null)return false;
    if(typeof a!=="object")return false;
    if(Array.isArray(a)||Array.isArray(b)){
      return Array.isArray(a)&&Array.isArray(b)&&a.length===b.length
        &&a.every((v,i)=>same(v,b[i]));
    }
    const keysA=Object.keys(a),keysB=Object.keys(b);
    return keysA.length===keysB.length
      &&keysA.every(k=>Object.prototype.hasOwnProperty.call(b,k)&&same(a[k],b[k]));
  };
  const message=(s,isHold=false)=>{
    $("status").textContent=s;
    $("status").dataset.status=isHold?"hold":"ready";
  };
  const td=(tr,text,tag="td")=>{
    const cell=document.createElement(tag);
    cell.textContent=String(text);
    tr.appendChild(cell);return cell;
  };
  const strictJSON=raw=>{
    let pos=0,nodes=0;
    const ws=()=>{while(pos<raw.length&&" \n\r\t".includes(raw[pos]))pos++;};
    const string=()=>{
      const start=pos;
      if(raw[pos++]!=='"')fail();
      while(pos<raw.length){
        const c=raw[pos++];
        if(c==='"')return JSON.parse(raw.slice(start,pos));
        if(c==="\\"){
          const e=raw[pos++];
          if(!e||!'"\\/bfnrtu'.includes(e))fail();
          if(e==="u"){
            if(!/^[a-fA-F0-9]{4}$/.test(raw.slice(pos,pos+4)))fail();
            pos+=4;
          }
        }else if(c.charCodeAt(0)<32)fail();
      }
      fail();
    };
    const value=depth=>{
      ws();
      if(++nodes>2048||depth>14)fail();
      const c=raw[pos];
      if(c==='"'){string();return;}
      if(c==="{"){
        pos++;ws();
        const seen=new Set();
        if(raw[pos]==="}"){pos++;return;}
        while(pos<raw.length){
          ws();const k=string();if(seen.has(k))fail();seen.add(k);ws();
          if(raw[pos++]!==":")fail();value(depth+1);ws();
          if(raw[pos]==="}"){pos++;return;}
          if(raw[pos++]!==",")fail();
        }fail();
      }
      if(c==="["){
        pos++;ws();
        if(raw[pos]==="]"){pos++;return;}
        while(pos<raw.length){
          value(depth+1);ws();
          if(raw[pos]==="]"){pos++;return;}
          if(raw[pos++]!==",")fail();
        }fail();
      }
      const found=/^(?:true|false|null|(?:0|[1-9]\d*))/.exec(raw.slice(pos));
      if(!found)fail();pos+=found[0].length;
    };
    value(0);ws();ensure(pos===raw.length);
    return JSON.parse(raw);
  };
  const read=async file=>{
    ensure(file&&file.size>0&&file.size<=16384);
    const bytes=await file.arrayBuffer();
    ensure(bytes.byteLength===file.size&&bytes.byteLength<=16384);
    const value=strictJSON(new TextDecoder("utf-8",{fatal:true}).decode(bytes));
    return value;
  };
  const stages=(v,slots)=>{
    ensure(exact(v,STAGES)&&STAGES.every(k=>number(v[k],0,slots))
      &&STAGES.reduce((t,k)=>t+v[k],0)===slots);
    return clone(v);
  };
  const plan=(v,slots)=>{
    ensure(exact(v,PLAN_FIELDS)&&number(v.attention,0,slots)
      &&number(v.dated,0,slots));
    const values=stages(v.stages,slots);
    ensure(v.attention===slots-values.locally_answered);
    return {attention:v.attention,dated:v.dated,stages:values};
  };
  const previous=v=>{
    ensure(exact(v,AGG_FIELDS)&&number(v.packets,1,12)
      &&number(v.slots,v.packets,144)&&number(v.questions,0,12000000)
      &&number(v.attention,0,v.slots)&&number(v.dated,0,v.slots)
      &&number(v.planned,0,v.packets)
      &&number(v.possible_same_numeric_shape_appearances,0,v.packets)
      &&exact(v.stages,STAGES)&&STAGES.every(k=>number(v.stages[k],0,v.slots))
      &&STAGES.reduce((t,k)=>t+v.stages[k],0)<=v.slots
      &&(v.planned!==0||(v.attention===0&&v.dated===0
        &&STAGES.every(k=>v.stages[k]===0))));
  };
  const acceptSession=v=>{
    header(v,SESS_FIELDS,"lightup.private_human_browser_numeric_session",
      "LOCAL_BROWSER_ONLY_NO_ORIGINAL_SOURCE_ATTESTATION",SESS_WARN);
    ensure(Array.isArray(v.packets)&&v.packets.length>=1&&v.packets.length<=12);
    const packets=v.packets.map(packet=>{
      ensure(exact(packet,PACKET_FIELDS)
        &&(packet.type==="inbox"||packet.type==="workroom")
        &&number(packet.slots,1,12)&&number(packet.questions,0,1000000));
      if(packet.type==="inbox"){ensure(packet.plan===null);}
      const normalized=packet.type==="inbox"?null:plan(packet.plan,packet.slots);
      return {type:packet.type,slots:packet.slots,questions:packet.questions,plan:normalized};
    });
    if(v.earlier_numeric_aggregate!==null)previous(v.earlier_numeric_aggregate);
    return packets;
  };
  const acceptBoard=(v,packets)=>{
    header(v,BOARD_FIELDS,"lightup.private_human_anonymous_followup_board",
      "LOCAL_HUMAN_FOLLOWUP_ONLY_NO_SOURCE_AUTHORITY",BOARD_WARN);
    ensure(Array.isArray(v.numeric_packets)&&v.numeric_packets.length===packets.length
      &&Array.isArray(v.assignments)&&v.assignments.length===packets.length);
    const canonical=p=>({type:p.type,slots:p.slots,questions:p.questions,
      plan:p.plan===null?null:clone(p.plan)});
    const expected=packets.map(canonical);
    for(let i=0;i<packets.length;i++){
      const p=v.numeric_packets[i];
      ensure(exact(p,PACKET_FIELDS)&&same(p,expected[i]));
      const a=v.assignments[i];
      ensure(exact(a,["ordinal","action","state"])&&a.ordinal===i+1
        &&typeof a.action==="string"&&Object.hasOwn(ACTIONS,a.action)
        &&typeof a.state==="string"&&Object.hasOwn(STATES,a.state));
    }
    return clone(v.assignments);
  };
  const active=()=>{ensure(session!==null&&original!==null&&draft!==null);};
  const updatedBoard=()=>{
    active();
    const board={kind:"lightup.private_human_anonymous_followup_board",
      schema_version:1,disposition:"LOCAL_HUMAN_FOLLOWUP_ONLY_NO_SOURCE_AUTHORITY",
      numeric_packets:clone(session),assignments:clone(draft),
      warning:BOARD_WARN,...flags()};
    acceptBoard(board,session);
    return board;
  };
  const download=(name,value,mime)=>{
    const blob=new Blob([value],{type:mime||"text/plain;charset=utf-8"});
    const url=URL.createObjectURL(blob);
    const link=document.createElement("a");
    link.href=url;link.download=name;document.body.appendChild(link);
    link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
  };
  const csvText=rows=>rows.map(row=>row.join(",")).join("\r\n")+"\r\n";
  const disabled=off=>{
    for(const name of ["saveBoard","summary","handoffCsv","handoffTxt","handoffHtml","deltaCsv","reset"])$(name).disabled=off;
    $("actionFilter").disabled=off;
    $("ordinalFilter").disabled=off;
  };
  const resetState=()=>{
    session=null;original=null;draft=null;peer=null;
    $("rows").replaceChildren();$("counts").textContent="No private session loaded";
    $("sourceStatus").textContent="Not imported";
    const ord=$("ordinalFilter");ord.replaceChildren();
    const opt=document.createElement("option");opt.value="all";
    opt.textContent="All anonymous local ordinals";ord.appendChild(opt);
    disabled(true);renderPeer();
  };
  const render=()=>{
    active();const rows=$("rows");rows.replaceChildren();
    const filters=new Map(Object.keys(ACTIONS).map(k=>[k,0]));
    let changes=0,questions=0;
    draft.forEach((row,i)=>{
      filters.set(row.action,filters.get(row.action)+1);
      questions+=session[i].questions;
      if(!same(row,original[i]))changes++;
      const tr=document.createElement("tr");
      td(tr,i+1,"th");td(tr,session[i].type);
      td(tr,session[i].slots);td(tr,session[i].questions);
      const actions=td(tr,"");const selectA=document.createElement("select");
      selectA.setAttribute("aria-label","Action for local ordinal "+(i+1));
      Object.keys(ACTIONS).forEach(code=>{
        const opt=document.createElement("option");opt.value=code;opt.textContent=ACTIONS[code];
        selectA.appendChild(opt);
      });
      selectA.value=row.action;
      selectA.addEventListener("change",()=>{row.action=selectA.value;render();});
      actions.appendChild(selectA);
      const states=td(tr,"");const selectS=document.createElement("select");
      selectS.setAttribute("aria-label","State for local ordinal "+(i+1));
      Object.keys(STATES).forEach(code=>{
        const opt=document.createElement("option");opt.value=code;opt.textContent=STATES[code];
        selectS.appendChild(opt);
      });
      selectS.value=row.state;
      selectS.addEventListener("change",()=>{row.state=selectS.value;render();});
      states.appendChild(selectS);rows.appendChild(tr);
    });
    const action=$("actionFilter").value;
    const ordinal=$("ordinalFilter").value;
    const count=draft.filter((row,i)=>row.action!=="none" &&
      (action==="all"||row.action===action) &&
      (ordinal==="all"||String(i+1)===ordinal)).length;
    $("counts").textContent=String(draft.length)+" anonymous packet appearances · "+
      String(questions)+" HUMAN question appearances · "+String(changes)+
      " locally edited routing choices";
    $("selectionCount").textContent=String(count);
    const found=count>0;
    for(const k of ["handoffCsv","handoffTxt","handoffHtml"])$(k).disabled=!found;
    $("deltaCsv").disabled=changes===0;
    $("saveBoard").disabled=changes===0;
    $("sourceStatus").textContent="Self-declared PRIVATE numeric session + exactly matched board; NOT source authenticated";
    renderPeer();
  };
  const renderPeer=()=>{
    const body=$("peerRows");body.replaceChildren();
    $("peerCsv").disabled=true;
    if(peer===null){
      $("peerSummary").textContent="No second HUMAN board admitted.";
      return;
    }
    if(session===null){peer=null;return;}
    let divergent=0,adopted=0;
    peer.forEach((candidate,i)=>{
      const base=original[i],current=draft[i];
      if(same(candidate,base))return;
      divergent++;
      if(same(candidate,current))adopted++;
      const tr=document.createElement("tr");
      td(tr,i+1,"th");
      td(tr,ACTIONS[base.action]+" / "+STATES[base.state]);
      td(tr,ACTIONS[candidate.action]+" / "+STATES[candidate.state]);
      td(tr,ACTIONS[current.action]+" / "+STATES[current.state]);
      const cell=td(tr,"");
      const button=document.createElement("button");
      button.type="button";button.textContent="Use peer choice locally";
      button.disabled=same(candidate,current);
      button.setAttribute("aria-label","Adopt self-declared peer choice for local ordinal "+(i+1));
      button.addEventListener("click",()=>{
        if(!confirm("Use the anonymous peer-suggested HUMAN choice for local ordinal "+
          (i+1)+"? It does not identify original cases or authenticate a reviewer."))return;
        draft[i]={ordinal:i+1,action:candidate.action,state:candidate.state};
        render();
        message("One locally suggested peer choice adopted; no real source record changed.");
      });
      cell.appendChild(button);body.appendChild(tr);
    });
    $("peerSummary").textContent=divergent+" anonymous peer-vs-base routing differences; "+
      adopted+" currently match the local draft. Same ordinals are NOT case identity.";
    $("peerCsv").disabled=divergent===0;
  };
  const peerDiffCsv=()=>{
    active();ensure(peer!==null);
    const diffs=[];
    peer.forEach((candidate,i)=>{
      const base=original[i],current=draft[i];
      if(same(candidate,base))return;
      diffs.push([i+1,base.action,candidate.action,current.action,
        base.state,candidate.state,current.state]);
    });
    ensure(diffs.length>0);
    return csvText([["local_ordinal_not_case","base_action","peer_action",
      "current_local_action","base_state","peer_state","current_local_state"],...diffs]);
  };
  const chosen=()=>{
    active();
    const filter=$("actionFilter").value;
    const ordinal=$("ordinalFilter").value;
    const rows=draft.map((r,i)=>({ordinal:i+1,action:r.action,state:r.state,
      type:session[i].type,slots:session[i].slots,questions:session[i].questions}))
      .filter(row=>row.action!=="none"&&(filter==="all"||filter===row.action)
        &&(ordinal==="all"||String(row.ordinal)===ordinal));
    ensure(rows.length>0);
    return rows.sort((a,b)=>b.questions-a.questions||a.ordinal-b.ordinal);
  };
  const handoffCsv=rows=>csvText([
    ["local_packet_ordinal_not_case","count_type","slot_appearances_not_unique",
      "unverified_human_question_appearances","human_action","local_state"],
    ...rows.map(r=>[r.ordinal,r.type,r.slots,r.questions,r.action,r.state])
  ]);
  const safe=s=>String(s).replaceAll("&","&amp;").replaceAll("<","&lt;")
    .replaceAll(">","&gt;").replaceAll('"',"&quot;");
  const handoffHtml=rows=>{
    const table=rows.map(r=>"<tr><th>"+r.ordinal+"</th><td>"+safe(r.type)+
      "</td><td>"+r.slots+"</td><td>"+r.questions+"</td><td>"+safe(ACTIONS[r.action])+
      "</td><td>"+safe(STATES[r.state])+"</td></tr>").join("");
    return '<!doctype html><html lang="en"><head><meta charset="utf-8">'+
      '<meta name="viewport" content="width=device-width,initial-scale=1">'+
      '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; connect-src &#39;none&#39;; base-uri &#39;none&#39;">'+
      '<title>LightUp PRIVATE HUMAN follow-up</title><style>body{font:16px/1.5 system-ui;'+
      'margin:auto;max-width:1050px;padding:40px;background:#101b2d;color:#eaf4fa}'+
      'p{max-width:880px}table{width:100%;border-collapse:collapse}th,td{padding:12px;'+
      'border-bottom:1px solid #536578;text-align:left}@media print{body{background:white;'+
      'color:black}}</style></head><body><small>INCUBATE / M3-M7 / DRAFT HOLD / HUMAN ONLY</small>'+
      '<h1>Local HUMAN action handoff — NOT SENT</h1><p>'+safe(HANDOFF_WARN)+
      '</p><p>Manually ask the current authenticated original HUMAN owner before'+
      ' making any real decision. This report does not map local ordinals to real cases.</p>'+
      '<table><thead><tr><th>Ordinal</th><th>Type</th><th>Slots</th><th>Questions</th>'+
      '<th>Proposed action</th><th>Local state</th></tr></thead><tbody>'+table+
      '</tbody></table></body></html>';
  };
  const handoffTxt=rows=>[
    "LIGHTUP / PRIVATE HUMAN LOCAL FOLLOW-UP / DRAFT HOLD / NOT SENT",HANDOFF_WARN,"",
    ...rows.map(r=>"Local ordinal "+r.ordinal+" (not case), "+r.questions+
      " unverified questions: "+ACTIONS[r.action]+"; "+STATES[r.state]),
    "","Authenticate original source, actual owner and permission separately."
  ].join("\n")+"\n";
  const deltaCsv=()=>{
    active();const diff=[];
    draft.forEach((v,i)=>{const prior=original[i];
      if(!same(v,prior))diff.push([i+1,prior.action,v.action,prior.state,v.state]);
    });
    ensure(diff.length>0);
    return csvText([["local_ordinal_not_case","earlier_local_action","later_local_action",
      "earlier_local_state","later_local_state"],...diff]);
  };
  const summary=()=>{
    active();
    return {kind:"lightup.private_browser_human_routing_preview",schema_version:1,
      disposition:"LOCAL_SELF_DECLARED_COUNTS_ONLY_DRAFT_HOLD",
      packet_appearances_not_unique:session.length,
      local_state_counts:Object.fromEntries(Object.keys(STATES)
        .map(state=>[state,draft.filter(x=>x.state===state).length])),
      local_action_counts:Object.fromEntries(Object.keys(ACTIONS)
        .map(action=>[action,draft.filter(x=>x.action===action).length])),
      changed_local_routing_appearances:draft.filter((x,i)=>!same(x,original[i])).length,
      warning:HANDOFF_WARN,...flags()};
  };
  const load=async()=>{
    // Transactional whole-pair admission: either both exact current inputs
    // become usable or neither does. Never silently fall back to stale files.
    resetState();
    try{
      const [s,b]=await Promise.all([read($("sessionFile").files[0]),
        read($("boardFile").files[0])]);
      const p=acceptSession(s);
      const a=acceptBoard(b,p);
      session=p;original=clone(a);draft=clone(a);
      const choice=$("ordinalFilter");
      for(let i=1;i<=session.length;i++){
        const opt=document.createElement("option");opt.value=String(i);
        opt.textContent="Local ordinal "+i+" (NOT case)";
        choice.appendChild(opt);
      }
      disabled(false);render();
      message("Private local pair admitted. HUMAN-only self-declared numbers; no original authority.");
    }catch(_){
      resetState();
      message("HOLD: no private session/board loaded. Check original export schema, size, flags and exact paired ordinals.",true);
    }
  };
  const loadPeer=async()=>{
    peer=null;renderPeer();
    try{
      active();
      const incoming=await read($("peerFile").files[0]);
      const imported=acceptBoard(incoming,session);
      peer=clone(imported);renderPeer();
      message("Second source-free local board admitted. Changes are proposed, not authentic owner decisions.");
    }catch(_){
      peer=null;renderPeer();
      message("HOLD: peer board not admitted; existing local HUMAN choices unchanged.",true);
    }
  };
  $("peerFile").addEventListener("change",()=>{
    peer=null;renderPeer();message("Second board changed: click Load second board for exact session admission.");
  });
  $("loadPeer").addEventListener("click",loadPeer);
  $("clearPeer").addEventListener("click",()=>{
    peer=null;$("peerFile").value="";renderPeer();
    message("Second local board cleared without changing current HUMAN choices.");
  });
  $("peerCsv").addEventListener("click",()=>{
    try{download("lightup-private-local-peer-choices.csv",peerDiffCsv(),"text/csv");}
    catch(_){message("HOLD: no admitted anonymous local peer differences.",true);}
  });
  $("load").addEventListener("click",load);
  for(const k of ["sessionFile","boardFile"])$(k).addEventListener("change",()=>{
    resetState();message("Inputs changed: both files must be admitted together again.");
  });
  $("reset").addEventListener("click",()=>{
    active();if(!confirm("Reset all local changes to original source-free board choices?"))return;
    draft=clone(original);render();message("Local choices reset; original files unchanged.");
  });
  $("actionFilter").addEventListener("change",()=>{if(session)render();});
  $("ordinalFilter").addEventListener("change",()=>{if(session)render();});
  $("saveBoard").addEventListener("click",()=>{
    try{const board=updatedBoard();download("lightup-private-human-board-return.json",
      JSON.stringify(board,null,2)+"\n","application/json");message("Native private board downloaded; manually restore against same numeric Studio session.");}
    catch(_){message("HOLD: invalid local private board; no export.",true);}
  });
  $("summary").addEventListener("click",()=>{
    try{download("lightup-private-human-routing-preview.json",
      JSON.stringify(summary(),null,2)+"\n","application/json");}
    catch(_){message("HOLD: no valid source-free numbers.",true);}
  });
  $("handoffCsv").addEventListener("click",()=>{try{
    download("lightup-local-human-handoff.csv",handoffCsv(chosen()),"text/csv");
  }catch(_){message("HOLD: no selected HUMAN action appearances.",true);}});
  $("handoffTxt").addEventListener("click",()=>{try{
    download("lightup-local-human-handoff.txt",handoffTxt(chosen()));
  }catch(_){message("HOLD: no selected HUMAN action appearances.",true);}});
  $("handoffHtml").addEventListener("click",()=>{try{
    download("lightup-local-human-handoff.html",handoffHtml(chosen()),"text/html");
  }catch(_){message("HOLD: no selected HUMAN action appearances.",true);}});
  $("deltaCsv").addEventListener("click",()=>{try{
    download("lightup-local-routing-changes.csv",deltaCsv(),"text/csv");
  }catch(_){message("HOLD: no local changes to compare.",true);}});
  resetState();message("Offline. Select the original private numeric session and matching HUMAN board.");
})();
