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
  let session=null, original=null, draft=null, peer=null, sourceSession=null;
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
    $("saveEncryptedHandoff").disabled=off || !globalThis.crypto?.subtle;
    $("saveEncrypted").disabled=off || !globalThis.crypto?.subtle;
  };
  const resetState=()=>{
    session=null;original=null;draft=null;peer=null;sourceSession=null;
    $("rows").replaceChildren();$("counts").textContent="No private session loaded";
    $("sourceStatus").textContent="Not imported";
    $("unlockedHandoffRows").replaceChildren();
    $("unlockedHandoffStatus").textContent="No encrypted handoff opened.";
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
    $("saveEncryptedHandoff").disabled=!found || !globalThis.crypto?.subtle;
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
      session=p;original=clone(a);draft=clone(a);sourceSession=clone(s);
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
  // AES-256-GCM with independent random salt/nonce and password-based PBKDF2.
  // No server, key escrow or persisted browser state. The complete plaintext
  // is authenticated under a fixed domain and independently re-admitted.
  const CRYPTO_MODES={
    workspace:{
      aad:"LIGHTUP_PRIVATE_HUMAN_LOCAL_WORKSESSION_AES_GCM_V1",
      kind:"lightup.private_human_encrypted_workspace_v1"
    },
    handoff:{
      aad:"LIGHTUP_PRIVATE_HUMAN_LOCAL_HANDOFF_AES_GCM_V1",
      kind:"lightup.private_human_encrypted_handoff_v1"
    }
  };
  const CRYPTO_ITERATIONS=600000;
  const CRYPTO_FIELDS=["kind","schema_version","disposition","kdf","iterations",
    "salt_b64","nonce_b64","ciphertext_b64"];
  const VAULT_FIELDS=["kind","schema_version","disposition","original_session",
    "original_board","working_board","peer_board","warning",...FLAGS];
  const VAULT_WARNING="Self-declared encrypted offline HUMAN routing draft. Not original authenticated evidence, client identity, consent, remediation, grant, verified fix or release.";
  const encoder=new TextEncoder();
  const decoder=new TextDecoder("utf-8",{fatal:true});
  const b64=bytes=>{
    let text="";
    for(let i=0;i<bytes.length;i+=8192)
      text+=String.fromCharCode(...bytes.subarray(i,i+8192));
    return btoa(text);
  };
  const fromB64=(s,min,max)=>{
    ensure(typeof s==="string" && s.length>0 && s.length<=max*2
      && /^[A-Za-z0-9+/]+={0,2}$/.test(s));
    const raw=atob(s);
    ensure(raw.length>=min&&raw.length<=max);
    const bytes=Uint8Array.from(raw,c=>c.charCodeAt(0));
    ensure(b64(bytes)===s);
    return bytes;
  };
  const passwordBytes=s=>{
    ensure(typeof s==="string" && s===s.normalize("NFC")
      && [...s].length>=14 && [...s].length<=256 && s.trim()===s);
    const bytes=encoder.encode(s);
    ensure(bytes.length>=14&&bytes.length<=1024);
    return bytes;
  };
  const aesKey=async(secret,salt)=>{
    ensure(globalThis.crypto?.subtle&&globalThis.crypto?.getRandomValues);
    const material=await crypto.subtle.importKey("raw",passwordBytes(secret),
      {name:"PBKDF2"},false,["deriveKey"]);
    return crypto.subtle.deriveKey(
      {name:"PBKDF2",hash:"SHA-256",salt,iterations:CRYPTO_ITERATIONS},
      material,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
  };
  const originalBoard=()=>{
    active();
    const payload={
      kind:"lightup.private_human_anonymous_followup_board",
      schema_version:1,disposition:"LOCAL_HUMAN_FOLLOWUP_ONLY_NO_SOURCE_AUTHORITY",
      numeric_packets:clone(session),assignments:clone(original),
      warning:BOARD_WARN,...flags()
    };
    acceptBoard(payload,session);
    return payload;
  };
  const peerBoard=()=>{
    if(peer===null)return null;
    const payload={...originalBoard(),assignments:clone(peer)};
    acceptBoard(payload,session);
    return payload;
  };
  const vaultSnapshot=()=>{
    active();ensure(sourceSession!==null);
    const payload={
      kind:"lightup.private_human_encrypted_workspace_payload",
      schema_version:1,
      disposition:"SELF_DECLARED_LOCAL_HUMAN_ONLY_DRAFT_HOLD",
      original_session:clone(sourceSession),
      original_board:originalBoard(),
      working_board:updatedBoard(),
      peer_board:peerBoard(),
      warning:VAULT_WARNING,
      ...flags()
    };
    vaultAdmit(payload);
    return payload;
  };
  const vaultAdmit=payload=>{
    header(payload,VAULT_FIELDS,"lightup.private_human_encrypted_workspace_payload",
      "SELF_DECLARED_LOCAL_HUMAN_ONLY_DRAFT_HOLD",VAULT_WARNING);
    const p=acceptSession(payload.original_session);
    const o=acceptBoard(payload.original_board,p);
    const w=acceptBoard(payload.working_board,p);
    const peerChoices=payload.peer_board===null?null:acceptBoard(payload.peer_board,p);
    ensure(p.length===o.length && p.length===w.length);
    return {packets:p,initial:o,current:w,other:peerChoices,source:payload.original_session};
  };
  const seal=async(payload,secret,scope="workspace")=>{
    ensure(Object.hasOwn(CRYPTO_MODES,scope));
    const plaintext=encoder.encode(JSON.stringify(payload));
    ensure(plaintext.length>0&&plaintext.length<=65536);
    const salt=crypto.getRandomValues(new Uint8Array(16));
    const nonce=crypto.getRandomValues(new Uint8Array(12));
    const key=await aesKey(secret,salt);
    const ciphertext=new Uint8Array(await crypto.subtle.encrypt({
      name:"AES-GCM",iv:nonce,additionalData:encoder.encode(CRYPTO_MODES[scope].aad),
      tagLength:128
    },key,plaintext));
    return {
      kind:CRYPTO_MODES[scope].kind,
      schema_version:1,
      disposition:"PASSWORD_ENCRYPTED_LOCAL_FILE_NOT_SOURCE_AUTHORITY",
      kdf:"PBKDF2-HMAC-SHA256-AES256GCM",
      iterations:CRYPTO_ITERATIONS,
      salt_b64:b64(salt),
      nonce_b64:b64(nonce),
      ciphertext_b64:b64(ciphertext)
    };
  };
  const openSealed=async(envelope,secret,scope="workspace")=>{
    ensure(Object.hasOwn(CRYPTO_MODES,scope));
    ensure(exact(envelope,CRYPTO_FIELDS)
      && envelope.kind===CRYPTO_MODES[scope].kind
      && envelope.schema_version===1
      && envelope.disposition==="PASSWORD_ENCRYPTED_LOCAL_FILE_NOT_SOURCE_AUTHORITY"
      && envelope.kdf==="PBKDF2-HMAC-SHA256-AES256GCM"
      && envelope.iterations===CRYPTO_ITERATIONS);
    const salt=fromB64(envelope.salt_b64,16,16);
    const nonce=fromB64(envelope.nonce_b64,12,12);
    const ciphertext=fromB64(envelope.ciphertext_b64,17,65600);
    const key=await aesKey(secret,salt);
    const plain=new Uint8Array(await crypto.subtle.decrypt({
      name:"AES-GCM",iv:nonce,additionalData:encoder.encode(CRYPTO_MODES[scope].aad),
      tagLength:128
    },key,ciphertext));
    ensure(plain.length>0&&plain.length<=65536);
    const payload=strictJSON(decoder.decode(plain));
    return scope==="workspace"?vaultAdmit(payload):handoffAdmit(payload);
  };
  const drawRestored=state=>{
    resetState();
    session=clone(state.packets);
    original=clone(state.initial);
    draft=clone(state.current);
    peer=state.other===null?null:clone(state.other);
    sourceSession=clone(state.source);
    const choice=$("ordinalFilter");
    for(let i=1;i<=session.length;i++){
      const opt=document.createElement("option");
      opt.value=String(i);opt.textContent="Local ordinal "+i+" (NOT case)";
      choice.appendChild(opt);
    }
    disabled(false);render();
  };
  $("saveEncrypted").addEventListener("click",async()=>{
    const secret=$("saveSecret").value;
    const repeated=$("confirmSecret").value;
    $("saveSecret").value="";$("confirmSecret").value="";
    $("saveEncrypted").disabled=true;
    try{
      ensure(secret===repeated);
      const payload=vaultSnapshot();
      const file=await seal(payload,secret);
      download("lightup-private-human-encrypted-worksession.lhew",
        JSON.stringify(file,null,2)+"\n","application/json");
      message("Encrypted PRIVATE workspace downloaded; retain password separately. No authenticated evidence or client data was verified.");
    }catch(_){
      message("HOLD: encryption unavailable, invalid password or source-free local session. No encrypted file saved.",true);
    }finally{
      $("saveEncrypted").disabled=session===null || !globalThis.crypto?.subtle;
    }
  });
  $("restoreEncrypted").addEventListener("click",async()=>{
    const secret=$("unlockSecret").value;
    $("unlockSecret").value="";
    $("restoreEncrypted").disabled=true;
    try{
      const file=$("encryptedFile").files[0];
      ensure(file&&file.size>0&&file.size<=131072);
      const bytes=await file.arrayBuffer();
      ensure(bytes.byteLength===file.size);
      const envelope=strictJSON(decoder.decode(bytes));
      const restored=await openSealed(envelope,secret);
      ensure(session===null||confirm(
        "Replace current unsaved LOCAL HUMAN browser choices with the decrypted self-declared private workspace?"));
      drawRestored(restored);
      message("Encrypted PRIVATE HUMAN session restored; independently re-admitted entire original numeric and native routing board lineage. No source authority.");
    }catch(_){
      message("HOLD: private session not restored. Password, file integrity, schema or local confirmation invalid. Existing choices unchanged.",true);
    }finally{
      $("restoreEncrypted").disabled=false;
    }
  });
  const HANDOFF_FIELDS=["kind","schema_version","disposition","rows",
    "warning",...FLAGS];
  const HANDOFF_ROW_FIELDS=["ordinal","type","slots","questions","action","state"];
  const HANDOFF_CAP_WARNING="Encrypted locally selected HUMAN follow-up counts only. An ordinal is NOT an authenticated case, recipient, finding, consent, original evidence, reviewer decision, remediation, scan authority or release.";
  const handoffAdmit=packet=>{
    header(packet,HANDOFF_FIELDS,"lightup.private_human_encrypted_handoff_payload",
      "LOCAL_SELECTED_HUMAN_COUNTS_DRAFT_HOLD",HANDOFF_CAP_WARNING);
    ensure(Array.isArray(packet.rows)&&packet.rows.length>=1&&packet.rows.length<=12);
    let lastOrdinal=0;
    return packet.rows.map(row=>{
      ensure(exact(row,HANDOFF_ROW_FIELDS)
        &&number(row.ordinal,lastOrdinal+1,12)
        &&(row.type==="inbox"||row.type==="workroom")
        &&number(row.slots,1,12)
        &&number(row.questions,0,1000000)
        &&typeof row.action==="string"&&Object.hasOwn(ACTIONS,row.action)
        &&row.action!=="none"
        &&typeof row.state==="string"&&Object.hasOwn(STATES,row.state));
      lastOrdinal=row.ordinal;
      return clone(row);
    });
  };
  const handoffSnapshot=()=>{
    const selected=chosen().sort((a,b)=>a.ordinal-b.ordinal)
      .map(r=>({ordinal:r.ordinal,type:r.type,slots:r.slots,
        questions:r.questions,action:r.action,state:r.state}));
    const packet={
      kind:"lightup.private_human_encrypted_handoff_payload",
      schema_version:1,
      disposition:"LOCAL_SELECTED_HUMAN_COUNTS_DRAFT_HOLD",
      rows:selected,warning:HANDOFF_CAP_WARNING,...flags()
    };
    handoffAdmit(packet);
    return packet;
  };
  const displayUnlockedHandoff=rows=>{
    const body=$("unlockedHandoffRows");
    body.replaceChildren();
    for(const r of rows){
      const tr=document.createElement("tr");
      td(tr,r.ordinal,"th");td(tr,r.type);
      td(tr,r.slots);td(tr,r.questions);
      td(tr,ACTIONS[r.action]);td(tr,STATES[r.state]);body.appendChild(tr);
    }
    $("unlockedHandoffStatus").textContent=
      rows.length+" locally selected anonymous HUMAN appearances. NOT sent, authenticated or verified.";
  };
  $("saveEncryptedHandoff").addEventListener("click",async()=>{
    const secret=$("handoffSecret").value;
    const confirmSecret=$("handoffConfirm").value;
    $("handoffSecret").value="";$("handoffConfirm").value="";
    $("saveEncryptedHandoff").disabled=true;
    try{
      ensure(secret===confirmSecret);
      const selected=handoffSnapshot();
      const file=await seal(selected,secret,"handoff");
      download("lightup-encrypted-selected-human-handoff.lheh",
        JSON.stringify(file,null,2)+"\n","application/json");
      message("Encrypted selected HUMAN handoff saved; no whole numeric session or original case data included.");
    }catch(_){
      message("HOLD: selected HUMAN handoff not encrypted. Check selected action, password and local WebCrypto.",true);
    }finally{
      const available=session!==null&&globalThis.crypto?.subtle;
      let count=0;
      if(available){try{count=chosen().length;}catch(_){count=0;}}
      $("saveEncryptedHandoff").disabled=!count;
    }
  });
  $("openEncryptedHandoff").addEventListener("click",async()=>{
    $("unlockedHandoffRows").replaceChildren();
    $("unlockedHandoffStatus").textContent="No authenticated handoff loaded.";
    const secret=$("handoffUnlock").value;
    $("handoffUnlock").value="";
    $("openEncryptedHandoff").disabled=true;
    try{
      const file=$("handoffEncryptedFile").files[0];
      ensure(file && file.size>0 && file.size<=131072);
      const bytes=await file.arrayBuffer();
      ensure(bytes.byteLength===file.size);
      const sealed=strictJSON(decoder.decode(bytes));
      const selected=await openSealed(sealed,secret,"handoff");
      displayUnlockedHandoff(selected);
      message("Encrypted selected HUMAN handoff opened locally. File proves no original source identity or authorization.");
    }catch(_){
      message("HOLD: encrypted HUMAN handoff not opened. Wrong passphrase, altered file, invalid schema or unsupported browser.",true);
    }finally{$("openEncryptedHandoff").disabled=false;}
  });
  $("wipe").addEventListener("click",()=>{
    if(!confirm("Clear all loaded LOCAL HUMAN session/board references, peer proposals, unlocked handoff display, file selections and password fields in this tab? Previously downloaded files will NOT be deleted."))return;
    resetState();
    for(const name of ["sessionFile","boardFile","peerFile","encryptedFile",
      "handoffEncryptedFile","saveSecret","confirmSecret","unlockSecret",
      "handoffSecret","handoffConfirm","handoffUnlock"])
      $(name).value="";
    $("actionFilter").value="all";
    $("ordinalFilter").value="all";
    message("Local HUMAN browser interface cleared. Previously downloaded files remain on disk.");
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
