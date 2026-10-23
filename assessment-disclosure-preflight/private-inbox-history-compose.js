"use strict";
/* Original PRIVATE HUMAN worksheet-to-history authoring; strictly local.
 * This browser flow never authenticates original sources, signs approvals,
 * grants scopes, scans assets, uploads data or saves raw HUMAN note text.
 */
(() => {
  const $ = id => document.getElementById(id);
  const FIELDS = ["board_sha256","slot","human_status","proposed_discussion_role",
    "human_question","human_next_action"];
  const BOARD_FIELDS = ["slot","source_declarations","human_a_choices",
    "human_b_choices","unselected_hold","result_transport",
    "local_file_custody","source_reopening","authority","human_followup"];
  const BOARD_KEYS = ["schema","status","source_free","source_authenticated",
    "reviewers_authenticated","client_consent_verified","operator_consent_verified",
    "authorization_granted","release_allowed","original_human_reopening_performed",
    "signed","rooms"];
  const STAGES = ["UNREVIEWED","NEEDS_INPUT","IN_PROGRESS","DISCUSSION_COMPLETE_NO_RELEASE"];
  const ROLES = ["UNASSIGNED","SECURITY","PRIVACY","CLIENT_OPERATIONS","PLATFORM"];
  const GROUPS = {
    NEEDS_INPUT:"HUMAN_INPUT_REQUESTED",
    UNREVIEWED:"HUMAN_INITIAL_REVIEW",
    IN_PROGRESS:"HUMAN_DISCUSSION_IN_PROGRESS",
    DISCUSSION_COMPLETE_NO_RELEASE:"HUMAN_RECHECK_NO_RELEASE"
  };
  const FALSE_FLAGS = ["source_authenticated","reviewers_authenticated",
    "chronology_authenticated","client_consent_verified","operator_consent_verified",
    "authorization_granted","release_allowed","signed"];
  let saved = null, generation = 0, showingComposed = false;

  function requireValid(ok) {
    if (!ok) throw Error("HOLD: original HUMAN source data not admitted");
  }
  function exactKeys(object, keys) {
    requireValid(object && typeof object === "object" && !Array.isArray(object) &&
      Object.keys(object).length === keys.length && keys.every(k=>Object.hasOwn(object,k)));
  }
  function integer(value,min,max) {
    requireValid(Number.isSafeInteger(value) && value >= min && value <= max);
  }
  function invalidate(message = "Private inputs changed. Compose again; no saved history.") {
    generation++;
    saved = null;
    // Never leave a stale preview visible as if it corresponded to revised
    // original input selections. Native imports stay independent.
    if (showingComposed) {
      showingComposed = false;
      window.LightUpPrivateHistory?.discardComposedPreview();
    }
    $("compose-download").disabled = true;
    $("compose-status").textContent = message;
    $("compose-status").dataset.failed = "false";
  }
  function buildFileFields() {
    invalidate("Select original board and complete HUMAN CSVs in manual order.");
    $("compose-revisions").replaceChildren();
    const n=Number($("compose-count").value);
    for(let i=1;i<=n;i++){
      const label=document.createElement("label");
      label.textContent="Manually ordered revision "+i+" of "+n;
      const input=document.createElement("input");
      input.type="file"; input.accept=".csv,text/csv";
      input.dataset.revision=String(i);
      input.addEventListener("change",()=>invalidate());
      label.append(input);$("compose-revisions").append(label);
    }
  }
  function csvRows(text) {
    // Keep the same six exact columns and original full slot ordering.
    text=text.replace(/^\uFEFF/u,"");
    const output=[]; let line=[],cell="",mode="start";
    const appendRow=()=>{
      line.push(cell);
      requireValid(line.length===FIELDS.length);
      output.push(line);line=[];cell="";mode="start";
    };
    for(let i=0;i<text.length;i++){
      const ch=text[i];
      if(mode==="quoted"){
        if(ch==='"'){
          if(text[i+1]==='"'){cell+='"';i++;}
          else mode="closed";
        }else cell+=ch;
      }else if(ch==='"'){
        requireValid(mode==="start");mode="quoted";
      }else if(ch==="," || ch==="\n" || ch==="\r"){
        requireValid(ch!== "\r" || text[i+1]==="\n");
        if(ch===","){
          line.push(cell);cell="";mode="start";
        }else{
          appendRow();if(ch==="\r")i++;
        }
      }else{
        requireValid(mode!=="closed");
        cell+=ch;mode="plain";
      }
    }
    requireValid(mode!=="quoted");
    if(mode!=="start" || line.length || cell!=="")appendRow();
    requireValid(output.length>=2 && output.length<=13 &&
      output[0].every((value,index)=>value===FIELDS[index]));
    return output.slice(1);
  }
  function safeNote(value) {
    requireValid(typeof value==="string" && [...value].length <= 1200);
    for(const ch of value)requireValid(!/[\p{C}\p{Zl}\p{Zp}]/u.test(ch));
    requireValid(!/^[\s]*[=+\-@]/u.test(value.normalize("NFKC")));
    return value;
  }
  function admitBoard(text) {
    const board=window.LightUpPrivateHistory.parseJSON(text);
    exactKeys(board,BOARD_KEYS);
    requireValid(board.schema==="lightup.private_human_inbox_board.v1" &&
      board.status==="REVIEW_ONLY" && board.source_free===true &&
      typeof board.original_human_reopening_performed==="boolean" &&
      ["source_authenticated","reviewers_authenticated","client_consent_verified",
       "operator_consent_verified","authorization_granted","release_allowed","signed"]
        .every(flag=>board[flag]===false));
    requireValid(Array.isArray(board.rooms) && board.rooms.length>=1 &&
      board.rooms.length<=12);
    board.rooms.forEach((row,index)=>{
      exactKeys(row,BOARD_FIELDS);
      integer(row.slot,index+1,index+1);
      integer(row.source_declarations,1,12);
      integer(row.human_a_choices,0,12);
      integer(row.human_b_choices,0,12);
      integer(row.unselected_hold,0,12);
      requireValid(row.human_a_choices+row.human_b_choices+
        row.unselected_hold===row.source_declarations);
      requireValid(["ENCRYPTED","PRIVATE_PLAINTEXT"].includes(row.result_transport) &&
        row.local_file_custody==="EXACT_UNSIGNED_BYTES" &&
        ["NOT_PERFORMED_BY_BOARD","ORIGINAL_NATIVE_REVIEW_ONLY"].includes(row.source_reopening) &&
        (row.source_reopening==="ORIGINAL_NATIVE_REVIEW_ONLY")===
          board.original_human_reopening_performed &&
        row.authority==="NONE" &&
        row.human_followup===(row.unselected_hold?"CHECK_HOLD_CHOICES":"INDEPENDENT_REVIEW_REQUIRED"));
    });
    return board.rooms;
  }
  function admitHumanRows(text,digest,rooms) {
    const output=csvRows(text);
    requireValid(output.length===rooms.length);
    return output.map((row,index)=>{
      requireValid(row[0]===digest && row[1]===String(index+1) &&
        STAGES.includes(row[2]) && ROLES.includes(row[3]));
      const question=safeNote(row[4]),next=safeNote(row[5]);
      requireValid(row[2]!=="UNREVIEWED" ||
        (row[3]==="UNASSIGNED"&&!question&&!next));
      requireValid(row[2]!=="DISCUSSION_COMPLETE_NO_RELEASE" ||
        (question.trim().length>0 && next.trim().length>0));
      return {
        slot:index+1,human_status:row[2],proposed_discussion_role:row[3],
        human_question:question,human_next_action:next
      };
    });
  }
  async function bytes(file,limit) {
    requireValid(file && file.size>0 && file.size<=limit);
    const result=await file.arrayBuffer();
    requireValid(result.byteLength===file.size);
    return result;
  }
  function decode(input) {
    return new TextDecoder("utf-8",{fatal:true}).decode(input);
  }
  async function sha256(raw) {
    requireValid(crypto && crypto.subtle && typeof crypto.subtle.digest==="function");
    const digest=await crypto.subtle.digest("SHA-256",raw);
    return [...new Uint8Array(digest)].map(value=>value.toString(16).padStart(2,"0")).join("");
  }
  async function fingerprint(file,limit) {
    return sha256(await bytes(file,limit));
  }
  function compose(rooms,revisions) {
    const rounds=revisions.length;
    const summaries=revisions.map((snapshot,index)=>{
      const statuses=Object.fromEntries(STAGES.map(status=>[status,0]));
      const roles=Object.fromEntries(ROLES.map(role=>[role,0]));
      snapshot.forEach(item=>{
        statuses[item.human_status]++;
        roles[item.proposed_discussion_role]++;
      });
      return {
        round:index+1,slots:rooms.length,human_status_counts:statuses,
        proposed_role_counts:roles,needs_input:statuses.NEEDS_INPUT,
        unreviewed:statuses.UNREVIEWED,
        discussion_complete_no_release:statuses.DISCUSSION_COMPLETE_NO_RELEASE
      };
    });
    const transitions=[],paths=[];
    rooms.forEach((source,index)=>{
      const snapshots=[];
      revisions.forEach((revision,roundIndex)=>{
        const row=revision[index];
        snapshots.push({
          round:roundIndex+1,human_status:row.human_status,
          proposed_role:row.proposed_discussion_role
        });
        if(!roundIndex)return;
        const previous=revisions[roundIndex-1][index];
        const changed=[];
        const questionChanged=previous.human_question!==row.human_question;
        const nextChanged=previous.human_next_action!==row.human_next_action;
        if(previous.human_status!==row.human_status)changed.push("human_status");
        if(previous.proposed_discussion_role!==row.proposed_discussion_role)
          changed.push("proposed_role");
        if(questionChanged)changed.push("question_text_changed");
        if(nextChanged)changed.push("next_action_text_changed");
        if(changed.length)transitions.push({
          slot:index+1,from_round:roundIndex,to_round:roundIndex+1,
          changed_fields:changed,previous_status:previous.human_status,
          current_status:row.human_status,
          previous_role:previous.proposed_discussion_role,
          current_role:row.proposed_discussion_role,
          question_text_changed:questionChanged,
          next_action_text_changed:nextChanged
        });
      });
      paths.push({slot:index+1,original_unselected_holds:source.unselected_hold,
        rounds:snapshots});
    });
    const attention=paths.map(path=>{
      const last=path.rounds[rounds-1];
      return {
        slot:path.slot,manual_round:rounds,discussion_group:GROUPS[last.human_status],
        human_status:last.human_status,suggested_role:last.proposed_role,
        original_unselected_holds:path.original_unselected_holds,
        actual_owner_assigned:false,release_allowed:false
      };
    });
    const priority=Object.values(GROUPS);
    attention.sort((a,b)=>priority.indexOf(a.discussion_group)-
      priority.indexOf(b.discussion_group)||a.slot-b.slot);
    return {
      schema:"lightup.private_human_inbox_history.v1",status:"REVIEW_ONLY",
      source_free:true,original_board_byte_binding_checked:true,
      complete_revision_membership_checked:true,
      manual_order_not_authenticated_chronology:true,
      ...Object.fromEntries(FALSE_FLAGS.map(flag=>[flag,false])),
      slot_count:rooms.length,round_count:rounds,round_summaries:summaries,
      slot_paths:paths,changed_transitions:transitions,
      latest_human_attention:attention
    };
  }
  async function composeClicked() {
    invalidate();
    const current=generation;
    try {
      requireValid($("compose-confirm").checked);
      requireValid(window.LightUpPrivateHistory && crypto && crypto.subtle);
      const board=$("compose-board").files[0];
      const worksheets=[...document.querySelectorAll("[data-revision]")]
        .map(input=>input.files[0]);
      requireValid(worksheets.length===Number($("compose-count").value) &&
        worksheets.length>=2&&worksheets.length<=8 && worksheets.every(Boolean));
      const boardRaw=await bytes(board,64*1024);
      // Native original board JSON does not accept a leading UTF-8 BOM.
      const head=new Uint8Array(boardRaw);
      requireValid(!(head[0]===0xef&&head[1]===0xbb&&head[2]===0xbf));
      const digest=await sha256(boardRaw);
      const original=admitBoard(decode(boardRaw));
      const revBytes=await Promise.all(worksheets.map(file=>bytes(file,128*1024)));
      const revHash=await Promise.all(revBytes.map(raw=>sha256(raw)));
      requireValid(new Set(revHash).size===revHash.length);
      const revisions=revBytes.map(raw=>admitHumanRows(decode(raw),digest,original));
      requireValid(current===generation);
      const outcome=compose(original,revisions);
      const json=JSON.stringify(outcome);
      const admission=window.LightUpPrivateHistory.openComposed(json);
      requireValid(admission===true && current===generation);
      showingComposed = true;
      // The source snapshots contain only browser File handles and hashes:
      // complete question/next-action notes never enter saved output.
      saved={json,files:[board,...worksheets],hashes:[digest,...revHash],limits:
        [64*1024,...worksheets.map(()=>128*1024)],at:current};
      $("compose-download").disabled=false;
      $("compose-status").textContent="REVIEW_ONLY: source-free HUMAN history composed and opened below. "+
        "No notes in output. Download privately if needed; native re-admission remains separate.";
      $("compose-status").dataset.failed="false";
    }catch(_error){
      if(current===generation){
        saved=null;$("compose-download").disabled=true;
        $("compose-status").textContent="HOLD: original board, complete HUMAN revisions, "+
          "cryptographic digest or browser availability not admitted. Nothing downloaded.";
        $("compose-status").dataset.failed="true";
      }
    }
  }
  async function downloadClicked() {
    const current=saved;
    $("compose-download").disabled=true;
    try{
      requireValid(current && current.at===generation);
      // Require the same explicitly selected original files, count and SHA.
      const selected=[$("compose-board").files[0],
        ...[...document.querySelectorAll("[data-revision]")].map(input=>input.files[0])];
      requireValid(selected.length===current.files.length &&
        selected.every((file,index)=>file===current.files[index]));
      const hashes=await Promise.all(selected.map((file,index)=>fingerprint(file,current.limits[index])));
      requireValid(hashes.every((hash,index)=>hash===current.hashes[index]) &&
        current.at===generation);
      const blob=new Blob([current.json+"\n"],{type:"application/json;charset=utf-8"});
      const url=URL.createObjectURL(blob);
      try{
        const anchor=document.createElement("a");
        anchor.href=url;anchor.download="PRIVATE-inbox-HUMAN-history-browser-unsigned.json";
        document.body.append(anchor);anchor.click();anchor.remove();
      }finally{setTimeout(()=>URL.revokeObjectURL(url),0);}
      $("compose-status").textContent="PRIVATE source-free JSON downloaded locally, unsigned. "+
        "This is not the native four-file custody report or release authorization.";
      $("compose-status").dataset.failed="false";
    }catch(_error){
      $("compose-status").textContent="HOLD: original inputs changed or were not re-admitted. "+
        "Compose again; no valid report was downloaded.";
      $("compose-status").dataset.failed="true";
      saved=null;
    }finally{
      $("compose-download").disabled=!saved;
    }
  }
  // The viewer owns the global PRIVATE session Clear action. It empties
  // both source File inputs and generated source-free output; crucially,
  // the original CSV files can no longer be reprocessed without reselection.
  window.addEventListener("lightup:history-clear-original-inputs", () => {
    // Avoid resetting a newly imported native history on the same signal.
    showingComposed = false;
    $("compose-board").value = "";
    $("compose-confirm").checked = false;
    buildFileFields();
  });
  $("compose-count").addEventListener("change",buildFileFields);
  $("compose-board").addEventListener("change",()=>invalidate());
  $("compose-confirm").addEventListener("change",()=>invalidate());
  $("compose-reset").addEventListener("click",()=>{
    $("compose-board").value="";
    $("compose-confirm").checked=false;
    buildFileFields();
  });
  $("compose-build").addEventListener("click",composeClicked);
  $("compose-download").addEventListener("click",downloadClicked);
  buildFileFields();
})();
