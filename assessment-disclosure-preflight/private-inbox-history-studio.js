"use strict";
/* Offline PRIVATE HUMAN history reader: source-free, memory-only, no authority.
 * The original native source-bound 4-file reopen is mandatory for custody.
 */
(() => {
  const $ = id => document.getElementById(id);
  const STAGES = ["UNREVIEWED","NEEDS_INPUT","IN_PROGRESS","DISCUSSION_COMPLETE_NO_RELEASE"];
  const ROLES = ["UNASSIGNED","SECURITY","PRIVACY","CLIENT_OPERATIONS","PLATFORM"];
  const ATTENTION = ["HUMAN_INPUT_REQUESTED","HUMAN_INITIAL_REVIEW",
    "HUMAN_DISCUSSION_IN_PROGRESS","HUMAN_RECHECK_NO_RELEASE"];
  const STAGE_ATTENTION = {
    NEEDS_INPUT: ATTENTION[0], UNREVIEWED: ATTENTION[1],
    IN_PROGRESS: ATTENTION[2], DISCUSSION_COMPLETE_NO_RELEASE: ATTENTION[3]
  };
  const FLAGS = ["source_authenticated","reviewers_authenticated",
    "chronology_authenticated","client_consent_verified",
    "operator_consent_verified","authorization_granted","release_allowed","signed"];
  const FIELDS = ["human_status","proposed_role",
    "question_text_changed","next_action_text_changed"];
  const MAX_BYTES = 256 * 1024;
  const TOP = ["schema","status","source_free","original_board_byte_binding_checked",
    "complete_revision_membership_checked","manual_order_not_authenticated_chronology",
    ...FLAGS,"slot_count","round_count","round_summaries","slot_paths",
    "changed_transitions","latest_human_attention"];
  let history = null;

  function admit(condition) {
    if (!condition) throw Error("HOLD: invalid or ambiguous PRIVATE HUMAN history");
  }
  function shape(input, keys) {
    admit(input && typeof input === "object" && !Array.isArray(input) &&
      Object.keys(input).length === keys.length &&
      keys.every(key => Object.hasOwn(input, key)));
  }
  function boundedInteger(value, min, max) {
    admit(Number.isSafeInteger(value) && value >= min && value <= max);
  }
  function strictJSON(raw) {
    // Duplicate decoded JSON keys (including escaped aliases) must fail closed.
    let pos = 0, count = 0;
    const spaces = () => {
      while (pos < raw.length && /[\u0009\u000a\u000d\u0020]/u.test(raw[pos])) pos++;
    };
    function stringToken() {
      admit(raw[pos] === '"');
      const start = pos++;
      while (pos < raw.length) {
        if (raw[pos] === "\\") { pos += 2; continue; }
        if (raw[pos++] === '"') return JSON.parse(raw.slice(start, pos));
      }
      admit(false);
    }
    function value(depth) {
      admit(depth < 32 && ++count <= 8000);
      spaces();
      if (raw[pos] === "{") {
        pos++;
        const seen = new Set();
        spaces();
        if (raw[pos] === "}") { pos++; return; }
        while (pos < raw.length) {
          spaces();
          const key = stringToken();
          admit(!seen.has(key)); seen.add(key);
          spaces(); admit(raw[pos++] === ":");
          value(depth + 1); spaces();
          if (raw[pos] === "}") { pos++; return; }
          admit(raw[pos++] === ",");
        }
        admit(false);
      } else if (raw[pos] === "[") {
        pos++; spaces();
        if (raw[pos] === "]") { pos++; return; }
        while (pos < raw.length) {
          value(depth + 1); spaces();
          if (raw[pos] === "]") { pos++; return; }
          admit(raw[pos++] === ",");
        }
        admit(false);
      } else if (raw[pos] === '"') stringToken();
      else {
        const match = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/u.exec(raw.slice(pos));
        admit(Boolean(match)); pos += match[0].length;
      }
    }
    value(0); spaces(); admit(pos === raw.length);
    return JSON.parse(raw);
  }
  function validate(input) {
    shape(input, TOP);
    admit(input.schema === "lightup.private_human_inbox_history.v1" &&
      input.status === "REVIEW_ONLY" && input.source_free === true &&
      input.original_board_byte_binding_checked === true &&
      input.complete_revision_membership_checked === true &&
      input.manual_order_not_authenticated_chronology === true &&
      FLAGS.every(flag => input[flag] === false));
    boundedInteger(input.round_count,2,8);
    boundedInteger(input.slot_count,1,12);
    admit(Array.isArray(input.slot_paths) && input.slot_paths.length === input.slot_count);
    admit(Array.isArray(input.round_summaries) && input.round_summaries.length === input.round_count);
    admit(Array.isArray(input.latest_human_attention) && input.latest_human_attention.length === input.slot_count);
    admit(Array.isArray(input.changed_transitions) &&
          input.changed_transitions.length <= input.slot_count * (input.round_count - 1));

    const counts = Array.from({length:input.round_count}, () => ({
      status:Object.fromEntries(STAGES.map(stage=>[stage,0])),
      role:Object.fromEntries(ROLES.map(role=>[role,0]))
    }));
    const keyedPaths = new Map();
    input.slot_paths.forEach((item,index) => {
      shape(item,["slot","original_unselected_holds","rounds"]);
      admit(item.slot === index + 1);
      boundedInteger(item.original_unselected_holds,0,12);
      admit(Array.isArray(item.rounds) && item.rounds.length === input.round_count);
      item.rounds.forEach((row,roundIndex) => {
        shape(row,["round","human_status","proposed_role"]);
        admit(row.round === roundIndex + 1 &&
          STAGES.includes(row.human_status) && ROLES.includes(row.proposed_role));
        counts[roundIndex].status[row.human_status]++;
        counts[roundIndex].role[row.proposed_role]++;
      });
      keyedPaths.set(item.slot,item);
    });

    input.round_summaries.forEach((item,index) => {
      shape(item,["round","slots","human_status_counts","proposed_role_counts",
        "needs_input","unreviewed","discussion_complete_no_release"]);
      admit(item.round === index + 1 && item.slots === input.slot_count);
      shape(item.human_status_counts,STAGES);
      shape(item.proposed_role_counts,ROLES);
      STAGES.forEach(stage => admit(item.human_status_counts[stage] === counts[index].status[stage]));
      ROLES.forEach(role => admit(item.proposed_role_counts[role] === counts[index].role[role]));
      admit(item.needs_input === counts[index].status.NEEDS_INPUT &&
        item.unreviewed === counts[index].status.UNREVIEWED &&
        item.discussion_complete_no_release === counts[index].status.DISCUSSION_COMPLETE_NO_RELEASE);
    });

    const seen = new Set();
    input.changed_transitions.forEach(item => {
      shape(item,["slot","from_round","to_round","changed_fields",
        "previous_status","current_status","previous_role","current_role",
        "question_text_changed","next_action_text_changed"]);
      boundedInteger(item.slot,1,input.slot_count);
      boundedInteger(item.from_round,1,input.round_count - 1);
      admit(item.to_round === item.from_round + 1);
      const pair = item.slot + ":" + item.to_round;
      admit(!seen.has(pair));seen.add(pair);
      const path = keyedPaths.get(item.slot);
      const before = path.rounds[item.from_round - 1];
      const after = path.rounds[item.to_round - 1];
      admit(item.previous_status === before.human_status &&
        item.current_status === after.human_status &&
        item.previous_role === before.proposed_role &&
        item.current_role === after.proposed_role &&
        typeof item.question_text_changed === "boolean" &&
        typeof item.next_action_text_changed === "boolean");
      admit(Array.isArray(item.changed_fields) && item.changed_fields.length >= 1 &&
        item.changed_fields.length <= 4 &&
        new Set(item.changed_fields).size === item.changed_fields.length &&
        item.changed_fields.every(field=>FIELDS.includes(field)));
      const expected = {
        human_status:before.human_status !== after.human_status,
        proposed_role:before.proposed_role !== after.proposed_role,
        question_text_changed:item.question_text_changed,
        next_action_text_changed:item.next_action_text_changed
      };
      FIELDS.forEach(field=>admit(item.changed_fields.includes(field) === expected[field]));
    });
    // Changed stages/roles cannot be silently omitted from the transition list.
    input.slot_paths.forEach(item => {
      for (let round=1;round<input.round_count;round++) {
        const a=item.rounds[round-1],b=item.rounds[round];
        if (a.human_status!==b.human_status || a.proposed_role!==b.proposed_role)
          admit(seen.has(item.slot+":"+(round+1)));
      }
    });
    const attentionSeen = new Set();
    let lastRank = -1, lastSlot = 0;
    input.latest_human_attention.forEach(item=>{
      shape(item,["slot","manual_round","discussion_group","human_status",
        "suggested_role","original_unselected_holds","actual_owner_assigned","release_allowed"]);
      boundedInteger(item.slot,1,input.slot_count);
      admit(!attentionSeen.has(item.slot));attentionSeen.add(item.slot);
      const path=keyedPaths.get(item.slot), last=path.rounds[input.round_count-1];
      admit(item.manual_round===input.round_count &&
        item.discussion_group===STAGE_ATTENTION[last.human_status] &&
        item.human_status===last.human_status &&
        item.suggested_role===last.proposed_role &&
        item.original_unselected_holds===path.original_unselected_holds &&
        item.actual_owner_assigned===false && item.release_allowed===false);
      const rank=ATTENTION.indexOf(item.discussion_group);
      admit(rank>=lastRank && (rank!==lastRank || item.slot>lastSlot));
      lastRank=rank;lastSlot=item.slot;
    });
    return input;
  }

  function node(tag,text,cls) {
    const element=document.createElement(tag);
    if (text !== undefined) element.textContent=String(text);
    if (cls) element.className=cls;
    return element;
  }
  function row(container,values) {
    const tr=node("tr");
    values.forEach(value=>tr.append(node("td",value)));
    container.append(tr);
    return tr;
  }
  function reset(message="No private HUMAN history loaded.",failed=false) {
    history=null;
    $("workspace").hidden=true;
    $("history-file").value="";
    ["metrics","cards","round-rows","attention-rows","change-rows","round"].forEach(id=>$(id).replaceChildren());
    $("stage").value="ALL";$("role").value="ALL";$("changes").checked=false;
    $("notice").textContent=message;$("notice").dataset.failed=String(failed);
    $("filter-count").textContent="";
  }
  function selectRound() {
    return Number($("round").value) || history.round_count;
  }
  function changedFor(slot,round) {
    return history.changed_transitions.find(row=>row.slot===slot&&row.to_round===round);
  }
  function summary() {
    const round=selectRound(), data=history.round_summaries[round-1];
    const metrics=[
      ["Original slots",history.slot_count],
      ["Manual round",round+" / "+history.round_count],
      ["Needs HUMAN input",data.needs_input],
      ["Unreviewed",data.unreviewed],
      ["Discussion complete · NO RELEASE",data.discussion_complete_no_release]
    ];
    $("metrics").replaceChildren();
    metrics.forEach(([label,count])=>{
      const tile=node("div",undefined,"metric");
      tile.append(node("span",label),node("strong",count));
      $("metrics").append(tile);
    });
  }
  function renderCards() {
    const round=selectRound(),stage=$("stage").value,role=$("role").value;
    const onlyChanged=$("changes").checked;
    $("cards").replaceChildren();
    let visible=0;
    history.slot_paths.forEach(item=>{
      const current=item.rounds[round-1];
      const delta=changedFor(item.slot,round);
      if ((stage!=="ALL"&&current.human_status!==stage)||
          (role!=="ALL"&&current.proposed_role!==role)||
          (onlyChanged&&!delta))return;
      visible++;
      const card=node("article",undefined,"card");
      const heading=node("h3","Slot "+item.slot);
      const badge=node("span",current.human_status,"stage");
      badge.dataset.stage=current.human_status;
      card.append(heading,badge,
        node("p","Suggested discussion: "+current.proposed_role),
        node("p","Original unresolved choices: "+item.original_unselected_holds));
      if(round>1)card.append(node("p",delta?
        "Since R"+(round-1)+": "+delta.changed_fields.join(", "):
        "No reported HUMAN field changes since R"+(round-1),"change"));
      else card.append(node("p","First manually supplied round: no prior comparison","change"));
      $("cards").append(card);
    });
    $("filter-count").textContent=visible+" of "+history.slot_count+
      " original slots shown for manually ordered round "+round+".";
    if(!visible)$("cards").append(node("p","No HUMAN slots match these display filters."));
  }
  function renderStatic() {
    const rounds=$("round");rounds.replaceChildren();
    history.round_summaries.forEach(item=>{
      const option=node("option","Manual round "+item.round);
      option.value=String(item.round);
      rounds.append(option);
      row($("round-rows"),[
        item.round,item.unreviewed,item.needs_input,
        item.human_status_counts.IN_PROGRESS,
        item.discussion_complete_no_release
      ]);
    });
    rounds.value=String(history.round_count);
    history.latest_human_attention.forEach(item=>row($("attention-rows"),[
      item.slot,item.discussion_group,item.human_status,item.suggested_role,
      item.original_unselected_holds
    ]));
    if (!history.changed_transitions.length) row($("change-rows"),[
      "—","—","No declared HUMAN changes","—","—"
    ]);
    history.changed_transitions.forEach(item=>row($("change-rows"),[
      item.slot,"R"+item.from_round+" → R"+item.to_round,
      item.changed_fields.join(", "),item.current_status,item.current_role
    ]));
    $("workspace").hidden=false;
    summary();renderCards();
    $("notice").textContent="PRIVATE HUMAN history admitted for local viewing only. "+
      "The original native 4-file reopener remains authoritative for local custody.";
    $("notice").dataset.failed="false";
  }
  async function onImport() {
    const file=$("history-file").files[0];
    reset();
    try {
      admit(file && file.size>0 && file.size<=MAX_BYTES);
      const bytes=await file.arrayBuffer();
      admit(bytes.byteLength===file.size);
      const text=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
      const next=validate(strictJSON(text));
      history=next;
      renderStatic();
    } catch(_error) {
      reset("HOLD: PRIVATE history rejected. Confirm an unchanged original native source-free history JSON (no duplicate fields, missing slots or authority claims).",true);
    }
  }
  $("history-file").addEventListener("change",onImport);
  $("clear").addEventListener("click",()=>reset());
  ["round","stage","role"].forEach(id=>$(id).addEventListener("change",()=>{
    if(history){summary();renderCards();}
  }));
  $("changes").addEventListener("change",()=>{if(history)renderCards();});
  $("print").addEventListener("click",()=>{if(history)window.print();});
  reset();
})();
