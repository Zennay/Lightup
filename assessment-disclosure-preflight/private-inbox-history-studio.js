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
  let loadGeneration = 0;
  let intervalRows = [];

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
  function renderRange() {
    intervalRows=[];
    $("range-rows").replaceChildren();
    const from=Number($("range-from").value),to=Number($("range-to").value);
    if(!history || !Number.isSafeInteger(from) || !Number.isSafeInteger(to) ||
       from<1 || to>history.round_count || from>=to) {
      $("range-summary").textContent="HOLD: select an earlier starting round.";
      $("range-export").disabled=true;
      return;
    }
    for(const item of history.slot_paths) {
      const before=item.rounds[from-1],after=item.rounds[to-1];
      const changes=history.changed_transitions.filter(change=>
        change.slot===item.slot && change.to_round>from && change.to_round<=to);
      const fields=new Set(changes.flatMap(change=>change.changed_fields));
      intervalRows.push({
        slot:item.slot,from_round:from,to_round:to,
        original_unselected_holds:item.original_unselected_holds,
        from_status:before.human_status,to_status:after.human_status,
        status_endpoint_changed:before.human_status!==after.human_status,
        status_edited_within_interval:fields.has("human_status"),
        from_role:before.proposed_role,to_role:after.proposed_role,
        role_endpoint_changed:before.proposed_role!==after.proposed_role,
        role_edited_within_interval:fields.has("proposed_role"),
        question_edited_within_interval:fields.has("question_text_changed"),
        next_action_edited_within_interval:fields.has("next_action_text_changed")
      });
    }
    const activity=item=>item.status_edited_within_interval ||
      item.role_edited_within_interval ||
      item.question_edited_within_interval ||
      item.next_action_edited_within_interval;
    const displayed=intervalRows.filter(item=>!$("range-changes").checked||activity(item));
    displayed.forEach(item=>row($("range-rows"),[
      item.slot,item.from_status+" → "+item.to_status,
      item.from_role+" → "+item.to_role,
      item.status_endpoint_changed?"Yes":"No",
      item.status_edited_within_interval?"Yes":"No",
      item.role_endpoint_changed?"Yes":"No",
      item.role_edited_within_interval?"Yes":"No",
      item.question_edited_within_interval?"Yes":"No",
      item.next_action_edited_within_interval?"Yes":"No"
    ]));
    if(!displayed.length)row($("range-rows"),[
       "—","No reported HUMAN activity","—","—","—","—","—","—","—"]);
    $("range-summary").textContent="Manual R"+from+" → R"+to+
      ": "+intervalRows.filter(activity).length+" of "+history.slot_count+
      " slots have reported HUMAN field activity; "+displayed.length+
       " shown. PRIVATE CSV preserves all "+history.slot_count+
      " slots. Original note text and verified chronology are unavailable.";
    $("range-export").disabled=false;
  }

  function downloadRange() {
    if(!history || $("range-export").disabled || !intervalRows.length) return;
    // Match original native PRIVATE interval CSV columns and order.
    // Equality of unsigned browser/native schema is NOT custody authority.
    const fields=[
      "slot","from_status","to_status","status_endpoint_changed",
      "status_edited_within_interval","from_proposed_role","to_proposed_role",
      "proposed_role_endpoint_changed","role_edited_within_interval",
      "question_edited_within_interval","next_action_edited_within_interval",
      "original_unselected_holds","manual_start_round","manual_end_round",
      "source_authenticated","chronology_authenticated","authorization_granted",
      "release_allowed"];
    const csvCell=value=>'"'+String(value).replaceAll('"','""')+'"';
    const lines=[fields.map(csvCell).join(",")];
    intervalRows.forEach(item=>lines.push([
      item.slot,item.from_status,item.to_status,item.status_endpoint_changed,
      item.status_edited_within_interval,item.from_role,item.to_role,
      item.role_endpoint_changed,item.role_edited_within_interval,
      item.question_edited_within_interval,item.next_action_edited_within_interval,
      item.original_unselected_holds,item.from_round,item.to_round,
      false,false,false,false
    ].map(csvCell).join(",")));
    const blob=new Blob([lines.join("\n")+"\n"],{type:"text/csv;charset=utf-8"});
    const url=URL.createObjectURL(blob);
    try {
      const link=node("a");
      link.href=url;
      link.download="PRIVATE-HUMAN-manual-round-interval-unsigned.csv";
      document.body.append(link);link.click();link.remove();
    } finally {
      setTimeout(()=>URL.revokeObjectURL(url),0);
    }
  }

  function reset(message="No private HUMAN history loaded.",failed=false) {
    // Invalidate any previous asynchronous File.arrayBuffer() import.
    loadGeneration++;
    history=null;
    $("workspace").hidden=true;
    $("history-file").value="";
    ["metrics","cards","round-rows","attention-rows","change-rows","round",
      "range-from","range-to","range-rows"].forEach(id=>$(id).replaceChildren());
    intervalRows=[];
    $("range-summary").textContent="Select two different manually ordered rounds.";
    $("range-export").disabled=true;
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
    for(let index=1;index<=history.round_count;index++) {
      for (const id of ["range-from","range-to"]) {
        const option=node("option","Round "+index);
        option.value=String(index);
        $(id).append(option);
      }
    }
    $("range-from").value="1";
    $("range-to").value=String(history.round_count);
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
    summary();renderCards();renderRange();
    $("notice").textContent="PRIVATE HUMAN history admitted for local viewing only. "+
      "The original native 4-file reopener remains authoritative for local custody.";
    $("notice").dataset.failed="false";
  }
  async function onImport() {
    const file=$("history-file").files[0];
    reset();
    // A new native import replaces any sensitive original CSV selection and
    // pending composed browser report in the other source file form.
    window.dispatchEvent(new Event("lightup:history-clear-original-inputs"));
    const active=loadGeneration;
    try {
      admit(file && file.size>0 && file.size<=MAX_BYTES);
      const bytes=await file.arrayBuffer();
      admit(active===loadGeneration && bytes.byteLength===file.size);
      const text=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
      const next=validate(strictJSON(text));
      admit(active===loadGeneration);
      history=next;
      renderStatic();
    } catch(_error) {
      if(active===loadGeneration)
        reset("HOLD: PRIVATE history rejected. Confirm an unchanged original native source-free history JSON (no duplicate fields, missing slots or authority claims).",true);
    }
  }
  // The adjacent PRIVATE composer uses the exact same strict source-free
  // schema admission and rendering, never reaching into private note memory.
  // This is a local browser-generated preview, not native output custody.
  window.LightUpPrivateHistory = Object.freeze({
    parseJSON: strictJSON,
    discardComposedPreview() { reset(); },
    clearPrivateSession() {
      reset();
      window.dispatchEvent(new Event("lightup:history-clear-original-inputs"));
    },
    openComposed(sourceFreeJSON) {
      try {
        const original = validate(strictJSON(sourceFreeJSON));
        reset();
        history=original;
        renderStatic();
        $("notice").textContent="REVIEW_ONLY: unsigned BROWSER-COMPOSED PRIVATE history. "+
          "All complete original inputs require separate native custody admission.";
        return true;
      } catch (_error) {
        reset("HOLD: browser-composed PRIVATE HUMAN history failed source-free admission.",true);
        return false;
      }
    }
  });
  $("history-file").addEventListener("change",onImport);
  $("clear").addEventListener("click",()=>window.LightUpPrivateHistory.clearPrivateSession());
  ["round","stage","role"].forEach(id=>$(id).addEventListener("change",()=>{
    if(history){summary();renderCards();}
  }));
  $("changes").addEventListener("change",()=>{if(history)renderCards();});
  ["range-from","range-to","range-changes"].forEach(id=>
    $(id).addEventListener("change",()=>{if(history)renderRange();}));
  $("range-export").addEventListener("click",downloadRange);
  $("print").addEventListener("click",()=>{if(history)window.print();});
  reset();
})();
