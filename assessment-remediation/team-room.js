"use strict";
/* LightUp human-only private team review.
   No network, account, storage, permission, scan, finding status or target calls. */
(() => {
  const $ = id => document.getElementById(id);
  const LIMIT = 262144;
  const FLAGS = ["authorized", "consent_verified", "dispatch_allowed", "release_allowed"];
  const FIELDS = ["stage", "reviewer", "next_action", "note"];
  const KEYS = ["scenario_id", "finding_id", ...FIELDS];
  const STAGES = ["needs_review", "investigating", "documented"];
  const SOURCE_KEYS = ["schema", "original_links_sha256", "comparison_sha256",
    "findings_sha256", "entries", "team_room_source_sha256", ...FLAGS];
  let source = null;
  let entries = [];
  let selected = 0;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const invalid = msg => { throw new Error(msg); };
  const exact = (obj, keys) => obj && typeof obj === "object" &&
    !Array.isArray(obj) && Object.keys(obj).length === keys.length &&
    keys.every(key => Object.hasOwn(obj, key));
  const hex = s => typeof s === "string" && /^[a-f0-9]{64}$/u.test(s);
  const good = (str, len) => typeof str === "string" && str.length <= len &&
    !/[\u0000-\u0008\u000b-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u.test(str);
  function status(msg, error = false) {
    $("status").textContent = msg;
    $("status").className = error ? "notice error" : "notice";
  }
  function element(parent, tag, value, klass) {
    const node = document.createElement(tag);
    node.textContent = value;
    if (klass) node.className = klass;
    parent.appendChild(node);
    return node;
  }
  function strictJSON(raw) {
    let pos = 0, count = 0;
    function whitespace() {
      while (pos < raw.length && /\s/u.test(raw[pos])) pos++;
    }
    function string() {
      if (raw[pos] !== '"') invalid("Malformed JSON string.");
      let start = pos++, escaped = false;
      while (pos < raw.length) {
        const ch = raw[pos++];
        if (ch === '"' && !escaped) return JSON.parse(raw.slice(start, pos));
        if (ch === "\\" && !escaped) escaped = true;
        else escaped = false;
      }
      invalid("Unterminated JSON string.");
    }
    function value(depth) {
      if (depth > 25 || ++count > 40000) invalid("Oversized or too-deep JSON.");
      whitespace();
      if (raw[pos] === '"') return string();
      if (raw[pos] === "{") {
        pos++; whitespace();
        const object = Object.create(null), keys = new Set();
        if (raw[pos] === "}") { pos++; return object; }
        while (true) {
          whitespace(); const key = string();
          if (keys.has(key)) invalid("Ambiguous duplicate JSON object key.");
          keys.add(key); whitespace();
          if (raw[pos++] !== ":") invalid("Malformed JSON field.");
          object[key] = value(depth + 1); whitespace();
          if (raw[pos] === "}") { pos++; return object; }
          if (raw[pos++] !== ",") invalid("Malformed JSON member.");
        }
      }
      if (raw[pos] === "[") {
        pos++; whitespace();
        const list = [];
        if (raw[pos] === "]") { pos++; return list; }
        for (;;) {
          list.push(value(depth + 1));
          if (list.length > 512) invalid("Too many private team entries.");
          whitespace();
          if (raw[pos] === "]") { pos++; return list; }
          if (raw[pos++] !== ",") invalid("Malformed JSON array.");
        }
      }
      for (const [literal, result] of [["true", true], ["false", false], ["null", null]]) {
        if (raw.startsWith(literal, pos)) { pos += literal.length; return result; }
      }
      const match = raw.slice(pos).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u);
      if (!match) invalid("Malformed JSON primitive.");
      pos += match[0].length;
      const n = Number(match[0]);
      if (!Number.isFinite(n)) invalid("Nonfinite JSON number.");
      return n;
    }
    const object = value(0);
    whitespace();
    if (pos !== raw.length) invalid("Trailing JSON payload.");
    return object;
  }
  function entryIsValid(item) {
    if (!exact(item, KEYS)) return false;
    for (const name of ["scenario_id", "finding_id"]) {
      const val = item[name];
      if (typeof val !== "string" || val.length < 1 || val.length > 256 ||
          val !== val.trim() || !/^[\x20-\x7e]+$/u.test(val)) return false;
    }
    return STAGES.includes(item.stage) &&
      good(item.reviewer, 100) && good(item.next_action, 300) &&
      good(item.note, 500);
  }
  function validate(input) {
    if (!exact(input, SOURCE_KEYS) ||
        input.schema !== "lightup.assessment_remediation_team_handoff.v1" ||
        FLAGS.some(key => input[key] !== false) ||
        ![input.original_links_sha256, input.comparison_sha256,
          input.findings_sha256, input.team_room_source_sha256].every(hex) ||
        !Array.isArray(input.entries) || input.entries.length > 512)
      invalid("Not a private unchanged original team handoff, or authority fields altered.");
    const seen = new Set();
    for (const item of input.entries) {
      if (!entryIsValid(item)) invalid("Malformed original human link.");
      const pair = JSON.stringify([item.scenario_id, item.finding_id]);
      if (seen.has(pair)) invalid("Repeated original link identity.");
      seen.add(pair);
    }
    return input;
  }
  function clear() {
    source = null; entries = []; selected = 0;
    $("workspace").hidden = true;
    $("items").replaceChildren();
  }
  async function load() {
    const file = $("handoff").files?.[0];
    if (!file || !file.size || file.size > LIMIT) {
      status("HOLD · Select an original owner-private team handoff under 256 KiB.", true);
      return;
    }
    try {
      const raw = new Uint8Array(await file.arrayBuffer());
      if (raw.length !== file.size) invalid("Private source changed during local import.");
      const candidate = validate(strictJSON(decoder.decode(raw)));
      source = candidate;
      entries = candidate.entries.map(item => ({...item}));
      selected = 0;
      $("workspace").hidden = false;
      render();
      status("Human-only original handoff loaded locally. Sender and engagement are NOT authenticated.");
    } catch (error) {
      clear();
      status("HOLD · " + error.message, true);
    }
  }
  function writeEditor() {
    const item = entries[selected];
    if (!item) { $("editor").hidden = true; return; }
    $("editor").hidden = false;
    $("selected").textContent = "Original pair " + (selected + 1) +
      " / " + entries.length + ": " + item.scenario_id + " ↔ " + item.finding_id;
    for (const name of FIELDS) $(name).value = item[name];
  }
  function render() {
    if (!source) return;
    const search = $("filter").value.toLowerCase();
    const list = $("items"); list.replaceChildren();
    const visible = entries.map((entry, position) => ({entry, position}))
      .filter(({entry}) => (entry.scenario_id + " " + entry.finding_id + " " +
        entry.stage + " " + entry.reviewer).toLowerCase().includes(search));
    for (const {entry, position} of visible) {
      const button = element(list, "button",
        (position + 1) + " · " + entry.scenario_id + " ↔ " +
        entry.finding_id + " · " + entry.stage, "choice");
      button.type = "button";
      button.setAttribute("aria-pressed", position === selected ? "true" : "false");
      button.addEventListener("click", () => { selected = position; render(); });
    }
    $("counter").textContent = entries.length + " source-bound human link(s), " +
      visible.length + " visible. Missing entries are not proof of a clean engagement.";
    writeEditor();
  }
  function save() {
    if (!source || !entries[selected]) return;
    const candidate = {...entries[selected]};
    for (const name of FIELDS) candidate[name] = $(name).value.trim();
    if (!entryIsValid(candidate)) {
      status("HOLD · Enter valid human-only fields within length limits.", true);
      return;
    }
    entries[selected] = candidate;
    render();
    status("Private human notes updated in memory only. Original IDs, finding statuses and scope unchanged.");
  }
  function stageBatch() {
    if (!source) return;
    const stage = $("bulkStage").value;
    if (!STAGES.includes(stage) || !$("batchConfirm").checked) {
      status("HOLD · Choose a human stage and explicitly confirm filtered notes only.", true);
      return;
    }
    const query = $("filter").value.toLowerCase();
    let changed = 0;
    entries = entries.map(row => {
      if ((row.scenario_id + " " + row.finding_id + " " + row.stage +
            " " + row.reviewer).toLowerCase().includes(query)) {
        if (row.stage !== stage) changed++;
        return {...row, stage};
      }
      return row;
    });
    $("batchConfirm").checked = false;
    render();
    status(changed + " local human stages edited; original source links and permission not modified.");
  }
  function exportReturn() {
    try {
      if (!source) invalid("No accepted private team handoff.");
      if (!entries.every(entryIsValid)) invalid("Invalid human entry in draft.");
      const output = {
        schema: "lightup.assessment_remediation_team_return.v1",
        original_links_sha256: source.original_links_sha256,
        comparison_sha256: source.comparison_sha256,
        findings_sha256: source.findings_sha256,
        entries: entries.map(row => ({...row})),
        authorized: false, consent_verified: false,
        dispatch_allowed: false, release_allowed: false
      };
      const payload = encoder.encode(JSON.stringify(output, null, 2) + "\n");
      if (payload.length > LIMIT) invalid("Private return exceeds allowed document size.");
      const url = URL.createObjectURL(new Blob([payload], {type:"application/json"}));
      const link = document.createElement("a");
      link.href = url;
      link.download = "lightup-private-team-return.json";
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      status("Unsigned human-only return exported. Original owner must verify sender and run team_handoff.py receive with exact original private baseline.");
    } catch (error) {
      status("HOLD · " + error.message, true);
    }
  }
  $("read").addEventListener("click", load);
  $("filter").addEventListener("input", render);
  $("editor").addEventListener("submit", event => { event.preventDefault(); save(); });
  $("batch").addEventListener("click", stageBatch);
  $("export").addEventListener("click", exportReturn);
})();