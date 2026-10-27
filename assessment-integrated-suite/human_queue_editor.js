"use strict";
(() => {
  const COLUMNS = ["snapshot_sha256", "workflow_key", "human_stage", "review_team",
                   "followup_date", "human_question"];
  const STAGES = ["UNASSESSED", "HOLD", "NEEDS_INPUT", "HUMAN_REVIEW", "HUMAN_FOLLOWUP"];
  const TEAMS = ["", "Security", "Privacy", "Client operations", "Platform"];
  const MAX_BYTES = 65536;
  const q = (id) => document.getElementById(id);
  const original = JSON.parse(q("original-data").textContent);
  const reference = original.rows;
  let draft = reference.map((row) => ({ ...row }));
  let dirty = false;
  let updateGeneration = 0;
  let exportedRevision = -1;
  let importAttempt = 0;
  const undoStack = [];
  const redoStack = [];
  const MAX_HISTORY = 25;
  const status = q("status");
  const savedHash = reference[0]?.snapshot_sha256 || "";
  const setMessage = (message, problem = false) => {
    status.textContent = message;
    status.className = problem ? "feedback error" : "feedback";
  };
  const safeQuestion = (value) => typeof value === "string" && value.length <= 240 &&
    !/[\x00-\x1f\x7f]/.test(value) && !/^[\s]*[=+\-@]/.test(value);
  const validDate = (value) => {
    if (!value) return true;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
    const [year, month, day] = value.split("-").map(Number);
    const object = new Date(Date.UTC(year, month - 1, day));
    return object.getUTCFullYear() === year && object.getUTCMonth() + 1 === month &&
      object.getUTCDate() === day;
  };
  function validRow(row) {
    return STAGES.includes(row.human_stage) && TEAMS.includes(row.review_team) &&
      validDate(row.followup_date) && safeQuestion(row.human_question) &&
      (row.human_stage !== "UNASSESSED" ||
       !(row.review_team || row.followup_date || row.human_question));
  }
  const PRIORITIES = ["HOLD", "MISSING_ORIGINAL", "PAST_DATE",
                     "DUE_DATE", "NEXT_WEEK", "UNASSIGNED", "OTHER"];
  // The operator supplies an explicit date. These are HUMAN-only labels,
  // not time-dependent enforcement, automatic scheduling or security rank.
  function attentionFor(row) {
    if (["HOLD", "NEEDS_INPUT"].includes(row.human_stage)) return "HOLD";
    if (row.local_state === "HOLD_PAGE_UNAVAILABLE" ||
        (row.human_stage !== "UNASSESSED" &&
         row.local_state !== "LOCAL_PAGE_PRESENT_REVIEW_ONLY"))
      return "MISSING_ORIGINAL";
    const referenceDate = document.getElementById("review-date").value;
    if (referenceDate && validDate(referenceDate) && row.followup_date) {
      if (row.followup_date < referenceDate) return "PAST_DATE";
      if (row.followup_date === referenceDate) return "DUE_DATE";
      const from = new Date(referenceDate + "T00:00:00Z");
      const due = new Date(row.followup_date + "T00:00:00Z");
      if (due.getTime() - from.getTime() <= 7 * 86400000) return "NEXT_WEEK";
    }
    if (row.human_stage !== "UNASSESSED" && !row.review_team) return "UNASSIGNED";
    return "OTHER";
  }
  function showAttention() {
    const summary = PRIORITIES.map((bucket) =>
      draft.filter((item) => attentionFor(item) === bucket).length +
      " " + bucket.toLowerCase().replaceAll("_", " ")
    ).join(" · ");
    q("attention-summary").textContent = summary;
    q("capacity").textContent = TEAMS.slice(1).map((team) =>
      team + ": " + draft.filter((row) =>
        row.review_team === team && row.human_stage !== "UNASSESSED").length
    ).join(" · ");
    q("date-warning").textContent = q("review-date").value ?
      "Manually declared review date, not a real booked appointment." :
      "Choose a HUMAN review date for overdue/today/next-week categories.";
  }
  function checkpoint() {
    undoStack.push({ rows: draft.map((row) => ({ ...row })), dirty });
    if (undoStack.length > MAX_HISTORY) undoStack.shift();
    redoStack.length = 0;
  }
  function timeTravel(from, to, message) {
    if (!from.length) return;
    to.push({ rows: draft.map((row) => ({ ...row })), dirty });
    if (to.length > MAX_HISTORY) to.shift();
    const earlier = from.pop();
    draft = earlier.rows.map((row) => ({ ...row }));
    dirty = earlier.dirty;
    updateGeneration += 1;
    exportedRevision = -1;
    setMessage(message + " This remains PRIVATE HUMAN-only.");
    render();
  }
  function visibleIndices() {
    const search = q("search").value.trim().toLocaleLowerCase();
    const stage = q("stage-filter").value;
    const team = q("team-filter").value;
    const priority = q("priority-filter").value;
    const indexes = [];
    draft.forEach((item, i) => {
      if (search && !(item.title + " " + item.workflow_key + " " + item.human_next)
        .toLocaleLowerCase().includes(search)) return;
      if (stage && stage !== item.human_stage) return;
      if (team && team !== item.review_team) return;
      if (priority && priority !== attentionFor(item)) return;
      indexes.push(i);
    });
    return indexes;
  }
  function showCounts() {
    const summary = STAGES.map((stage) => {
      const count = draft.filter((item) => item.human_stage === stage).length;
      return count + " " + stage.toLowerCase().replaceAll("_", " ");
    }).join(" · ");
    q("counts").textContent = summary;
    q("dirty").textContent = dirty ?
      "HUMAN edits not acknowledged saved — export CSV and confirm local custody." :
      "No unacknowledged HUMAN edits since original/admitted CSV.";
    q("undo").disabled = undoStack.length === 0;
    q("redo").disabled = redoStack.length === 0;
    q("saved").disabled = exportedRevision !== updateGeneration;
    showAttention();
  }
  function el(name, className, value) {
    const node = document.createElement(name);
    if (className) node.className = className;
    if (value !== undefined) node.textContent = value;
    return node;
  }
  function optionSelect(values, current, onChange, ariaLabel) {
    const select = el("select");
    select.setAttribute("aria-label", ariaLabel);
    for (const choice of values) {
      const option = el("option", "", choice || "Not assigned");
      option.value = choice;
      select.append(option);
    }
    select.value = current;
    select.addEventListener("change", () => onChange(select.value));
    return select;
  }
  function markChanged(row, key, value) {
    const revised = { ...draft[row], [key]: value };
    // Reset all downstream HUMAN metadata on returning to UNASSESSED, but
    // only after explicit user selection, never on normal rendering.
    if (key === "human_stage" && value === "UNASSESSED") {
      revised.review_team = "";
      revised.followup_date = "";
      revised.human_question = "";
    }
    if (!validRow(revised)) {
      setMessage("HOLD: invalid HUMAN stage, date, question, or spreadsheet formula prefix.", true);
      return false;
    }
    if (["human_stage", "review_team", "followup_date", "human_question"]
      .every((field) => revised[field] === draft[row][field])) return true;
    checkpoint();
    draft[row] = revised;
    dirty = true;
    updateGeneration += 1;
    exportedRevision = -1;
    showCounts();
    return true;
  }
  function render() {
    const host = q("list");
    host.replaceChildren();
    const visibleRows = visibleIndices();
    for (const i of visibleRows) {
      const item = draft[i];
      const card = el("article", "card");
      card.append(el("h3", "", item.title));
      const state = el("p", "hint", "Original page: " +
        item.local_state.replaceAll("_", " ") + " · HUMAN-only · " + item.group);
      card.append(state);
      card.append(el("p", "attention-tag", "HUMAN attention: " +
        attentionFor(item).replaceAll("_", " ") + " (not a security verdict)"));
      const fields = el("div", "grid");
      const stageWrap = el("label", "", "Provisional HUMAN stage");
      stageWrap.append(optionSelect(STAGES, item.human_stage, (v) => {
        if (markChanged(i, "human_stage", v)) render();
      }, "HUMAN stage for " + item.title));
      fields.append(stageWrap);
      const teamWrap = el("label", "", "Proposed HUMAN team");
      teamWrap.append(optionSelect(TEAMS, item.review_team, (v) => {
        if (markChanged(i, "review_team", v)) render();
      }, "HUMAN team for " + item.title));
      fields.append(teamWrap);
      const dateWrap = el("label", "", "Follow-up date, not scheduled");
      const dateInput = el("input");
      dateInput.type = "date";
      dateInput.value = item.followup_date;
      dateInput.addEventListener("change", () => {
        if (markChanged(i, "followup_date", dateInput.value)) render();
        else dateInput.value = draft[i].followup_date;
      });
      dateWrap.append(dateInput);
      fields.append(dateWrap);
      card.append(fields);
      const questionWrap = el("label", "question", "PRIVATE HUMAN question (up to 240 characters)");
      const note = el("input");
      note.type = "text";
      note.maxLength = 240;
      note.autocomplete = "off";
      note.value = item.human_question;
      note.addEventListener("change", () => {
        if (markChanged(i, "human_question", note.value)) render();
        else note.value = draft[i].human_question;
      });
      questionWrap.append(note);
      card.append(questionWrap);
      card.append(el("p", "hint", "Suggested manual next step: " + item.human_next));
      if (item.local_href && item.local_href.startsWith("file:///")) {
        const link = el("a", "", "Open original owner-private page");
        link.href = item.local_href;
        link.rel = "noopener noreferrer";
        card.append(link);
      }
      host.append(card);
    }
    q("visible").textContent = visibleRows.length + " of " + draft.length +
      " original workflow rows shown (filters do not exclude rows from export).";
    showCounts();
  }
  // Strict CSV reader handling UTF-8 quotes, embedded comma, LF and CRLF.
  // Reject malformed quoting and isolated CR.
  function csvParse(source) {
    const table = [];
    let row = [], cell = "", quoted = false, closed = false;
    for (let i = 0; i < source.length; i++) {
      const ch = source[i];
      if (quoted) {
        if (ch === '"') {
          if (source[i + 1] === '"') { cell += '"'; i++; }
          else { quoted = false; closed = true; }
        } else cell += ch;
        continue;
      }
      if (closed && ch !== "," && ch !== "\r" && ch !== "\n") throw new Error("Invalid CSV quote boundary");
      if (ch === "," || ch === "\r" || ch === "\n") {
        row.push(cell); cell = ""; closed = false;
        if (ch === ",") continue;
        if (ch === "\r") {
          if (source[i + 1] !== "\n") throw new Error("Expected canonical CRLF");
          i++;
        } else if (ch !== "\n") throw new Error("Expected LF or CRLF");
        table.push(row); row = [];
      } else if (ch === '"') {
        if (cell || closed) throw new Error("Invalid CSV quote");
        quoted = true;
      } else cell += ch;
    }
    if (quoted) throw new Error("Unterminated CSV quote");
    if (cell || row.length || closed) {
      row.push(cell); table.push(row);
    }
    return table;
  }
  function readRows(csv) {
    const lines = csvParse(csv);
    if (lines.length !== reference.length + 1 ||
        JSON.stringify(lines[0]) !== JSON.stringify(COLUMNS))
      throw new Error("Expected the exact original 6-column HUMAN queue, in original row order.");
    const records = [];
    for (let index = 0; index < reference.length; index++) {
      const cells = lines[index + 1];
      if (cells.length !== COLUMNS.length) throw new Error("Unexpected CSV field count.");
      const obj = Object.fromEntries(COLUMNS.map((name, idx) => [name, cells[idx]]));
      if (obj.workflow_key !== reference[index].workflow_key ||
          obj.snapshot_sha256 !== savedHash)
        throw new Error("The original path snapshot or workflow order differs. HOLD.");
      if (!validRow(obj)) throw new Error("Invalid HUMAN date, stage, team or question.");
      records.push({ ...reference[index], ...obj });
    }
    return records;
  }
  function encodedCSV(rows) {
    function csvCell(value) {
      if (!/[",\r\n]/.test(value)) return value;
      return '"' + value.replaceAll('"', '""') + '"';
    }
    const head = COLUMNS.join(",");
    const lines = rows.map((row) => COLUMNS.map((key) => csvCell(row[key])).join(","));
    return head + "\r\n" + lines.join("\r\n") + "\r\n";
  }
  async function importCSV(file) {
    if (!file) return;
    if (file.size === 0 || file.size > MAX_BYTES) {
      setMessage("HOLD: original CSV must be between 1 and 65,536 bytes.", true);
      return;
    }
    const revision = updateGeneration;
    const attempt = ++importAttempt;
    try {
      const decoder = new TextDecoder("utf-8", { fatal: true });
      const source = decoder.decode(await file.arrayBuffer());
      const admitted = readRows(source);
      if (revision !== updateGeneration || attempt !== importAttempt)
        throw new Error("A newer import or HUMAN edit superseded this file.");
      const fields = ["human_stage", "review_team", "followup_date", "human_question"];
      const changed = admitted.filter((row, i) =>
        fields.some((field) => row[field] !== draft[i][field]));
      const fieldChanges = Object.fromEntries(fields.map((field) => [
        field, admitted.filter((row, i) => row[field] !== draft[i][field]).length
      ]));
      const brief = changed.slice(0, 8).map((row) => row.title).join("; ");
      const proposal = "Source-PATH-bound local HUMAN CSV accepted for review. " +
        changed.length + " of " + admitted.length + " workflows differ. " +
        "Changes: " + fieldChanges.human_stage + " stages, " +
        fieldChanges.review_team + " team assignments, " +
        fieldChanges.followup_date + " follow-up dates, " +
        fieldChanges.human_question + " PRIVATE questions (texts hidden)." +
        (brief ? "\nAffected workflows: " + brief : "") +
        "\nReplace the entire in-memory draft? Original disk files stay unchanged.";
      if (!window.confirm(proposal)) {
        setMessage("CSV change preview declined. All current HUMAN edits preserved.");
        return;
      }
      if (revision !== updateGeneration || attempt !== importAttempt)
        throw new Error("Another HUMAN change intervened before confirmation.");
      checkpoint();
      draft = admitted;
      dirty = false;
      updateGeneration += 1;
      exportedRevision = -1;
      setMessage("Original matching HUMAN CSV loaded in memory; no disk files changed.");
      render();
    } catch (error) {
      setMessage("HOLD: source-bound CSV import rejected. No in-memory changes. " +
        String(error.message || "Invalid file"), true);
    }
  }
  function exportCSV() {
    for (const item of draft) {
      if (!validRow(item)) {
        setMessage("HOLD: fix unsupported HUMAN values before export.", true);
        return;
      }
    }
    if (!window.confirm("Export the entire PRIVATE HUMAN CSV for manual local custody? Browser downloads may NOT have owner-only permissions; move to a private 0700 directory and set 0600 permissions before native import. No approval or dispatch is implied.")) return;
    const bytes = new TextEncoder().encode(encodedCSV(draft));
    if (bytes.length > MAX_BYTES) {
      setMessage("HOLD: private HUMAN CSV exceeds the native 65,536-byte limit.", true);
      return;
    }
    const file = new Blob([bytes], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(file);
    const anchor = el("a");
    anchor.href = url;
    anchor.download = "LightUp-PRIVATE-HUMAN-QUEUE-review-only.csv";
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 30000);
    exportedRevision = updateGeneration;
    showCounts();
    setMessage("CSV download REQUESTED, not verified saved. Confirm actual browser download and owner-only 0700/0600 custody, then explicitly acknowledge local save.");
  }
  for (const id of ["search", "stage-filter", "team-filter",
                   "priority-filter", "review-date"])
    q(id).addEventListener(id === "search" ? "input" : "change", render);
  q("csv-input").addEventListener("change", async (event) => {
    const file = event.target.files?.[0];
    await importCSV(file);
    event.target.value = "";
  });
  q("download").addEventListener("click", exportCSV);
  q("saved").addEventListener("click", () => {
    if (exportedRevision !== updateGeneration) {
      setMessage("HOLD: latest export is older than the HUMAN draft.", true);
      return;
    }
    if (window.confirm("Did you verify the CSV download, move it into owner-only 0700, and set 0600 permissions? This is NOT approval or source authentication.")) {
      dirty = false;
      exportedRevision = -1;
      setMessage("Local HUMAN save acknowledged. Original native CSV admission remains required.");
      showCounts();
    }
  });
  q("undo").addEventListener("click", () => timeTravel(
    undoStack, redoStack, "Undid previous HUMAN change."));
  q("redo").addEventListener("click", () => timeTravel(
    redoStack, undoStack, "Reapplied HUMAN change."));
  q("bulk").addEventListener("click", () => {
    const choice = q("bulk-stage").value;
    if (!["HOLD", "NEEDS_INPUT"].includes(choice)) {
      setMessage("HOLD: only non-authorizing bulk actions are supported.", true);
      return;
    }
    const visible = visibleIndices();
    const changed = visible.filter((i) => draft[i].human_stage !== choice);
    if (!changed.length) {
      setMessage("No visible HUMAN workflow needs this status change.");
      return;
    }
    if (!window.confirm("Set " + changed.length + " of " + visible.length +
      " FILTERED visible HUMAN rows to " + choice +
      "? Hidden rows are untouched. No assessment will execute.")) return;
    checkpoint();
    changed.forEach((i) => { draft[i] = { ...draft[i], human_stage: choice }; });
    dirty = true;
    exportedRevision = -1;
    updateGeneration += 1;
    setMessage("Only " + changed.length + " visible HUMAN rows set to " + choice +
      ". Undo is available. Original files are unchanged.");
    render();
  });
  q("bulk-team").addEventListener("click", () => {
    const team = q("bulk-team-select").value;
    if (!TEAMS.slice(1).includes(team)) {
      setMessage("HOLD: one explicit HUMAN team selection is required.", true);
      return;
    }
    const visible = visibleIndices();
    const eligible = visible.filter((i) => draft[i].human_stage !== "UNASSESSED");
    const changed = eligible.filter((i) => draft[i].review_team !== team);
    if (!changed.length) {
      setMessage("No visible already-staged HUMAN workflow needs reassignment.");
      return;
    }
    if (!window.confirm("Assign " + changed.length + " already-staged HUMAN items to " +
      team + "? " + (visible.length - eligible.length) +
      " visible UNASSESSED workflows and all hidden rows stay unchanged. " +
      "This is an unauthenticated task proposal, not permission or dispatch.")) return;
    checkpoint();
    changed.forEach((i) => { draft[i] = { ...draft[i], review_team: team }; });
    dirty = true;
    exportedRevision = -1;
    updateGeneration += 1;
    setMessage("Only " + changed.length + " eligible visible HUMAN rows assigned to " +
      team + ". Use undo or export as needed. No recipient was contacted.");
    render();
  });
  q("reset").addEventListener("click", () => {
    if (!dirty || window.confirm("Discard unexported HUMAN edits and return to original, source-bound draft?")) {
      checkpoint();
      draft = reference.map((row) => ({ ...row }));
      dirty = false; updateGeneration += 1;
      exportedRevision = -1;
      setMessage("Original HUMAN queue draft restored in memory. No files changed.");
      render();
    }
  });
  window.addEventListener("beforeunload", (event) => {
    if (dirty) { event.preventDefault(); event.returnValue = ""; }
  });
  q("stage-filter").replaceChildren(el("option", "", "All HUMAN stages"));
  q("stage-filter").firstChild.value = "";
  STAGES.forEach((stage) => {
    const option = el("option", "", stage.replaceAll("_", " "));
    option.value = stage; q("stage-filter").append(option);
  });
  q("team-filter").replaceChildren(el("option", "", "All HUMAN teams"));
  q("team-filter").firstChild.value = "";
  TEAMS.slice(1).forEach((team) => {
    const option = el("option", "", team);
    option.value = team; q("team-filter").append(option);
  });
  TEAMS.slice(1).forEach((team) => {
    const option = el("option", "", team);
    option.value = team;
    q("bulk-team-select").append(option);
  });
  q("priority-filter").replaceChildren(
    el("option", "", "All HUMAN attention categories"));
  q("priority-filter").firstChild.value = "";
  PRIORITIES.forEach((bucket) => {
    const option = el("option", "", bucket.replaceAll("_", " "));
    option.value = bucket;
    q("priority-filter").append(option);
  });
  setMessage("Owner-private, source-PATH-bound HUMAN queue loaded in memory. No external requests.");
  render();
})();
