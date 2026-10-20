/* LightUp PRIVATE HUMAN focus meeting browser editor.
 * Strict native portfolio_focus_review.py remains the only final admission.
 * Offline, source-free, no network, storage, timers, scans, grants or consent.
 */
(() => {
  "use strict";
  const MAX = 1048576;
  const STAGES = ["needs_discussion", "proposed_followup", "hold"];
  const PRIORITY = ["human_urgent", "near_term", "routine", "unset"];
  const BUCKETS = ["past_proposed_day", "selected_reference_day",
    "later_proposed_day", "no_proposed_day"];
  const FIELDS = ["local_case", "historical_transition", "original_kit",
    "human_priority", "human_status", "proposed_day", "date_bucket",
    "proposed_owner", "next_human_step"];
  const TOP = ["schema", "authority", "historical_only", "sources_reopened",
    "recipient_authenticated", "consent_assumed", "actions_dispatched",
    "appointments_booked", "verified_remediation", "original_portfolio_sha256",
    "original_case_contexts", "meeting_title", "manually_selected_reference_day",
    "proposed_human_owner_filter", "selected_date_buckets",
    "selected_human_priorities", "historical_human_proposals"];
  const AUTH = ["authorization", "consent", "verified_finding", "release_approval"];
  const $ = id => document.getElementById(id);
  let meeting = null, snapshot = [], meetingHash = "", dirty = false;
  const uniqueKeys = (value, keys) => value && typeof value === "object" &&
    !Array.isArray(value) && Object.keys(value).length === keys.length &&
    keys.every(key => Object.prototype.hasOwnProperty.call(value, key));
  const validHex = s => typeof s === "string" && /^[a-f0-9]{64}$/.test(s);
  const num = (n, min, max) => Number.isInteger(n) && n >= min && n <= max;
  const human = (s, max) => typeof s === "string" && s.length <= max &&
    !/[\u0000-\u001f\u007f]/.test(s) && !/^\s*[=+@-]/.test(s);
  const error = message => { $("status").textContent = "PRIVATE HOLD: " + message; };
  const clear = () => {
    meeting = null; snapshot = []; meetingHash = ""; dirty = false;
    $("workspace").hidden = true; $("rows").replaceChildren();
    $("summary").textContent = "";
    $("meetingTitle").textContent = "";
    $("status").textContent = "Select the original PRIVATE focus meeting JSON.";
  };
  function admissible(doc) {
    if (!uniqueKeys(doc, TOP) ||
      doc.schema !== "lightup.private.workspace-ledger-human-focus.v1" ||
      !uniqueKeys(doc.authority, AUTH) || !AUTH.every(k => doc.authority[k] === false) ||
      doc.historical_only !== true || ![
        "sources_reopened", "recipient_authenticated", "consent_assumed",
        "actions_dispatched", "appointments_booked", "verified_remediation"
      ].every(k => doc[k] === false) ||
      !validHex(doc.original_portfolio_sha256) ||
      !human(doc.meeting_title, 100) || !doc.meeting_title ||
      !Array.isArray(doc.original_case_contexts) ||
      !Array.isArray(doc.historical_human_proposals) ||
      doc.historical_human_proposals.length < 1 ||
      doc.historical_human_proposals.length > 2048 ||
      !Array.isArray(doc.selected_human_priorities) ||
      !Array.isArray(doc.selected_date_buckets) ||
      !doc.selected_human_priorities.length || !doc.selected_date_buckets.length ||
      !doc.selected_human_priorities.every(p => PRIORITY.includes(p)) ||
      !doc.selected_date_buckets.every(b => BUCKETS.includes(b)) ||
      (doc.proposed_human_owner_filter !== null &&
       !human(doc.proposed_human_owner_filter, 80))) {
      throw new Error("Unexpected or authority-claiming HUMAN meeting JSON");
    }
    const seen = new Set();
    for (const row of doc.historical_human_proposals) {
      if (!uniqueKeys(row, FIELDS) ||
        !num(row.local_case, 1, 8) || !num(row.historical_transition, 1, 11) ||
        !num(row.original_kit, 1, 12) || !PRIORITY.includes(row.human_priority) ||
        !BUCKETS.includes(row.date_bucket) ||
        typeof row.human_status !== "string" ||
        typeof row.proposed_day !== "string" || row.proposed_day.length > 10 ||
        !human(row.proposed_owner, 80) || !human(row.next_human_step, 240)) {
        throw new Error("Invalid or oversized HUMAN proposal field");
      }
      const key = row.local_case + ":" + row.historical_transition + ":" +
        row.original_kit;
      if (seen.has(key)) throw new Error("Duplicate original HUMAN case slot");
      seen.add(key);
    }
    return true;
  }
  function el(tag, className, content) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (content !== undefined) node.textContent = String(content);
    return node;
  }
  function helpCell(label, content) {
    const div = el("div", "fact");
    div.append(el("strong", "", label), el("span", "", content || "—"));
    return div;
  }
  function updateSummary() {
    const total = snapshot.length;
    const counts = Object.fromEntries(STAGES.map(stage => [
      stage, snapshot.filter(row => row.reviewStage === stage).length
    ]));
    $("summary").textContent = total + " ORIGINAL historical HUMAN slots · " +
      counts.needs_discussion + " needs discussion · " +
      counts.proposed_followup + " proposed follow-up · " + counts.hold +
      " HOLD · " + snapshot.filter(row => row.note !== "").length +
      " private notes" + (dirty ? " · unsaved changes" : "");
  }
  function render() {
    const needle = $("query").value.toLocaleLowerCase();
    const selectedPriority = $("priority").value;
    const selectedStage = $("stage").value;
    const list = $("rows");
    list.replaceChildren();
    let visible = 0;
    for (const row of snapshot) {
      const found = (row.proposed_owner + " " + row.next_human_step + " " +
        row.local_case + " " + row.human_status).toLocaleLowerCase().includes(needle);
      if (!found || (selectedPriority && row.human_priority !== selectedPriority) ||
        (selectedStage && row.reviewStage !== selectedStage)) continue;
      visible++;
      const card = el("article", "card");
      const title = el("h3", "", "Case " + row.local_case + " · transition " +
        row.historical_transition + " · kit " + row.original_kit);
      const info = el("div", "facts");
      info.append(
        helpCell("Original HUMAN priority", row.human_priority),
        helpCell("Original HUMAN stage", row.human_status),
        helpCell("Historical proposed day", row.proposed_day),
        helpCell("Historical day group", row.date_bucket),
        helpCell("Proposed owner — not authenticated", row.proposed_owner),
        helpCell("Original PRIVATE next step", row.next_human_step)
      );
      const fields = el("div", "edit");
      const stageLabel = el("label", "", "New HUMAN meeting review stage");
      const stage = document.createElement("select");
      for (const candidate of STAGES) {
        const option = el("option", "", candidate.replaceAll("_", " "));
        option.value = candidate;
        stage.append(option);
      }
      stage.value = row.reviewStage;
      stage.addEventListener("change", () => {
        row.reviewStage = stage.value; dirty = true; updateSummary();
        if ($("stage").value) render();
      });
      stageLabel.append(stage);
      const noteLabel = el("label", "", "PRIVATE HUMAN note (240 characters max)");
      const note = document.createElement("textarea");
      note.maxLength = 240; note.rows = 2; note.value = row.note;
      note.placeholder = "Human proposal only; no credentials or personal secrets.";
      note.addEventListener("input", () => {
        row.note = note.value; dirty = true; updateSummary();
      });
      noteLabel.append(note);
      fields.append(stageLabel, noteLabel);
      card.append(title, info, fields);
      list.append(card);
    }
    $("visibility").textContent = visible + " visible, " + snapshot.length +
      " always included in the source-exact export. Filtering never discards rows.";
    updateSummary();
  }
  function parseCsv(input) {
    const result = [], row = [];
    let field = "", quoted = false, closed = false;
    for (let i = 0; i < input.length; i++) {
      const c = input[i];
      if (quoted) {
        if (c === '"') {
          if (input[i + 1] === '"') { field += '"'; i++; }
          else { quoted = false; closed = true; }
        } else { field += c; }
      } else if (c === '"' && field === "" && !closed) {
        quoted = true;
      } else if (c === '"') {
        throw new Error("Unexpected quote in review CSV");
      } else if (c === "," || c === "\n" || c === "\r") {
        row.push(field); field = ""; closed = false;
        if (c !== ",") {
          if (c === "\r") {
            if (input[i + 1] !== "\n") throw new Error("Invalid CSV newline");
            i++;
          }
          result.push(row.splice(0));
        }
      } else if (closed) {
        throw new Error("Invalid bytes after CSV quote");
      } else { field += c; }
    }
    if (quoted) throw new Error("Unclosed review CSV quote");
    if (field !== "" || row.length) { row.push(field); result.push(row); }
    return result;
  }
  async function importReview(file) {
    if (!meeting || !meetingHash || !snapshot.length)
      return error("Open the exact original meeting before restoring private HUMAN draft");
    if (!file || !file.size || file.size > MAX)
      return error("Review CSV must be a bounded original human export");
    try {
      const content = new TextDecoder("utf-8", {fatal: true}).decode(await file.arrayBuffer());
      const data = parseCsv(content);
      const names = ["local_case", "historical_transition", "original_kit",
        "meeting_sha256", "human_meeting_stage", "human_decision_note"];
      if (data.length !== snapshot.length + 1 ||
        data[0].length !== names.length ||
        !data[0].every((value, index) => value === names[index])) {
        throw new Error("CSV row population/schema differs");
      }
      const proposals = [];
      for (let i = 0; i < snapshot.length; i++) {
        const original = snapshot[i];
        const row = data[i + 1];
        if (row.length !== names.length ||
          row[0] !== String(original.local_case) ||
          row[1] !== String(original.historical_transition) ||
          row[2] !== String(original.original_kit) ||
          row[3] !== meetingHash || !STAGES.includes(row[4]) ||
          !human(row[5], 240)) {
          throw new Error("Original HUMAN row/sha/decision mismatch");
        }
        proposals.push({reviewStage: row[4], note: row[5]});
      }
      if (!confirm("Replace current in-memory HUMAN draft with the exact-source CSV? " +
        "Native finalizer still must independently admit all original bytes.")) return;
      proposals.forEach((row, i) => {
        snapshot[i].reviewStage = row.reviewStage;
        snapshot[i].note = row.note;
      });
      dirty = true;
      render();
      $("status").textContent = "PRIVATE REVIEW_ONLY: entire original meeting-bound " +
        "HUMAN CSV loaded into memory. NOT source-authenticated or finalized.";
    } catch (_e) {
      error("HUMAN draft restore refused; all prior in-memory decisions preserved");
    }
  }
  function field(value) {
    const text = String(value);
    return '"' + text.replaceAll('"', '""') + '"';
  }
  function download() {
    if (!meeting || !meetingHash || !snapshot.length) return error("No original meeting selected");
    const headers = ["local_case", "historical_transition", "original_kit",
      "meeting_sha256", "human_meeting_stage", "human_decision_note"];
    const lines = [headers.join(",")];
    for (const row of snapshot) {
      if (!STAGES.includes(row.reviewStage) || !human(row.note, 240)) {
        return error("Rejecting unsafe or spreadsheet-formula HUMAN note; correct the entry first");
      }
      lines.push([
        row.local_case, row.historical_transition, row.original_kit,
        meetingHash, row.reviewStage, row.note
      ].map(field).join(","));
    }
    const blob = new Blob([lines.join("\n") + "\n"], {
      type: "text/csv;charset=utf-8"
    });
    if (blob.size > MAX) return error("PRIVATE HUMAN CSV exceeds native byte bound");
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url; link.download = "HUMAN-meeting-review-template.csv";
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    dirty = false;
    updateSummary();
    $("status").textContent = "PRIVATE REVIEW_ONLY: browser download requested. " +
      "Treat Downloads as potentially shared. Store edited CSV as PRIVATE 0600 " +
      "and run the original native portfolio_focus_review.py finalizer. " +
      "This browser did NOT verify original sources or permissions.";
  }
  async function load(file) {
    clear();
    if (!file || !file.size || file.size > MAX) return error("Select bounded original PRIVATE meeting JSON (1 MiB max)");
    if (!globalThis.crypto || !crypto.subtle) return error(
      "Browser has no local SHA-256 Web Crypto. No source-bound export is possible.");
    try {
      const bytes = await file.arrayBuffer();
      if (bytes.byteLength !== file.size) throw new Error("Original file changed during browser read");
      const decoded = new TextDecoder("utf-8", {fatal: true}).decode(bytes);
      const input = JSON.parse(decoded);
      admissible(input);
      const sha = await crypto.subtle.digest("SHA-256", bytes);
      meetingHash = Array.from(new Uint8Array(sha), x => x.toString(16).padStart(2, "0")).join("");
      meeting = input;
      snapshot = input.historical_human_proposals.map(row => ({
        ...row, reviewStage: "needs_discussion", note: ""
      }));
      $("meetingTitle").textContent = input.meeting_title +
        " · manually selected reference " + input.manually_selected_reference_day;
      $("query").value = ""; $("priority").value = ""; $("stage").value = "";
      $("workspace").hidden = false;
      dirty = false;
      $("status").textContent = "LOCAL HUMAN draft from original selected bytes (" +
        file.size + " bytes, unsigned SHA-256 " + meetingHash.slice(0, 12) +
        "…). Native finalizer must independently reject duplicates, validate " +
        "canonical data and recheck original source.";
      render();
    } catch (_e) {
      clear();
      error("Original meeting cannot be previewed as an admissible HUMAN draft");
    }
  }
  $("source").addEventListener("change", event => {
    const file = event.target.files && event.target.files[0];
    void load(file);
  });
  $("restore").addEventListener("change", event => {
    const file = event.target.files && event.target.files[0];
    void importReview(file);
    event.target.value = "";
  });
  $("query").addEventListener("input", render);
  $("priority").addEventListener("change", render);
  $("stage").addEventListener("change", render);
  $("download").addEventListener("click", download);
  $("clear").addEventListener("click", () => {
    if (dirty && !confirm("Discard unsaved LOCAL HUMAN notes and selections?")) return;
    $("source").value = ""; $("restore").value = ""; clear();
  });
  window.addEventListener("beforeunload", event => {
    if (dirty) { event.preventDefault(); event.returnValue = ""; }
  });
  window.addEventListener("pagehide", () => { $("source").value = ""; $("restore").value = ""; clear(); });
  clear();
})();
