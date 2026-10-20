/* Source-free LightUp PRIVATE HUMAN owner reply editor.
 * HUMAN proposals only. Original native strict admission remains mandatory.
 * No remote I/O, persistence, permissions, grants, scanner or dispatch.
 */
(() => {
  "use strict";
  const $ = name => document.getElementById(name);
  const MAX = 1048576;
  const KEYS = ["schema", "authority", "historical_only", "sources_reopened",
    "recipient_authenticated", "consent_assumed", "actions_dispatched",
    "appointments_booked", "verified_remediation", "proposed_human_owner_label",
    "original_source_portfolio_sha256", "original_source_meeting_sha256",
    "original_review_return_sha256", "human_rows_only_for_selected_owner"];
  const ROW_KEYS = ["local_case", "historical_transition", "original_kit",
    "original_human_priority", "original_proposed_day", "human_review_stage",
    "original_private_human_next_step", "private_human_meeting_note"];
  const AUTH_KEYS = ["authorization", "consent", "verified_finding",
    "release_approval"];
  const STAGES = ["needs_discussion", "proposed_followup", "hold"];
  const CSV_KEYS = ["local_case", "historical_transition", "original_kit",
    "original_owner_packet_sha256", "human_reply_stage", "private_reply_note"];
  let original = null, sha = "", rows = [], dirty = false;
  const exact = (o, keys) => o && typeof o === "object" &&
    !Array.isArray(o) && Object.keys(o).length === keys.length &&
    keys.every(k => Object.prototype.hasOwnProperty.call(o, k));
  const hash = s => typeof s === "string" && /^[a-f0-9]{64}$/.test(s);
  const status = value => { $("status").textContent = value; };
  const hold = value => status("PRIVATE HOLD: " + value);
  const allowed = s => typeof s === "string" && s.length <= 240 &&
    !/[\x00-\x1f\x7f]/.test(s) && !/^\s*[=+@-]/.test(s);
  function verify(doc) {
    if (!exact(doc, KEYS) ||
      doc.schema !== "lightup.private.workspace-ledger-human-owner-handoff.v1" ||
      !exact(doc.authority, AUTH_KEYS) ||
      !AUTH_KEYS.every(k => doc.authority[k] === false) ||
      doc.historical_only !== true ||
      !["sources_reopened", "recipient_authenticated", "consent_assumed",
        "actions_dispatched", "appointments_booked", "verified_remediation"
      ].every(k => doc[k] === false) ||
      !hash(doc.original_source_portfolio_sha256) ||
      !hash(doc.original_source_meeting_sha256) ||
      !hash(doc.original_review_return_sha256) ||
      typeof doc.proposed_human_owner_label !== "string" ||
      !doc.proposed_human_owner_label || doc.proposed_human_owner_label.length > 80 ||
      !Array.isArray(doc.human_rows_only_for_selected_owner) ||
      !doc.human_rows_only_for_selected_owner.length ||
      doc.human_rows_only_for_selected_owner.length > 2048) {
      throw Error("Unknown HUMAN owner packet authority/schema");
    }
    const identities = new Set();
    for (const row of doc.human_rows_only_for_selected_owner) {
      if (!exact(row, ROW_KEYS)) throw Error("Unknown original owner row");
      const id = [row.local_case, row.historical_transition, row.original_kit];
      if (id.some(v => !Number.isInteger(v)) || id[0] < 1 || id[0] > 8 ||
        id[1] < 1 || id[1] > 11 || id[2] < 1 || id[2] > 12) {
        throw Error("Out-of-range original owner row");
      }
      const literal = id.join(":");
      if (identities.has(literal)) throw Error("Duplicate original owner row");
      identities.add(literal);
      if (!STAGES.includes(row.human_review_stage) ||
        !["human_urgent", "near_term", "routine", "unset"].includes(row.original_human_priority) ||
        typeof row.original_proposed_day !== "string" ||
        row.original_proposed_day.length > 10 ||
        !allowed(row.original_private_human_next_step) ||
        !allowed(row.private_human_meeting_note)) {
        throw Error("Invalid private original HUMAN proposal");
      }
    }
  }
  function clear() {
    original = null; sha = ""; rows = []; dirty = false;
    $("workroom").hidden = true;
    $("cards").replaceChildren();
    $("owner").textContent = ""; $("totals").textContent = "";
    status("Choose original local PRIVATE-HUMAN-owner.json. No network will be used.");
  }
  function make(tag, value, className) {
    const element = document.createElement(tag);
    if (value !== undefined) element.textContent = String(value);
    if (className) element.className = className;
    return element;
  }
  function render() {
    const search = $("search").value.trim().toLocaleLowerCase();
    const filter = $("stageFilter").value;
    const container = $("cards");
    container.replaceChildren();
    let displayed = 0;
    for (const row of rows) {
      const corpus = (row.local_case + " " + row.original_human_priority + " " +
        row.original_private_human_next_step + " " +
        row.private_human_meeting_note).toLocaleLowerCase();
      if ((search && !corpus.includes(search)) ||
        (filter && row.replyStage !== filter)) continue;
      displayed++;
      const card = make("article", undefined, "card");
      card.append(make("h3", "Case " + row.local_case + " / transition " +
        row.historical_transition + " / kit " + row.original_kit));
      const meta = make("div", undefined, "facts");
      for (const [title, value] of [
        ["Original HUMAN priority", row.original_human_priority],
        ["Original HUMAN stage", row.human_review_stage],
        ["Historical proposed date", row.original_proposed_day || "none"],
        ["Original PRIVATE HUMAN next step", row.original_private_human_next_step],
        ["Original PRIVATE review note", row.private_human_meeting_note]
      ]) {
        const block = make("div", undefined, "fact");
        block.append(make("strong", title), make("span", value || "—"));
        meta.append(block);
      }
      const editor = make("div", undefined, "edit");
      const label = make("label", "My HUMAN-only proposed follow-up");
      const select = document.createElement("select");
      for (const name of STAGES) {
        const option = make("option", name.replaceAll("_", " "));
        option.value = name; select.append(option);
      }
      select.value = row.replyStage;
      select.addEventListener("change", () => {
        row.replyStage = select.value; dirty = true;
        if (filter) render(); else update();
      });
      label.append(select);
      const noteLabel = make("label", "PRIVATE HUMAN reply note (240 characters)");
      const note = document.createElement("textarea");
      note.rows = 2; note.maxLength = 240; note.value = row.replyNote;
      note.placeholder = "Discussion proposal only; no passwords, tokens or personal secrets.";
      note.addEventListener("input", () => {
        row.replyNote = note.value; dirty = true; update();
      });
      noteLabel.append(note);
      editor.append(label, noteLabel);
      card.append(meta, editor);
      container.append(card);
    }
    $("visible").textContent = displayed + " visible / " + rows.length +
      " original owner rows. All rows will be retained on export.";
    update();
  }
  function update() {
    const counts = Object.fromEntries(STAGES.map(s => [
      s, rows.filter(row => row.replyStage === s).length
    ]));
    $("totals").textContent = rows.length + " original HUMAN proposals · " +
      counts.needs_discussion + " discussion · " +
      counts.proposed_followup + " proposed follow-up · " +
      counts.hold + " HOLD · " +
      rows.filter(row => row.replyNote.length).length + " notes" +
      (dirty ? " · unsaved edits" : "");
  }
  async function load(file) {
    clear();
    if (!file || !file.size || file.size > MAX) return hold("Original private owner JSON must be 1–1048576 bytes");
    if (!crypto || !crypto.subtle) return hold(
      "Local secure SHA-256 unavailable; cannot export original-bound response");
    try {
      const raw = await file.arrayBuffer();
      if (raw.byteLength !== file.size) throw Error("source changed");
      const data = JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(raw));
      verify(data);
      const dig = await crypto.subtle.digest("SHA-256", raw);
      sha = Array.from(new Uint8Array(dig), b => b.toString(16).padStart(2, "0")).join("");
      original = data;
      rows = data.human_rows_only_for_selected_owner.map(row => ({
        ...row, replyStage: "needs_discussion", replyNote: ""
      }));
      $("owner").textContent = "Original proposed owner label: " +
        data.proposed_human_owner_label + ". This does NOT authenticate identity.";
      $("search").value = ""; $("stageFilter").value = ""; dirty = false;
      $("workroom").hidden = false;
      status("PRIVATE DRAFT ONLY: selected source bytes hashed locally (" +
        sha.slice(0, 12) + "…). Native strict original-source admission remains mandatory.");
      render();
    } catch (_e) {
      clear();
      hold("Original owner packet is not an admissible browser preview");
    }
  }
  function quote(value) {
    return '"' + String(value).replaceAll('"', '""') + '"';
  }
  function download() {
    if (!original || !sha || !rows.length) return hold("No original source packet");
    const result = [CSV_KEYS.join(",")];
    for (const row of rows) {
      if (!STAGES.includes(row.replyStage) || !allowed(row.replyNote))
        return hold("Invalid HUMAN stage/note: no unsafe CSV export");
      result.push([
        row.local_case, row.historical_transition, row.original_kit,
        sha, row.replyStage, row.replyNote
      ].map(quote).join(","));
    }
    const csv = new Blob([result.join("\n") + "\n"], {type:"text/csv;charset=utf-8"});
    if (csv.size > MAX) return hold("HUMAN reply exceeds original private limit");
    const url = URL.createObjectURL(csv);
    const a = document.createElement("a");
    a.href = url; a.download = "HUMAN-owner-reply-template.csv";
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    dirty = false; update();
    status("PRIVATE REVIEW_ONLY: local browser download requested. Move CSV to trusted " +
      "0600 storage, then run original portfolio_owner_reply.py native finalizer. " +
      "No consent, grant, identity, sending or actual security finding verified.");
  }
  $("source").addEventListener("change", event => {
    void load(event.target.files && event.target.files[0]);
  });
  $("search").addEventListener("input", render);
  $("stageFilter").addEventListener("change", render);
  $("download").addEventListener("click", download);
  $("clear").addEventListener("click", () => {
    if (dirty && !confirm("Discard unsaved local HUMAN draft edits?")) return;
    $("source").value = ""; clear();
  });
  window.addEventListener("beforeunload", e => {
    if (dirty) { e.preventDefault(); e.returnValue = ""; }
  });
  window.addEventListener("pagehide", () => { $("source").value = ""; clear(); });
  clear();
})();
