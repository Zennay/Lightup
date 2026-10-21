"use strict";
// Local-only PRIVATE HUMAN editing. Native finalize is the only source-bound
// admission; browser exports are unsigned and never proof of authority.
(() => {
  const FIELDS = ["board_sha256", "slot", "human_status", "proposed_discussion_role", "human_question", "human_next_action"];
  const STATUSES = ["UNREVIEWED", "NEEDS_INPUT", "IN_PROGRESS", "DISCUSSION_COMPLETE_NO_RELEASE"];
  const ROLES = ["UNASSIGNED", "SECURITY", "PRIVACY", "CLIENT_OPERATIONS", "PLATFORM"];
  const MAX_BYTES = 128 * 1024;
  const MAX_TEXT = 1200;
  const $ = id => document.getElementById(id);
  let rows = [];
  let digest = "";
  let lastBulkUndo = null;
  let pendingCsv = null;

  function clear() {
    rows = [];
    digest = "";
    lastBulkUndo = null;
    pendingCsv = null;
    $("export-preview").hidden = true;
    $("confirm-export").disabled = true;
    $("export-preview-summary").textContent = "";
    $("export-preview-breakdown").replaceChildren();
    $("upload").value = "";
    $("bulk-apply").disabled = true;
    $("bulk-undo").disabled = true;
    $("bulk-status").value = "";
    $("bulk-role").value = "";
    $("bulk-message").textContent = "No original HUMAN action sheet loaded. Nothing will be exported without its complete source-ordered rows.";
    $("bulk-message").dataset.error = "false";
    $("bulk-visible-count").textContent = "";
    $("cards").replaceChildren();
    $("editor").hidden = true;
    $("message").textContent = "No original HUMAN action sheet loaded.";
    $("export-message").textContent = "";
  }

  function parseCSV(raw) {
    const text = raw.replace(/^\uFEFF/, "");
    const rowsOut = [];
    let row = [];
    let field = "";
    let state = 0; // 0 new, 1 unquoted, 2 quoted, 3 after closing quote
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (state === 2) {
        if (ch === '"') {
          if (text[i + 1] === '"') { field += '"'; i++; }
          else state = 3;
        } else field += ch;
        continue;
      }
      if (ch === '"') {
        if (state !== 0) throw Error("Ambiguous quote in source row");
        state = 2; continue;
      }
      if (ch === "," || ch === "\n" || ch === "\r") {
        if (ch === "\r" && text[i + 1] !== "\n") throw Error("Noncanonical CSV line ending");
        row.push(field); field = ""; state = 0;
        if (ch !== ",") {
          if (row.length !== FIELDS.length) throw Error("Source columns are incomplete");
          rowsOut.push(row); row = [];
          if (ch === "\r") i++;
        }
        continue;
      }
      if (state === 3) throw Error("Data after quoted CSV field");
      if (state === 0) state = 1;
      field += ch;
    }
    if (state === 2) throw Error("Unclosed CSV quote");
    if (field !== "" || row.length) {
      row.push(field);
      if (row.length !== FIELDS.length) throw Error("Incomplete final source row");
      rowsOut.push(row);
    }
    return rowsOut;
  }

  function admitText(text, title) {
    if (typeof text !== "string" || text.length > MAX_TEXT) throw Error(title + " exceeds 1200 characters");
    for (const ch of text) {
      if (/[\p{C}\p{Zl}\p{Zp}]/u.test(ch))
        throw Error(title + " contains unsafe Unicode control, format, or separator characters");
    }
    // Native finalization repeats this guard for CSV files edited outside the browser.
    if (/^[\s]*[=+\-@]/u.test(text.normalize("NFKC")))
      throw Error(title + " could be interpreted as a spreadsheet formula after Unicode normalization");
    return text;
  }

  function validRow(row, i, expectedDigest) {
    if (row.length !== FIELDS.length || row[0] !== expectedDigest ||
        row[1] !== String(i + 1) || !STATUSES.includes(row[2]) ||
        !ROLES.includes(row[3])) throw Error("Original source binding or HUMAN row format changed");
    admitText(row[4], "HUMAN question");
    admitText(row[5], "HUMAN next action");
    if (row[2] === "UNREVIEWED" && (row[3] !== "UNASSIGNED" || row[4] || row[5]))
      throw Error("Unreviewed HUMAN row must be empty/unassigned");
    if (row[2] === "DISCUSSION_COMPLETE_NO_RELEASE" && (!row[4].trim() || !row[5].trim()))
      throw Error("Finished discussion requires a HUMAN question and next action");
  }

  function csvEncode(parts) {
    return parts.map(field => '"' + String(field).replaceAll('"','""') + '"').join(",");
  }

  function optionMenu(values, selected, label) {
    const select = document.createElement("select");
    select.setAttribute("aria-label",label);
    for (const choice of values) {
      const item = document.createElement("option");
      item.value = choice; item.textContent = choice;
      if (choice === selected) item.selected = true;
      select.append(item);
    }
    return select;
  }

  function fieldCardLabel(name, control) {
    const label = document.createElement("label");
    label.textContent = name;
    label.append(control);
    return label;
  }

  function show() {
    $("cards").replaceChildren();
    $("editor").hidden = rows.length === 0;
    for (let i = 0; i < rows.length; i++) {
      const data = rows[i];
      const card = document.createElement("article");
      card.className = "card";
      card.dataset.slot = String(i + 1);
      const title = document.createElement("h3");
      title.textContent = "HUMAN slot " + (i + 1);
      const tag = document.createElement("p");
      tag.className = "tag";
      tag.textContent = "Original PRIVATE source order · NOT an asset, identity or verified finding";
      const status = optionMenu(STATUSES, data.status, "HUMAN discussion stage, slot "+(i+1));
      const role = optionMenu(ROLES, data.role, "Proposed HUMAN role, slot "+(i+1));
      const question = document.createElement("textarea");
      question.maxLength = MAX_TEXT; question.value = data.question;
      question.setAttribute("aria-label", "PRIVATE HUMAN discussion question slot "+(i+1));
      const next = document.createElement("textarea");
      next.maxLength = MAX_TEXT; next.value = data.next;
      next.setAttribute("aria-label", "PRIVATE HUMAN next action slot "+(i+1));
      status.addEventListener("change", () => { data.status = status.value; invalidateBulkUndo(); filter(); });
      role.addEventListener("change", () => { data.role = role.value; invalidateBulkUndo(); });
      question.addEventListener("input", () => { data.question = question.value; invalidateBulkUndo(); });
      next.addEventListener("input", () => { data.next = next.value; invalidateBulkUndo(); });
      card.append(title, tag,
        fieldCardLabel("HUMAN stage (never a security verdict)", status),
        fieldCardLabel("Suggested discussion role (not assignment)", role),
        fieldCardLabel("Original PRIVATE HUMAN question", question),
        fieldCardLabel("Next manual HUMAN action", next));
      $("cards").append(card);
    }
    filter();
  }

  function filter() {
    const value = $("filter").value;
    let displayed = 0;
    for (const card of $("cards").children) {
      const status = rows[Number(card.dataset.slot)-1].status;
      const visible = value === "ALL" ||
        (value === "OPEN" && ["UNREVIEWED","NEEDS_INPUT"].includes(status)) ||
        (value === "PROGRESS" && status === "IN_PROGRESS") ||
        (value === "DISCUSSION" && status === "DISCUSSION_COMPLETE_NO_RELEASE");
      card.hidden = !visible;
      if (visible) displayed++;
    }
    $("counter").textContent = displayed + " visible · " + rows.length + " original slots retained in full export";
    updateBulkControls(displayed);
  }

  function updateBulkControls(visibleCount) {
    const count = visibleCount ?? [...$("cards").children].filter(card => !card.hidden).length;
    $("bulk-apply").disabled = rows.length === 0 || count === 0;
    $("bulk-undo").disabled = !lastBulkUndo;
    $("bulk-visible-count").textContent = rows.length ? count + " visible slot(s) · batch changes affect only these rows" : "";
  }

  function invalidateExportPreview(message) {
    const hadPreview = pendingCsv !== null;
    pendingCsv = null;
    $("export-preview").hidden = true;
    $("confirm-export").disabled = true;
    if (hadPreview && message) {
      $("export-message").textContent = message;
      $("export-message").dataset.error = "false";
    }
  }

  function invalidateBulkUndo() {
    invalidateExportPreview("A HUMAN row changed. Prepare a new full-export preview before downloading.");
    if (lastBulkUndo) {
      lastBulkUndo = null;
      $("bulk-message").textContent = "An individual row was edited; the previous bulk Undo was cleared to preserve the newer change.";
      $("bulk-message").dataset.error = "false";
    }
    updateBulkControls();
  }

  $("upload").addEventListener("change", async event => {
    const file = event.target.files?.[0];
    clear();
    if (!file) return;
    if (file.size <= 0 || file.size > MAX_BYTES) {
      $("message").textContent = "HOLD: original PRIVATE action worksheet exceeds file bound";
      return;
    }
    try {
      const decoded = new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
      const parsed = parseCSV(decoded);
      if (parsed.length < 2 || parsed.length > 13 ||
          JSON.stringify(parsed[0]) !== JSON.stringify(FIELDS))
        throw Error("Original six-column native action sheet required");
      const actualDigest = parsed[1][0];
      if (!/^[0-9a-f]{64}$/.test(actualDigest)) throw Error("Missing exact original board SHA");
      const items = parsed.slice(1);
      items.forEach((row,i) => validRow(row,i,actualDigest));
      digest = actualDigest;
      rows = items.map(row => ({ status:row[2],role:row[3],question:row[4],next:row[5] }));
      $("message").textContent = "PRIVATE source-bound worksheet locally admitted: " +
        rows.length + " complete original slot" + (rows.length===1?"":"s") + ". Not authenticated or approved.";
      $("export-message").textContent = "";
      show();
    } catch (err) {
      clear();
      $("message").textContent = "HOLD: original HUMAN worksheet refused (" + String(err.message||"invalid local source") + ")";
    }
  });

  $("filter").addEventListener("change", filter);
  $("bulk-apply").addEventListener("click", () => {
    if (!rows.length) return;
    const stage = $("bulk-status").value, role = $("bulk-role").value;
    const visible = [...$("cards").children].map((card,index)=>({card,index})).filter(item=>!item.card.hidden).map(item=>item.index);
    if (!visible.length || (!stage && !role)) return;
    const proposed = rows.map(row=>({...row}));
    for (const index of visible) {
      if (stage) proposed[index].status = stage;
      if (role) proposed[index].role = role;
    }
    try {
      proposed.forEach((row,index)=>validRow([digest,String(index+1),row.status,row.role,row.question,row.next],index,digest));
      if (!confirm("Apply these HUMAN-only proposals to exactly "+visible.length+" currently visible original slots? All hidden rows stay unchanged. If the native worksheet rules are not met, no changes are applied.")) return;
      invalidateExportPreview("The HUMAN worksheet changed. Prepare a new full-export preview before downloading.");
      lastBulkUndo = rows.map(row=>({...row}));
      rows = proposed;
      show();
      $("bulk-message").textContent = "HUMAN-only batch applied to "+visible.length+" visible slot(s). One Undo is available; every original slot remains in the export.";
      $("bulk-message").dataset.error = "false";
    } catch (err) {
      $("bulk-message").textContent = "HOLD: no batch changes applied ("+String(err.message||"worksheet rule refused")+"). Correct the conflicting rows individually or choose a different proposal.";
      $("bulk-message").dataset.error = "true";
    }
  });
  $("bulk-undo").addEventListener("click", () => {
    if (!lastBulkUndo) return;
    invalidateExportPreview("The HUMAN worksheet changed. Prepare a new full-export preview before downloading.");
    rows = lastBulkUndo; lastBulkUndo = null; show();
    $("bulk-message").textContent = "Last HUMAN-only batch undone. No source slot or original evidence changed.";
    $("bulk-message").dataset.error = "false";
  });
  $("clear").addEventListener("click", clear);
  function currentCsv() {
    if (!rows.length) throw Error("No original PRIVATE worksheet loaded");
    const values = [FIELDS];
    rows.forEach((r,i) => {
      const record = [digest,String(i+1),r.status,r.role,r.question,r.next];
      validRow(record,i,digest); values.push(record);
    });
    const csv = values.map(csvEncode).join("\n") + "\n";
    if (new TextEncoder().encode(csv).length > MAX_BYTES) throw Error("Edited PRIVATE actions exceed native file limit");
    return csv;
  }

  $("export").addEventListener("click", () => {
    invalidateExportPreview();
    $("export-message").textContent = "";
    try {
      pendingCsv = currentCsv();
      const stages = Object.fromEntries(STATUSES.map(value=>[value,0]));
      const roles = Object.fromEntries(ROLES.map(value=>[value,0]));
      rows.forEach(row=>{stages[row.status]++;roles[row.role]++;});
      const breakdown = $("export-preview-breakdown"); breakdown.replaceChildren();
      for (const value of STATUSES) { const item=document.createElement("li");item.textContent="Stage "+value+": "+stages[value];breakdown.append(item); }
      for (const value of ROLES) { const item=document.createElement("li");item.textContent="Proposed role "+value+": "+roles[value];breakdown.append(item); }
      for (const [label,count] of [["Rows with HUMAN question",rows.filter(row=>row.question.trim()).length],["Rows with HUMAN next action",rows.filter(row=>row.next.trim()).length]]) {
        const item=document.createElement("li");item.textContent=label+": "+count+" / "+rows.length;breakdown.append(item);
      }
      $("export-preview-summary").textContent = rows.length+" original slot(s) will be exported in original order. The current CSV is "+new TextEncoder().encode(pendingCsv).length+" bytes. No file has been downloaded yet.";
      $("export-preview").hidden = false; $("confirm-export").disabled = false;
      $("export-message").textContent = "Preview ready. Inspect the full local worksheet, then explicitly confirm the download. This remains REVIEW_ONLY.";
      $("export-message").dataset.error = "false";
    } catch (err) {
      invalidateExportPreview();
      $("export-message").textContent = "HOLD: original PRIVATE HUMAN preview refused ("+String(err.message||"invalid row")+")";
      $("export-message").dataset.error = "true";
    }
  });
  $("confirm-export").addEventListener("click", () => {
    try {
      if (pendingCsv === null) throw Error("No current full-export preview");
      const csv = currentCsv();
      if (csv !== pendingCsv) throw Error("HUMAN worksheet changed after preview");
      const blob = new Blob([csv],{type:"text/csv;charset=utf-8"});
      const url = URL.createObjectURL(blob);
      try {
        const a = document.createElement("a"); a.href=url; a.download="PRIVATE-inbox-HUMAN-actions.csv";
        document.body.append(a); a.click(); a.remove();
      } finally { setTimeout(()=>URL.revokeObjectURL(url),1000); }
      invalidateExportPreview();
      $("export-message").textContent = "REVIEW_ONLY: full original slot-ordered PRIVATE CSV download requested. This does NOT prove disk persistence. Use unchanged native finalize and independent original HUMAN review.";
      $("export-message").dataset.error = "false";
    } catch (err) {
      invalidateExportPreview();
      $("export-message").textContent = "HOLD: full PRIVATE HUMAN export refused ("+String(err.message||"invalid row")+")";
      $("export-message").dataset.error = "true";
    }
  });
  $("cancel-export").addEventListener("click", () => {
    invalidateExportPreview();
    $("export-message").textContent = "Export preview canceled; no file was downloaded.";
    $("export-message").dataset.error = "false";
  });
})();
