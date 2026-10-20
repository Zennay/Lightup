"use strict";
// PRIVATE source-attached HUMAN desk. No network, local storage, cookies,
// automatic client authority, grants, scans or review promotion.
(() => {
  const form = document.getElementById("scope-review");
  const records = Array.from(document.querySelectorAll("tbody tr[data-source]"));
  const stages = new Set(["unreviewed","investigating","escalated","documented"]);
  const status = document.getElementById("status");
  const stageFilter = document.getElementById("stage-filter");
  const changeFilter = document.getElementById("change-filter");
  const query = document.getElementById("query");
  const oldManifest = form.dataset.previous;
  const newManifest = form.dataset.current;
  const header = ["previous_manifest_sha256","current_manifest_sha256",
    "source_file_path","change_status","previous_sha256","current_sha256",
    "human_stage","human_team","human_notes"];
  let edited = false;
  if (!/^[a-f0-9]{64}$/.test(oldManifest) || !/^[a-f0-9]{64}$/.test(newManifest)
      || !records.length || records.length > 256) {
    form.replaceChildren(document.createTextNode("HOLD — invalid source-bound review workroom."));
    return;
  }
  const textSafe = (value, max) =>
    typeof value === "string" && value.length <= max &&
    !/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u.test(value) &&
    !/^[\s]*[=+\-@]/u.test(value);
  const getHuman = (r) => ({
    stage: r.querySelector(".review-stage").value,
    team: r.querySelector(".review-team").value,
    notes: r.querySelector(".review-notes").value,
  });
  const identity = (r) => [
    oldManifest,newManifest,r.dataset.source,r.dataset.change,r.dataset.old,r.dataset.new
  ];
  const fail = (msg) => { status.textContent = "HOLD: " + msg; status.setAttribute("role","alert"); };
  const update = () => {
    const wanted = query.value.toLocaleLowerCase();
    let visible = 0, attention = 0;
    for (const r of records) {
      const h = getHuman(r);
      const show = (!changeFilter.value || r.dataset.change === changeFilter.value) &&
        (!stageFilter.value || h.stage === stageFilter.value) &&
        (!wanted || r.dataset.source.toLocaleLowerCase().includes(wanted) ||
          h.team.toLocaleLowerCase().includes(wanted));
      r.hidden = !show;
      if (show) visible++;
      if (h.stage !== "documented") attention++;
    }
    document.getElementById("summary").textContent = visible + "/" + records.length +
      " visible · " + attention + " HUMAN stages not documented (not a permission/fix verdict).";
  };
  for (const r of records) {
    if (!["unchanged","changed","added","absent"].includes(r.dataset.change) ||
        !/^[a-f0-9]{64}$/.test(r.dataset.old || "0".repeat(64)) ||
        !/^[a-f0-9]{64}$/.test(r.dataset.new || "0".repeat(64))) {
      fail("Source labels invalid"); return;
    }
    for (const input of r.querySelectorAll("select,input,textarea")) {
      input.addEventListener("input", () => { edited = true; update(); });
    }
  }
  for (const control of [query,stageFilter,changeFilter]) control.addEventListener("input", update);
  function csvCell(s) { return '"' + s.replaceAll('"','""') + '"'; }
  function encode(rows) { return rows.map(r => r.map(csvCell).join(",")).join("\n") + "\n"; }
  function createDownload(name, data) {
    const blob = new Blob([data], {type:"text/csv;charset=utf-8"});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = name; a.rel = "noopener";
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }
  function snapshot() {
    const rows = [];
    for (const r of records) {
      const h = getHuman(r);
      if (!stages.has(h.stage) || !textSafe(h.team,80) || !textSafe(h.notes,500))
        throw new Error("Invalid HUMAN stage/team/notes. No controls, lines or spreadsheet formula prefixes.");
      rows.push([...identity(r),h.stage,h.team,h.notes]);
    }
    return rows;
  }
  document.getElementById("export").addEventListener("click", () => {
    try {
      const rows = snapshot();
      if (!confirm("Export a PRIVATE source-sensitive HUMAN CSV? Names, SHA-256 and notes must remain with authorized recipients.")) return;
      createDownload("LightUp-PRIVATE-source-HUMAN-review.csv", encode([header,...rows]));
      status.textContent = "PRIVATE CSV download prepared. Check that it was saved securely; this is not a review approval.";
      edited = false;
    } catch (err) { fail(err.message); }
  });
  function parseCSV(content) {
    if (content.length > 400000) throw new Error("HUMAN CSV larger than 400 KB");
    const rows = [], row = []; let cells = row, field = "", inside = false, closed = false;
    for (let i = 0; i < content.length; i++) {
      const c = content[i];
      if (inside) {
        if (c === '"') {
          if (content[i+1] === '"') { field += '"'; ++i; }
          else { inside = false; closed = true; }
        } else field += c;
      } else if (closed) {
        if (c === ",") { cells.push(field); field = ""; closed = false; }
        else if (c === "\n") { cells.push(field); rows.push(cells); cells = []; field = ""; closed = false; }
        else throw new Error("Ambiguous CSV quoted field");
      } else if (c === '"' && field === "") inside = true;
      else if (c === ",") { cells.push(field); field = ""; }
      else if (c === "\n") { cells.push(field); rows.push(cells); cells = []; field = ""; }
      else if (c === "\r") throw new Error("CR forbidden in source-bound CSV");
      else if (c === '"') throw new Error("CSV unquoted quote");
      else field += c;
      if (rows.length > 257) throw new Error("Too many HUMAN rows");
    }
    if (inside) throw new Error("Unterminated CSV quote");
    if (closed || field !== "" || cells.length) { cells.push(field); rows.push(cells); }
    return rows;
  }
  document.getElementById("import").addEventListener("change", async (event) => {
    const file = event.target.files?.[0]; event.target.value = "";
    if (!file) return;
    try {
      if (file.size > 400000) throw new Error("PRIVATE HUMAN CSV file exceeds 400 KB");
      const data = parseCSV(await file.text());
      if (data.length !== records.length + 1 ||
          data[0]?.length !== header.length || !data[0].every((x,i) => x === header[i]))
        throw new Error("Missing or extra source rows/columns");
      const changes = [];
      records.forEach((r, i) => {
        const row = data[i + 1];
        if (row.length !== header.length ||
            !identity(r).every((expected, col) => row[col] === expected) ||
            !stages.has(row[6]) || !textSafe(row[7],80) || !textSafe(row[8],500))
          throw new Error("PRIVATE HUMAN CSV does not match exact original source bytes, order or allowed fields at row " + (i+1));
        changes.push({stage:row[6],team:row[7],notes:row[8]});
      });
      if (!confirm("Import this fully source-matched HUMAN worksheet into memory? Unsaved human changes would be replaced; no grants or source data are modified.")) return;
      records.forEach((r,i) => {
        r.querySelector(".review-stage").value = changes[i].stage;
        r.querySelector(".review-team").value = changes[i].team;
        r.querySelector(".review-notes").value = changes[i].notes;
      });
      edited = true; update();
      status.textContent = "HUMAN entries restored in memory from exact original source labels. Export them explicitly to save.";
    } catch (err) { fail(err.message); }
  });
  window.addEventListener("beforeunload", (event) => {
    if (edited) { event.preventDefault(); event.returnValue = ""; }
  });
  update();
})();
