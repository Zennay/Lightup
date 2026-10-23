"use strict";
/* LightUp PRIVATE HUMAN recipient workroom. No network, storage, source IDs or permissions. */
(() => {
  const SEED = JSON.parse(document.getElementById("source-seed").textContent);
  const STAGES = ["open", "in_review", "waiting_source_owner", "answered_human"];
  const ROUTES = ["unassigned", "source_owner", "human_reviewer", "privacy_reviewer"];
  const WARNING = "UNVERIFIED private HUMAN recipient notes; original client/source/cohort authenticity and remediation status UNKNOWN. Counts, timestamps and notes never authorize or verify a fix, grant, scan or retest.";
  const $ = (id) => document.getElementById(id);
  const entries = SEED.reasons.map(r => ({
    reason: r.reason, count: r.count, delta: r.delta,
    stage: "open", route: "unassigned", note: ""
  }));
  const status = $("status");
  const save = $("save");
  const input = $("restore");
  const rows = $("rows");
  const stats = $("stats");

  function label(tag, text) {
    const element = document.createElement(tag);
    element.textContent = text;
    return element;
  }
  function options(select, values, current) {
    for (const value of values) {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = value.replaceAll("_", " ");
      option.selected = current === value;
      select.appendChild(option);
    }
  }
  function matchKeys(object, keys) {
    if (!object || Array.isArray(object) || typeof object !== "object") return false;
    const real = Object.keys(object).sort();
    return real.length === keys.length &&
      real.every((key, index) => key === [...keys].sort()[index]);
  }
  function validEntry(entry, canonical) {
    if (!matchKeys(entry, ["reason","count","delta","stage","route","note"])) return false;
    if (entry.reason !== canonical.reason || entry.count !== canonical.count ||
        entry.delta !== canonical.delta || !STAGES.includes(entry.stage) ||
        !ROUTES.includes(entry.route) || typeof entry.note !== "string" ||
        entry.note.length > 800 || new TextEncoder().encode(entry.note).length > 1200 ||
        /[\p{C}\p{Zl}\p{Zp}]/u.test(entry.note.replaceAll("\n", ""))) return false;
    return true;
  }
  function validate(doc) {
    if (!matchKeys(doc, ["kind","schema_version","disposition","source_sha256",
                          "warning","entries"])) return false;
    if (doc.kind !== "lightup.private_recipient_human_reason_journal" ||
        doc.schema_version !== 1 || doc.disposition !== "HUMAN_NOT_ACTION_AUTHORITY" ||
        doc.source_sha256 !== SEED.source_sha256 || doc.warning !== WARNING ||
        !Array.isArray(doc.entries) || doc.entries.length !== entries.length) return false;
    return doc.entries.every((row, index) => validEntry(row, SEED.reasons[index]));
  }
  function snapshot() {
    return {kind: "lightup.private_recipient_human_reason_journal",
      schema_version: 1, disposition: "HUMAN_NOT_ACTION_AUTHORITY",
      source_sha256: SEED.source_sha256, warning: WARNING,
      entries: entries.map(item => ({...item}))};
  }
  function counts() {
    const tally = Object.fromEntries(STAGES.map(x => [x, 0]));
    for (const row of entries) tally[row.stage] += 1;
    stats.textContent = entries.length + " HUMAN reason groups · " +
      STAGES.map(x => x.replaceAll("_", " ") + ": " + tally[x]).join(" · ");
  }
  function render() {
    rows.replaceChildren();
    for (let index=0; index < entries.length; index++) {
      const entry = entries[index], prompt = SEED.reasons[index];
      const card = document.createElement("section");
      card.className = "reason";
      const title = label("h3", (index+1) + ". " + entry.reason.replaceAll("_"," "));
      const detail = label("p", entry.count + " original local count occurrence(s); " +
          "selected difference " + (entry.delta > 0 ? "+" : "") + entry.delta +
          ". " + prompt.advice);
      const stageLabel = label("label","HUMAN follow-up stage");
      const stage = document.createElement("select");
      stage.setAttribute("aria-label", "Human stage for " + entry.reason);
      options(stage, STAGES, entry.stage);
      stage.addEventListener("change", () => {entry.stage = stage.value; counts();});
      stageLabel.appendChild(stage);
      const routeLabel = label("label","HUMAN proposed routing (not a work order)");
      const route = document.createElement("select");
      route.setAttribute("aria-label", "Human routing for " + entry.reason);
      options(route, ROUTES, entry.route);
      route.addEventListener("change", () => {entry.route=route.value;});
      routeLabel.appendChild(route);
      const noteLabel = label("label","PRIVATE recipient note (never sent)");
      const note = document.createElement("textarea");
      note.rows=3; note.maxLength=800; note.value=entry.note;
      note.setAttribute("aria-label", "Private note for " + entry.reason);
      note.placeholder="Discuss with original source owner; no customer IDs or evidence here.";
      note.addEventListener("input", () => {entry.note=note.value;});
      noteLabel.appendChild(note);
      card.append(title,detail,stageLabel,routeLabel,noteLabel);
      rows.appendChild(card);
    }
    counts();
  }
  function download(blob, name) {
    const url=URL.createObjectURL(blob);
    const link=document.createElement("a");
    link.href=url; link.download=name;
    document.body.appendChild(link);
    link.click(); link.remove();
    setTimeout(()=>URL.revokeObjectURL(url),5000);
  }
  save.addEventListener("click", () => {
    const doc=snapshot();
    if (!validate(doc)) {
      status.textContent="HOLD: invalid private notes or source identity; nothing exported.";
      return;
    }
    download(new Blob([JSON.stringify(doc,null,2)+"\n"],{type:"application/json"}),
             "lightup-PRIVATE-HUMAN-journal.json");
    status.textContent="PRIVATE HUMAN journal saved locally. No network upload or source change.";
  });
  input.addEventListener("change", async () => {
    const file=input.files && input.files[0]; input.value="";
    if (!file) return;
    if (file.size > 65536) {status.textContent="HOLD: journal larger than 64 KiB.";return;}
    try {
      const raw=new TextDecoder("utf-8",{fatal:true,ignoreBOM:true}).decode(await file.arrayBuffer());
      if (raw.charCodeAt(0)===0xfeff) throw new Error("BOM not accepted");
      const doc=JSON.parse(raw);
      if (raw!==JSON.stringify(doc,null,2)+"\n") throw new Error("Noncanonical JSON");
      if (!validate(doc)) throw new Error("Snapshot or categories mismatch");
      for (let i=0;i<entries.length;i++) Object.assign(entries[i],doc.entries[i]);
      render();
      status.textContent="PRIVATE journal restored for matching source-free snapshot. "+
        "Native Python admission still required before private handoff.";
    } catch (_) {
      status.textContent="HOLD: journal not accepted; existing HUMAN entries unchanged.";
    }
  });
  $("reset").addEventListener("click", () => {
    if (!window.confirm("Discard all unsaved HUMAN-only edits in this browser tab?")) return;
    for (const entry of entries) {entry.stage="open";entry.route="unassigned";entry.note="";}
    render();status.textContent="Local HUMAN draft cleared. Original source unchanged.";
  });
  render();
})();