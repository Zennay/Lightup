"use strict";
/* Offline source-only original-kit version comparison. Never grants authority. */
(() => {
  const el = id => document.getElementById(id);
  const panel = el("version-delta-panel"), oldFile = el("version-delta-file");
  const oldDigest = el("version-delta-sha"), inspect = el("version-delta-compare");
  const status = el("version-delta-status"), inventory = el("version-delta-inventory");
  const saveReport = el("version-delta-save");
  const mandatory = [
    "workspace/LightUp-Scope-Offline-DRAFT-HOLD.zip",
    "workspace/SOURCE-MANIFEST.json","workspace/DIST-MANIFEST.json",
    "workspace/verify.html","courier/PRIVATE-encrypted-courier.html",
    "privacy/disclosure-preflight.html","privacy/disclosure-recipient-verify.html"
  ];
  let current = null, result = null, revision = 0;
  const digest = async bytes => Array.from(new Uint8Array(
    await crypto.subtle.digest("SHA-256",bytes)),
    b => b.toString(16).padStart(2,"0")).join("");
  const validHex = value => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
  function reset(hide = true) {
    revision++; result = null;
    status.dataset.state = "idle"; status.textContent = "";
    inventory.replaceChildren(); saveReport.hidden = true;
    inspect.disabled = !current;
    if (hide) {
      current = null; panel.hidden = true; oldFile.value = ""; oldDigest.value = "";
    }
  }
  document.addEventListener("lightup:selection-reset", () => reset());
  document.addEventListener("lightup:full-kit-admitted", event => {
    reset();
    const detail = event.detail;
    if (!detail || !(detail.entries instanceof Map) ||
        !validHex(detail.sha256) || mandatory.some(name=>!detail.entries.has(name))) return;
    current = {entries:detail.entries,sha256:detail.sha256};
    panel.hidden = false; inspect.disabled = false;
    status.textContent = "Current original source-only kit admitted. Supply a separate authenticated SHA-256 for the earlier kit.";
  });
  for (const node of [oldFile, oldDigest]) {
    node.addEventListener(node === oldFile ? "change" : "input", () => reset(false));
  }
  const sorted = items => items.sort((a,b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  async function inventoryOf(entries, revisionAtStart) {
    if (!(entries instanceof Map) || entries.size < mandatory.length ||
        mandatory.some(name => !entries.has(name)) || entries.size > 64) {
      throw Error("Source-only ZIP missing original scope members");
    }
    const rows = [];
    for (const [path, entry] of entries) {
      if (revision !== revisionAtStart) return null;
      if (!entry || !(entry.bytes instanceof Uint8Array) ||
          !Number.isSafeInteger(entry.size) || entry.size !== entry.bytes.length) {
        throw Error("Malformed member identity");
      }
      rows.push({path, bytes:entry.size, sha256:await digest(entry.bytes)});
    }
    return sorted(rows);
  }
  inspect.addEventListener("click", async () => {
    const token = ++revision;
    inspect.disabled = true; result = null;
    saveReport.hidden = true; inventory.replaceChildren();
    status.dataset.state = "idle";
    const hold = () => {
      if (token !== revision) return;
      result = null; inventory.replaceChildren();
      saveReport.hidden = true; status.dataset.state = "hold";
      status.textContent = "HOLD — earlier source-only ZIP or separately supplied digest was not admitted. Nothing compared.";
    };
    try {
      const file = oldFile.files && oldFile.files[0];
      const expected = oldDigest.value.trim();
      if (!current || !crypto?.subtle || !validHex(expected) ||
          !file || oldFile.files.length !== 1 || !/\.zip$/i.test(file.name) ||
          !Number.isSafeInteger(file.size) || file.size < 100 ||
          file.size > 2500000) {hold();return;}
      status.textContent = "Reading two local source inventories; no uploads...";
      const bytes = await file.arrayBuffer();
      if (token !== revision) return;
      if (bytes.byteLength !== file.size || await digest(bytes) !== expected) {hold();return;}
      if (token !== revision) return;
      const request = {bytes,entries:null};
      document.dispatchEvent(new CustomEvent("lightup:strict-zip-read",{detail:request}));
      const previous = await inventoryOf(request.entries,token);
      const next = await inventoryOf(current.entries,token);
      if (token !== revision || !previous || !next) return;
      const oldMap = new Map(previous.map(row => [row.path,row]));
      const nextMap = new Map(next.map(row => [row.path,row]));
      const added = next.filter(row => !oldMap.has(row.path));
      const removed = previous.filter(row => !nextMap.has(row.path));
      const changed = next.filter(row => oldMap.has(row.path) &&
        (oldMap.get(row.path).sha256 !== row.sha256 || oldMap.get(row.path).bytes !== row.bytes))
        .map(row=>({path:row.path,before:oldMap.get(row.path),after:row}));
      const unchanged = next.length - added.length - changed.length;
      result = {
        format:"lightup.scope_offline_source_delta.v1",
        posture:"INCUBATE_M3_M7_DRAFT_HOLD",decision:"REVIEW_ONLY",
        signed:false,authenticated_sender:false,client_consent:false,
        operator_consent:false,grant:false,release:false,
        earlier_zip_sha256:expected,current_zip_sha256:current.sha256,
        earlier_members:previous.length,current_members:next.length,
        unchanged,added,removed,changed,
        note:"UNSIGNED exact local source-byte comparison; no identity, consent, security review or authorization."
      };
      for (const [type,rows] of [["Added",added],["Removed",removed],["Changed",changed]]) {
        for (const row of rows) {
          const line = document.createElement("li");
          line.textContent = type + ": " + row.path + (type === "Changed" ?
            " · before " + row.before.sha256 + " · after " + row.after.sha256 :
            " · " + row.bytes + " bytes · SHA-256 " + row.sha256);
          inventory.append(line);
        }
      }
      if (token !== revision) return;
      status.dataset.state = "match";
      status.textContent = "SOURCE BYTE DELTA / REVIEW ONLY · " + added.length +
        " added, " + changed.length + " changed, " + removed.length +
        " removed, " + unchanged + " unchanged. Independent sender identity and original release gates remain.";
      saveReport.hidden = false;
    } catch (_) {hold();}
    finally {if (token === revision) inspect.disabled = false;}
  });
  saveReport.addEventListener("click", () => {
    if (!result || !current || result.current_zip_sha256 !== current.sha256) return;
    if (!window.confirm("Save unsigned PRIVATE source-only difference metadata? No security approval is implied.")) return;
    const blob = new Blob([JSON.stringify(result,null,2)+"\n"],{type:"application/octet-stream"});
    const url = URL.createObjectURL(blob), a = document.createElement("a");
    a.href=url;a.download="LightUp-PRIVATE-source-delta-REVIEW-ONLY.json";
    a.rel="noopener";document.body.append(a);a.click();a.remove();
    setTimeout(()=>URL.revokeObjectURL(url),30000);
  });
})();
