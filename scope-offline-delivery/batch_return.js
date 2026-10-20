"use strict";
/* PRIVATE in-memory multi-role HUMAN byte-reconciliation board. No delivery/consent claims. */
(() => {
  const el = id => document.getElementById(id);
  const panel = el("batch-return-panel"), list = el("batch-return-rows");
  const headline = el("batch-return-status"), save = el("save-batch-return");
  let sourceSha = null, records = new Map(), generation = 0;
  const sha = x => typeof x === "string" && /^[0-9a-f]{64}$/.test(x);
  function reset() {
    generation++; sourceSha = null; records.clear();
    list.replaceChildren(); save.hidden = true; panel.hidden = true;
    headline.textContent = "";
  }
  document.addEventListener("lightup:selection-reset",reset);
  document.addEventListener("lightup:sender-note-revoked",reset);

  function render() {
    if (!sourceSha || records.size !== 3) return;
    list.replaceChildren();
    let notes = 0, matches = 0;
    for (const record of records.values()) {
      const item = document.createElement("li");
      const prepared = sha(record.noteSha);
      const matched = prepared && sha(record.returnSha);
      if (prepared) notes++;
      if (matched) matches++;
      item.textContent = record.profile + " · source ZIP " + record.roleSha +
        " · HUMAN note " + (prepared ? "source bytes prepared" : "not prepared") +
        " · returned receipt " + (matched ? "exact byte match" : "not matched") +
        " · NEVER proof of delivery, recipient identity, consent or grant.";
      list.append(item);
    }
    headline.textContent = notes + "/3 separate HUMAN notes prepared · " +
      matches + "/3 exact returned byte receipts matched. All remain UNSIGNED / REVIEW ONLY.";
    save.hidden = false;
  }

  document.addEventListener("lightup:batch-roles-prepared", event => {
    reset();
    const d = event.detail;
    const expected = ["privacy-recipient","privacy-editor","scope-reviewer"];
    if (!d || !sha(d.sourceSha256) || !Array.isArray(d.roles) ||
        d.roles.length !== 3 ||
        new Set(d.roles.map(r => r.profile)).size !== 3 ||
        expected.some(name => !d.roles.some(row=>row.profile===name)) ||
        d.roles.some(row=>!sha(row.sha256) || !Number.isSafeInteger(row.bytes) ||
          row.bytes < 1 || row.bytes > 1500000)) return;
    sourceSha = d.sourceSha256;
    for (const row of d.roles) {
      records.set(row.profile,{
        profile:row.profile,roleSha:row.sha256,bytes:row.bytes,
        noteSha:null,returnSha:null
      });
    }
    panel.hidden = false;render();
  });
  document.addEventListener("lightup:sender-note-ready", event => {
    if (!sourceSha) return;
    const d = event.detail, row = d && records.get(d.profile);
    if (!row || d.sourceOuterSha256 !== sourceSha ||
        d.sha256 !== row.roleSha || d.size !== row.bytes ||
        !sha(d.noteSha256)) return;
    if (row.noteSha !== d.noteSha256) row.returnSha = null;
    row.noteSha = d.noteSha256;render();
  });
  document.addEventListener("lightup:return-ack-admitted", event => {
    if (!sourceSha) return;
    const d = event.detail, row = d && records.get(d.profile);
    if (!row || d.sourceSha256 !== sourceSha ||
        d.roleSha256 !== row.roleSha ||
        d.senderNoteSha256 !== row.noteSha ||
        !sha(d.receiptSha256)) return;
    row.returnSha = d.receiptSha256;render();
  });
  save.addEventListener("click", () => {
    if (!sourceSha || records.size !== 3) return;
    if (!window.confirm("Save an UNSIGNED source-only HUMAN status sheet? No receipt proves identity, actual delivery, consent or permission.")) return;
    const rows = [...records.values()].map(row=>({
      role:row.profile,role_zip_sha256:row.roleSha,role_zip_bytes:row.bytes,
      unsigned_sender_note_sha256:row.noteSha,
      unsigned_return_receipt_sha256:row.returnSha,
      result:row.returnSha ? "BYTE_MATCH_REVIEW_ONLY" :
        row.noteSha ? "AWAITING_UNVERIFIED_RECEIPT" : "HUMAN_NOTE_NOT_PREPARED"
    }));
    const out = {
      format:"lightup.scope_private_role_return_board.v1",
      posture:"INCUBATE_M3_M7_DRAFT_HOLD",decision:"REVIEW_ONLY",
      authenticated_sender:false,authenticated_recipient:false,
      client_consent:false,operator_consent:false,grant:false,release:false,
      full_source_sha256:sourceSha,rows,
      note:"UNSIGNED source-only byte observations. This is not proof of HUMAN delivery or approval."
    };
    const blob = new Blob([JSON.stringify(out,null,2)+"\n"],{type:"application/octet-stream"});
    const url = URL.createObjectURL(blob), link=document.createElement("a");
    link.href=url;link.download="LightUp-PRIVATE-role-return-status-REVIEW-ONLY.json";
    link.rel="noopener";document.body.append(link);link.click();link.remove();
    setTimeout(()=>URL.revokeObjectURL(url),30000);
  });
})();
