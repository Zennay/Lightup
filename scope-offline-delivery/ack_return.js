"use strict";
// Offline PRIVATE return-receipt comparison for the original HUMAN sender.
// Canonical byte equality only, never identity, permission or release.
(() => {
  const el = id => document.getElementById(id);
  const panel = el("return-ack-panel"), input = el("return-ack-file");
  const separate = el("return-ack-separate-channel"), button = el("compare-return-ack");
  const status = el("return-ack-status"), saveButton = el("save-return-review");
  let prepared = null, accepted = null, generation = 0;
  function clear() {
    generation++; prepared = null; accepted = null; input.value = "";
    separate.checked = false; panel.hidden = true;
    button.disabled = true; saveButton.hidden = true;
    status.textContent = ""; status.dataset.state = "idle";
  }
  function invalidate() {
    generation++; accepted = null; saveButton.hidden = true;
    status.dataset.state = "idle";
    status.textContent = "No returned HUMAN recipient acknowledgement compared.";
    button.disabled = !prepared;
  }
  document.addEventListener("lightup:selection-reset", clear);
  document.addEventListener("lightup:sender-note-revoked", clear);
  document.addEventListener("lightup:sender-note-ready", event => {
    clear();
    const d = event.detail;
    if (!d || !["privacy-recipient","privacy-editor","scope-reviewer"].includes(d.profile) ||
        !Number.isSafeInteger(d.size) || d.size < 1 ||
        !Array.isArray(d.files) || d.files.length < 4 || d.files.length > 7 ||
        ![d.sha256,d.sourceOuterSha256,d.noteSha256].every(v =>
          typeof v === "string" && /^[0-9a-f]{64}$/.test(v))) return;
    prepared = {profile:d.profile,size:d.size,sha256:d.sha256,
      sourceOuterSha256:d.sourceOuterSha256,noteSha256:d.noteSha256,
      files:d.files.map(row=>({path:row.path,bytes:row.bytes,sha256:row.sha256}))};
    panel.hidden = false; invalidate();
  });
  input.addEventListener("change",invalidate);
  separate.addEventListener("change",invalidate);

  function expectedAcknowledgment(item) {
    // Exact canonical output of the original browser's recipient handoff desk.
    return new TextEncoder().encode(JSON.stringify({
      format:"lightup.scope_private_human_recipient_review.v1",
      posture:"INCUBATE_M3_M7_DRAFT_HOLD",decision:"REVIEW_ONLY",
      authenticated_sender:false,authenticated_recipient:false,
      client_consent:false,operator_consent:false,grant:false,release:false,
      role:item.profile,received_zip_sha256:item.sha256,
      received_zip_bytes:item.size,original_source_sha256:item.sourceOuterSha256,
      human_sender_note_sha256:item.noteSha256,
      files:item.files.map(row=>({...row})),
      note:"UNSIGNED local offline equality only. HUMAN must independently authenticate recipient, sender, consent and transfer."
    },null,2)+"\n");
  }
  const sha = async bytes => Array.from(new Uint8Array(
    await crypto.subtle.digest("SHA-256",bytes)), b=>b.toString(16).padStart(2,"0")).join("");
  button.addEventListener("click",async () => {
    const current = ++generation;
    accepted = null; saveButton.hidden = true; button.disabled = true;
    status.dataset.state = "idle";
    const hold = () => {
      if (current !== generation) return;
      accepted = null; saveButton.hidden = true; button.disabled = false;
      status.dataset.state = "hold";
      status.textContent = "HOLD — returned unsigned review does not match the original locally built role ZIP and HUMAN sender note.";
    };
    try {
      const f = input.files && input.files[0];
      if (!prepared || !separate.checked || !f || input.files.length !== 1 ||
          !/\.json$/i.test(f.name) || !Number.isSafeInteger(f.size) ||
          f.size < 200 || f.size > 12000 || !crypto?.subtle) {hold();return;}
      status.textContent = "Comparing exact original role and HUMAN note fingerprints locally...";
      const received = new Uint8Array(await f.arrayBuffer());
      if (current !== generation) return;
      const reference = expectedAcknowledgment(prepared);
      if (received.byteLength !== f.size || received.byteLength !== reference.byteLength ||
          reference.some((byte,i) => byte !== received[i])) {hold();return;}
      const receiptSha256 = await sha(received);
      if (current !== generation) return;
      accepted = {generation:current,receiptSha256,prepared};
      document.dispatchEvent(new CustomEvent("lightup:return-ack-admitted",{detail:{
        profile:prepared.profile,roleSha256:prepared.sha256,
        sourceSha256:prepared.sourceOuterSha256,
        senderNoteSha256:prepared.noteSha256,receiptSha256
      }}));
      status.dataset.state = "match";
      status.textContent = "RETURN RECEIPT BYTE MATCH / REVIEW ONLY — exact original ZIP, HUMAN note and source fingerprints agree. No sender/recipient identity, consent or authorization has been established.";
      saveButton.hidden = false;
    } catch (_) {hold();}
    finally {if (current === generation) button.disabled = false;}
  });
  saveButton.addEventListener("click", () => {
    if (!accepted || accepted.generation !== generation || !prepared || !separate.checked) return;
    if (!window.confirm("Save an UNSIGNED source-only HUMAN return summary? This does not authorize actions.")) return;
    const out = {
      format:"lightup.scope_private_human_return_summary.v1",
      status:"REVIEW_ONLY",posture:"INCUBATE_M3_M7_DRAFT_HOLD",
      verified_identity:false,client_consent:false,operator_consent:false,
      grant:false,release:false,
      profile:prepared.profile,original_zip_sha256:prepared.sha256,
      original_source_sha256:prepared.sourceOuterSha256,
      original_human_note_sha256:prepared.noteSha256,
      received_human_ack_sha256:accepted.receiptSha256,
      note:"UNSIGNED byte-equality only. All HUMAN consent and release gates remain."
    };
    const blob = new Blob([JSON.stringify(out,null,2)+"\n"], {type:"application/octet-stream"});
    const url = URL.createObjectURL(blob), a = document.createElement("a");
    a.href=url; a.download="LightUp-PRIVATE-HUMAN-return-REVIEW-ONLY.json";
    a.rel="noopener"; document.body.append(a); a.click(); a.remove();
    setTimeout(()=>URL.revokeObjectURL(url),30000);
  });
})();
