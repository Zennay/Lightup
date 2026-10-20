"use strict";
// Offline HUMAN sender-note reconciliation against a separately SHA-verified,
// fully source-admitted ORIGINAL role ZIP. No grants, identity or consent.
(() => {
  const el = id => document.getElementById(id);
  const panel = el("received-handoff-panel"), input = el("received-handoff-note");
  const separate = el("handoff-separate-channel"), compare = el("compare-handoff");
  const feedback = el("handoff-status"), acknowledgment = el("save-handoff-ack");
  const digestOutput = el("handoff-digest");
  const knownOriginals = new Set([
    "workspace/LightUp-Scope-Offline-DRAFT-HOLD.zip",
    "workspace/SOURCE-MANIFEST.json", "workspace/DIST-MANIFEST.json",
    "workspace/verify.html", "courier/PRIVATE-encrypted-courier.html",
    "privacy/disclosure-preflight.html", "privacy/disclosure-recipient-verify.html"
  ]);
  let admitted = null, accepted = null, generation = 0;

  function clearAll() {
    generation++;
    admitted = null; accepted = null; input.value = ""; separate.checked = false;
    panel.hidden = true; acknowledgment.hidden = true; compare.disabled = true;
    feedback.textContent = ""; feedback.dataset.state = "idle";
    digestOutput.textContent = "";
  }
  function invalidate() {
    generation++; accepted = null; acknowledgment.hidden = true;
    feedback.dataset.state = "idle";
    digestOutput.textContent = "";
    feedback.textContent = "Unsigned sender note not yet compared; no identity, consent or authority established.";
    compare.disabled = !admitted;
  }
  document.addEventListener("lightup:selection-reset", clearAll);
  document.addEventListener("lightup:received-role-admitted", event => {
    clearAll();
    const detail = event.detail;
    if (!detail || !["privacy-recipient","privacy-editor","scope-reviewer"].includes(detail.profile) ||
        !/^[0-9a-f]{64}$/.test(detail.sha256) ||
        !/^[0-9a-f]{64}$/.test(detail.sourceOuterSha256) ||
        !Number.isSafeInteger(detail.size) || detail.size < 1 ||
        !Array.isArray(detail.files)) return;
    // Source admission and byte validation occurred in the original receiver.
    admitted = {profile: detail.profile, sha256: detail.sha256,
      sourceOuterSha256: detail.sourceOuterSha256, size: detail.size,
      files: detail.files.map(row => ({path:row.path,bytes:row.bytes,sha256:row.sha256}))};
    panel.hidden = false;
    invalidate();
  });
  input.addEventListener("change", invalidate);
  separate.addEventListener("change", invalidate);

  function expectedNote(item) {
    const original = item.files.filter(row => knownOriginals.has(row.path));
    const lines = [
      "LIGHTUP PRIVATE HUMAN ROLE HANDOFF — REVIEW ONLY / DRAFT HOLD",
      "format: lightup.scope_private_human_sender_note.v1",
      "role: " + item.profile,
      "original-source-zip-sha256: " + item.sourceOuterSha256,
      "role-zip-sha256: " + item.sha256,
      "role-zip-bytes: " + item.size,
      "original-source-components: " + original.length,
      "",
      "Included unchanged original source components:"
    ];
    for (const row of original) {
      lines.push(row.path + " | " + row.bytes + " bytes | sha256=" + row.sha256);
    }
    lines.push("", "UNSIGNED. No consent, authorization, origin, grant, release or approval.",
      "Independently authenticate the recipient and a SEPARATE trusted channel.",
      "Share the expected ZIP digest through that channel, NOT as self-proof",
      "attached to the same untrusted archive. Encrypt private material with",
      "the separately sourced original HUMAN courier before transferring.",
      "Manual review and original LightUp authorization/release gates remain.", "");
    return new TextEncoder().encode(lines.join("\n"));
  }
  const hex = bytes => Array.from(new Uint8Array(bytes), x => x.toString(16).padStart(2,"0")).join("");
  function save(bytes, filename) {
    const url = URL.createObjectURL(new Blob([bytes], {type: "application/octet-stream"}));
    const a = document.createElement("a");
    a.href = url; a.download = filename; a.rel = "noopener";
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }
  compare.addEventListener("click", async () => {
    const current = ++generation;
    const hold = () => {
      if (current !== generation) return;
      accepted = null; acknowledgment.hidden = true;
      feedback.dataset.state = "hold";
      feedback.textContent = "HOLD — original role bytes and received HUMAN note do not agree, or note is not separately sourced. No handoff accepted.";
      compare.disabled = false;
    };
    accepted = null; acknowledgment.hidden = true; compare.disabled = true;
    digestOutput.textContent = ""; feedback.dataset.state = "idle";
    try {
      const f = input.files && input.files[0];
      if (!admitted || !separate.checked || !f || input.files.length !== 1 ||
          !/\.txt$/i.test(f.name) || !Number.isSafeInteger(f.size) ||
          f.size < 200 || f.size > 4096 || !crypto?.subtle) {
        hold(); return;
      }
      feedback.textContent = "Comparing exact source-bound note bytes locally...";
      const snapshot = await f.arrayBuffer();
      if (current !== generation) return;
      if (snapshot.byteLength !== f.size) {hold();return;}
      const wanted = expectedNote(admitted);
      const got = new Uint8Array(snapshot);
      if (wanted.byteLength !== got.byteLength ||
          wanted.some((byte, index) => byte !== got[index])) {hold();return;}
      const noteSha = hex(await crypto.subtle.digest("SHA-256",snapshot));
      if (current !== generation) return;
      accepted = {generation: current, received: admitted, noteSha};
      feedback.dataset.state = "match";
      feedback.textContent = "SOURCE+NOTE MATCH / REVIEW ONLY — exact role and original byte receipt agree. Sender/recipient identities, separate-channel authenticity and legal permission remain UNVERIFIED.";
      digestOutput.textContent = "Role ZIP SHA-256 " + admitted.sha256 +
        " · unsigned HUMAN note SHA-256 " + noteSha;
      acknowledgment.hidden = false;
    } catch (_) {hold();}
    finally {if (current === generation) compare.disabled = false;}
  });
  acknowledgment.addEventListener("click", () => {
    if (!accepted || accepted.generation !== generation || !separate.checked || !admitted) return;
    if (!window.confirm("Save PRIVATE, UNSIGNED local recipient byte-match acknowledgement? This is NOT authorization, sender identity or consent.")) return;
    const out = {
      format:"lightup.scope_private_human_recipient_review.v1",
      posture:"INCUBATE_M3_M7_DRAFT_HOLD",decision:"REVIEW_ONLY",
      authenticated_sender:false,authenticated_recipient:false,
      client_consent:false,operator_consent:false,grant:false,release:false,
      role:admitted.profile,received_zip_sha256:admitted.sha256,
      received_zip_bytes:admitted.size,original_source_sha256:admitted.sourceOuterSha256,
      human_sender_note_sha256:accepted.noteSha,
      files:admitted.files.map(row=>({...row})),
      note:"UNSIGNED local offline equality only. HUMAN must independently authenticate recipient, sender, consent and transfer."
    };
    save(new TextEncoder().encode(JSON.stringify(out,null,2)+"\n"),
      "LightUp-PRIVATE-role-receipt-REVIEW-ONLY.json");
  });
})();
