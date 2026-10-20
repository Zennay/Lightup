"use strict";
// Byte equality only; NEVER origin, safety, consent, identity or authorization.
const pick = id => document.getElementById(id);
const selected = pick("selected");
const expected = pick("expected");
const status = pick("status");
const details = pick("details");
const button = pick("verify");
let revision = 0;

function reset() {
  revision += 1;
  document.dispatchEvent(new Event("lightup:selection-reset"));
  status.textContent = "No comparison performed. Do not treat this as permission.";
  status.dataset.state = "idle";
  details.textContent = "";
  button.disabled = false;
}

selected.addEventListener("change", reset);
expected.addEventListener("input", reset);

button.addEventListener("click", async () => {
  const current = ++revision;
  button.disabled = true;
  status.dataset.state = "idle";
  details.textContent = "";
  const fail = (reason) => {
    if (revision !== current) return;
    status.dataset.state = "hold";
    status.textContent = "HOLD — " + reason;
    button.disabled = false;
  };
  try {
    const file = selected.files && selected.files[0];
    if (!file) { fail("Select exactly one local file first."); return; }
    if (selected.files.length !== 1) { fail("Ambiguous file selection."); return; }
    const claim = expected.value.trim();
    if (!/^[0-9a-f]{64}$/.test(claim)) {
      fail("Enter the full lowercase SHA-256 received through a separate authenticated channel.");
      return;
    }
    if (!Number.isSafeInteger(file.size) || file.size < 1 || file.size > 2500000) {
      fail("File is empty or exceeds the 2.5 MB local review limit.");
      return;
    }
    status.textContent = "Locally reading and hashing bytes; no upload...";
    const bytes = await file.arrayBuffer();
    if (revision !== current) return;
    if (bytes.byteLength !== file.size) { fail("Selected bytes changed during review."); return; }
    if (!globalThis.crypto || !crypto.subtle) {
      fail("This browser context lacks local WebCrypto SHA-256. Use the Python inspector.");
      return;
    }
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    if (revision !== current) return;
    const actual = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
    details.textContent = "File: " + file.name + " · " + file.size.toLocaleString() +
      " bytes · computed local SHA-256: " + actual;
    if (actual !== claim) {
      fail("The computed file bytes do not match your separately supplied digest.");
      return;
    }
    document.dispatchEvent(new CustomEvent("lightup:byte-match", {detail: {bytes, name: file.name, sha256: actual}}));
    status.dataset.state = "match";
    status.textContent = "BYTE MATCH / REVIEW ONLY — still no sender identity, client consent, grant, confidentiality approval or release.";
    button.disabled = false;
  } catch (_) {
    fail("Local read or hash unavailable. Nothing has been verified.");
  }
});
