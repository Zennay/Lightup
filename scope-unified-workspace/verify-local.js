"use strict";
// Local digest comparison only. No network, no storage, no auth, no grant.
(() => {
  const form = document.getElementById("digest-form");
  const picker = document.getElementById("bundle-file");
  const expected = document.getElementById("expected-digest");
  const status = document.getElementById("digest-status");
  const digest = document.getElementById("actual-digest");
  const MAX_BYTES = 8 * 1024 * 1024;
  const update = (text, ok) => {
    status.textContent = text;
    status.dataset.state = ok ? "match" : "hold";
  };
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    digest.textContent = "—";
    const file = picker.files && picker.files[0];
    const original = expected.value.trim().toLowerCase();
    if (!file) {
      update("HOLD — kies een lokaal ZIP-bestand.", false);
      return;
    }
    if (file.size < 4 || file.size > MAX_BYTES) {
      update("HOLD — ongeldig of te groot bestand (maximum 8 MiB).", false);
      return;
    }
    if (original && !/^[0-9a-f]{64}$/.test(original)) {
      update("HOLD — gebruik exact 64 hextekens voor de apart geverifieerde SHA-256.", false);
      return;
    }
    if (!globalThis.crypto || !crypto.subtle) {
      update("HOLD — lokale Web Crypto SHA-256 ontbreekt; gebruik de Python CLI uit de bundel.", false);
      return;
    }
    update("Lokaal SHA-256 berekenen…", false);
    try {
      const bytes = await file.arrayBuffer();
      const magic = new Uint8Array(bytes, 0, 4);
      if (magic[0] !== 0x50 || magic[1] !== 0x4b || magic[2] !== 0x03 || magic[3] !== 0x04) {
        update("HOLD — geen verwacht ZIP-local-headerformaat.", false);
        return;
      }
      const sum = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
      const hex = Array.from(sum, (b) => b.toString(16).padStart(2, "0")).join("");
      digest.textContent = hex;
      if (!original) {
        update("REVIEW_ONLY — lokale digest berekend; voer een onafhankelijk geverifieerde waarde in om te vergelijken.", false);
      } else if (hex === original) {
        update("REVIEW_ONLY — SHA-256 KOMT OVEREEN. Alleen exacte transportbytes vergeleken; NOOIT toestemming of authenticatiebewijs.", true);
      } else {
        update("HOLD — SHA-256 VERSCHILT. Open of deel deze bundel niet als het verwachte pakket.", false);
      }
    } catch (_) {
      update("HOLD — lokale bestandslezing of digestberekening niet beschikbaar.", false);
    }
  });
})();
