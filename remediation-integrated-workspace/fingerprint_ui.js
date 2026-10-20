"use strict";
(() => {
  const picker = document.getElementById("packet-files");
  const analyze = document.getElementById("packet-analyze");
  const clear = document.getElementById("packet-clear");
  const exportButton = document.getElementById("packet-export");
  const output = document.getElementById("packet-result");
  const notice = document.getElementById("packet-message");
  const comparison = document.getElementById("packet-comparison");
  const limitCount = 8;
  const limitItem = 20 * 1024 * 1024;
  const limitTotal = 64 * 1024 * 1024;
  let inventory = [];

  function forget() {
    inventory = [];
    output.replaceChildren();
    comparison.textContent = "";
    exportButton.disabled = true;
  }
  function message(s) {
    notice.textContent = s;
  }
  function hex(bytes) {
    return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, "0")).join("");
  }
  function table(results) {
    const tab = document.createElement("table");
    const cap = document.createElement("caption");
    cap.textContent = "PRIVATE lokale bytes, geen geauthenticeerde bron of goedkeuring";
    tab.append(cap);
    const head = document.createElement("thead");
    const row = document.createElement("tr");
    for (const title of ["Lokaal bestand", "Grootte", "SHA-256 van exacte bytes"]) {
      const th = document.createElement("th");
      th.textContent = title;
      row.append(th);
    }
    head.append(row);
    tab.append(head);
    const body = document.createElement("tbody");
    for (const item of results) {
      const tr = document.createElement("tr");
      for (const text of [item.label, item.size.toLocaleString("nl-NL") + " bytes", item.sha256]) {
        const td = document.createElement("td");
        td.textContent = text;
        tr.append(td);
      }
      body.append(tr);
    }
    tab.append(body);
    output.replaceChildren(tab);
  }

  analyze.addEventListener("click", async () => {
    forget();
    const files = Array.from(picker.files || []);
    if (!files.length) {
      message("Kies eerst 1 tot 8 oorspronkelijke lokale bestanden.");
      return;
    }
    if (files.length > limitCount ||
        files.some(f => !Number.isSafeInteger(f.size) || f.size <= 0 || f.size > limitItem) ||
        files.reduce((sum, f) => sum + f.size, 0) > limitTotal) {
      picker.value = "";
      message("HOLD: maximaal 8 bestanden, 20 MiB per stuk, 64 MiB samen; lege bestanden niet toegestaan.");
      return;
    }
    if (!window.crypto || !crypto.subtle || typeof crypto.subtle.digest !== "function") {
      message("HOLD: veilige lokale WebCrypto SHA-256 is hier niet beschikbaar. Geen upload/fallback.");
      return;
    }
    analyze.disabled = true;
    const candidate = [];
    message("Exacte bytes worden alleen in dit browservenster gelezen en lokaal gehasht.");
    try {
      for (let i = 0; i < files.length; i++) {
        const f = files[i];
        const raw = await f.arrayBuffer();
        if (raw.byteLength !== f.size || raw.byteLength > limitItem) {
          throw Error("De geselecteerde bronbytes veranderden tijdens het lezen.");
        }
        const sha256 = hex(await crypto.subtle.digest("SHA-256", raw));
        candidate.push({
          slot: i + 1,
          label: "Lokaal bestand " + (i + 1),
          size: f.size,
          sha256
        });
      }
      inventory = candidate;
      table(candidate);
      if (candidate.length === 2) {
        const same = candidate[0].size === candidate[1].size &&
                     candidate[0].sha256 === candidate[1].sha256;
        comparison.textContent = same
          ? "De twee geselecteerde bestanden hebben dezelfde SHA-256 en lengte. Dit bewijst GEEN oorsprong, onafhankelijke beoordelaars, handtekening of toestemming."
          : "De twee geselecteerde bestanden verschillen in lengte of SHA-256. Stop en vraag de oorspronkelijke bronhouder naar de bedoelde pakketversie; niet automatisch vervangen of vertrouwen.";
      } else if (candidate.length > 2) {
        const distinct = new Set(candidate.map(x => x.size + ":" + x.sha256)).size;
        comparison.textContent = distinct + " van " + candidate.length +
          " verschillende lokale byte-identiteiten. Volgorde, identiteit, echte tijdlijn en autorisatie blijven ONBEKEND.";
      } else {
        comparison.textContent = "Deze fingerprint kan later op een afzonderlijk geautoriseerd apparaat worden vergeleken; er is geen geauthenticeerde afzender of inhoudstoelating.";
      }
      exportButton.disabled = false;
      message("PRIVATE fingerprint-overzicht klaar. Geen bestanden verzonden of bewaard. Verwijder lokaal na gebruik.");
    } catch (_) {
      forget();
      message("HOLD: lokaal lezen of SHA-256 mislukt. Geen gedeeltelijke resultaten behouden.");
    } finally {
      analyze.disabled = false;
      picker.value = "";
    }
  });
  clear.addEventListener("click", () => {
    picker.value = "";
    forget();
    message("Resultaten uit het browsergeheugen gewist; er zijn geen bronbestanden aangepast.");
  });
  exportButton.addEventListener("click", () => {
    if (!inventory.length) return;
    if (!window.confirm("Dit maakt een PRIVATE JSON-bestand met SHA-256-digests en lengtes. Zelfs zonder bestandsnamen kunnen fingerprints gevoelig of koppelbaar zijn. Alleen voor afzonderlijk geautoriseerde offline overdracht. Doorgaan?")) return;
    const receipt = {
      kind: "lightup.private_unsigned_local_byte_fingerprints",
      schema_version: 1,
      disposition: "HUMAN_REVIEW_ONLY_DRAFT_HOLD",
      authority_granted: false,
      sender_authenticated: false,
      consent_verified: false,
      remediation_verified: false,
      chronology_verified: false,
      files: inventory.map(({slot, size, sha256}) => ({slot, bytes: size, sha256})),
      warning: "Unkeyed SHA-256 is local byte consistency only, not original provenance, client consent, verified fix, scan, grant, security clearance or HUMAN GO."
    };
    const payload = JSON.stringify(receipt, null, 2) + "\n";
    const url = URL.createObjectURL(new Blob([payload], {type: "application/json"}));
    try {
      const link = document.createElement("a");
      link.href = url;
      link.download = "private-unsigned-byte-fingerprints.json";
      link.rel = "noopener";
      document.body.append(link);
      link.click();
      link.remove();
      message("PRIVATE hashreceipt lokaal aangeboden. Behandel dit bestand als gevoelig en ONDERTEKEND: nee.");
    } finally {
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
  });
})();
