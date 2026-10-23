"use strict";
(() => {
  const picker = document.getElementById("packet-files");
  const analyze = document.getElementById("packet-analyze");
  const clear = document.getElementById("packet-clear");
  const exportButton = document.getElementById("packet-export");
  const output = document.getElementById("packet-result");
  const notice = document.getElementById("packet-message");
  const comparison = document.getElementById("packet-comparison");
  const expected = document.getElementById("packet-expected");
  const expectedSize = document.getElementById("packet-expected-size");
  const expectedResult = document.getElementById("packet-expected-result");
  const limitCount = 8;
  const limitItem = 20 * 1024 * 1024;
  const limitTotal = 64 * 1024 * 1024;
  let inventory = [];
  // Invalidate every in-flight File.arrayBuffer/WebCrypto digest whenever the
  // operator clears results or changes the original file selection.
  let generation = 0;
  let busy = false;

  function forget() {
    generation++;
    // A cleared or replaced selection must be immediately usable, even
    // while an earlier File.arrayBuffer/WebCrypto promise is still pending.
    // That old generation may finish later but cannot touch the new UI.
    busy = false;
    analyze.disabled = false;
    inventory = [];
    output.replaceChildren();
    comparison.textContent = "";
    exportButton.disabled = true;
    compareDeclaredSource();
  }
  function message(s) {
    notice.textContent = s;
  }
  function compareDeclaredSource() {
    expectedResult.textContent = "";
    const digest = expected.value.trim();
    const sizeText = expectedSize.value.trim();
    if (!digest && !sizeText) return;
    if (!digest || !/^[0-9a-f]{64}$/.test(digest)) {
      expectedResult.textContent = "HOLD: voer exact 64 kleine hexadecimale SHA-256-tekens in.";
      return;
    }
    if (sizeText && (!/^[1-9][0-9]{0,11}$/.test(sizeText) ||
                     !Number.isSafeInteger(Number(sizeText)) ||
                     Number(sizeText) > limitItem)) {
      expectedResult.textContent = "HOLD: verwachte lengte moet een geldige originele bytegrootte <= 20 MiB zijn.";
      return;
    }
    if (!inventory.length) {
      expectedResult.textContent = "Eerst lokaal pakketten selecteren en SHA-256 berekenen.";
      return;
    }
    const targetSize = sizeText ? Number(sizeText) : null;
    const matches = inventory.filter(x => x.sha256 === digest &&
      (targetSize === null || x.size === targetSize));
    if (!matches.length) {
      expectedResult.textContent = "HOLD: geen lokaal bestand heeft deze verwachte SHA-256 / bytegrootte. Controleer onafhankelijk de oorspronkelijke pakketversie. Geen automatische vervanging.";
      return;
    }
    expectedResult.textContent = matches.map(x => "Lokaal slot " + x.slot).join(", ") +
      " heeft dezelfde bytes-fingerprint" + (targetSize === null ? "" : " en bytegrootte") +
      " als het afzonderlijke controlebestand. Dit is geen digitale handtekening en bewijst geen afzender of toestemming.";
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

  expected.addEventListener("input", compareDeclaredSource);
  expectedSize.addEventListener("input", compareDeclaredSource);
  picker.addEventListener("change", () => {
    forget();
    message("Nieuwe lokale selectie. Bereken de nieuwe fingerprints opnieuw.");
  });
  analyze.addEventListener("click", async () => {
    if (busy) return;
    forget();
    const requestGeneration = generation;
    const files = Array.from(picker.files || []);
    if (!files.length) {
      message("Kies eerst 1 tot 8 oorspronkelijke lokale bestanden.");
      return;
    }
    if (files.some(f => !/\.(luhx|luhz|luhp)$/.test(f.name))) {
      picker.value = "";
      message("HOLD: kies uitsluitend daadwerkelijk ontvangen bronvrije .luhx, .luhz of .luhp overdrachtspakketten. Geen originele cliënt-evidence of generieke ZIP/JSON.");
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
    busy = true;
    analyze.disabled = true;
    const candidate = [];
    message("Exacte bytes worden alleen in dit browservenster gelezen en lokaal gehasht.");
    try {
      for (let i = 0; i < files.length; i++) {
        const f = files[i];
        const raw = await f.arrayBuffer();
        if (requestGeneration !== generation) return;
        if (raw.byteLength !== f.size || raw.byteLength > limitItem) {
          throw Error("De geselecteerde bronbytes veranderden tijdens het lezen.");
        }
        const sha256 = hex(await crypto.subtle.digest("SHA-256", raw));
        if (requestGeneration !== generation) return;
        candidate.push({
          slot: i + 1,
          label: "Lokaal bestand " + (i + 1),
          size: f.size,
          sha256
        });
      }
      if (requestGeneration !== generation) return;
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
      compareDeclaredSource();
      message("PRIVATE fingerprint-overzicht klaar. Geen bestanden verzonden of bewaard. Verwijder lokaal na gebruik.");
    } catch (_) {
      if (requestGeneration === generation) {
        forget();
        message("HOLD: lokaal lezen of SHA-256 mislukt. Geen gedeeltelijke resultaten behouden.");
      }
    } finally {
      // A stale read must NEVER unlock a newer still-running comparison.
      // Clearing or selecting a new file already unlocked its own generation.
      if (requestGeneration === generation) {
        busy = false;
        analyze.disabled = false;
        picker.value = "";
      }
    }
  });
  clear.addEventListener("click", () => {
    // "Wis fingerprints" must also clear the independently typed original
    // checksum and byte count. Their retention would contradict the operator
    // expectation that all on-screen fingerprint values have been forgotten.
    picker.value = "";
    expected.value = "";
    expectedSize.value = "";
    forget(); // Also invalidates any still-running File/WebCrypto operation.
    message("Lokale hashes en ingevulde controlewaarden gewist. Eerder gekopieerde of gedownloade bestanden blijven buiten deze browser bestaan.");
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
