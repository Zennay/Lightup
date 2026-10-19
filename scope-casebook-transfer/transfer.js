(() => {
  "use strict";
  const SCHEMA = "lightup-private-casebook-transfer";
  const MAX_FILES = 13, MAX_EACH = 4 * 1024 * 1024, MAX_TOTAL = 12 * 1024 * 1024;
  const MAX_VAULT = 26 * 1024 * 1024, ITERATIONS = 310000;
  const encoder = new TextEncoder(), decoder = new TextDecoder("utf-8", { fatal: true });
  const $ = id => document.getElementById(id);
  let current = null;
  const setStatus = (message, error = false) => {
    $("status").textContent = message;
    $("status").classList.toggle("error", error);
  };
  const fail = message => { throw new Error(message); };
  const exactKeys = (obj, names) => obj && typeof obj === "object" &&
    !Array.isArray(obj) && JSON.stringify(Object.keys(obj)) === JSON.stringify(names);
  const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
  const sha = async bytes => hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
  const to64 = bytes => {
    let binary = "";
    for (let i = 0; i < bytes.length; i += 16384)
      binary += String.fromCharCode(...bytes.subarray(i, i + 16384));
    return btoa(binary);
  };
  const from64 = value => {
    if (typeof value !== "string" || value.length > MAX_VAULT * 2 ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))
      fail("Niet-canonieke base64 in PRIVATE overdracht.");
    let decoded;
    try { decoded = atob(value); } catch { fail("Beschadigde base64."); }
    const bytes = Uint8Array.from(decoded, c => c.charCodeAt(0));
    if (to64(bytes) !== value) fail("Niet-canonieke base64-padbits.");
    return bytes;
  };
  function sourceName(name) {
    return /^casebook-(?:0[1-9]|1[0-2])\.json$/.test(name) ||
      name === "workroom-current-template.csv";
  }
  function checkNames(items) {
    if (!Array.isArray(items) || items.length < 1 || items.length > MAX_FILES)
      fail("Selecteer 1–12 originele Casebook-bestanden en eventueel één huidige HUMAN-CSV.");
    const names = items.map(x => x.name);
    if (names.some(n => typeof n !== "string" || !sourceName(n)))
      fail("Alleen originele casebook-NN.json en workroom-current-template.csv zijn toegestaan.");
    if (new Set(names).size !== names.length) fail("Dubbele bestandsnaam.");
    const expected = [...names].sort();
    if (JSON.stringify(names) !== JSON.stringify(expected))
      fail("Bestanden moeten in vaste originele volgorde worden opgenomen.");
    const originals = names.filter(n => n.endsWith(".json"));
    if (!originals.length) fail("Minimaal één oorspronkelijk Casebook-bronbestand is nodig.");
    for (let i = 0; i < originals.length; i++)
      if (originals[i] !== "casebook-" + String(i + 1).padStart(2, "0") + ".json")
        fail("Casebook-bronbestanden moeten beginnen bij 01 zonder hiaten.");
  }
  async function collectSources(fileList) {
    const files = Array.from(fileList).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
    checkNames(files);
    let total = 0;
    const records = [];
    for (const f of files) {
      if (!Number.isSafeInteger(f.size) || f.size < 1 || f.size > MAX_EACH)
        fail("Elk geselecteerd bestand moet 1 byte tot 4 MiB groot zijn.");
      total += f.size;
      if (total > MAX_TOTAL) fail("De totale ongecodeerde bronset mag niet groter zijn dan 12 MiB.");
      const bytes = new Uint8Array(await f.arrayBuffer());
      if (bytes.length !== f.size) fail("Bronbestand wijzigde tijdens het lezen.");
      records.push({ name: f.name, size: bytes.length, sha256: await sha(bytes), bytes });
    }
    return records;
  }
  function fileDownload(name, bytes, type = "application/octet-stream") {
    const url = URL.createObjectURL(new Blob([bytes], { type }));
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.rel = "noopener";
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }
  async function makeKey(password, salt) {
    const material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" },
      material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
  }
  function clearWorking() {
    if (current) for (const r of current) r.bytes.fill(0);
    current = null;
    $("records").replaceChildren();
    $("summary").textContent = "Geen lokale werkset geladen. Browsergeheugen is niet gegarandeerd fysiek gewist.";
  }
  function show(records) {
    clearWorking();
    current = records;
    const total = records.reduce((n, x) => n + x.size, 0);
    $("summary").textContent = records.length + " privé bronbestand(en), " + total.toLocaleString("nl-NL") +
      " bytes · lokale kopie · NIET geauthenticeerd of gevalideerd als actuele toestemming.";
    const panel = $("records");
    for (const r of records) {
      const row = document.createElement("div"); row.className = "row"; row.setAttribute("role", "listitem");
      const left = document.createElement("div"), strong = document.createElement("strong");
      strong.textContent = r.name;
      const detail = document.createElement("small");
      detail.textContent = r.size.toLocaleString("nl-NL") + " bytes · bronbytes SHA-256 " + r.sha256;
      left.append(strong, detail);
      const button = document.createElement("button"); button.type = "button";
      button.className = "subtle"; button.textContent = "Exporteer exacte bytes";
      button.addEventListener("click", () => {
        if (!current || !current.includes(r)) return;
        fileDownload(r.name, r.bytes);
        setStatus("PRIVATE origineel lokaal gedownload. Controleer dit bestand met de oorspronkelijke Casebook-validator vóór enig gebruik.");
      });
      row.append(left, button); panel.append(row);
    }
  }
  const busy = (state) => { $("encrypt").disabled = state; $("decrypt").disabled = state; };
  $("encrypt").addEventListener("click", async () => {
    busy(true);
    try {
      if (!window.crypto?.subtle || !window.isSecureContext)
        fail("Deze browser geeft geen veilige WebCrypto-context voor het lokale bestand.");
      if (!$("ack").checked) fail("Bevestig eerst de HUMAN-only waarschuwing.");
      const password = $("new-password").value;
      if ([...password].length < 12 || encoder.encode(password).length > 1024)
        fail("Kies een wachtwoord van minimaal 12 tekens en maximaal 1024 UTF-8 bytes.");
      const records = await collectSources($("source-files").files);
      const body = { schema: SCHEMA, version: 1, files: records.map(r =>
        ({ name: r.name, size: r.size, sha256: r.sha256, content_b64: to64(r.bytes) })) };
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const key = await makeKey(password, salt);
      const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
        { name: "AES-GCM", iv }, key, encoder.encode(JSON.stringify(body))
      ));
      const envelope = { schema: SCHEMA, version: 1, kdf: "PBKDF2-SHA256",
        iterations: ITERATIONS, cipher: "AES-256-GCM", salt_b64: to64(salt),
        iv_b64: to64(iv), ciphertext_b64: to64(ciphertext) };
      const encoded = encoder.encode(JSON.stringify(envelope));
      if (encoded.length > MAX_VAULT) fail("Versleutelde overdracht groter dan de toegestane 26 MiB.");
      fileDownload("lightup-casebook-private-transfer.lupt", encoded, "application/octet-stream");
      show(records);
      setStatus("Versleutelde PRIVATE overdracht lokaal gedownload. Sla het wachtwoord elders veilig op. De oorspronkelijke bron is niet als echt, actueel of geautoriseerd geverifieerd.");
    } catch (e) { setStatus(e.message || "Versleutelen geweigerd.", true); }
    finally {
      $("new-password").value = "";
      $("source-files").value = "";
      busy(false);
    }
  });
  $("decrypt").addEventListener("click", async () => {
    busy(true);
    try {
      if (!window.crypto?.subtle || !window.isSecureContext)
        fail("Deze browser geeft geen veilige WebCrypto-context voor het lokale bestand.");
      const f = $("vault-file").files[0];
      if (!f || f.name !== "lightup-casebook-private-transfer.lupt" ||
          f.size < 100 || f.size > MAX_VAULT)
        fail("Kies een oorspronkelijke, begrensde .lupt overdracht.");
      const password = $("open-password").value;
      if (!password) fail("Voer het lokale wachtwoord in.");
      const raw = await f.text();
      let envelope;
      try { envelope = JSON.parse(raw); } catch { fail("PRIVATE overdracht is geen geldig JSON."); }
      if (JSON.stringify(envelope) !== raw ||
        !exactKeys(envelope, ["schema", "version", "kdf", "iterations", "cipher", "salt_b64", "iv_b64", "ciphertext_b64"]) ||
        envelope.schema !== SCHEMA || envelope.version !== 1 || envelope.kdf !== "PBKDF2-SHA256" ||
        envelope.iterations !== ITERATIONS || envelope.cipher !== "AES-256-GCM")
        fail("PRIVATE overdracht heeft niet de exacte oorspronkelijke canonieke v1-envelope.");
      const salt = from64(envelope.salt_b64), iv = from64(envelope.iv_b64);
      const encrypted = from64(envelope.ciphertext_b64);
      if (salt.length !== 16 || iv.length !== 12 || encrypted.length < 16 || encrypted.length > MAX_VAULT)
        fail("Ongeldige salt, nonce of cryptogramlengte.");
      const key = await makeKey(password, salt);
      let plaintext;
      try { plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted)); }
      catch { fail("Ontsleutelen geweigerd: onjuist wachtwoord of gewijzigde overdracht."); }
      if (plaintext.length > 20 * 1024 * 1024) fail("Ontsleutelde inhoud te groot.");
      let body;
      try {
        const text = decoder.decode(plaintext);
        body = JSON.parse(text);
        if (JSON.stringify(body) !== text) fail("Niet-canonieke ontsleutelde JSON.");
      } catch { fail("Ongeldige of gewijzigde ontsleutelde inhoud."); }
      if (!exactKeys(body, ["schema", "version", "files"]) ||
          body.schema !== SCHEMA || body.version !== 1 || !Array.isArray(body.files))
        fail("Niet-herkende overdrachtsinhoud.");
      checkNames(body.files);
      const candidate = []; let total = 0;
      for (const r of body.files) {
        if (!exactKeys(r, ["name", "size", "sha256", "content_b64"]) ||
            !Number.isSafeInteger(r.size) || r.size < 1 || r.size > MAX_EACH ||
            typeof r.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(r.sha256))
          fail("Ongeldige bronrecord-structuur.");
        total += r.size;
        if (total > MAX_TOTAL) fail("Ontsleutelde bronset groter dan 12 MiB.");
        const bytes = from64(r.content_b64);
        if (bytes.length !== r.size || await sha(bytes) !== r.sha256)
          fail("Oorspronkelijke bronbytes/digest komen niet overeen met de inhoud.");
        candidate.push({ name: r.name, size: r.size, sha256: r.sha256, bytes });
      }
      if (!window.confirm("Alle " + candidate.length +
        " bronbestanden zijn lokaal ontsleuteld en intern byte-vergeleken. Dit valideert GEEN originele bron, grant, toestemming of intrekking. Vervang de huidige lokale werkset?"))
        fail("Heropenen geannuleerd; bestaande lokale werkset ongewijzigd.");
      show(candidate);
      setStatus("PRIVATE overdracht lokaal ontsleuteld. Exacte bronbytes beschikbaar voor expliciete download en controle met originele validators. Geen bevoegdheid verleend.");
    } catch (e) { setStatus(e.message || "Heropenen geweigerd.", true); }
    finally {
      $("open-password").value = "";
      $("vault-file").value = "";
      busy(false);
    }
  });
  $("clear").addEventListener("click", () => {
    if (!current || window.confirm("Verwijder alle referenties naar de huidige bronbestanden uit deze pagina? Dit kan geen browsergeheugen fysiek gegarandeerd wissen.")) {
      clearWorking(); setStatus("Lokale werkset vrijgegeven. Sluit de tab voor extra geheugenhygiëne.");
    }
  });
  setStatus("Offline. Kies uitsluitend PRIVATE originele Casebook-bestanden. Dit hulpmiddel verleent nooit toestemming.");
})();