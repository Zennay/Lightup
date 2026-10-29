(() => {
  "use strict";
  const SCHEMA = "lightup-private-casebook-transfer";
  const MAX_FILES = 13, MAX_EACH = 4 * 1024 * 1024, MAX_TOTAL = 12 * 1024 * 1024;
  const MAX_VAULT = 26 * 1024 * 1024, ITERATIONS = 310000;
  const encoder = new TextEncoder(), decoder = new TextDecoder("utf-8", { fatal: true });
  const $ = id => document.getElementById(id);
  let current = null;
  let sourceRevision = 0, pendingContinuation = null;
  const humanDirty = () => !!window.LightUpCasebookHandoff?.hasUnsavedEdits?.();
  function assertHumanSaved() {
    if (humanDirty()) fail("Sla eerst de HUMAN-wijzigingen op voordat je deze bronset vervangt of versleutelt.");
  }
  function discardContinuation() {
    if (pendingContinuation) for (const r of pendingContinuation.candidate) r.bytes.fill(0);
    pendingContinuation = null;
    if ($("next-apply")) $("next-apply").disabled = true;
    window.LightUpCasebookContinuity?.render(null);
  }
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
  function parseCasebookJson(bytes) {
    // Strict offline source-shape intake only. Does not authenticate producer or authorization.
    let text;
    try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); }
    catch { fail("Casebook-bronbestand bevat ongeldig UTF-8."); }
    let document;
    try { document = JSON.parse(text); }
    catch { fail("Casebook-bronbestand is geen geldig JSON."); }
    let i = 0;
    const skip = () => { while (i < text.length && /[\u0020\u0009\u000A\u000D]/.test(text[i])) i++; };
    function string() {
      if (text[i] !== '"') fail("Ongeldige JSON-bronstructuur.");
      const start = i++;
      while (i < text.length) {
        if (text[i] === "\\") { i += 2; continue; }
        if (text[i++] === '"') return JSON.parse(text.slice(start, i));
      }
      fail("Ongeldige JSON-brontekst.");
    }
    function value(depth) {
      if (depth > 32) fail("Casebook-bronstructuur te diep.");
      skip();
      if (text[i] === "{") {
        i++; skip();
        const keys = new Set();
        if (text[i] === "}") { i++; return; }
        while (i < text.length) {
          const key = string();
          if (keys.has(key)) fail("Dubbele JSON-sleutel in oorspronkelijk Casebook-bestand.");
          keys.add(key); skip();
          if (text[i++] !== ":") fail("Ongeldige JSON-bronstructuur.");
          value(depth + 1); skip();
          if (text[i] === "}") { i++; return; }
          if (text[i++] !== ",") fail("Ongeldige JSON-bronstructuur.");
          skip();
        }
        fail("Onvolledige JSON-bronstructuur.");
      }
      if (text[i] === "[") {
        i++; skip();
        if (text[i] === "]") { i++; return; }
        while (i < text.length) {
          value(depth + 1); skip();
          if (text[i] === "]") { i++; return; }
          if (text[i++] !== ",") fail("Ongeldige JSON-bronstructuur.");
        }
        fail("Onvolledige JSON-bronlijst.");
      }
      if (text[i] === '"') { string(); return; }
      const start = i;
      while (i < text.length && !/[\u0020\u0009\u000A\u000D,\]}]/.test(text[i])) i++;
      if (i === start) fail("Ongeldige JSON-bronwaarde.");
    }
    value(0); skip();
    if (i !== text.length) fail("Extra niet-toegelaten Casebook-brondata.");
    if (!document || typeof document !== "object" || Array.isArray(document))
      fail("Geen geldig oorspronkelijk Casebook-object.");
    const expected = ["schema", "status", "source", "as_of", "client_id",
      "requests", "engagements", "grants", "risk_approvals", "case_overview",
      "declared_counts", "source_authenticated", "client_consent_verified",
      "operator_consent_verified", "authorization_granted", "execution_allowed",
      "release_approved"];
    if (Object.keys(document).length !== expected.length ||
        expected.some(key => !Object.prototype.hasOwnProperty.call(document, key)) ||
        document.schema !== "lightup.auth_casebook.v1" ||
        document.status !== "REVIEW_ONLY" ||
        document.source !== "original_persisted_domain_unverified" ||
        typeof document.client_id !== "string" ||
        !/^[\x21-\x7e]{1,180}$/.test(document.client_id) ||
        ["requests", "engagements", "grants", "risk_approvals", "case_overview"]
          .some(key => !Array.isArray(document[key])) ||
        !document.declared_counts || typeof document.declared_counts !== "object" ||
        Array.isArray(document.declared_counts) ||
        ["source_authenticated", "client_consent_verified", "operator_consent_verified",
         "authorization_granted", "execution_allowed", "release_approved"]
          .some(key => document[key] !== false))
      fail("Oorspronkelijke Casebook-v1 bronvorm/HUMAN-only authority-declaraties zijn niet compatibel.");
    return document.client_id;
  }
  async function collectSources(fileList) {
    const files = Array.from(fileList).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
    checkNames(files);
    let total = 0;
    const records = [];
    let sourceClient = null;
    for (const f of files) {
      if (!Number.isSafeInteger(f.size) || f.size < 1 || f.size > MAX_EACH)
        fail("Elk geselecteerd bestand moet 1 byte tot 4 MiB groot zijn.");
      total += f.size;
      if (total > MAX_TOTAL) fail("De totale ongecodeerde bronset mag niet groter zijn dan 12 MiB.");
      const bytes = new Uint8Array(await f.arrayBuffer());
      if (bytes.length !== f.size) fail("Bronbestand wijzigde tijdens het lezen.");
      if (f.name.endsWith(".json")) {
        const declaredClient = parseCasebookJson(bytes);
        if (sourceClient !== null && sourceClient !== declaredClient)
          fail("Casebook-bundel mengt verschillende oorspronkelijke client-ID's.");
        sourceClient = declaredClient;
      }
      records.push({ name: f.name, size: bytes.length, sha256: await sha(bytes), bytes });
    }
    if (!window.LightUpCasebookHandoff) fail("PRIVATE HUMAN-admissiemodule ontbreekt.");
    window.LightUpCasebookHandoff.admit(records);
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
    sourceRevision++;
    discardContinuation();
    if (current) for (const r of current) r.bytes.fill(0);
    current = null;
    $("records").replaceChildren();
    $("summary").textContent = "Geen lokale werkset geladen. Browsergeheugen is niet gegarandeerd fysiek gewist.";
    window.LightUpCasebookHandoff?.render(null);
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
    window.LightUpCasebookHandoff?.render(records);
  }
  const busy = state => {
    $("encrypt").disabled = state;
    $("decrypt").disabled = state;
    $("next-preview").disabled = state;
    $("next-apply").disabled = state || !pendingContinuation;
    $("rekey").disabled = state;
  };
  function checkPassword(password) {
    if ([...password].length < 12 || encoder.encode(password).length > 1024)
      fail("Kies een wachtwoord van minimaal 12 tekens en maximaal 1024 UTF-8 bytes.");
  }
  async function encryptPrivateRecords(records, password) {
    checkPassword(password);
    if (!window.LightUpCasebookHandoff) fail("Brongebonden HUMAN module ontbreekt.");
    window.LightUpCasebookHandoff.admit(records);
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
  }
  $("encrypt").addEventListener("click", async () => {
    busy(true);
    try {
      if (!window.crypto?.subtle || !window.isSecureContext)
        fail("Deze browser geeft geen veilige WebCrypto-context voor het lokale bestand.");
      if (!$("ack").checked) fail("Bevestig eerst de HUMAN-only waarschuwing.");
      const password = $("new-password").value;
      assertHumanSaved();
      const records = await collectSources($("source-files").files);
      await encryptPrivateRecords(records, password);
      show(records);
      setStatus("Versleutelde PRIVATE overdracht lokaal gedownload. Sla het wachtwoord elders veilig op. De oorspronkelijke bron is niet als echt, actueel of geautoriseerd geverifieerd.");
    } catch (e) { setStatus(e.message || "Versleutelen geweigerd.", true); }
    finally {
      $("new-password").value = "";
      $("source-files").value = "";
      busy(false);
    }
  });
  $("rekey").addEventListener("click", async () => {
    busy(true);
    try {
      if (!window.crypto?.subtle || !window.isSecureContext)
        fail("Deze browser geeft geen veilige WebCrypto-context.");
      if (!current || current.length === 0) fail("Laad eerst originele privé-bestanden of open een bestaande overdracht.");
      assertHumanSaved();
      const password = $("rekey-password").value;
      checkPassword(password);
      if (!window.confirm("Maak een NIEUW lokaal versleuteld bestand met dezelfde reeds geladen originele bytes? Er wordt geen toestemming of bronvalidatie verleend."))
        fail("Dooroverdracht geannuleerd; huidige werkset ongewijzigd.");
      await encryptPrivateRecords(current, password);
      setStatus("Nieuwe PRIVATE overdracht opnieuw versleuteld met een verse willekeurige salt/nonce. Geen extra originele plaintextbestanden gedownload. Wachtwoord apart veilig delen.");
    } catch (e) { setStatus(e.message || "Dooroverdracht geweigerd.", true); }
    finally { $("rekey-password").value = ""; busy(false); }
  });
  $("decrypt").addEventListener("click", async () => {
    busy(true);
    try {
      if (!window.crypto?.subtle || !window.isSecureContext)
        fail("Deze browser geeft geen veilige WebCrypto-context voor het lokale bestand.");
      assertHumanSaved();
      const f = $("vault-file").files[0];
      if (!f || typeof f.name !== "string" || f.name.length > 160 ||
          !/\.lupt$/i.test(f.name) || f.size < 100 || f.size > MAX_VAULT)
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
      const candidate = []; let total = 0; let sourceClient = null;
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
        if (r.name.endsWith(".json")) {
          const declaredClient = parseCasebookJson(bytes);
          if (sourceClient !== null && sourceClient !== declaredClient)
            fail("Ontsleutelde bronset mengt verschillende oorspronkelijke client-ID's.");
          sourceClient = declaredClient;
        }
        candidate.push({ name: r.name, size: r.size, sha256: r.sha256, bytes });
      }
      if (!window.LightUpCasebookHandoff) fail("Brongebonden HUMAN module ontbreekt.");
      window.LightUpCasebookHandoff.admit(candidate);
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
  // Source-declared offline continuity: no account, network or authorization mutation.
  $("next-preview").addEventListener("click", async () => {
    busy(true);
    try {
      if (!current || !window.LightUpCasebookContinuity)
        fail("Open eerst een PRIVATE oorspronkelijke Casebook-bronset.");
      assertHumanSaved();
      discardContinuation();
      const files = Array.from($("next-files").files)
        .sort((a,b)=>a.name.localeCompare(b.name,"en"));
      if (!files.length) fail("Kies minimaal één exact volgend origineel Casebook-bronbestand.");
      const old = current.filter(r=>/^casebook-(?:0[1-9]|1[0-2])\.json$/.test(r.name));
      if (old.length + files.length > 12)
        fail("Originele bronreeksen blijven beperkt tot 12 opeenvolgende momenten.");
      let total = old.reduce((acc,r)=>acc+r.size,0);
      const candidate = old.map(r=>({...r, bytes:r.bytes.slice()}));
      const sourceClient = parseCasebookJson(old[0].bytes);
      for(let i=0;i<files.length;i++){
        const file=files[i];
        const ordinal=String(old.length+i+1).padStart(2,"0");
        if(file.name!=="casebook-"+ordinal+".json")
          fail("Verwacht exact het volgende originele bronmoment: casebook-"+ordinal+".json.");
        if (!Number.isSafeInteger(file.size) || file.size<1 || file.size>MAX_EACH)
          fail("Elk nieuw bronmoment moet 1 byte tot 4 MiB groot zijn.");
        total+=file.size;
        if(total>MAX_TOTAL)fail("De originele bronreeks mag niet groter dan 12 MiB zijn.");
        const bytes=new Uint8Array(await file.arrayBuffer());
        if (bytes.length!==file.size) fail("Bronbestand is tijdens het lezen veranderd.");
        if (parseCasebookJson(bytes)!==sourceClient)
          fail("Nieuw origineel bronmoment verklaart een andere cliënt.");
        candidate.push({name:file.name,size:bytes.length,sha256:await sha(bytes),bytes});
      }
      checkNames(candidate);
      window.LightUpCasebookHandoff.admit(candidate);
      const report=window.LightUpCasebookContinuity.prepare(current,candidate);
      const csvBytes=encoder.encode(window.LightUpCasebookHandoff.serialize(report.rows));
      if (csvBytes.length>131072)fail("Nieuwe HUMAN-opvolg-CSV groter dan 128 KiB.");
      candidate.push({name:"workroom-current-template.csv",size:csvBytes.length,
        sha256:await sha(csvBytes),bytes:csvBytes});
      candidate.sort((a,b)=>a.name < b.name?-1:a.name>b.name?1:0);
      checkNames(candidate);
      if(candidate.reduce((sum,r)=>sum+r.size,0)>MAX_TOTAL)
        fail("De complete PRIVATE bronreeks is groter dan 12 MiB.");
      window.LightUpCasebookHandoff.admit(candidate);
      pendingContinuation={candidate,report,sourceRevision};
      window.LightUpCasebookContinuity.render(report);
      $("next-apply").disabled=false;
      setStatus("Nieuwe bronreeks en HUMAN-overnamevoorstel lokaal klaargezet. Controleer PRIVATE gevolgen vóór versleutelde overdracht; er is geen actuele toestemming verleend.");
    }catch(e){
      discardContinuation();
      setStatus("HOLD: "+(e.message||"Originele bronopvolging geweigerd.")+
        " Eerdere PRIVATE werkset ongewijzigd.",true);
    }finally{busy(false);}
  });
  $("next-apply").addEventListener("click", async () => {
    busy(true);
    try {
      assertHumanSaved();
      const pending=pendingContinuation;
      if(!pending || pending.sourceRevision!==sourceRevision || !current)
        fail("Continuïteitsvoorstel is verouderd. Maak eerst een nieuw voorstel.");
      if (!window.crypto?.subtle || !window.isSecureContext)
        fail("Geen beveiligde lokale WebCrypto-context.");
      const password=$("next-password").value;
      checkPassword(password);
      const c=pending.report.counts;
      if(!window.confirm(
        "Maak een NIEUW versleuteld PRIVATE bestand met de volledige bronreeks? "+
        "Ongewijzigd en meegenomen: "+c.carry+"; heropend: "+c.changed+"; bronverzoek-HOLD: "+c.source_hold+
        "; zonder oude HUMAN-CSV: "+c.unrecorded+"; nieuw: "+c.appeared+"; ontbreekt in laatste bron: "+c.absent+
        ". Ontbrekende records bewijzen GEEN intrekking, risicoreductie of toestemming."
      )) return;
      await encryptPrivateRecords(pending.candidate,password);
      // Prevent clearWorking from destroying the candidate being adopted.
      pendingContinuation=null;
      show(pending.candidate);
      setStatus("Nieuw bronmoment en HUMAN-volgstaten in volledige nieuwe versleutelde PRIVATE overdracht vastgelegd. Alleen bronidentieke dossiers hebben eerdere lokale HUMAN-keuzes behouden. Oorspronkelijke brondata ongewijzigd.");
    }catch(e){
      setStatus("HOLD: "+(e.message||"Versleutelde vervolgopname geweigerd.")+
        " Bestaande werkset behouden.",true);
    }finally{$("next-password").value="";$("next-files").value="";busy(false);}
  });
  window.LightUpTransfer = Object.freeze({
    async setHumanCSV(rows) {
      if (!current || !window.LightUpCasebookHandoff) fail("Geen PRIVATE bronset geladen.");
      const csv = window.LightUpCasebookHandoff.serialize(rows);
      const bytes = encoder.encode(csv);
      if (bytes.length < 1 || bytes.length > 131072) fail("HUMAN-CSV moet kleiner dan 128 KiB zijn.");
      const existing = current.filter(r => r.name !== "workroom-current-template.csv");
      const copy = existing.map(r => ({...r, bytes: r.bytes.slice()}));
      copy.push({name:"workroom-current-template.csv",size:bytes.length,
        sha256:await sha(bytes),bytes});
      copy.sort((a,b)=>a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
      checkNames(copy);
      if (copy.reduce((n,r)=>n+r.size,0) > MAX_TOTAL) fail("Gecombineerde PRIVATE set groter dan 12 MiB.");
      window.LightUpCasebookHandoff.admit(copy);
      show(copy);
      setStatus("Alleen de PRIVATE HUMAN-opvolg-CSV in lokale werkset bijgewerkt en aan huidige originele bron gekoppeld. Nieuwe versleutelde overdracht via dooroverdrachtknop vereist.");
    }
  });
  $("clear").addEventListener("click", () => {
    if (!current || window.confirm("Verwijder alle referenties naar de huidige bronbestanden uit deze pagina? Dit kan geen browsergeheugen fysiek gegarandeerd wissen.")) {
      clearWorking(); setStatus("Lokale werkset vrijgegeven. Sluit de tab voor extra geheugenhygiëne.");
    }
  });
  setStatus("Offline. Kies uitsluitend PRIVATE originele Casebook-bestanden. Dit hulpmiddel verleent nooit toestemming.");
})();