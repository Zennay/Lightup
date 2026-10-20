"use strict";
/* PRIVATE, unsigned, local-only HUMAN metadata workroom. No network, scans, deletes or grants. */
(() => {
  const MAX_FILES = 12, MAX_FILE_BYTES = 8 * 1024 * 1024, MAX_TOTAL_BYTES = 64 * 1024 * 1024;
  const MAX_RECEIPT_BYTES = 131072;
  const STATES = Object.freeze({
    needs_review: "Nog beoordelen",
    retain: "Behouden (voorstel)",
    quarantine: "Afzonderen (voorstel)",
    propose_delete: "Verwijdering voorstellen — GEEN wisopdracht"
  });
  const AUTHORITY = Object.freeze({
    authorizes_scan: false, authorizes_delete: false, verifies_finding: false,
    verifies_remediation: false, proves_consent: false, authenticates_source: false
  });
  let entries = [];
  let processing = false;
  const $ = id => document.getElementById(id);
  const status = (s, bad = false) => {
    $("message").textContent = s;
    $("message").classList.toggle("error", bad);
  };
  const isPlain = value => !!value && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
  const keysAre = (value, keys) => isPlain(value) &&
    Object.keys(value).sort().join("|") === keys.slice().sort().join("|");
  const safeHuman = (value, max) => typeof value === "string" &&
    value.length <= max && !/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u206f]/u.test(value);
  const validDate = s => s === "" || (typeof s === "string" && /^20\d{2}-\d{2}-\d{2}$/.test(s) &&
    !Number.isNaN(Date.parse(s + "T00:00:00Z")) &&
    new Date(s + "T00:00:00Z").toISOString().slice(0,10) === s);
  const hexSha = buffer => Array.from(new Uint8Array(buffer), b => b.toString(16).padStart(2, "0")).join("");
  const digest = async file => hexSha(await crypto.subtle.digest("SHA-256", await file.arrayBuffer()));
  function download(name, type, contents) {
    const blob = new Blob([contents], {type});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = name; a.hidden = true;
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }
  function text(tag, value, className) {
    const element = document.createElement(tag);
    element.textContent = value;
    if (className) element.className = className;
    return element;
  }
  function input(value, max, placeholder, update) {
    const e = document.createElement("input");
    e.type = "text"; e.value = value; e.maxLength = max;
    e.placeholder = placeholder; e.addEventListener("change", () => {
      if (!safeHuman(e.value, max)) { e.value = value; status("Ongeldige controle-/richtingskarakters geweigerd.", true); return; }
      update(e.value); updateCounts();
    });
    return e;
  }
  function updateCounts() {
    $("source-count").textContent = entries.length + " / " + MAX_FILES + " bronnen";
    const sums = Object.fromEntries(Object.keys(STATES).map(key => [key, 0]));
    for (const e of entries) sums[e.status] += 1;
    const target = $("stats");
    target.replaceChildren();
    for (const [key, label] of Object.entries(STATES)) {
      const card = text("div", sums[key] + " · " + label, "stat");
      target.append(card);
    }
  }
  function render() {
    const body = $("rows");
    body.replaceChildren();
    const q = $("query").value.trim().toLowerCase();
    const filter = $("status-filter").value;
    const shown = entries.filter(e => (!filter || e.status === filter) &&
      (!q || e.alias.toLowerCase().includes(q) || e.sha256.includes(q)));
    for (const item of shown) {
      const row = document.createElement("tr");
      const identity = document.createElement("td");
      identity.append(text("strong", item.sha256.slice(0, 14) + "…"),
        text("small", item.bytes.toLocaleString("nl-NL") + " bytes"));
      const alias = document.createElement("td");
      alias.append(input(item.alias, 80, "Vrij alias", value => { item.alias = value; }));
      const stage = document.createElement("td");
      const select = document.createElement("select");
      for (const [value, label] of Object.entries(STATES)) {
        const option = new Option(label, value); select.add(option);
      }
      select.value = item.status;
      select.addEventListener("change", () => {
        item.status = select.value; updateCounts();
        if ($("status-filter").value) render();
      });
      stage.append(select);
      const due = document.createElement("td");
      const date = document.createElement("input");
      date.type = "date"; date.min = "2000-01-01"; date.max = "2099-12-31";
      date.value = item.review_date;
      date.addEventListener("change", () => {
        if (!validDate(date.value)) { date.value = item.review_date; status("Geen geldige reviewdatum.", true); return; }
        item.review_date = date.value;
      });
      due.append(date);
      const action = document.createElement("td");
      action.append(input(item.action, 400, "Menselijke vervolgstap, geen uitvoeropdracht", value => { item.action = value; }));
      const remove = document.createElement("td");
      const btn = document.createElement("button");
      btn.textContent = "Verwijder rij"; btn.className = "danger"; btn.type = "button";
      btn.addEventListener("click", () => {
        entries = entries.filter(e => e.sha256 !== item.sha256);
        status("Alleen de bronrij is uit het browsergeheugen verwijderd; geen bronbestand gewist.");
        render();
      });
      remove.append(btn);
      row.append(identity, alias, stage, due, action, remove);
      body.append(row);
    }
    if (!shown.length) {
      const tr = document.createElement("tr"); const td = document.createElement("td");
      td.colSpan = 6; td.textContent = entries.length ? "Geen rijen voor dit filter." : "Selecteer eerst bestanden.";
      tr.append(td); body.append(tr);
    }
    updateCounts();
  }
  async function ingest(event) {
    if (processing) return;
    processing = true;
    const chosen = Array.from(event.target.files || []);
    try {
      if (!chosen.length) return;
      if (!globalThis.crypto?.subtle) throw new Error("WebCrypto SHA-256 is hier niet beschikbaar; open op een vertrouwde HTTPS/file-browseromgeving.");
      if (chosen.length + entries.length > MAX_FILES) throw new Error("Maximaal " + MAX_FILES + " bestanden.");
      let size = entries.reduce((a, e) => a + e.bytes, 0);
      const seen = new Set(entries.map(e => e.sha256));
      const staged = [];
      for (const file of chosen) {
        if (!file.size || file.size > MAX_FILE_BYTES) throw new Error("Lege of te grote bron geweigerd (maximaal 8 MiB).");
        size += file.size;
        if (size > MAX_TOTAL_BYTES) throw new Error("Totale invoer groter dan 64 MiB.");
        const sha256 = await digest(file);
        if (seen.has(sha256)) throw new Error("Dubbel identiek bestand; geen herhaalde bronidentiteiten.");
        seen.add(sha256);
        staged.push({sha256, bytes:file.size, alias:"Bron " + (entries.length + staged.length + 1),
          status:"needs_review", review_date:"", action:""});
      }
      // Atomic: no selected source is installed before every new source has been admitted.
      entries = entries.concat(staged);
      $("query").value = ""; $("status-filter").value = "";
      render(); status(staged.length + " echte lokale bestandsidentiteiten gecontroleerd en toegevoegd. Geen bytes geüpload.");
    } catch (e) {
      status("HOLD: " + e.message + " Er is niets uit deze selectie toegevoegd.", true);
    } finally {
      event.target.value = ""; processing = false;
    }
  }
  function record(e) {
    return {sha256:e.sha256, bytes:e.bytes, alias:e.alias,
      status:e.status, review_date:e.review_date, action:e.action};
  }
  function exportReceipt() {
    if (!entries.length || processing) return status("Selecteer eerst privébronnen.", true);
    const obj = {
      kind:"lightup.private.assessment.retention.plan", version:1,
      authority:AUTHORITY,
      rows:entries.map(record).sort((a,b) => a.sha256.localeCompare(b.sha256))
    };
    download("lightup-private-assessment-retention.json", "application/json", JSON.stringify(obj));
    status("PRIVATE ongetekend menselijk plan geëxporteerd. Geen broninhoud, bestandsnaam of scanpermissie inbegrepen.");
  }
  function validateReceipt(raw) {
    let obj;
    try { obj = JSON.parse(raw); } catch { throw new Error("Geen geldig JSON-plan."); }
    // JSON.stringify roundtrip rejects duplicate-key JSON, alternative/ambiguous encodings and noncanonical input.
    if (JSON.stringify(obj) !== raw.trim()) throw new Error("Niet-canonieke of mogelijk ambigue JSON.");
    if (!keysAre(obj, ["kind","version","authority","rows"]) ||
        obj.kind !== "lightup.private.assessment.retention.plan" || obj.version !== 1 ||
        !keysAre(obj.authority, Object.keys(AUTHORITY)) ||
        Object.keys(AUTHORITY).some(key => obj.authority[key] !== false) ||
        !Array.isArray(obj.rows) || !obj.rows.length || obj.rows.length > MAX_FILES) {
      throw new Error("Onbekend plancontract of bevoegdheidsclaim.");
    }
    const proposed = new Map();
    for (const row of obj.rows) {
      if (!keysAre(row, ["sha256","bytes","alias","status","review_date","action"]) ||
          !/^[a-f0-9]{64}$/.test(row.sha256) || !Number.isSafeInteger(row.bytes) ||
          row.bytes < 1 || row.bytes > MAX_FILE_BYTES || !safeHuman(row.alias, 80) ||
          !Object.hasOwn(STATES, row.status) || !validDate(row.review_date) ||
          !safeHuman(row.action, 400) || proposed.has(row.sha256)) {
        throw new Error("Onbekende, herhaalde of ambigue oorspronkelijke bron/HUMAN-rij.");
      }
      proposed.set(row.sha256, row);
    }
    if (proposed.size !== entries.length ||
        entries.some(e => !proposed.has(e.sha256) || proposed.get(e.sha256).bytes !== e.bytes)) {
      throw new Error("Bronset wijkt af: selecteer opnieuw de exacte originele bestanden. Geen gedeeltelijke carry.");
    }
    return proposed;
  }
  async function importReceipt(event) {
    if (processing) return;
    processing = true;
    try {
      const file = event.target.files?.[0];
      if (!file) return;
      if (!entries.length) throw new Error("Selecteer eerst originele bronbestanden voor SHA-binding.");
      if (file.size > MAX_RECEIPT_BYTES || file.size < 1) throw new Error("Planbestand overschrijdt de 128 KiB grens.");
      const raw = await file.text();
      const rows = validateReceipt(raw);
      if (!window.confirm("Alle geselecteerde echte bestandsbytes komen overeen. De volledige bestaande HUMAN-planning lokaal overnemen? Dit verleent GEEN consent, toestemming tot wissen, bron-authenticatie of scanbevoegdheid.")) {
        status("Overname geannuleerd. De huidige werkruimte blijft intact."); return;
      }
      entries = entries.map(e => ({...e, ...record(rows.get(e.sha256))}));
      $("query").value = ""; $("status-filter").value = "";
      render(); status("Volledige exact-brongebonden PRIVATE HUMAN-planning heropend. Bronbestanden ongewijzigd.");
    } catch (e) {
      status("HOLD: " + e.message + " Huidige planning ongewijzigd.", true);
    } finally {
      event.target.value = ""; processing = false;
    }
  }
  function exportCounts() {
    if (!entries.length || processing) return status("Geen aantallen zonder geselecteerde privébronnen.", true);
    const rows = ["status,count"];
    for (const key of Object.keys(STATES)) {
      rows.push(key + "," + entries.filter(e => e.status === key).length);
    }
    download("lightup-private-human-retention-counts.csv", "text/csv;charset=utf-8",
      "\ufeff" + rows.join("\r\n") + "\r\n");
    status("Alleen conservatieve HUMAN-aantallen geëxporteerd; bij kleine groepen nog steeds PRIVATE.");
  }
  $("sources").addEventListener("change", ingest);
  $("receipt").addEventListener("change", importReceipt);
  $("export-plan").addEventListener("click", exportReceipt);
  $("export-counts").addEventListener("click", exportCounts);
  $("query").addEventListener("input", render);
  $("status-filter").addEventListener("change", render);
  $("print").addEventListener("click", () => {
    if (!entries.length) return status("Geen overzicht om te printen.", true);
    if (window.confirm("Dit is een PRIVATE, ongetekend overzicht. Afdrukken kan lokale printsporen maken. Alleen op een vertrouwde printer doorgaan?")) window.print();
  });
  $("clear").addEventListener("click", () => {
    if (entries.length && !window.confirm("Alle niet-opgeslagen HUMAN-keuzes uit dit tabblad wissen? Eerder gedownloade privébestanden worden niet gewist.")) return;
    entries = []; $("sources").value = ""; $("receipt").value = "";
    $("query").value = ""; $("status-filter").value = "";
    render(); status("Lokale werkruimte leeggemaakt (geen garantie op veilig geheugenwissen).");
  });
  window.addEventListener("beforeunload", event => {
    if (!entries.length) return;
    event.preventDefault(); event.returnValue = "";
  });
  render();
})();