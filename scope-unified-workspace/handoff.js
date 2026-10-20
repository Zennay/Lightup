"use strict";
// PRIVATE, in-tab-only file handoff shelf. Never parses source authority or calls network.
(() => {
  const MAX_ITEMS = 16;
  const MAX_FILE = 8 * 1024 * 1024;
  const MAX_TOTAL = 32 * 1024 * 1024;
  const routes = Object.freeze({
    none: ["Handmatig beoordelen", ""],
    studio: ["Scope Studio", "../studio/index.html"],
    intake: ["Scope Intake Matrix", "../scope-intake-matrix/standalone.html"],
    casebook: ["Casebook Transfer", "../scope-casebook-transfer/standalone.html"],
    reconcile: ["Casebook Reconcile", "../scope-casebook-reconcile/standalone.html"],
    risk: ["Authorization Risk Portfolio", "../authorization-portfolio/standalone.html"],
    stop: ["Withdrawal / STOP Desk", "../withdrawal-desk/standalone.html"],
    vault: ["Private Scope Packet Vault", "../scope-vault/standalone.html"]
  });
  const stages = Object.freeze({
    unreviewed: "Nog niet beoordeeld (HUMAN)",
    preparing: "Menselijk onderzoek loopt (HUMAN)",
    escalated: "Menselijke escalatie nodig (HUMAN)",
    documented: "Opvolging gedocumenteerd (NIET opgelost)"
  });
  const teams = Object.freeze({
    unassigned: "Nog geen team", security: "Security", privacy: "Privacy",
    client_ops: "Client operations", platform: "Platform"
  });
  const items = [];
  let busy = false;
  let generation = 0;
  // Changes to HUMAN choices must also invalidate an in-flight PRIVATE restore.
  let humanRevision = 0;
  const el = (id) => document.getElementById(id);
  const input = el("shelf-files");
  const rows = el("shelf-rows");
  const message = el("shelf-status");
  const summary = el("shelf-summary");
  const sourceCopy = el("private-copy");
  const anonymousCopy = el("counts-copy");
  const stageFilter = el("shelf-stage-filter");
  const teamFilter = el("shelf-team-filter");
  const workload = el("shelf-workload");
  const searchFilter = el("shelf-search");
  const driftFile = el("shelf-drift-file");
  const driftStatus = el("shelf-drift-status");
  const driftRows = el("shelf-drift-rows");
  const driftExport = el("shelf-drift-export");
  let driftReview = null;

  const reviewUndo = [];
  const reviewRedo = [];
  const HISTORY_LIMIT = 32;
  const captureReview = () => items.map(e => ({
    original_name: e.file.name, unsigned_sha256: e.hash,
    route: e.route, stage: e.stage, team: e.team, note: e.note
  }));
  const sameReviewSources = snapshot => snapshot.length === items.length &&
    snapshot.every((saved, i) => saved.original_name === items[i].file.name &&
      saved.unsigned_sha256 === items[i].hash);
  const clearReviewHistory = () => { reviewUndo.length = 0; reviewRedo.length = 0; humanRevision++; };
  const recordReviewEdit = () => {
    reviewUndo.push(captureReview());
    if (reviewUndo.length > HISTORY_LIMIT) reviewUndo.shift();
    reviewRedo.length = 0;
  };
  const restoreReview = (snapshot) => {
    if (!sameReviewSources(snapshot)) return false;
    for (let i = 0; i < items.length; i++) {
      items[i].route = snapshot[i].route;
      items[i].stage = snapshot[i].stage;
      items[i].team = snapshot[i].team;
      items[i].note = snapshot[i].note;
    }
    humanRevision++;
    return true;
  };
  const moveReviewHistory = (previous, next, verb) => {
    if (!previous.length) return;
    const snapshot = previous[previous.length - 1];
    if (!sameReviewSources(snapshot)) {
      clearReviewHistory();
      render();
      return report("HOLD — bronselectie gewijzigd; oude HUMAN geschiedenis veilig verworpen.");
    }
    const current = captureReview();
    previous.pop();
    next.push(current);
    if (next.length > HISTORY_LIMIT) next.shift();
    restoreReview(snapshot);
    render();
    report("REVIEW_ONLY — PRIVATE HUMAN wijziging " + verb + ". Bronbestanden en werkelijke autorisatie niet veranderd.");
  };
  const invalidateDrift = () => {
    driftReview = null;
    driftRows.replaceChildren();
    driftExport.disabled = true;
    driftStatus.textContent = "Bronselectie gewijzigd; vergelijk opnieuw met de eerdere PRIVATE inventaris.";
  };
  const SHA = (bytes) => crypto.subtle.digest("SHA-256", bytes).then((x) =>
    Array.from(new Uint8Array(x), (n) => n.toString(16).padStart(2, "0")).join(""));
  const cleanName = (name) => typeof name === "string" && name.length > 0 &&
    name.length <= 220 && !/[\x00-\x1f\x7f]/.test(name);
  const report = (text) => { message.textContent = text; };
  const cell = (row, value, cls) => {
    const c = document.createElement("td");
    if (cls) c.className = cls;
    c.textContent = value;
    row.append(c);
    return c;
  };
  const link = (href, label) => {
    const a = document.createElement("a");
    a.href = href;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    a.textContent = label;
    a.className = "shelf-open";
    return a;
  };
  const download = (file, name) => {
    const url = URL.createObjectURL(file);
    try {
      const a = document.createElement("a");
      a.href = url;
      a.download = name;
      document.body.append(a);
      a.click();
      a.remove();
    } finally {
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
  };
  const exportJSON = (name, documentBody) => {
    const blob = new Blob([JSON.stringify(documentBody, null, 2) + "\n"], { type: "application/json" });
    download(blob, name);
  };
  const viewSummary = () => items.length
    ? items.length + " PRIVATE bronbestanden · " + items.reduce((s, e) => s + e.file.size, 0).toLocaleString("nl-NL") +
      " bytes · " + items.filter((e) => e.stage === "escalated").length + " HUMAN escalaties · " +
      items.filter((e) => e.stage === "unreviewed").length + " onbeoordeeld · NOOIT GEAUTORISEERD"
    : "Nog geen PRIVATE bestanden ingeladen. Geen inhoud of bestandsnaam wordt opgeslagen.";
  const visibleHumanRow = (item) =>
    (stageFilter.value === "all" || item.stage === stageFilter.value) &&
    (teamFilter.value === "all" || item.team === teamFilter.value) &&
    (!searchFilter.value.trim() || item.file.name.normalize("NFC").toLowerCase().includes(
      searchFilter.value.trim().normalize("NFC").toLowerCase()));
  function render() {
    rows.replaceChildren();
    el("shelf-review-undo").disabled = reviewUndo.length === 0;
    el("shelf-review-redo").disabled = reviewRedo.length === 0;
    el("shelf-review-history-status").textContent = reviewUndo.length + " lokale HUMAN wijzigingen terug te draaien · " + reviewRedo.length + " opnieuw. Alleen tabgeheugen; nieuwe bronselectie wist deze geschiedenis.";
    summary.textContent = viewSummary();
    const teamCounts = Object.fromEntries(Object.keys(teams).map(k => [k, 0]));
    for (const item of items) teamCounts[item.team] += 1;
    workload.textContent = items.length ? "HUMAN teamlast · " + Object.entries(teamCounts).filter(([,n]) => n).map(([k,n]) => teams[k] + ": " + n).join(" · ") + " · Geen geverifieerde autoriteit" : "Geen teamopvolging geselecteerd. HUMAN-only en nooit uitvoerautoriteit.";

    const teamBoard = el("shelf-team-board");
    teamBoard.replaceChildren();
    for (const [teamId, teamLabel] of Object.entries(teams)) {
      const assigned = items.filter(item => item.team === teamId);
      if (!assigned.length) continue;
      const card = document.createElement("article");
      card.className = "shelf-team-card";
      const heading = document.createElement("strong");
      heading.textContent = teamLabel + " · " + assigned.length;
      const stats = document.createElement("p");
      stats.textContent = "Escalatie: " + assigned.filter(e => e.stage === "escalated").length +
        " · Nog te beoordelen: " + assigned.filter(e => e.stage === "unreviewed").length +
        " · Onderzoek: " + assigned.filter(e => e.stage === "preparing").length +
        " · Gedocumenteerd (NIET opgelost): " + assigned.filter(e => e.stage === "documented").length;
      const focus = document.createElement("button");
      focus.type = "button";
      focus.textContent = "Bekijk HUMAN dossierlijst";
      focus.setAttribute("aria-label", "Bekijk uitsluitend de HUMAN dossiers van " + teamLabel);
      focus.addEventListener("click", () => {
        teamFilter.value = teamId;
        stageFilter.value = "all";
        searchFilter.value = "";
        render();
        report("REVIEW_ONLY — alleen het PRIVATE HUMAN teamfilter ingesteld; geen bron of autorisatie gewijzigd.");
      });
      card.append(heading, stats, focus);
      teamBoard.append(card);
    }
    if (!teamBoard.childElementCount) {
      const empty = document.createElement("p");
      empty.textContent = "Nog geen PRIVATE HUMAN bronbestanden in deze werkruimte geselecteerd.";
      teamBoard.append(empty);
    }
    for (const item of items) {
      if (!visibleHumanRow(item)) continue;
      const tr = document.createElement("tr");
      cell(tr, item.file.name, "file-name");
      cell(tr, item.file.size.toLocaleString("nl-NL") + " B");
      cell(tr, item.hash, "hash");
      cell(tr, item.inspection.label + " · uitsluitend structurele hint", "kind");
      const routeCell = document.createElement("td");
      const select = document.createElement("select");
      select.setAttribute("aria-label", "HANDMATIGE routing voor " + item.file.name);
      for (const [id, info] of Object.entries(routes)) {
        const opt = document.createElement("option");
        opt.value = id;
        opt.textContent = info[0];
        select.append(opt);
      }
      select.value = item.route;
      select.addEventListener("change", () => {
        if (!Object.hasOwn(routes, select.value)) return;
        if (item.route === select.value) return;
        recordReviewEdit();
        item.route = select.value;
        humanRevision++;
        render();
      });
      routeCell.append(select);
      tr.append(routeCell);
      const triage = document.createElement("td");
      const addChoice = (label, options, value, update) => {
        const caption = document.createElement("label");
        caption.textContent = label;
        const picker = document.createElement("select");
        picker.setAttribute("aria-label", label + " voor " + item.file.name);
        for (const [key, name] of Object.entries(options)) {
          const option = document.createElement("option");
          option.value = key;
          option.textContent = name;
          picker.append(option);
        }
        picker.value = value;
        picker.addEventListener("change", () => {
          if (!Object.hasOwn(options, picker.value)) return;
          if (picker.value === value) return;
          recordReviewEdit();
          update(picker.value);
          humanRevision++;
          render();
        });
        caption.append(picker);
        triage.append(caption);
      };
      addChoice("HUMAN reviewfase", stages, item.stage, (v) => { item.stage = v; });
      addChoice("HUMAN opvolgteam", teams, item.team, (v) => { item.team = v; });
      const privateLabel = document.createElement("label");
      privateLabel.textContent = "Optionele PRIVATE opvolgnotitie (max. 280 tekens)";
      const note = document.createElement("textarea");
      note.maxLength = 280;
      note.rows = 2;
      note.value = item.note;
      note.setAttribute("aria-label", "PRIVATE opvolgnotitie voor " + item.file.name);
      let noteStarted = false;
      note.addEventListener("blur", () => { noteStarted = false; });
      note.addEventListener("input", () => {
        if (!noteStarted) { recordReviewEdit(); noteStarted = true; }
        item.note = note.value;
        humanRevision++;
      });
      privateLabel.append(note);
      triage.append(privateLabel);
      tr.append(triage);
      const actions = document.createElement("td");
      if (routes[item.route][1]) actions.append(link(routes[item.route][1], "Open werkruimte ↗"));
      const save = document.createElement("button");
      save.type = "button";
      save.className = "plain-action";
      save.textContent = "Origineel opnieuw opslaan";
      save.addEventListener("click", () => {
        if (confirm("PRIVATE origineel lokaal opnieuw opslaan? Dit verifieert geen authenticiteit, consent of scope.")) {
          download(item.file, item.file.name);
        }
      });
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "plain-action danger";
      remove.textContent = "Verwijder";
      remove.addEventListener("click", () => {
        generation++;
        clearReviewHistory();
        invalidateDrift();
        items.splice(items.indexOf(item), 1);
        render();
        report("REVIEW_ONLY — bestand uit huidige lokale werkset verwijderd; bestaande schijfbestanden blijven bestaan.");
      });
      actions.append(save, remove);
      tr.append(actions);
      rows.append(tr);
    }
    if (items.length) summary.textContent += " · " + rows.childElementCount + " zichtbaar na lokale filters";
  }
  stageFilter.addEventListener("change", render);
  teamFilter.addEventListener("change", render);
  el("shelf-review-undo").addEventListener("click", () => moveReviewHistory(reviewUndo, reviewRedo, "ongedaan gemaakt"));
  el("shelf-review-redo").addEventListener("click", () => moveReviewHistory(reviewRedo, reviewUndo, "opnieuw toegepast"));
  el("shelf-bulk-apply").addEventListener("click", () => {
    const team = el("shelf-bulk-team").value;
    const stage = el("shelf-bulk-stage").value;
    if (team !== "unchanged" && !Object.hasOwn(teams, team)) return report("HOLD — onbekend HUMAN team.");
    if (stage !== "unchanged" && !Object.hasOwn(stages, stage)) return report("HOLD — onbekende HUMAN reviewfase.");
    if (team === "unchanged" && stage === "unchanged") return report("HOLD — kies eerst een HUMAN team of reviewfase.");
    const selected = items.filter(visibleHumanRow);
    if (!selected.length) return report("HOLD — geen dossiers zichtbaar onder de huidige filters.");
    const detail = (team === "unchanged" ? "ongewijzigd team" : teams[team]) + " / " +
      (stage === "unchanged" ? "ongewijzigde fase" : stages[stage]);
    if (!confirm("Wijzig uitsluitend " + selected.length + " zichtbare PRIVATE HUMAN dossiers naar " + detail +
      "? De originele bronbestanden blijven ongewijzigd. Dit is geen toestemming, oplossing of geverifieerde revocatie.")) return;
    recordReviewEdit();
    humanRevision++;
    for (const item of selected) {
      if (team !== "unchanged") item.team = team;
      if (stage !== "unchanged") item.stage = stage;
    }
    render();
    report("REVIEW_ONLY — " + selected.length + " gefilterde HUMAN dossiers bewust gerouteerd; geen bron, grant of toestemming gewijzigd.");
  });
  searchFilter.addEventListener("input", render);
  input.addEventListener("change", async () => {
    const chosen = Array.from(input.files || []);
    input.value = "";
    if (!chosen.length || busy) return;
    const bytes = chosen.reduce((sum, file) => sum + file.size, 0);
    if (items.length + chosen.length > MAX_ITEMS || bytes + items.reduce((sum, e) => sum + e.file.size, 0) > MAX_TOTAL ||
        chosen.some((file) => file.size < 1 || file.size > MAX_FILE || !cleanName(file.name))) {
      report("HOLD — hele nieuwe batch afgewezen: max. 16 bestanden, 8 MiB per bestand, 32 MiB totaal, zonder control-tekens.");
      return;
    }
    if (!globalThis.crypto || !crypto.subtle) {
      report("HOLD — lokale Web Crypto SHA-256 ontbreekt. Er is niets toegevoegd.");
      return;
    }
    busy = true;
    const epoch = generation;
    input.disabled = true;
    report("Lokale SHA-256 berekening; bestanden verlaten de browser niet…");
    try {
      const proposed = [];
      const existing = new Set(items.map((e) => e.hash));
      const names = new Set(items.map((e) => e.file.name.normalize("NFC").toLowerCase()));
      for (const file of chosen) {
        if (epoch !== generation) throw new Error("cancelled");
        const key = file.name.normalize("NFC").toLowerCase();
        if (names.has(key)) throw new Error("name-conflict");
        names.add(key);
        const inspection = await LightUpPrivateSourceInspector.inspect(file);
        if (epoch !== generation) throw new Error("cancelled");
        const hash = await SHA(await file.arrayBuffer());
        if (existing.has(hash)) throw new Error("duplicate");
        existing.add(hash);
        proposed.push({ file, hash, inspection, route: inspection.route, stage: "unreviewed", team: "unassigned", note: "" });
      }
      if (epoch !== generation) throw new Error("cancelled");
      generation++;
      clearReviewHistory();
      invalidateDrift();
      items.push(...proposed);  // atomic admission
      render();
      report("REVIEW_ONLY — nieuwe PRIVATE bestanden en SHA-256 lokaal geladen. Structurele bronherkenning is géén bron-/toestemmingsvalidatie.");
    } catch (error) {
      report(error && error.message === "name-conflict"
        ? "HOLD — dubbele of tegenstrijdige oorspronkelijke bestandsnaam. Bestaande bron blijft intact; verwijder bewust eerst een oude versie en selecteer opnieuw."
        : "HOLD — formaat onduidelijk/ongeldig, bronclaim tegenstrijdig, import geannuleerd of identieke bytes al aanwezig. Hele nieuwe batch geweigerd; vorige werkset behouden.");
    } finally {
      busy = false;
      input.disabled = false;
    }
  });
  driftFile.addEventListener("change", async () => {
    const prior = driftFile.files && driftFile.files[0];
    driftFile.value = "";
    if (!prior || busy) return;
    invalidateDrift();
    if (!items.length) {
      driftStatus.textContent = "HOLD — selecteer eerst de actuele originele bestanden. Afwezig in een tabblad betekent geen ingetrokken grant.";
      return;
    }
    busy = true;
    input.disabled = true;
    driftFile.disabled = true;
    const epoch = generation;
    try {
      const older = await LightUpPrivateSourceInspector.readHumanInventory(prior);
      if (epoch !== generation) throw Error("source set changed during comparison");
      const result = LightUpPrivateDrift.compare(older, items);
      if (epoch !== generation) throw Error("source changed during comparison");
      for (const row of result.rows) {
        const tr = document.createElement("tr");
        cell(tr, row.original_name, "file-name");
        cell(tr, row.human_action, row.status === "UNCHANGED" ? "" : "kind");
        cell(tr, row.previous_unsigned_sha256 || "—", "hash");
        cell(tr, row.selected_unsigned_sha256 || "—", "hash");
        driftRows.append(tr);
      }
      driftReview = result;
      driftExport.disabled = false;
      driftStatus.textContent = "REVIEW_ONLY · " + result.totals.UNCHANGED + " zelfde bronbytes · " +
        result.totals.CHANGED_REVIEW_REQUIRED + " veranderd · " +
        result.totals.NEW_REVIEW_REQUIRED + " nieuw geselecteerd · " +
        result.totals.ABSENT_FROM_LOCAL_SELECTION + " niet opnieuw geselecteerd. " +
        "Iedere verandering vraagt afzonderlijke echte bron-/consentcontrole; geen auto-carry van HUMAN-statussen.";
    } catch (_) {
      invalidateDrift();
      driftStatus.textContent = "HOLD — onleesbare/onbetrouwbare vorige PRIVATE inventaris of bronselectie gewijzigd. Geen vergelijking of bronmutatie uitgevoerd.";
    } finally {
      busy = false;
      input.disabled = false;
      driftFile.disabled = false;
    }
  });
  driftExport.addEventListener("click", () => {
    if (!driftReview) return;
    if (!confirm("PRIVATE bronverschil-export maken met originele bestandsnamen en SHA-256? Dit is slechts historische lokale waarneming, geen revocation of consent, en kan identiteiten onthullen.")) return;
    exportJSON("lightup-scope-PRIVATE-original-source-drift.json", {
      format: "lightup.scope_handoff_PRIVATE_drift_review.v1", disposition: "REVIEW_ONLY",
      authority: { client_consent: false, operator_consent: false, grant: false,
        scan: false, deploy: false, release: false },
      counts: driftReview.totals, comparisons: driftReview.rows,
      disclaimer: "Unsigned local history. ABSENT does not mean withdrawn, CHANGED does not imply remediated. Never use as permission or source authorization."
    });
    report("REVIEW_ONLY — expliciet PRIVATE bronverschil lokaal gedownload; alle oorspronkelijke HUMAN-keuzes ongewijzigd.");
  });
  const selectiveInput = el("shelf-selective-reopen");
  const selectiveStatus = el("shelf-selective-status");
  selectiveInput.addEventListener("change", async () => {
    const priorFile = selectiveInput.files && selectiveInput.files[0];
    selectiveInput.value = "";
    if (!priorFile || busy) return;
    if (!items.length) return void (selectiveStatus.textContent = "HOLD — selecteer eerst de huidige oorspronkelijke bronbestanden.");
    busy = true;
    selectiveInput.disabled = true;
    input.disabled = true;
    const epoch = generation, humanAtStart = humanRevision;
    try {
      const priorRows = await LightUpPrivateSourceInspector.readHumanInventory(priorFile);
      if (epoch !== generation || humanAtStart !== humanRevision) throw Error("local source/review edits in progress");
      const priorByName = new Map(priorRows.map(row => [row.original_name.normalize("NFC").toLowerCase(), row]));
      const currentNames = new Set(items.map(item => item.file.name.normalize("NFC").toLowerCase()));
      const matches = [];
      let changed = 0, newer = 0;
      for (const item of items) {
        const previous = priorByName.get(item.file.name.normalize("NFC").toLowerCase());
        if (!previous) { newer++; continue; }
        if (previous.original_name === item.file.name &&
            previous.byte_length === item.file.size &&
            previous.unsigned_sha256 === item.hash &&
            previous.structural_kind_unverified === item.inspection.kind) {
          matches.push({item, previous});
        } else changed++;
      }
      const absent = priorRows.filter(row => !currentNames.has(row.original_name.normalize("NFC").toLowerCase())).length;
      if (!matches.length) {
        selectiveStatus.textContent = "HOLD — geen exact gelijke bronnen. " + changed +
          " gewijzigd, " + newer + " nieuw geselecteerd, " + absent +
          " niet opnieuw geselecteerd. Geen HUMAN status overgenomen.";
        return;
      }
      selectiveStatus.textContent = "VOORSTEL / NIET TOEGEPAST — " + matches.length +
        " exact ongewijzigd, " + changed + " gewijzigde bron, " + newer +
        " nieuw geselecteerd, " + absent + " niet opnieuw geselecteerd. Niet gekozen is geen intrekking of fix.";
      if (!confirm("Neem voor precies " + matches.length + " exact ongewijzigde oorspronkelijke bronnen eerdere PRIVATE HUMAN-keuzes over? " +
          changed + " gewijzigde, " + newer + " nieuwe en " + absent +
          " afwezige bronnen krijgen GEEN overgenomen besluiten. Alle overige bestaande lokale HUMAN statussen blijven intact. Nooit echte toestemming.")) return;
      if (epoch !== generation || humanAtStart !== humanRevision) throw Error("source or HUMAN state changed before import");
      recordReviewEdit();
      for (const {item, previous} of matches) {
        item.route = previous.human_route;
        item.stage = previous.human_stage;
        item.team = previous.human_team;
        item.note = previous.private_human_note;
      }
      humanRevision++;
      render();
      selectiveStatus.textContent = "REVIEW_ONLY — " + matches.length +
        " bronexacte PRIVATE HUMAN-keuzes overgenomen; gewijzigde/nieuwe/afwezige bronnen niet gemuteerd. Geen bronbevoegdheid of revocation.";
      report("REVIEW_ONLY — selectieve HUMAN broncontinuïteit op " + matches.length +
        " exact gelijke bronbestanden; via undo herstelbaar.");
    } catch (_) {
      selectiveStatus.textContent = "HOLD — ongeldig PRIVATE plan, bron-/HUMAN-state gewijzigd of ambiguë bron; niets toegepast.";
    } finally {
      busy = false;
      selectiveInput.disabled = false;
      input.disabled = false;
    }
  });
  const restoreInput = el("shelf-review-reopen");
  restoreInput.addEventListener("change", async () => {
    const backup = restoreInput.files && restoreInput.files[0];
    restoreInput.value = "";
    if (!backup || busy) return;
    if (!items.length) {
      report("HOLD — importeer eerst exact dezelfde oorspronkelijke bestanden en volgorde voordat HUMAN-keuzes mogen terugkomen.");
      return;
    }
    busy = true;
    restoreInput.disabled = true;
    input.disabled = true;
    const epoch = generation;
    const humanAtStart = humanRevision;
    try {
      const rows = await LightUpPrivateSourceInspector.readHumanInventory(backup);
      if (epoch !== generation || humanAtStart !== humanRevision || rows.length !== items.length) {
        throw Error("different source set or concurrent clear");
      }
      for (let i = 0; i < rows.length; i++) {
        const row = rows[i], original = items[i];
        if (row.original_name !== original.file.name ||
            row.byte_length !== original.file.size ||
            row.unsigned_sha256 !== original.hash ||
            row.structural_kind_unverified !== original.inspection.kind) {
          throw Error("source bytes, name, order or kind changed");
        }
      }
      if (!confirm("PRIVATE HUMAN-keuzes herstellen voor exact " + rows.length +
          " opnieuw geselecteerde originele bestanden? Alleen lokale route, HUMAN fase, team en notities veranderen. Geen echte autorisatie, bronwijziging of grant.")) {
        report("REVIEW_ONLY — herstel geannuleerd; bestaande HUMAN werkset ongewijzigd.");
        return;
      }
      if (epoch !== generation || humanAtStart !== humanRevision) throw Error("source or HUMAN edits changed before replacement");
      recordReviewEdit();
      humanRevision++;
      for (let i = 0; i < rows.length; i++) {
        items[i].route = rows[i].human_route;
        items[i].stage = rows[i].human_stage;
        items[i].team = rows[i].human_team;
        items[i].note = rows[i].private_human_note;
      }
      render();
      report("REVIEW_ONLY — exacte originele source-bytes en volgorde herkend; uitsluitend PRIVATE HUMAN-reviewkeuzes hersteld. Nooit toestemming of revocation.");
    } catch (_) {
      report("HOLD — onjuist/ambigue PRIVATE plan of andere originele bestanden. Geen enkele bestaande HUMAN-keuze is gewijzigd.");
    } finally {
      busy = false;
      restoreInput.disabled = false;
      input.disabled = false;
    }
  });
  el("shelf-clear").addEventListener("click", () => {
    if (!items.length && !busy) return;
    if (!confirm("Alle PRIVATE bestandshandles uit dit tabblad wissen? Je oorspronkelijke bestanden blijven op schijf.")) return;
    generation++; // invalidate any asynchronous import in flight
    clearReviewHistory();
    invalidateDrift();
    items.splice(0);
    render();
    report("REVIEW_ONLY — tabblad-werkset gewist. Browser/JavaScript garanderen geen fysieke geheugenwissing.");
  });

  el("shelf-team-counts").addEventListener("click", () => {
    if (!items.length) return report("HOLD — geen HUMAN dossiers voor een bronvrije teamtelling.");
    if (!confirm("Alleen vaste HUMAN team/fase-aantallen delen? Geen namen, originele SHA-256, routes of notities worden geëxporteerd. Bij kleine aantallen kan context alsnog gevoelig zijn.")) return;
    const matrix = Object.fromEntries(Object.keys(teams).map(team =>
      [team, Object.fromEntries(Object.keys(stages).map(stage => [stage, 0]))]));
    for (const item of items) {
      if (!Object.hasOwn(matrix, item.team) || !Object.hasOwn(stages, item.stage)) {
        return report("HOLD — onverwachte HUMAN indeling, geen export gemaakt.");
      }
      matrix[item.team][item.stage] += 1;
    }
    exportJSON("lightup-scope-handoff-anonymous-team-workload.json", {
      format: "lightup.scope_handoff_anonymous_human_team_counts.v1",
      status: "REVIEW_ONLY", posture: "INCUBATE_M3_M7_DRAFT_HOLD",
      authority: { client_consent: false, operator_consent: false, grant: false, scan: false, deploy: false, release: false },
      number_of_local_files: items.length,
      human_declared_team_by_stage_counts: matrix,
      warning: "Small-group counts may still identify people by inference. No source authenticity, finding validity, solved issue, real human identity, permission or release is asserted."
    });
    report("REVIEW_ONLY — alleen HUMAN team/fase-tellingen lokaal gedownload, zonder oorspronkelijke bronmetadata.");
  });
  anonymousCopy.addEventListener("click", () => {
    if (!items.length) return report("HOLD — er is nog niets voor een bronvrije telling geselecteerd.");
    if (!confirm("Bronvrij HUMAN-exportje met aantallen delen? Kleine aantallen kunnen in context toch gevoelig zijn.")) return;
    const byRoute = Object.fromEntries(Object.keys(routes).map((k) => [k, 0]));
    for (const item of items) byRoute[item.route] += 1;
    exportJSON("lightup-scope-handoff-anonymous-counts.json", {
      format: "lightup.scope_handoff_anonymous_counts.v1", status: "REVIEW_ONLY",
      authority: { client_consent: false, operator_consent: false, grant: false, scan: false, deploy: false, release: false },
      number_of_local_files: items.length, human_selected_routes: byRoute,
      warning: "Only tentative human routing counts; not original source, authentication, permission or safety evidence."
    });
    report("REVIEW_ONLY — alleen aantallen gedownload, zonder namen, digests of inhoud.");
  });


  el("shelf-minimum-handoff").addEventListener("click", () => {
    const team = el("shelf-recipient-team").value;
    if (!Object.hasOwn(teams, team)) return report("HOLD — kies expliciet precies één HUMAN team.");
    const chosen = items.filter(e => e.team === team);
    if (!chosen.length) return report("HOLD — voor het gekozen HUMAN team bestaan geen geselecteerde dossiers.");
    if (!confirm("Maak een PRIVATE teambrief met ALLEEN " + chosen.length + " bronverwijzingen voor " +
      teams[team] + "? Bevat mogelijk vertrouwelijke oorspronkelijke namen, SHA-256 en notities. Deze keuze authenticeert de ontvanger niet: controleer die apart en gebruik een passend privé-kanaal.")) return;
    const order = ["escalated", "unreviewed", "preparing", "documented"];
    const lines = [
      "# LightUp — minimum noodzakelijke PRIVATE HUMAN teambrief",
      "",
      "REVIEW_ONLY · INCUBATE M3/M7 · DRAFT/HOLD",
      "Deze ongetekende brief is uitsluitend een lokaal HUMAN routeringsvoorstel.",
      "AUTHENTICATED=false · CLIENT_CONSENT=false · OPERATOR_CONSENT=false · GRANT=false · SCAN=false · DEPLOY=false · RELEASE=false",
      "",
      "## Geselecteerd HUMAN team",
      teams[team],
      "Aantal expliciet toegewezen PRIVATE bronverwijzingen: " + chosen.length,
      "Geen dossiers van andere teams zijn opgenomen. Tabelweergavefilters zijn niet stilzwijgend toegepast.",
      ""
    ];
    for (const stage of order) {
      const group = chosen.filter(e => e.stage === stage);
      if (!group.length) continue;
      lines.push("## " + stages[stage] + " · " + group.length, "");
      for (const e of group) {
        lines.push("- PRIVÉ bestandsnaam: " + JSON.stringify(e.file.name),
          "  - Bronbytes: " + e.file.size + ", ongetekende SHA-256: " + e.hash,
          "  - Onbevestigde structurele hint: " + JSON.stringify(e.inspection.label),
          "  - Handmatig voorgestelde HUMAN route: " + JSON.stringify(routes[e.route][0]),
          "  - PRIVATE opvolgnotitie: " + JSON.stringify(e.note || "(geen)"),
          "  - Actie: verifieer onafhankelijk authentieke bronhouder, echte scope, klant/operator en actuele intrekking voordat enige oorspronkelijke actie wordt overwogen.",
          "");
      }
    }
    lines.push("## Vertrouwelijkheid en onveranderde uitvoergrens", "",
      "Geen originele broninhoud ingebed; bronbestanden niet gewijzigd, verwijderd of overgedragen.",
      "Bestandsnamen, menselijke reviewkeuzes en ongetekende hashes zijn geen tenant-authenticatie, consent, grant, revocation, oplossing of findingvalidatie.",
      "Ongewijzigd vereist: geauthenticeerde werkelijke client+operator, oorspronkelijke action-time revocation, actuele exacte scope en risico, bronhouder/security/privacy/browserreview, exacte hosted+named-VPS CI en expliciete HUMAN GO.",
      "Deze PRIVATE brief kan identificeerbare bronmetadata bevatten: vertrouw uitsluitend apart geauthenticeerde ontvangers via een beschermd kanaal.", "");
    download(new Blob([lines.join("\n")], {type:"text/markdown;charset=utf-8"}),
      "lightup-scope-PRIVATE-HUMAN-team-" + team + ".md");
    report("REVIEW_ONLY — precies " + chosen.length + " uitsluitend voor " + teams[team] +
      " geselecteerde HUMAN dossiers lokaal in PRIVATE brief; andere teams uitgesloten.");
  });
  el("shelf-workplan").addEventListener("click", () => {
    if (!items.length) return report("HOLD — selecteer eerst PRIVATE bronbestanden voor een HUMAN teambrief.");
    if (!confirm("PRIVATE HUMAN teambrief exporteren met originele bestandsnamen, hashes en mogelijk vertrouwelijke notities? Ontvanger en kanaal moeten afzonderlijk worden geauthenticeerd; dit verleent geen toestemming.")) return;
    const ordered = ["escalated", "unreviewed", "preparing", "documented"];
    const lines = [
      "# LightUp — PRIVATE HUMAN teamoverdracht",
      "",
      "REVIEW_ONLY · INCUBATE M3/M7 · DRAFT/HOLD · GEEN SCAN OF TOESTEMMING",
      "",
      "Deze ongetekende, lokaal gemaakte brief bevat uitsluitend door een mens gekozen vervolgstappen.",
      "Bestandsnaam, structurele bronhint en SHA-256 bewijzen geen bronhouder, echte toestemming, intrekking, oplossing of vrijgave.",
      "AUTHENTICATED=false · CLIENT_CONSENT=false · OPERATOR_CONSENT=false · GRANT=false · SCAN=false · DEPLOY=false · RELEASE=false",
      "",
      "## Overzicht",
      "PRIVATE bronnen: " + items.length,
      "Escalatie nodig: " + items.filter(e => e.stage === "escalated").length,
      "Nog niet beoordeeld: " + items.filter(e => e.stage === "unreviewed").length,
      "Team nog niet toegewezen: " + items.filter(e => e.team === "unassigned").length,
      "Bronbestanden zelf zijn niet ingebed en zijn niet gewijzigd.",
      ""
    ];
    for (const [team, label] of Object.entries(teams)) {
      const assigned = items.filter(e => e.team === team);
      if (!assigned.length) continue;
      lines.push("## " + label + " — " + assigned.length + " HUMAN bronverwijzingen", "");
      for (const stage of ordered) {
        const group = assigned.filter(e => e.stage === stage);
        if (!group.length) continue;
        lines.push("### " + stages[stage] + " (" + group.length + ")", "");
        for (const e of group) {
          lines.push("- PRIVATE oorspronkelijk bestand: " + JSON.stringify(e.file.name),
            "  - Bytes: " + e.file.size + "; ongetekende SHA-256: " + e.hash,
            "  - Structurele hint (NIET geauthenticeerd): " + JSON.stringify(e.inspection.label),
            "  - Voorgestelde HUMAN route: " + JSON.stringify(routes[e.route][0]),
            "  - Menselijke PRIVATE notitie: " + JSON.stringify(e.note || "(geen)"),
            "  - Vereiste vervolgstap: bronhouder, originele toestemming, actuele revocatie en context afzonderlijk laten controleren.",
            "");
        }
      }
    }
    lines.push("## Onveranderde harde grens", "",
      "Geen enkele status, bronhash, reviewtekst of oefenresultaat mag als echte request/grant worden gebruikt.",
      "Originele security/privacy/browserreview, exact-head hosted en named-VPS CI, aparte actuele client/operator-consent met revocation-at-use en expliciete HUMAN GO blijven vereist.",
      "Dit document is vertrouwelijk en ongetekend; verspreid uitsluitend via een passend apart geauthenticeerd privé-kanaal.", "");
    download(new Blob([lines.join("\n")], {type:"text/markdown;charset=utf-8"}), "lightup-scope-PRIVATE-HUMAN-team-brief.md");
    report("REVIEW_ONLY — PRIVATE HUMAN teambrief lokaal gedownload; bronbestanden ongewijzigd, nooit vrijgave.");
  });
  sourceCopy.addEventListener("click", () => {
    if (!items.length) return report("HOLD — geen PRIVATE bronbestanden geselecteerd.");
    if (!confirm("PRIVATE INVENTARIS exporteren inclusief originele bestandsnamen, bytes en SHA-256? Kan klant- of projectdetails onthullen. Deel uitsluitend met bedoelde, apart geauthenticeerde ontvanger.")) return;
    exportJSON("lightup-scope-handoff-PRIVATE-source-inventory.json", {
      format: "lightup.scope_handoff_PRIVATE_inventory.v1", status: "REVIEW_ONLY",
      authority: { client_consent: false, operator_consent: false, grant: false, scan: false, deploy: false, release: false },
      entries: items.map((e) => ({ original_name: e.file.name, byte_length: e.file.size,
        unsigned_sha256: e.hash, structural_kind_unverified: e.inspection.kind,
        human_route: e.route, human_stage: e.stage, human_team: e.team, private_human_note: e.note })),
      warning: "PRIVATE unsigned inventory, never source or recipient authentication. No file content included."
    });
    report("REVIEW_ONLY — expliciete PRIVATE ongetekende bestandsinventaris lokaal gedownload.");
  });
  render();
  window.addEventListener("pagehide", () => {
    generation++;  // never repopulate a private tab after navigation / bfcache
    clearReviewHistory();
    invalidateDrift();
    items.splice(0);
  });
})();
