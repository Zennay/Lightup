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
  let lastReturnReceipt = null;
  const returnJournal = [];
  let nextLocalReturnOrdinal = 1;
  const renderReturnJournal = () => {
    const holder = el("shelf-return-journal-list");
    holder.replaceChildren();
    for (const round of returnJournal) {
      const row = document.createElement("li");
      const label = document.createElement("span");
      label.textContent = "Lokale ronde " + round.ordinal +
        " · " + round.receipt.selected_private_human_changes.length +
        " bronexacte HUMAN keuzewijzigingen · HISTORISCH, geen actuele toestemming.";
      row.append(label);
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = "Download PRIVATE historische ronde " + round.ordinal;
      button.addEventListener("click", () => {
        if (!confirm("PRIVATE historische HUMAN ronde " + round.ordinal +
          " downloaden met oorspronkelijke namen, ongetekende SHA-256 en HANDMATIGE oude/nieuwe team/fase? Dit is geen actuele bron of toestemming. Ontvanger en kanaal apart controleren.")) return;
        exportJSON("lightup-scope-PRIVATE-HUMAN-round-" + round.ordinal + ".json", round.receipt);
        report("REVIEW_ONLY — lokaal historisch HUMAN retourbewijs gedownload, niet een actuele security-beslissing.");
      });
      row.append(button);
      holder.append(row);
    }
    if (!returnJournal.length) {
      const empty = document.createElement("li");
      empty.textContent = "Nog geen historische lokale HUMAN retourrondes.";
      holder.append(empty);
    }
    el("shelf-return-journal-export").disabled = returnJournal.length === 0;
    el("shelf-return-journal-clear").disabled = returnJournal.length === 0;
  };
  const appendReturnJournal = receipt => {
    returnJournal.push({ordinal: nextLocalReturnOrdinal++, receipt});
    if (returnJournal.length > 12) returnJournal.shift();
    renderReturnJournal();
  };

  const invalidateReturnReceipt = () => {
    if (typeof discardPeerPreview === "function" && peerPreview) discardPeerPreview();
    if (typeof invalidatePeerReceipt === "function") invalidatePeerReceipt();
    if (lastReturnReceipt === null) return;
    lastReturnReceipt = null;
    el("shelf-return-receipt").disabled = true;
    el("shelf-return-receipt-note").textContent = "PRIVATE HUMAN review/bronselectie gewijzigd sinds de laatste retourimport. De vorige ontvangstbon mag niet opnieuw als actuele staat worden uitgegeven.";
  };
  const el = (id) => document.getElementById(id);
  const input = el("shelf-files");
  const rows = el("shelf-rows");
  const message = el("shelf-status");
  const summary = el("shelf-summary");
  const sourceCopy = el("private-copy");
  // Never carry an explicit disclosure opt-in into a different original source
  // selection or a restored browser page (including bfcache restoration).
  const resetPrivateDisclosure = () => {
    el("shelf-all-private-notes").checked = false;
    el("shelf-team-private-notes").checked = false;
  };
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
  const clearReviewHistory = () => {
    reviewUndo.length = 0; reviewRedo.length = 0; humanRevision++;
    discardSelectivePreview();
    invalidateReturnReceipt();
  };
  const recordReviewEdit = () => {
    discardSelectivePreview();
    invalidateReturnReceipt();
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
    discardSelectivePreview();
    invalidateReturnReceipt();
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
  // Disclosure preview is made only from counts and fixed local labels;
  // no original filename, hash or PRIVATE note is copied into the preview.
  const renderDisclosurePreview = () => {
    const groups = Object.entries(teams).filter(([key]) => items.some(i => i.team===key))
      .map(([,label]) => label);
    const noteCount = items.filter(i => i.note.length>0).length;
    const optedIn = el("shelf-all-private-notes").checked;
    el("shelf-disclosure-preview").textContent = items.length
      ? "PRIVATE EXPORT INZAGE · " + items.length + " originele bestandsnamen + SHA-256 uit " +
        groups.length + " HUMAN teams (" + groups.join(", ") + "). " +
        "Bronbytes worden nooit ingesloten. HUMAN privé-notitieteksten: " +
        (optedIn ? "BEWUST AAN ("+noteCount+" ingevuld; in beide ALLE-TEAMS exports)" :
          "UIT ("+noteCount+" ingevulde notities niet verspreid)") +
        ". Geen geauthenticeerde ontvanger, consent of grant."
      : "Nog geen oorspronkelijke lokale bronbestanden geselecteerd. ALLE-TEAMS exports bevatten altijd originele namen en SHA-256, maar PRIVATE notities staan standaard UIT.";
  };
  function render() {
    rows.replaceChildren();
    renderDisclosurePreview();
    el("shelf-return-receipt").disabled = lastReturnReceipt === null;
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
        resetPrivateDisclosure();
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
  el("shelf-all-private-notes").addEventListener("change", renderDisclosurePreview);
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
      resetPrivateDisclosure();
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
  const selectiveRows = el("shelf-selective-rows");
  const selectiveApply = el("shelf-selective-apply");
  let pendingSelective = null;
  const discardSelectivePreview = () => {
    if (!pendingSelective) return;
    pendingSelective = null;
    selectiveApply.disabled = true;
    selectiveRows.replaceChildren();
    selectiveStatus.textContent = "Bron-/HUMAN werkset gewijzigd na preview; kies het vorige PRIVATE plan opnieuw. Geen overname toegepast.";
  };
  selectiveInput.addEventListener("change", async () => {
    const priorFile = selectiveInput.files && selectiveInput.files[0];
    selectiveInput.value = "";
    pendingSelective = null;
    selectiveApply.disabled = true;
    selectiveRows.replaceChildren();
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
          // Never silently replace review choices that were already made in this tab.
          // A receiving team must opt in for locally reviewed or differently routed items.
          const hasLocalReview = item.stage !== "unreviewed" ||
            item.team !== "unassigned" || item.note.length > 0;
          matches.push({item, previous, selected: !hasLocalReview, conflict: hasLocalReview});
        } else changed++;
      }
      const absent = priorRows.filter(row => !currentNames.has(row.original_name.normalize("NFC").toLowerCase())).length;
      for (const item of items) {
        const previous = priorByName.get(item.file.name.normalize("NFC").toLowerCase());
        const exact = matches.some(entry => entry.item === item);
        const exactEntry = matches.find(entry => entry.item === item);
        const tr = document.createElement("tr");
        cell(tr, item.file.name, "file-name");
        cell(tr, exact ? "EXACT / zelfde naam, bytes, grootte en type" : previous ? "CHANGED / NIEUWE HUMAN REVIEW" : "NEW / GEEN EERDERE HUMAN REVIEW");
        cell(tr, exactEntry
          ? (exactEntry.conflict
            ? "LOKALE HUMAN REVIEW BESTAAT: " + teams[item.team] + " / " + stages[item.stage] +
              ". Ontvangen: " + teams[previous.human_team] + " / " + stages[previous.human_stage] +
              ". Vergelijk PRIVÉ notities in een vertrouwde omgeving vóór individuele overname."
            : "Nog niet lokaal beoordeeld. Ontvangen: " + teams[previous.human_team] +
              " / " + stages[previous.human_stage])
          : "Geen eerdere HUMAN besluiten meenemen");
        const choice = document.createElement("td");
        if (exactEntry) {
          const label = document.createElement("label");
          label.textContent = "HUMAN keuze overnemen ";
          const checkbox = document.createElement("input");
          checkbox.type = "checkbox";
          checkbox.checked = exactEntry.selected;
          checkbox.setAttribute("aria-label", "HUMAN keuzes uit eerdere PRIVATE inventaris overnemen voor " + item.file.name);
          checkbox.addEventListener("change", () => {
            if (!pendingSelective || pendingSelective.matches !== matches) return;
            exactEntry.selected = checkbox.checked;
            selectiveApply.disabled = !matches.some(e => e.selected);
          });
          label.append(checkbox);
          choice.append(label);
        } else choice.textContent = "Niet beschikbaar";
        tr.append(choice);
        selectiveRows.append(tr);
      }
      for (const previous of priorRows) {
        if (currentNames.has(previous.original_name.normalize("NFC").toLowerCase())) continue;
        const tr = document.createElement("tr");
        cell(tr, previous.original_name, "file-name");
        cell(tr, "ABSENT IN LOKALE SELECTIE");
        cell(tr, "Geen automatische intrekking, fix of lagere risicostatus");
        cell(tr, "Niet beschikbaar");
        selectiveRows.append(tr);
      }
      selectiveStatus.textContent = "VOORSTEL / NOG NIET TOEGEPAST — " + matches.length +
        " ongewijzigd, " + changed + " gewijzigd, " + newer + " nieuw, " + absent +
        " afwezig. Inspecteer elke bronregel vóór de aparte bevestiging.";
      if (!matches.length) return;
      pendingSelective = {matches, changed, newer, absent, epoch, humanAtStart};
      selectiveApply.disabled = !matches.some(entry => entry.selected);
    } catch (_) {
      pendingSelective = null;
      selectiveApply.disabled = true;
      selectiveRows.replaceChildren();
      selectiveStatus.textContent = "HOLD — ongeldig PRIVATE plan, bron-/HUMAN-state gewijzigd of ambiguë bron; niets toegepast.";
    } finally {
      busy = false;
      selectiveInput.disabled = false;
      input.disabled = false;
    }
  });
  selectiveApply.addEventListener("click", () => {
    if (!pendingSelective || busy) return;
    const plan = pendingSelective;
    if (plan.epoch !== generation || plan.humanAtStart !== humanRevision ||
        !plan.matches.every(({item, previous}) => items.includes(item) &&
          item.file.name === previous.original_name &&
          item.file.size === previous.byte_length &&
          item.hash === previous.unsigned_sha256 &&
          item.inspection.kind === previous.structural_kind_unverified)) {
      pendingSelective = null;
      selectiveApply.disabled = true;
      selectiveRows.replaceChildren();
      selectiveStatus.textContent = "HOLD — bron of HUMAN-keuzes gewijzigd na de preview; kies opnieuw het eerdere PRIVATE plan.";
      return;
    }
    const chosen = plan.matches.filter(entry => entry.selected);
    if (!chosen.length) return report("HOLD — geen afzonderlijke HUMAN reviewrijen geselecteerd voor overname.");
    const explicitConflicts = chosen.filter(entry => entry.conflict).length;
    if (!confirm("Neem ALLEEN " + chosen.length + " bewust aangevinkte bronexacte PRIVATE HUMAN-rijen over, waarvan " +
      explicitConflicts + " al een lokale HUMAN review hadden? " + plan.changed +
      " gewijzigde, " + plan.newer + " nieuwe en " + plan.absent +
      " niet opnieuw geselecteerde bronnen blijven ongewijzigd. Voorgaande lokale keuzes van de aangevinkte rij worden vervangen; undo blijft beschikbaar. GEEN echte bevoegdheid.")) return;
    if (plan.epoch !== generation || plan.humanAtStart !== humanRevision) return;
    // Only the actually selected original-byte-bound HUMAN transitions enter this private receipt.
    const originalReviewChanges = chosen.map(({item, previous, conflict}) => ({
      original_name: item.file.name,
      byte_length: item.file.size,
      unsigned_sha256: item.hash,
      structural_kind_unverified: item.inspection.kind,
      had_local_review: conflict,
      before: {human_route:item.route, human_stage:item.stage, human_team:item.team},
      after: {human_route:previous.human_route, human_stage:previous.human_stage,
        human_team:previous.human_team},
      private_note_transferred: previous.private_note_included,
      private_note_changed: previous.private_note_included &&
        item.note !== previous.private_human_note
    }));
    recordReviewEdit();
    for (const {item, previous} of chosen) {
      item.route = previous.human_route;
      item.stage = previous.human_stage;
      item.team = previous.human_team;
      // Redacted V2 packet means "note not supplied", NEVER "erase local note".
      if (previous.private_note_included) item.note = previous.private_human_note;
    }
    humanRevision++;
    pendingSelective = null;
    selectiveApply.disabled = true;
    lastReturnReceipt = {
      format: "lightup.scope_PRIVATE_human_return_receipt.v1",
      status: "REVIEW_ONLY",
      posture: "INCUBATE_M3_M7_DRAFT_HOLD",
      authority: {client_consent:false, operator_consent:false, grant:false, scan:false, deploy:false, release:false},
      selected_private_human_changes: originalReviewChanges,
      original_source_selection_counts: {
        chosen_for_human_return: chosen.length,
        existing_local_review_explicitly_replaced: explicitConflicts,
        exact_but_not_selected: plan.matches.length - chosen.length,
        changed_not_copied: plan.changed, new_not_copied: plan.newer,
        absent_from_local_selection: plan.absent
      },
      warning: "LOCAL unsigned HUMAN decisions, not authenticated source, reviewer or recipient. No proof of grant, scope, revocation, fixed issue, CI, security approval or release."
    };
    appendReturnJournal(lastReturnReceipt);
    el("shelf-return-receipt-note").textContent = "PRIVATE HUMAN ontvangstbon voor " + chosen.length +
      " bewust geselecteerde bronexacte menselijke wijzigingen beschikbaar. Bevat geen oorspronkelijke broninhoud en geen PRIVATE notitieteksten.";
    render();
    selectiveStatus.textContent = "REVIEW_ONLY — " + chosen.length +
      " bewust geselecteerde brongebonden HUMAN-keuzes toegepast (" + explicitConflicts +
      " lokale reviews expliciet vervangen); " + plan.changed + " gewijzigd, " +
      plan.newer + " nieuw en " + plan.absent +
      " niet opnieuw geselecteerd bleven zonder overname. Ongedaan maken is beschikbaar.";
    report("REVIEW_ONLY — " + chosen.length + " expliciet geselecteerde PRIVATE HUMAN-rijen overgenomen; lokale conflicten niet stilzwijgend vervangen.");
  });


  // Multi-packet offline HUMAN coordination only. No reviewer identity,
  // client consent, source authenticity, grant or security release follows.
  const MAX_PEER_PACKETS = 8;
  const peerInput = el("shelf-peer-files");
  const peerRows = el("shelf-peer-rows");
  const peerStatus = el("shelf-peer-status");
  const peerApply = el("shelf-peer-apply");
  const peerSummaryExport = el("shelf-peer-summary-export");
  let peerPreview = null;
  let lastPeerReceipt = null;
  const invalidatePeerReceipt = () => {
    if (lastPeerReceipt === null) return;
    lastPeerReceipt = null;
    el("shelf-peer-receipt").disabled = true;
    el("shelf-peer-receipt-note").textContent =
      "De PRIVATE bron-/HUMAN-workroom is gewijzigd; de vorige ontvangstbon is niet meer actueel.";
  };
  const discardPeerPreview = () => {
    if (!peerPreview) return;
    peerPreview = null;
    peerApply.disabled = true;
    peerSummaryExport.disabled = true;
    el("shelf-peer-agenda").disabled = true;
    el("shelf-peer-team-agenda").disabled = true;
    el("shelf-peer-draft-save").disabled = true;
    el("shelf-peer-draft-open").disabled = true;
    el("shelf-peer-draft-status").textContent = "PRIVATE conceptkeuze vervallen door oorspronkelijke bron-/HUMAN-wijziging.";
    peerRows.replaceChildren();
    el("shelf-peer-filter-count").textContent = "Geen actuele bronexacte menselijke vergelijking.";
    el("shelf-peer-decision-preview").textContent = "Geen actuele bewuste HUMAN overname gekozen.";
    peerStatus.textContent = "PRIVATE bron-/HUMAN-state gewijzigd. Kies de reviewpakketten opnieuw.";
  };
  const sourceEqual = (row,item) => !!row &&
    row.original_name === item.file.name &&
    row.byte_length === item.file.size &&
    row.unsigned_sha256 === item.hash &&
    row.structural_kind_unverified === item.inspection.kind;
  const humanRouteEqual = (a,b) =>
    a.human_route === b.human_route &&
    a.human_stage === b.human_stage && a.human_team === b.human_team;
  const peerLabel = row => row
    ? teams[row.human_team] + " / " + stages[row.human_stage] +
      " / " + routes[row.human_route][0] +
      (row.private_note_included ? " / PRIVATE notitie aangeleverd" : " / notitie afgeschermd")
    : "Geen voorstel voor deze oorspronkelijke bron";
  const peerPending = () => peerPreview &&
    peerPreview.decisions.some(d => Number.isInteger(d.choice) && d.choice >= 0);
  // A local-only triage desk: filtering never modifies selected HUMAN choices.
  const peerFilter = el("shelf-peer-filter");
  const peerSearch = el("shelf-peer-search");
  const peerAgenda = el("shelf-peer-agenda");
  const peerTeamAgenda = el("shelf-peer-team-agenda");
  const peerAgendaTeam = el("shelf-peer-agenda-team");
  const peerDraftSave = el("shelf-peer-draft-save");
  const peerDraftOpen = el("shelf-peer-draft-open");
  const peerDraftStatus = el("shelf-peer-draft-status");
  const peerPreviewText = el("shelf-peer-decision-preview");
  const peerFilterCount = el("shelf-peer-filter-count");
  const peerHumanShort = row => row
    ? teams[row.human_team] + " / " + stages[row.human_stage] +
      " / " + routes[row.human_route][0] +
      (row.private_note_included ? " / PRIVÉ notitie aangeleverd" : " / PRIVÉ notitie onbekend")
    : "NIETS OVERNEMEN";
  const refreshPeerDesk = () => {
    const plan = peerPreview;
    if (!plan) {
      peerFilterCount.textContent = "Geen actuele bronexacte menselijke vergelijking.";
      peerPreviewText.textContent = "Nog geen bewuste HUMAN overname gekozen.";
      return;
    }
    const filter = peerFilter.value;
    const term = peerSearch.value.normalize("NFC").toLowerCase().trim();
    const chosen = plan.decisions.filter(d => d.choice >= 0);
    peerDraftSave.disabled = !chosen.length;
    let visible = 0;
    for (const d of plan.decisions) {
      const attention = d.mismatch || d.conflicting || d.noteUncertain ||
        d.proposalCount < plan.counts.packets;
      const matches =
        (filter === "all" || filter === "attention" && attention ||
         filter === "conflicts" && d.conflicting ||
         filter === "redacted" && d.noteUncertain ||
         filter === "partial" && d.proposalCount < plan.counts.packets ||
         filter === "mismatch" && d.mismatch ||
         filter === "selected" && d.choice >= 0) &&
        (!term || d.item.file.name.normalize("NFC").toLowerCase().includes(term));
      d.row.hidden = !matches;
      d.row.classList.toggle("shelf-peer-row-hidden",!matches);
      if (matches) visible++;
    }
    peerFilterCount.textContent = visible + "/" + plan.decisions.length +
      " PRIVATE originele bronnen zichtbaar; " + chosen.length +
      " bewust gekozen HUMAN voorstellen (ook buiten de huidige filter). Filters nemen niets over.";
    const container = document.createElement("div");
    if (!chosen.length) {
      container.textContent = "Geen HUMAN voorstel gekozen. Zelfs overeenstemmende reviewers veranderen de huidige lokale werkset niet.";
    } else {
      const intro = document.createElement("p");
      intro.textContent = chosen.length + " EXPLICIETE LOCAL HUMAN keuzes, nog NIET toegepast. " +
        "Huidige PRIVATE notities worden niet in deze voorvertoning weergegeven.";
      container.append(intro);
      const ol = document.createElement("ol");
      ol.className = "shelf-peer-preview-list";
      for (const d of chosen) {
        const li = document.createElement("li");
        const selected = d.allowed[d.choice];
        li.textContent = d.item.file.name + ": HUIDIG " +
          teams[d.item.team] + " / " + stages[d.item.stage] + " / " +
          routes[d.item.route][0] + " → PAKKET " + (d.choice+1) + " " +
          peerHumanShort(selected) +
          (d.conflicting ? " · HUMAN CONFLICT" : "") +
          (d.noteUncertain ? " · NOTITIE ONZEKER" : "");
        ol.append(li);
      }
      container.append(ol);
    }
    peerPreviewText.replaceChildren(container);
  };
  const updateTeamAgenda = () => {
    peerTeamAgenda.disabled = !peerPreview ||
      !["security","privacy","client_ops","platform"].includes(peerAgendaTeam.value) ||
      !peerPreview.decisions.some(d=>d.item.team===peerAgendaTeam.value);
  };
  peerFilter.addEventListener("change", refreshPeerDesk);
  peerSearch.addEventListener("input", refreshPeerDesk);
  peerAgendaTeam.addEventListener("change",updateTeamAgenda);
  peerInput.addEventListener("change", async () => {
    const files = Array.from(peerInput.files || []);
    peerInput.value = "";
    peerPreview = null; peerRows.replaceChildren();
    peerApply.disabled = true; peerSummaryExport.disabled = true; peerAgenda.disabled = true;
    peerTeamAgenda.disabled = true;
    peerDraftSave.disabled = true; peerDraftOpen.disabled = true;
    peerDraftStatus.textContent = "Selecteer opnieuw dezelfde originele bron- en reviewerbestanden voor HUMAN conceptkeuzes.";
    peerPreviewText.textContent = "Geen actuele HUMAN-keuze.";
    peerFilterCount.textContent = "Geen actuele PRIVATE reviewpakketten.";
    peerFilter.value = "all"; peerSearch.value = "";
    if (busy || !items.length || files.length < 2 || files.length > MAX_PEER_PACKETS ||
        files.some(f => f.size < 10 || f.size > 96 * 1024)) {
      peerStatus.textContent = "HOLD — selecteer originele bronnen en 2–8 PRIVATE reviewpakketten (maximaal 96 KiB per pakket).";
      return;
    }
    const epoch = generation, revision = humanRevision;
    busy = true; peerInput.disabled = true; input.disabled = true;
    try {
      // Reject byte-identical packages: copying the same document must not be
      // represented as several independently proposed HUMAN decisions.
      const fingerprints = new Set();
      const packetBytes = [];
      const inventories = [];
      for (const f of files) {
        const bytes = await f.arrayBuffer();
        const fingerprint = await SHA(bytes);
        if (fingerprints.has(fingerprint)) throw Error("duplicate peer document");
        fingerprints.add(fingerprint);
        packetBytes.push({local_packet_number:packetBytes.length+1,
          original_packet_byte_length:bytes.byteLength, unsigned_original_packet_sha256:fingerprint});
        // The existing strict decoder must see exactly the hashed bytes, not
        // a second read of a potentially replaced user-selected disk file.
        const immutableLocalCopy = new Blob([bytes], {type:"application/json"});
        inventories.push(await LightUpPrivateSourceInspector.readHumanInventory(immutableLocalCopy));
        if (epoch !== generation || revision !== humanRevision) throw Error("stale source");
      }
      const lookups = inventories.map(entries => new Map(entries.map(row =>
        [row.original_name.normalize("NFC").toLowerCase(),row])));
      const currentNames = new Set(items.map(item =>
        item.file.name.normalize("NFC").toLowerCase()));
      const outsideNames = new Set();
      for (const lookup of lookups) for (const name of lookup.keys()) {
        if (!currentNames.has(name)) outsideNames.add(name);
      }
      const decisions = [], counts = {
        packets:files.length, original_sources:items.length,
        consensus:0, divergent_human_choices:0, uncertain_private_notes:0,
        partial_reviewer_coverage:0, single_packet:0,
        original_source_mismatch:0, no_proposal:0,
        absent_from_local_selection:outsideNames.size
      };
      for (const item of items) {
        const key = item.file.name.normalize("NFC").toLowerCase();
        const originals = lookups.map(m => m.get(key) || null);
        // One supplied but mismatching reference fences all proposals under
        // this literal source identity, even if another proposal matches.
        const mismatch = originals.some(row => row && !sourceEqual(row,item));
        const allowed = mismatch ? originals.map(() => null) : originals;
        const proposals = allowed.filter(Boolean);
        // Count incomplete participation for EVERY non-mismatched source, even
        // when only one reviewer supplied a HUMAN proposal.
        if (!mismatch && proposals.length > 0 && proposals.length < files.length) {
          counts.partial_reviewer_coverage++;
        }
        let state;
        if (mismatch) { state = "BRONVERSCHIL / NIETS OVERNEMEN"; counts.original_source_mismatch++; }
        else if (!proposals.length) { state = "GEEN PAKKETVOORSTEL"; counts.no_proposal++; }
        else if (proposals.length === 1) { state = "ÉÉN VOORSTEL / GEEN CONSENSUS"; counts.single_packet++; }
        else {
          const sameRoutes = proposals.every(row => humanRouteEqual(proposals[0],row));
          const redacted = proposals.some(row => !row.private_note_included);
          // Redaction means UNKNOWN, but known distinct disclosed notes remain
          // a definite conflict even with other packets that redact notes.
          const disclosedNotes = proposals.filter(row => row.private_note_included)
            .map(row => row.private_human_note);
          const conflictingDisclosedNotes = new Set(disclosedNotes).size > 1;
          if (!sameRoutes || conflictingDisclosedNotes) {
            state = "TEGENSTRIJDIGE HUMAN-KEUZES"; counts.divergent_human_choices++;
          } else if (redacted) {
            state = "PRIVATE NOTITIEDEKKING ONBEKEND"; counts.uncertain_private_notes++;
          } else {
            state = "GELIJKE HUMAN-VOORSTELLEN (ONGEATTESTEERD)"; counts.consensus++;
          }
        }
        const entry = {item,allowed,choice:-1,mismatch,state,
          presentPacketSlots:originals.flatMap((row,index)=>row?[index+1]:[]),
          proposalCount:proposals.length,
          conflicting:state==="TEGENSTRIJDIGE HUMAN-KEUZES",
          noteUncertain:state==="PRIVATE NOTITIEDEKKING ONBEKEND"};
        decisions.push(entry);
        const tr = document.createElement("tr");
        cell(tr,item.file.name,"file-name");
        cell(tr,state + " · " + proposals.length + "/" + files.length + " pakketten" +
          (proposals.length > 0 && proposals.length < files.length ? " · ONVOLLEDIGE DEKKING" : ""));
        const proposalsCell = document.createElement("td");
        const list = document.createElement("ol");
        list.className = "shelf-peer-list";
        for (let j=0;j<files.length;j++) {
          const line = document.createElement("li");
          line.textContent = "Pakket " + (j+1) + ": " +
            (mismatch && originals[j]
              ? "GEHELE BRON GEBLOKKEERD (inconsistent bronbestand)"
              : peerLabel(allowed[j]));
          list.append(line);
        }
        proposalsCell.append(list); tr.append(proposalsCell);
        const td = document.createElement("td");
        if (proposals.length) {
          const select = document.createElement("select");
          select.setAttribute("aria-label","Kies PRIVATE HUMAN voorstel voor "+item.file.name);
          const empty = document.createElement("option");
          empty.value = "-1"; empty.textContent = "NIETS OVERNEMEN (standaard)";
          select.append(empty);
          for (let j=0;j<allowed.length;j++) {
            if (!allowed[j]) continue;
            const option = document.createElement("option");
            option.value = String(j);
            option.textContent = "Pakket " + (j+1) + " BEWUST overnemen";
            select.append(option);
          }
          select.addEventListener("change",()=>{
            if (!peerPreview || peerPreview.decisions !== decisions) return;
            const selected = Number(select.value);
            entry.choice = Number.isInteger(selected) && (selected===-1 || allowed[selected])
              ? selected : -1;
            peerApply.disabled = !peerPending();
            refreshPeerDesk();
          });
          entry.select = select;
          td.append(select);
        } else td.textContent = "Niet mogelijk";
        tr.append(td); entry.row = tr; peerRows.append(tr);
      }
      if (epoch !== generation || revision !== humanRevision) throw Error("stale review");
      peerPreview = {decisions,epoch,revision,counts,packetBytes};
      peerSummaryExport.disabled = false;
      peerAgenda.disabled = false;
      updateTeamAgenda();
      peerDraftOpen.disabled = false;
      peerDraftStatus.textContent = "Pakketten bronexact geladen. HUMAN conceptkeuzes kunnen nu worden bewaard of opnieuw gebonden.";
      refreshPeerDesk();
      peerStatus.textContent = "REVIEW_ONLY / NIETS AUTOMATISCH TOEGEPAST — " +
        files.length + " ongetekende pakketten, " + counts.consensus +
        " menselijke overeenkomsten, " + counts.divergent_human_choices +
        " conflicten, " + counts.uncertain_private_notes +
        " onbekende notitiedekkingen, " + counts.original_source_mismatch +
        " inconsistente originele bronnen. Zelfs consensus verleent NOOIT toestemming.";
    } catch (_) {
      peerPreview = null; peerRows.replaceChildren();
      peerSummaryExport.disabled = true; peerApply.disabled = true; peerAgenda.disabled = true;
      peerTeamAgenda.disabled = true;
    peerDraftSave.disabled = true; peerDraftOpen.disabled = true;
      peerDraftStatus.textContent = "Ongeldige PRIVATE reviewer-pakketten; geen concept heropend.";
      peerFilterCount.textContent = "Geen geldige reviewpakketten.";
      peerPreviewText.textContent = "Geen menselijke keuze mogelijk.";
      peerStatus.textContent =
        "HOLD — ongeldige, byte-identieke, ambigue of stale PRIVATE reviewpakketten. Bestaande HUMAN-keuzes behouden.";
    } finally {
      busy = false; peerInput.disabled = false; input.disabled = false;
    }
  });
  peerDraftSave.addEventListener("click", () => {
    const plan = peerPreview;
    if (!plan || busy || plan.epoch !== generation || plan.revision !== humanRevision) {
      if (plan) discardPeerPreview();
      return report("HOLD — geen actuele bronexacte HUMAN conceptkeuzes om te bewaren.");
    }
    const chosen = plan.decisions.filter(d => d.choice >= 0);
    if (!chosen.length) return report("HOLD — geen handmatig gekozen HUMAN voorstel, concept leeg.");
    if (!confirm("Bewaar PRIVATE HUMAN conceptkeuzes voor "+chosen.length+
      " bewust geselecteerde bron(nen) op "+plan.decisions.length+
      " oorspronkelijke bronbestanden? Het PRIVATE JSON bevat alle oorspronkelijke namen, SHA-256 "+
      "en per origineel reviewer-pakket de bytegebonden SHA-256. Geen notitieteksten, originele bronbytes, consent, grant of uitvoerrecht. "+
      "Later alleen heropenen met exact DEZELFDE bron- en pakketvolgorde.")) return;
    exportJSON("lightup-scope-PRIVATE-HUMAN-peer-decision-draft.json",{
      format:"lightup.scope_PRIVATE_human_proposal_draft.v1",
      status:"REVIEW_ONLY",
      authority:{client_consent:false,operator_consent:false,grant:false,
        scan:false,deploy:false,release:false},
      packets:plan.packetBytes.map(p => ({
        local_packet_number:p.local_packet_number,
        original_packet_byte_length:p.original_packet_byte_length,
        unsigned_original_packet_sha256:p.unsigned_original_packet_sha256
      })),
      sources:plan.decisions.map(d => ({
        original_name:d.item.file.name,
        byte_length:d.item.file.size,
        unsigned_sha256:d.item.hash,
        structural_kind_unverified:d.item.inspection.kind,
        packet_choice:d.choice < 0 ? -1 : d.choice+1
      })),
      warning:"Unsigned private HUMAN draft only. Reopen with exact same original files and peer packet bytes. No stored source content, notes, recipient authentication, consent, grant, scan or release."
    });
    peerDraftStatus.textContent = "REVIEW_ONLY — PRIVATE concept voor "+chosen.length+
      " HANDMATIGE pakketkeuzes lokaal opgeslagen. Originele bron- en HUMAN reviews niet aangepast.";
    report("REVIEW_ONLY — bron- en pakketgebonden PRIVATE HUMAN conceptkeuzes lokaal bewaard, geen overname toegepast.");
  });
  peerDraftOpen.addEventListener("change", async () => {
    const file = peerDraftOpen.files && peerDraftOpen.files[0];
    peerDraftOpen.value = "";
    const plan = peerPreview;
    if (!file || !plan || busy) return;
    if (plan.epoch !== generation || plan.revision !== humanRevision) {
      discardPeerPreview();
      return report("HOLD — stale HUMAN review, concept niet geopend.");
    }
    busy = true; input.disabled = true; peerInput.disabled = true; peerDraftOpen.disabled = true;
    try {
      const draft = await LightUpPrivateSourceInspector.readHumanProposalDraft(file);
      if (peerPreview !== plan || plan.epoch !== generation ||
          plan.revision !== humanRevision ||
          draft.packets.length !== plan.packetBytes.length ||
          draft.sources.length !== plan.decisions.length) {
        throw Error("changed original set");
      }
      // Portable continuation: bind by exact ORIGINAL reviewer packet bytes
      // rather than trusting positions from a reopened file-picker selection.
      // The strict reader already rejects duplicate packet digests and names.
      const remappedPackets = draft.packets.map(packet =>
        plan.packetBytes.findIndex(current =>
          packet.original_packet_byte_length === current.original_packet_byte_length &&
          packet.unsigned_original_packet_sha256 === current.unsigned_original_packet_sha256));
      if (remappedPackets.includes(-1) ||
          new Set(remappedPackets).size !== plan.packetBytes.length) {
        throw Error("missing, duplicate, or changed original reviewer packet");
      }
      const byOriginalName = new Map(plan.decisions.map(d=>[d.item.file.name,d]));
      const restoredChoices = new Map();
      for (const row of draft.sources) {
        const d=byOriginalName.get(row.original_name);
        if (!d || !items.includes(d.item) ||
            row.byte_length !== d.item.file.size ||
            row.unsigned_sha256 !== d.item.hash ||
            row.structural_kind_unverified !== d.item.inspection.kind) {
          throw Error("changed original source identity");
        }
        const currentSlot = row.packet_choice === -1
          ? -1 : remappedPackets[row.packet_choice - 1];
        if (currentSlot !== -1 &&
            (!d.allowed[currentSlot] || !sourceEqual(d.allowed[currentSlot],d.item))) {
          throw Error("source mismatch or missing reviewer choice");
        }
        restoredChoices.set(d.item.file.name,currentSlot);
      }
      if (restoredChoices.size !== plan.decisions.length) {
        throw Error("incomplete original source coverage");
      }
      const selected=[...restoredChoices.values()].filter(slot=>slot>=0).length;
      const reorderPackets=remappedPackets.some((slot,i)=>slot!==i);
      const reorderSources=draft.sources.some((row,i)=>
        row.original_name!==plan.decisions[i].item.file.name);
      if (!confirm("Herstel UITSLUITEND " + selected +
          " voorlopige HUMAN conceptkeuzes? Alle originele bronnen en " +
          draft.packets.length + " originele reviewer-pakketten zijn exact dezelfde bytes. " +
          (reorderPackets ? "REVIEWER PAKKETVOLGORDE IS ANDERS: pakketkeuzes worden veilig per exacte SHA-256 omgezet. " : "") +
          (reorderSources ? "ORIGINELE BRONVOLGORDE IS ANDERS: bronnen worden exact op identiteit gekoppeld. " : "") +
          "Geen oorspronkelijke bronbestanden, huidige HUMAN fase/team/route/notities, " +
          "echte consent of grant veranderen. Een latere toepassing vereist een NIEUWE expliciete menselijke bevestiging.")) {
        peerDraftStatus.textContent = "Heropenen door gebruiker geannuleerd. Bestaande conceptkeuzes blijven behouden.";
        return;
      }
      if (peerPreview!==plan || plan.epoch!==generation || plan.revision!==humanRevision ||
          !plan.decisions.every(d=>{
            const currentSlot=restoredChoices.get(d.item.file.name);
            return Number.isInteger(currentSlot) && items.includes(d.item) &&
              (currentSlot===-1 || !!d.allowed[currentSlot] &&
                sourceEqual(d.allowed[currentSlot],d.item));
          })) {
        throw Error("stale confirmation");
      }
      // Replace ONLY the unapplied HTML choices, never current HUMAN reviews.
      for (const d of plan.decisions) {
        d.choice=restoredChoices.get(d.item.file.name);
        if (d.select) d.select.value=String(d.choice);
      }
      peerApply.disabled = !peerPending();
      refreshPeerDesk();
      peerDraftStatus.textContent = "REVIEW_ONLY — "+selected+
        " oorspronkelijke HUMAN conceptkeuze(n) hersteld; "+
        (reorderPackets ? "reviewer-pakketten bronexact hernummerd; " : "")+
        (reorderSources ? "bronvolgorde veilig gekoppeld; " : "")+
        "alle huidige lokale bron/HUMAN waarden intact.";
      report("REVIEW_ONLY — exact bron- en pakketgebonden concept heropend; GEEN voorstel toegepast of geautoriseerd.");
    } catch (_) {
      peerDraftStatus.textContent =
        "HOLD — ongeldig of inconsistent PRIVATE concept: bronvolgorde, bronnen of exacte reviewpakketbytes wijken af. Niets gewijzigd.";
      report("HOLD — HUMAN concept kan niet bron- én pakketexact heropend worden; alle bestaande keuzes blijven intact.");
    } finally {
      busy = false; input.disabled = false; peerInput.disabled = false;
      peerDraftOpen.disabled = !peerPreview;
    }
  });

  const exportPeerAgenda = teamOnly => {
    const plan = peerPreview;
    if (!plan || busy) return report("HOLD — er is geen actuele bronexacte HUMAN bespreeklijst.");
    if (plan.epoch !== generation || plan.revision !== humanRevision) {
      discardPeerPreview();
      return report("HOLD — HUMAN bron/reviewrevisie gewijzigd; agenda niet gemaakt.");
    }
    const selectedTeam = peerAgendaTeam.value;
    if (teamOnly && !["security","privacy","client_ops","platform"].includes(selectedTeam)) {
      return report("HOLD — kies één concreet HUMAN ontvangend team.");
    }
    const scope = teamOnly ? plan.decisions.filter(d=>d.item.team===selectedTeam) : plan.decisions;
    if (teamOnly && !scope.length) return report("HOLD — dit team heeft geen eigen brongebonden HUMAN dossiers.");
    // Do not disclose any reviewer packet digest unrelated to this team's
    // original source references. Never apply active UI table filters.
    const packetSlots = teamOnly
      ? new Set(scope.flatMap(d=>d.presentPacketSlots)) : null;
    const includedPacketBytes = teamOnly
      ? plan.packetBytes.filter(p=>packetSlots.has(p.local_packet_number))
      : plan.packetBytes;
    const counts = teamOnly
      ? {
          source_scope_count:scope.length, reviewer_packet_slots_total:plan.counts.packets,
          referenced_packet_slots:includedPacketBytes.length,
          source_mismatches:scope.filter(d=>d.mismatch).length,
          human_conflicts:scope.filter(d=>d.conflicting).length,
          redacted_note_uncertainty:scope.filter(d=>d.noteUncertain).length,
          partial_participation:scope.filter(d=>d.proposalCount>0 &&
            d.proposalCount<plan.counts.packets).length,
          unreviewed_sources:scope.filter(d=>d.proposalCount===0).length
        } : plan.counts;
    const attention = scope.filter(d => d.mismatch || d.conflicting ||
      d.noteUncertain || d.proposalCount < plan.counts.packets);
    if (!confirm("Download " + (teamOnly ? "ALLEEN de "+scope.length+
      " oorspronkelijke PRIVATE HUMAN dossiers van team "+teams[selectedTeam] :
      "de VOLLEDIGE PRIVATE HUMAN bespreekagenda voor "+scope.length+" oorspronkelijke bronnen")+
      ", inclusief "+attention.length+" aandachtspunten? "+
      (teamOnly ? "Alleen SHA-256 van de "+includedPacketBytes.length+
        " reviewpakketten met voorstellen voor dit team worden opgenomen. " :
        "Ook oorspronkelijke reviewer-pakketdigests voor de volledige selectie worden opgenomen. ")+
      "De agenda bevat vertrouwelijke oorspronkelijke namen, hashes en HUMAN keuzes, "+
      "geen bronbytes of PRIVATE notitieteksten. UI filters gelden NIET voor dit document. "+
      "Controleer ontvangende mens en kanaal apart; geen echte toestemming of grant.")) return;
    // Unfiltered, source-bound private HUMAN meeting docket. All entries are
    // serialized via JSON inside Markdown code fences, not rendered as active HTML.
    const rank = d => d.mismatch ? 0 : d.conflicting ? 1 :
      d.noteUncertain ? 2 : d.proposalCount < plan.counts.packets ? 3 : 4;
    const order = [...scope].sort((a,b) => rank(a)-rank(b));
    const humanRecord = row => row ? {
      human_team:row.human_team, human_stage:row.human_stage,
      human_route:row.human_route, private_note_included:row.private_note_included
    } : null;
    // Original filenames are untrusted. JSON string escapes must prevent
    // literal Markdown code-fence markers from becoming active markup.
    // JSON backslash-u0060 represents the original backtick character.
    const agendaJSON = value => JSON.stringify(value,null,2).replace(/\x60/gu,"\\u0060");
    const agenda = [
      teamOnly ? "# LightUp — PRIVATE HUMAN TEAM-reviewbespreekagenda" : "# LightUp — PRIVATE HUMAN review-bespreekagenda",
      "",
      "**REVIEW_ONLY · INCUBATE M3/M7 · DRAFT/HOLD · geen autorisatie of scannerrecht.**",
      "",
      "Vereist: afzonderlijk gecontroleerde bronhouder, echte actuele client/operatorconsent, "+
        "revocation-at-use, originele CI/review en expliciete HUMAN GO; dit document vervangt niets daarvan.",
      "",
      "Deze export bevat vertrouwelijke oorspronkelijke namen, SHA-256 en menschlijke team/route/fase-keuzes.",
      "PRIVATE notitieteksten en oorspronkelijke bronbytes ontbreken. "+
        "Gelijke ongetekende voorstellen bewijzen geen onafhankelijke revieweridentiteit of consent.",
      teamOnly ? "ALLEEN team "+teams[selectedTeam]+" en bijhorende originele bronnen. Andere teamdossiers en niet-gerelateerde reviewer-digests zijn uitgesloten." : "Tabel- en zoekfilters zijn NIET op deze complete agenda toegepast.",
      "",
      "## Ontvangen ongetekende HUMAN pakketten (lokale volgorde)",
      "",
      "```json",
      agendaJSON(includedPacketBytes),
      "```",
      "",
      "## Bronvrije triageaantallen",
      "",
      "```json",
      agendaJSON(counts),
      "```",
      "",
      teamOnly ? "## Alleen oorspronkelijke dossiers van team "+teams[selectedTeam]+" op bespreekprioriteit" : "## Alle oorspronkelijke dossiers op bespreekprioriteit",
      ""
    ];
    for (const [idx,d] of order.entries()) {
      const originallySelected = d.choice >= 0 ? d.allowed[d.choice] : null;
      const entry = {
        original_source:{
          name:d.item.file.name,
          byte_length:d.item.file.size,
          unsigned_sha256:d.item.hash,
          structural_kind_unverified:d.item.inspection.kind
        },
        human_status:d.state,
        present_proposals:d.proposalCount,
        reviewed_packet_count:plan.counts.packets,
        fenced_all_reviewers:d.mismatch,
        local_human_before:{
          human_team:d.item.team,human_stage:d.item.stage,human_route:d.item.route,
          private_note_present:d.item.note.length>0
        },
        human_packets:d.allowed.map((row,index) => ({
          local_packet_number:index+1,review:humanRecord(row)
        })).filter(p=>!teamOnly || d.presentPacketSlots.includes(p.local_packet_number)),
        explicit_choice:d.choice < 0 ? "NIETS OVERNEMEN" : "PAKKET "+(d.choice+1),
        chosen_human_after:humanRecord(originallySelected),
        no_execution_authority:true
      };
      agenda.push("### Dossier "+(idx+1)+" — "+d.state,"",
        "```json",agendaJSON(entry),"```","");
    }
    agenda.push("## HUMAN afhandelpunten", "",
      "1. Leg apart de ontvanger en oorspronkelijke broneigenaar vast; hashes tonen alleen bytes.",
      "2. Los conflicten en afgeschermde notities afzonderlijk buiten dit document op.",
      "3. Bepaal per bron opnieuw de handmatige HUMAN keuze; geen bulkautorisatie.",
      "4. Deel alleen via vertrouwd PRIVATE kanaal. Geen oorspronkelijke bronbestandbytes opgenomen.",
      "5. Bestaande echte toestemming, grant, revocation, security review en CI blijven gescheiden.",
      "");
    download(new Blob([agenda.join("\n")],{type:"text/markdown;charset=utf-8"}),
      teamOnly ? "lightup-scope-PRIVATE-HUMAN-"+selectedTeam+"-peer-review-agenda.md" :
        "lightup-scope-PRIVATE-HUMAN-multi-peer-review-agenda.md");
    report("REVIEW_ONLY — PRIVATE HUMAN bespreekagenda van "+
      (teamOnly ? "uitsluitend team "+teams[selectedTeam]+" met " : "alle teams met ")+
      order.length+" oorspronkelijke dossiers lokaal gedownload. Geen bronbytes, notitietekst of toestemming.");
  };
  peerAgenda.addEventListener("click",()=>exportPeerAgenda(false));
  peerTeamAgenda.addEventListener("click",()=>exportPeerAgenda(true));

  el("shelf-peer-summary-export").addEventListener("click", () => {
    const plan = peerPreview;
    if (!plan) return report("HOLD — eerst een actuele PRIVATE vergelijking maken.");
    if (plan.epoch!==generation || plan.revision!==humanRevision) {
      discardPeerPreview(); return report("HOLD — stale HUMAN vergelijking.");
    }
    if (!confirm("Exporteer uitsluitend PRIVATE HUMAN aantallen zonder bronbestandnamen, SHA-256, teamroutes of notities? Kleine aantallen kunnen indirect herleidbaar blijven.")) return;
    exportJSON("lightup-scope-PRIVATE-HUMAN-multi-peer-counts.json",{
      format:"lightup.scope_PRIVATE_human_multi_peer_counts.v1",status:"REVIEW_ONLY",
      posture:"INCUBATE_M3_M7_DRAFT_HOLD",
      authority:{client_consent:false,operator_consent:false,grant:false,
        scan:false,deploy:false,release:false},
      comparison_counts:plan.counts,
      warning:"Unsigned untrusted local counts. Equal proposals do not authenticate separate reviewers, source identity, authorization or security status."
    });
    report("REVIEW_ONLY — alleen bronvrije HUMAN aantallen lokaal gedownload.");
  });
  el("shelf-peer-receipt").addEventListener("click", () => {
    if (!lastPeerReceipt) return report("HOLD — geen actuele PRIVATE HUMAN-retourbon.");
    if (!confirm("Download brongebonden PRIVATE HUMAN-retourbon met oorspronkelijke bestandsnamen en ongetekende SHA-256, pakketkeuze en handmatige vóór/na waarden? Geen bronbytes of PRIVATE notitietekst; verifieer ontvanger en kanaal apart. Nooit echte toestemming.")) return;
    exportJSON("lightup-scope-PRIVATE-HUMAN-multi-peer-receipt.json",lastPeerReceipt);
    report("REVIEW_ONLY — PRIVATE HUMAN peer-retourbon lokaal gedownload.");
  });
  peerApply.addEventListener("click", () => {
    const plan = peerPreview;
    if (!plan || busy) return;
    const chosen = plan.decisions.filter(d=>d.choice>=0);
    if (!chosen.length) return;
    if (plan.epoch!==generation || plan.revision!==humanRevision ||
        !chosen.every(d=>items.includes(d.item) && !d.mismatch &&
          sourceEqual(d.allowed[d.choice],d.item))) {
      discardPeerPreview(); return report("HOLD — oorspronkelijke bron/HUMAN-revisie gewijzigd; niets toegepast.");
    }
    const conflicts = chosen.filter(d=>d.conflicting).length;
    const uncertain = chosen.filter(d=>d.noteUncertain).length;
    const replacing = chosen.filter(({item})=>item.route!=="none" ||
      item.stage!=="unreviewed" || item.team!=="unassigned" ||
      item.note.length>0).length;
    if (!confirm("Neem " + chosen.length + " individueel GEKOZEN PRIVATE HUMAN voorstellen over, inclusief " +
      conflicts + " reviewerconflicten, " + uncertain + " onzekere notitiedekkingen en " +
      replacing + " bestaande lokale HUMAN reviews? Alle overige bronnen blijven onaangeroerd. " +
      "Dit verleent GEEN toestemming of beveiligingsgoedkeuring. Undo blijft mogelijk.")) return;
    if (plan.epoch!==generation || plan.revision!==humanRevision) return;
    const changes = chosen.map(d=>{
      const source=d.allowed[d.choice];
      return {
        original_name:d.item.file.name,byte_length:d.item.file.size,
        unsigned_sha256:d.item.hash,structural_kind_unverified:d.item.inspection.kind,
        human_packet_selected:d.choice+1,
        reviewer_choices_disagreed:d.conflicting,
        note_disclosure_incomplete:d.noteUncertain,
        before:{human_route:d.item.route,human_stage:d.item.stage,human_team:d.item.team},
        after:{human_route:source.human_route,human_stage:source.human_stage,human_team:source.human_team},
        private_note_transferred:source.private_note_included,
        private_note_changed:source.private_note_included && d.item.note!==source.private_human_note
      };
    });
    recordReviewEdit();
    for (const d of chosen) {
      const src=d.allowed[d.choice];
      d.item.route=src.human_route;
      d.item.stage=src.human_stage;
      d.item.team=src.human_team;
      if (src.private_note_included) d.item.note=src.private_human_note;
    }
    humanRevision++;
    lastPeerReceipt={
      format:"lightup.scope_PRIVATE_human_multi_peer_receipt.v1",
      status:"REVIEW_ONLY",posture:"INCUBATE_M3_M7_DRAFT_HOLD",
      authority:{client_consent:false,operator_consent:false,grant:false,
        scan:false,deploy:false,release:false},
      reviewed_packet_count:plan.counts.packets,
      original_private_reviewer_packets:plan.packetBytes,
      original_source_bound_human_choices:changes,
      conflicting_human_choices_explicitly_selected:conflicts,
      unverified_note_disclosures_explicitly_selected:uncertain,
      local_human_reviews_replaced:replacing,
      warning:"Unsigned SHA-256 on PRIVATE packet bytes binds only the local reviewed copies, never reviewer identity, origin trust, consent, grant, revocation, scan or release."
    };
    el("shelf-peer-receipt").disabled=false;
    el("shelf-peer-receipt-note").textContent=
      "PRIVATE brongebonden HUMAN retourbon voor "+chosen.length+
      " handmatig gekozen regels; geen PRIVATE notitietekst, geen echte autorisatie.";
    render();
    peerStatus.textContent="REVIEW_ONLY — "+chosen.length+
      " individueel gekozen HUMAN voorstellen uit "+plan.counts.packets+
      " pakketten overgenomen; de overige lokale reviews behouden.";
    // The existing preview cannot be replayed against the changed HUMAN workset.
    peerPreviewText.textContent = "Toegepaste HUMAN keuzes: "+chosen.length+
      ". Kies opnieuw originele reviewpakketten voor een nieuwe vóór/na-vergelijking.";
    report("REVIEW_ONLY — alleen expliciete bronexacte PRIVATE HUMAN-keuzes toegepast.");
  });

  el("shelf-return-receipt").addEventListener("click", () => {
    if (!lastReturnReceipt) return report("HOLD — geen actuele PRIVATE HUMAN ontvangstbon. Importeer eerst bewust bronexacte HUMAN-keuzes.");
    if (!confirm("Download PRIVATE ontvangstbon met oorspronkelijke bestandsnamen, ongetekende SHA-256 en oude/nieuwe HUMAN team/fase (zonder oorspronkelijke bronbytes of notitieteksten)? Deze informatie kan vertrouwelijk zijn. Ontvanger en kanaal afzonderlijk verifiëren. Geen echte toestemming, bewijs of security-vrijgave.")) return;
    exportJSON("lightup-scope-PRIVATE-HUMAN-return-receipt.json", lastReturnReceipt);
    report("REVIEW_ONLY — ontvangstbon lokaal gedownload voor de laatste daadwerkelijk gekozen HUMAN statusovername. Geen originele bron, grant of toestemming gewijzigd.");
  });
  el("shelf-return-journal-export").addEventListener("click", () => {
    if (!returnJournal.length) return;
    if (!confirm("PRIVATE historisch HUMAN retourjournaal exporteren met maximaal 12 lokaal gemaakte rondes? Bevat vertrouwelijke oorspronkelijke namen en SHA-256, maar geen bronbytes of PRIVATE notitieteksten. Oude rondes zijn GEEN huidige reviewstatus, revoke of toestemming.")) return;
    exportJSON("lightup-scope-PRIVATE-HUMAN-historical-return-journal.json", {
      format: "lightup.scope_PRIVATE_human_return_journal.v1",
      status: "REVIEW_ONLY",
      posture: "INCUBATE_M3_M7_DRAFT_HOLD",
      authority: {client_consent:false,operator_consent:false,grant:false,scan:false,deploy:false,release:false},
      historical_only: true,
      local_rounds: returnJournal.map(round => ({local_ordinal: round.ordinal, human_receipt: round.receipt})),
      warning: "Untrusted local historical HUMAN notes; no identity, original source authenticity, current consent, revocation, grant, fixed issue, valid scan or release asserted."
    });
    report("REVIEW_ONLY — PRIVATE historisch journaal lokaal gedownload. Geen actuele bron, bewijs of toestemming.");
  });
  el("shelf-return-journal-clear").addEventListener("click", () => {
    if (!returnJournal.length) return;
    if (!confirm("Alle " + returnJournal.length + " uitsluitend lokaal bewaarde historische HUMAN retourrondes uit dit tabblad wissen? Eerder gedownloade bestanden blijven bestaan.")) return;
    returnJournal.length = 0;
    renderReturnJournal();
    report("REVIEW_ONLY — lokaal historisch HUMAN journaal geleegd; dit wist geen eerder gedownloade bestanden.");
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
        if (rows[i].private_note_included) items[i].note = rows[i].private_human_note;
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
    resetPrivateDisclosure();
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


  el("shelf-recipient-inventory").addEventListener("click", () => {
    const selectedTeam = el("shelf-recipient-team").value;
    if (!Object.hasOwn(teams, selectedTeam) || selectedTeam === "unassigned") {
      return report("HOLD — kies een concreet HUMAN ontvangend team. Een niet-toegewezen werkset mag niet als teampakket worden verstuurd.");
    }
    const scoped = items.filter(e => e.team === selectedTeam);
    const includeNotes = el("shelf-team-private-notes").checked;
    if (!scoped.length) return report("HOLD — het gekozen team heeft geen expliciet geselecteerde PRIVATE dossiers.");
    if (!confirm("PRIVATE bronexact JSON-teampakket met uitsluitend " + scoped.length +
      " aan " + teams[selectedTeam] + " toegewezen dossiers exporteren? Het bevat oorspronkelijke namen en SHA-256. PRIVATE notitieteksten: " +
      (includeNotes ? "BEWUST INBEGREPEN" : "UITGESLOTEN") +
      ". Controleer de ontvanger afzonderlijk; deze app verifieert GEEN identiteit, bronhouder, consent of toestemming.")) return;
    exportJSON("lightup-scope-PRIVATE-sourcebound-human-" + selectedTeam + ".json", {
      format: "lightup.scope_handoff_PRIVATE_inventory.v2",
      status: "REVIEW_ONLY",
      authority: {
        client_consent: false, operator_consent: false, grant: false,
        scan: false, deploy: false, release: false
      },
      entries: scoped.map(e => ({
        original_name: e.file.name,
        byte_length: e.file.size,
        unsigned_sha256: e.hash,
        structural_kind_unverified: e.inspection.kind,
        human_route: e.route,
        human_stage: e.stage,
        human_team: e.team,
        private_note_included: includeNotes,
        private_human_note: includeNotes ? e.note : ""
      })),
      warning: "PRIVATE HUMAN review subset only; no source bytes or original authenticity. Separate recipient verification mandatory. Use selective source-exact import; no grant, scan, revocation or release."
    });
    if (includeNotes) el("shelf-team-private-notes").checked = false; // one download, one deliberate disclosure
    report("REVIEW_ONLY — bronexact PRIVATE HUMAN-teampakket voor uitsluitend " + teams[selectedTeam] +
      " gedownload. Ontvanger kan na onafhankelijke bronselectie via selectieve import terugkoppelen.");
  });
  el("shelf-minimum-handoff").addEventListener("click", () => {
    const team = el("shelf-recipient-team").value;
    if (!Object.hasOwn(teams, team)) return report("HOLD — kies expliciet precies één HUMAN team.");
    const chosen = items.filter(e => e.team === team);
    const includeNotes = el("shelf-team-private-notes").checked;
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
          "  - PRIVATE opvolgnotitie: " + (includeNotes ? JSON.stringify(e.note || "(geen)") : "(bewust niet meegestuurd)"),
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
    if (includeNotes) el("shelf-team-private-notes").checked = false;
    report("REVIEW_ONLY — precies " + chosen.length + " uitsluitend voor " + teams[team] +
      " geselecteerde HUMAN dossiers lokaal in PRIVATE brief; andere teams uitgesloten.");
  });
  el("shelf-workplan").addEventListener("click", () => {
    if (!items.length) return report("HOLD — selecteer eerst PRIVATE bronbestanden voor een HUMAN teambrief.");
    const includePrivateNotes = el("shelf-all-private-notes").checked;
    const noteCount = items.filter(e => e.note.length > 0).length;
    if (!confirm("PRIVATE HUMAN teambrief voor ALLE " + items.length + " geselecteerde originele bronverwijzingen maken? De brief bevat namen en SHA-256 van ALLE teams. PRIVATE notitieteksten: " + (includePrivateNotes ? "BEWUST INBEGREPEN (" + noteCount + " ingevuld)" : "STANDAARD UIT (" + noteCount + " afgeschermd)") + ". Controleer afnemer en kanaal onafhankelijk; geen toestemming of grant.")) return;
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
            "  - Menselijke PRIVATE notitie: " + (includePrivateNotes ? JSON.stringify(e.note || "(geen)") : "(bewust niet meegestuurd)"),
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
    if (includePrivateNotes) {
      el("shelf-all-private-notes").checked = false;
      renderDisclosurePreview();
    }
    report("REVIEW_ONLY — PRIVATE HUMAN brief van alle teams lokaal gedownload, notitieteksten " + (includePrivateNotes ? "bewust opgenomen" : "afgeschermd") + "; bronbestanden niet gewijzigd.");
  });
  sourceCopy.addEventListener("click", () => {
    if (!items.length) return report("HOLD — geen PRIVATE bronbestanden geselecteerd.");
    const includePrivateNotes = el("shelf-all-private-notes").checked;
    const noteCount = items.filter(e => e.note.length > 0).length;
    if (!confirm("PRIVATE INVENTARIS met " + items.length + " originele namen, bytes en SHA-256 van ALLE teams exporteren? PRIVATE HUMAN-notities: " + (includePrivateNotes ? "BEWUST INBEGREPEN (" + noteCount + " ingevuld)" : "STANDAARD UIT (" + noteCount + " afgeschermd)") + ". Deel alleen via een apart geauthenticeerde vertrouwelijke ontvanger. Geen toestemming of grant.")) return;
    exportJSON("lightup-scope-handoff-PRIVATE-source-inventory.json", {
      format: "lightup.scope_handoff_PRIVATE_inventory.v2", status: "REVIEW_ONLY",
      authority: { client_consent: false, operator_consent: false, grant: false, scan: false, deploy: false, release: false },
      entries: items.map((e) => ({ original_name: e.file.name, byte_length: e.file.size,
        unsigned_sha256: e.hash, structural_kind_unverified: e.inspection.kind,
        human_route: e.route, human_stage: e.stage, human_team: e.team,
        private_note_included: includePrivateNotes,
        private_human_note: includePrivateNotes ? e.note : "" })),
      warning: "PRIVATE unsigned V2 HUMAN inventory; notes omitted unless explicitly enabled. Original files and producer identity are not included or authenticated."
    });
    if (includePrivateNotes) {
      el("shelf-all-private-notes").checked = false;
      renderDisclosurePreview();
    }
    report("REVIEW_ONLY — privé broninventaris van alle teams gedownload, notitieteksten " + (includePrivateNotes ? "bewust opgenomen." : "veilig afgeschermd."));
  });
  // A completed comparison can leave a visual table even though its pending
  // proposal has already been applied. Clear those DOM nodes explicitly too.
  const scrubPrivateDOM = () => {
    pendingSelective = null;
    selectiveRows.replaceChildren();
    selectiveApply.disabled = true;
    selectiveStatus.textContent = "REVIEW_ONLY — vorige PRIVATE vergelijking gewist. Selecteer oorspronkelijke bestanden opnieuw.";
    peerPreview = null;
    peerRows.replaceChildren();
    peerApply.disabled = true;
    peerSummaryExport.disabled = true;
    peerAgenda.disabled = true;
    peerTeamAgenda.disabled = true;
    peerDraftSave.disabled = true; peerDraftOpen.disabled = true;
    peerDraftStatus.textContent = "PRIVATE conceptkeuzes gewist bij verlaten van de lokale werkruimte.";
    peerSearch.value = "";
    peerFilter.value = "all";
    peerFilterCount.textContent = "PRIVATE reviewvoorstellen uit de browser gewist.";
    peerPreviewText.textContent = "Geen actuele bronexacte reviewkeuze.";
    peerStatus.textContent = "REVIEW_ONLY — vorige PRIVATE reviewpakketten gewist.";
    lastPeerReceipt = null;
    el("shelf-peer-receipt").disabled = true;
    el("shelf-peer-receipt-note").textContent = "Geen actuele PRIVATE HUMAN retourbon.";
    lastReturnReceipt = null;
    el("shelf-return-receipt").disabled = true;
    el("shelf-return-receipt-note").textContent = "Geen actuele PRIVATE HUMAN retourbon.";
    driftRows.replaceChildren();
    driftExport.disabled = true;
  };
  resetPrivateDisclosure(); // browser form restoration is not a privacy opt-in
  render();
  renderReturnJournal();
  window.addEventListener("pageshow", event => {
    if (event.persisted) {
      resetPrivateDisclosure();
      scrubPrivateDOM();
      // The original private files are no longer in the in-tab workset.
      // Also clear all stale DOM rows upon back/forward cache restoration.
      render();
      renderReturnJournal();
      report("REVIEW_ONLY — tab heropend: vorige PRIVATE bronwerkset en HUMAN-overzichten zijn gewist. Kies originele bronnen opnieuw.");
    }
  });
  window.addEventListener("pagehide", () => {
    returnJournal.length = 0;
    lastReturnReceipt = null;
    generation++;  // never repopulate a private tab after navigation / bfcache
    resetPrivateDisclosure();
    clearReviewHistory();
    invalidateDrift();
    items.splice(0);
    scrubPrivateDOM();
    renderReturnJournal();
    render(); // never preserve source filenames, hashes or HUMAN notes in bfcache DOM
  });
})();
