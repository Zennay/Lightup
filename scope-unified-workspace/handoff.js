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
  const items = [];
  let busy = false;
  const el = (id) => document.getElementById(id);
  const input = el("shelf-files");
  const rows = el("shelf-rows");
  const message = el("shelf-status");
  const summary = el("shelf-summary");
  const sourceCopy = el("private-copy");
  const anonymousCopy = el("counts-copy");
  const SHA = (bytes) => crypto.subtle.digest("SHA-256", bytes).then((x) =>
    Array.from(new Uint8Array(x), (n) => n.toString(16).padStart(2, "0")).join(""));
  const cleanName = (name) => typeof name === "string" && name.length > 0 &&
    name.length <= 220 && !/[\x00-\x1f\x7f]/.test(name);
  const suggest = (name) => {
    const n = name.toLowerCase();
    if (n.endsWith(".lupt")) return "casebook";
    if (n.endsWith(".lucb") || n.endsWith(".luie")) return "intake";
    if (n.includes("withdraw") || n.includes("stop-")) return "stop";
    if (n.includes("readiness") && n.endsWith(".json")) return "risk";
    if (n.includes("scope-proposal") && n.endsWith(".json")) return "studio";
    return "none";
  };
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
  function render() {
    rows.replaceChildren();
    summary.textContent = items.length
      ? items.length + " PRIVATE bronbestanden · " + items.reduce((s, e) => s + e.file.size, 0).toLocaleString("nl-NL") + " bytes · alle keuzes HUMAN / REVIEW_ONLY"
      : "Nog geen PRIVATE bestanden ingeladen. Geen inhoud of bestandsnaam wordt opgeslagen.";
    for (const item of items) {
      const tr = document.createElement("tr");
      cell(tr, item.file.name, "file-name");
      cell(tr, item.file.size.toLocaleString("nl-NL") + " B");
      cell(tr, item.hash, "hash");
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
        item.route = select.value;
        render();
      });
      routeCell.append(select);
      tr.append(routeCell);
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
        items.splice(items.indexOf(item), 1);
        render();
        report("REVIEW_ONLY — bestand uit huidige lokale werkset verwijderd; bestaande schijfbestanden blijven bestaan.");
      });
      actions.append(save, remove);
      tr.append(actions);
      rows.append(tr);
    }
  }
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
    input.disabled = true;
    report("Lokale SHA-256 berekening; bestanden verlaten de browser niet…");
    try {
      const proposed = [];
      const existing = new Set(items.map((e) => e.hash));
      for (const file of chosen) {
        const hash = await SHA(await file.arrayBuffer());
        if (existing.has(hash)) throw new Error("duplicate");
        existing.add(hash);
        proposed.push({ file, hash, route: suggest(file.name) });
      }
      items.push(...proposed);  // atomic admission
      render();
      report("REVIEW_ONLY — nieuwe PRIVATE bestanden en SHA-256 lokaal geladen. Bestandsnaamhints zijn géén bronvalidatie.");
    } catch (_) {
      report("HOLD — import onvolledig of identieke inhoud al aanwezig. Hele nieuwe batch geweigerd; vorige werkset behouden.");
    } finally {
      busy = false;
      input.disabled = false;
    }
  });
  el("shelf-clear").addEventListener("click", () => {
    if (!items.length) return;
    if (!confirm("Alle PRIVATE bestandshandles uit dit tabblad wissen? Je oorspronkelijke bestanden blijven op schijf.")) return;
    items.splice(0);
    render();
    report("REVIEW_ONLY — tabblad-werkset gewist. Browser/JavaScript garanderen geen fysieke geheugenwissing.");
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
  sourceCopy.addEventListener("click", () => {
    if (!items.length) return report("HOLD — geen PRIVATE bronbestanden geselecteerd.");
    if (!confirm("PRIVATE INVENTARIS exporteren inclusief originele bestandsnamen, bytes en SHA-256? Kan klant- of projectdetails onthullen. Deel uitsluitend met bedoelde, apart geauthenticeerde ontvanger.")) return;
    exportJSON("lightup-scope-handoff-PRIVATE-source-inventory.json", {
      format: "lightup.scope_handoff_PRIVATE_inventory.v1", status: "REVIEW_ONLY",
      authority: { client_consent: false, operator_consent: false, grant: false, scan: false, deploy: false, release: false },
      entries: items.map((e) => ({ original_name: e.file.name, byte_length: e.file.size, unsigned_sha256: e.hash, human_route: e.route })),
      warning: "PRIVATE unsigned inventory, never source or recipient authentication. No file content included."
    });
    report("REVIEW_ONLY — expliciete PRIVATE ongetekende bestandsinventaris lokaal gedownload.");
  });
  render();
  window.addEventListener("pagehide", () => { items.splice(0); });
})();
