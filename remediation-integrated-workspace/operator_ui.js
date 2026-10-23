"use strict";
(() => {
  const root = document.getElementById("operations");
  const specs = JSON.parse(root.textContent);
  const byName = new Map(specs.map(item => [item.name, item]));
  const category = document.getElementById("category");
  const search = document.getElementById("search");
  const actions = document.getElementById("actions");
  const fields = document.getElementById("fields");
  const title = document.getElementById("chosen-title");
  const purpose = document.getElementById("purpose");
  const special = document.getElementById("special");
  const command = document.getElementById("command");
  const copy = document.getElementById("copy");
  const reset = document.getElementById("reset");
  const message = document.getElementById("message");
  const primaryNames = new Set([
    "owner-encrypted-receipt", "archives", "continue-review",
    "fingerprint-compare", "inspect-archive", "receive-software"
  ]);
  let chosen = specs.find(s => s.name === "owner-encrypted-receipt") || specs[0];
  let inputElements = new Map();
  let showAll = false;
  const more = document.createElement("button");
  more.type = "button";
  more.className = "more-workflows";
  more.setAttribute("aria-controls", "actions");
  actions.after(more);
  more.addEventListener("click", () => {
    showAll = !showAll;
    renderNav();
  });

  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text != null) element.textContent = text;
    return element;
  }
  function showMessage(text, isError) {
    message.textContent = text;
    message.dataset.kind = isError ? "error" : "info";
  }
  function quotePath(value) {
    return "'" + value.replace(/'/g, "'\\''") + "'";
  }
  function allPaths() {
    const result = new Map();
    for (const field of chosen.fields) {
      const item = inputElements.get(field.flag);
      let raw = item.value;
      if (!raw.trim()) {
        if (field.required) throw Error("Verplicht: " + field.label);
        result.set(field.flag, []);
        continue;
      }
      const values = field.repeat ? raw.split(/\n/) : [raw];
      const collected = [];
      for (const value of values) {
        if (field.repeat && value === "") continue;
        if (value !== value.trim()) throw Error("Geen spaties rondom paden: " + field.flag);
        if (!value.startsWith("/") || value.startsWith("//") ||
            value.includes("\r") || value.includes("\0") || /[\x00-\x1f\x7f]/.test(value)) {
          throw Error("Gebruik een letterlijk absoluut Linux-pad: " + field.flag);
        }
        if (value.split("/").includes("..") || value.split("/").includes(".")) {
          throw Error("Gebruik geen . of .. als padsegment: " + field.flag);
        }
        if (value.length > 1024) throw Error("Pad te lang: " + field.flag);
        collected.push(value);
      }
      if (collected.length > 12) throw Error("Maximaal 12 originele paden bij " + field.flag);
      if (field.required && !collected.length) throw Error("Verplicht: " + field.label);
      result.set(field.flag, collected);
    }
    const vals = key => result.get(key) || [];
    if (chosen.name.startsWith("owner") &&
        !vals("--input-dir").length && !vals("--bundle").length) {
      throw Error("Selecteer minstens één echt oorspronkelijk evidencepakket.");
    }
    if (chosen.name === "archives" &&
        !vals("--archive").length && !vals("--encrypted-archive").length) {
      throw Error("Selecteer minstens één daadwerkelijk ontvangen oorspronkelijk archief.");
    }
    if (chosen.name === "archives" &&
        Boolean(vals("--archive").length) === Boolean(vals("--encrypted-archive").length)) {
      throw Error("Kies originele .luhz OF versleutelde .luhx, niet beide: de native ontvangst weigert gemengde invoer.");
    }
    if (chosen.name === "archives" &&
        (vals("--archive").some(x => !x.endsWith(".luhz")) ||
         vals("--encrypted-archive").some(x => !x.endsWith(".luhx")))) {
      throw Error("Gebruik de oorspronkelijke .luhz of .luhx bronvrije bestandstypen.");
    }
    if (["fingerprint-create", "fingerprint-compare"].includes(chosen.name)) {
      const packets = vals("--packet");
      if (packets.length > 8 || new Set(packets).size !== packets.length ||
          packets.some(path => ![".luhx", ".luhz", ".luhp"].some(ext => path.endsWith(ext)))) {
        throw Error("Gebruik 1–8 verschillende oorspronkelijke .luhx/.luhz/.luhp bronvrije bestanden.");
      }
    }
    if (["fingerprint-archive", "receive-software", "inspect-archive"].includes(chosen.name)) {
      // Mirror original native source/recipient separation before preparing a
      // terminal command. Normalize redundant separators only for checking;
      // the command still shows exactly the operator-entered literal paths.
      const clean = path => path.replace(/\/+/g, "/").replace(/\/+$/g, "") || "/";
      const zip = clean(vals("--archive")[0]);
      const parent = zip.slice(0, zip.lastIndexOf("/")) || "/";
      const expected = vals("--expected-sha256-file")[0];
      if (expected && clean(expected) === zip) {
        throw Error("Fingerprintbestand mag niet hetzelfde zijn als het originele ZIP-bestand.");
      }
      const planned = chosen.name === "inspect-archive"
        ? [["--planned-output-dir", true], ["--planned-checksum-file", false]]
        : chosen.name === "fingerprint-archive"
          ? [["--output-file", false]] : [["--output-dir", true]];
      for (const [flag, isReceiver] of planned) {
        const proposed = vals(flag)[0];
        if (!proposed) continue;
        const destination = clean(proposed);
        if (parent === "/" || destination === zip || destination === parent ||
            destination.startsWith(parent + "/") ||
            (isReceiver &&
              (zip.startsWith(destination + "/") || destination === "/"))) {
          throw Error("Nieuwe output moet buiten de gehele oorspronkelijke software-ZIP-map blijven.");
        }
        if (flag === "--planned-checksum-file" && expected &&
            destination === clean(expected)) {
          throw Error("Het nieuwe checksum-bestand mag niet dezelfde naam hebben als de ontvangen originele checksum.");
        }
      }
      if (chosen.name === "inspect-archive") {
        const recipient = vals("--planned-output-dir")[0];
        const checksum = vals("--planned-checksum-file")[0];
        if (recipient && checksum &&
            (clean(recipient) === clean(checksum) ||
             clean(checksum).startsWith(clean(recipient) + "/") ||
             clean(recipient).startsWith(clean(checksum) + "/"))) {
          throw Error("Geplande softwareontvangst en checksum moeten gescheiden nieuwe paden gebruiken, nooit in elkaars map.");
        }
      }
    }
    if (chosen.name === "recipient" && vals("--cockpit").length > 12) {
      throw Error("Maximaal 12 echte source-free Cockpits.");
    }
    if (chosen.name === "pack-review" &&
        Boolean(vals("--journal").length) === Boolean(vals("--journal-vault").length)) {
      throw Error("Kies precies één oorspronkelijke HUMAN journalvorm.");
    }
    if (chosen.name === "owner-package" || chosen.name === "owner-encrypted" || chosen.name === "owner-encrypted-receipt") {
      const destination = vals("--output-dir")[0];
      const packet = vals("--output-file")[0];
      if (packet === destination || packet.startsWith(destination + "/")) {
        throw Error("Bronvrij pakket moet BUITEN de originele owner-map blijven.");
      }
      const extension = chosen.name === "owner-package" ? ".luhz" : ".luhx";
      if (!packet.endsWith(extension)) throw Error("Gebruik uitsluitend " + extension + " voor deze overdracht.");
      if (chosen.name === "owner-encrypted-receipt") {
        const receipt = vals("--receipt-file")[0];
        if (!receipt.endsWith(".json") || receipt === packet || receipt === destination ||
            receipt.startsWith(destination + "/") || packet.startsWith(receipt + "/") ||
            receipt.startsWith(packet + "/")) {
          throw Error("Gebruik een afzonderlijk nieuw privé .json ontvangstbewijs BUITEN de originele eigenaarmap.");
        }
      }
      const originalInputs = [...vals("--input-dir"), ...vals("--bundle")];
      if (chosen.name === "owner-encrypted-receipt") {
        const receipt = vals("--receipt-file")[0];
        if (originalInputs.some(source => receipt === source || receipt.startsWith(source + "/") || source.startsWith(receipt + "/"))) {
          throw Error("Privé hashbewijs mag de originele bronbestanden niet overschrijven of binnen hun map vallen.");
        }
      }
      if (originalInputs.some(source => packet === source ||
          packet.startsWith(source + "/") || source.startsWith(packet + "/"))) {
        throw Error("Nieuwe bronvrije output mag NOOIT in oorspronkelijke PRIVATE evidence staan.");
      }
    }
    return result;
  }

  function renderCommand() {
    command.value = "";
    copy.disabled = true;
    let values;
    try {
      values = allPaths();
    } catch (err) {
      showMessage(err.message, true);
      return;
    }
    const parts = ["python3", "remediation-integrated-workspace/private_desk.py",
                   chosen.name];
    for (const field of chosen.fields) {
      for (const path of values.get(field.flag) || []) {
        parts.push(field.flag, quotePath(path));
      }
    }
    command.value = parts.join(" \\\n  ");
    copy.disabled = false;
    showMessage("Lokaal commando voorbereid. Nog niets uitgevoerd, gedeeld of geautoriseerd.", false);
  }

  function renderNav() {
    actions.replaceChildren();
    const term = search.value.toLocaleLowerCase("nl");
    const group = category.value;
    const full = showAll || group !== "Alles" || term.length > 0;
    const hits = specs.filter(spec =>
      (full || primaryNames.has(spec.name) || spec.name === chosen.name) &&
      (group === "Alles" || spec.category === group) &&
      [spec.label, spec.name, spec.purpose, spec.category, ...spec.fields.map(f => f.label)]
        .join(" ").toLocaleLowerCase("nl").includes(term));
    more.hidden = term.length > 0 || group !== "Alles" || specs.length <= primaryNames.size;
    more.setAttribute("aria-expanded", String(showAll));
    more.textContent = showAll ? "Toon de belangrijkste acties" : "Bekijk alle " + specs.length + " acties";
    for (const item of hits) {
      const button = node("button", "action", item.label);
      button.type = "button";
      button.dataset.selected = String(item.name === chosen.name);
      button.setAttribute("aria-pressed", String(item.name === chosen.name));
      const caption = node("small", "", item.purpose);
      button.append(caption);
      button.addEventListener("click", () => select(item.name));
      actions.append(button);
    }
    if (!hits.length) actions.append(node("p", "hint", "Geen passende offline workflow."));
  }

  function select(name) {
    chosen = byName.get(name);
    inputElements = new Map();
    title.textContent = chosen.label;
    purpose.textContent = chosen.purpose;
    fields.replaceChildren();
    for (const field of chosen.fields) {
      const wrapper = node("div", "field");
      const identifier = "field-" + field.flag.slice(2);
      const label = node("label", "", field.label + (field.required ? " *" : ""));
      label.htmlFor = identifier;
      const input = document.createElement(field.repeat ? "textarea" : "input");
      input.id = identifier;
      input.name = field.flag;
      if (field.repeat) {
        input.rows = 3;
        input.placeholder = "/absolute/eerste-bron\n/absolute/tweede-bron";
      } else {
        input.type = "text";
        input.placeholder = "/absolute/privé/pad";
      }
      input.spellcheck = false;
      input.autocomplete = "off";
      input.maxLength = field.repeat ? 12288 : 1024;
      input.addEventListener("input", renderCommand);
      inputElements.set(field.flag, input);
      wrapper.append(label, input);
      wrapper.append(node("div", "micro",
        field.repeat ? "Optioneel meerdere paden: één per regel, maximaal 12."
                     : "Letterlijk absoluut pad. Laat originele bestanden ongewijzigd."));
      fields.append(wrapper);
    }
    special.textContent = chosen.name === "owner-encrypted-receipt"
      ? "Volledige oorspronkelijke PRIVATE bronhouderactie: versleutel een bronvrij .luhx pakket, schrijf afzonderlijk PRIVATE unsigned JSON-fingerprintbewijs. Niets wordt verzonden; ontvanger vergelijkt vóór decryptie met zijn werkelijk ontvangen pakket."
      : chosen.name === "owner-encrypted"
      ? "Voorkeursroute: origineel owner-evidence blijft lokaal, bronvrij .luhx wordt rechtstreeks in geheugen versleuteld. Wachtwoord alleen in privéterminal."
      : chosen.name === "owner-package"
      ? "Bronvrij .luhz blijft ONVERSLEUTELD en ONDERTEKEND: nee. Niet automatisch verzenden."
      : chosen.name === "archives"
      ? "De ontvangende native tool maakt alleen HUMAN-opvolging vanuit werkelijk ontvangen originele pakketten; geen verzonnen historie."
      : "De native tool beslist na zijn eigen volledige oorspronkelijke broncontrole of de handeling REVIEW_ONLY kan worden uitgevoerd.";
    search.value = "";
    renderNav();
    renderCommand();
  }

  for (const name of ["Alles", ...new Set(specs.map(s => s.category))]) {
    const option = document.createElement("option");
    option.value = name;
    option.textContent = name;
    category.append(option);
  }
  for (const button of document.querySelectorAll("[data-workflow]")) {
    button.addEventListener("click", () => {
      const name = button.dataset.workflow;
      if (!byName.has(name)) return;
      category.value = "Alles";
      select(name);
      const first = fields.querySelector("input,textarea");
      if (first) first.focus();
    });
  }
  category.addEventListener("change", renderNav);
  search.addEventListener("input", renderNav);
  reset.addEventListener("click", () => {
    for (const item of inputElements.values()) item.value = "";
    command.value = "";
    copy.disabled = true;
    renderCommand();
  });
  copy.addEventListener("click", async () => {
    if (!command.value) return;
    const value = command.value;
    try {
      if (!navigator.clipboard || !navigator.clipboard.writeText) throw Error("No clipboard API");
      await navigator.clipboard.writeText(value);
      showMessage("Alleen naar lokaal klembord gekopieerd. Controleer terminal en echte toestemming.", false);
    } catch (_) {
      command.focus();
      command.select();
      showMessage("Selecteer het commando en kopieer met Ctrl+C; klembordtoegang is hier uitgeschakeld.", false);
    }
  });
  // Separate read-only preview of the native 65-byte software ZIP receipt.
  // File objects never leave this browser; no fetch, upload, storage or install.
  const softwareZip = document.getElementById("software-zip");
  const softwareHash = document.getElementById("software-sha256");
  const softwareCompare = document.getElementById("software-compare");
  const softwareClear = document.getElementById("software-clear");
  const softwareResult = document.getElementById("software-result");
  let softwareGeneration = 0;
  let softwareBusy = false;
  function clearSoftwareResult(clearFiles = false) {
    softwareGeneration++;
    if (clearFiles) {
      softwareZip.value = "";
      softwareHash.value = "";
    }
    softwareResult.textContent = "Nog geen lokale bytesvergelijking. Geen bestanden verzonden.";
    softwareResult.dataset.kind = "info";
  }
  softwareZip.addEventListener("change", () => clearSoftwareResult());
  softwareHash.addEventListener("change", () => clearSoftwareResult());
  softwareClear.addEventListener("click", () => clearSoftwareResult(true));
  softwareCompare.addEventListener("click", async () => {
    if (softwareBusy) return;
    const zip = softwareZip.files && softwareZip.files[0];
    const receipt = softwareHash.files && softwareHash.files[0];
    if (!zip || !receipt || !zip.name.endsWith(".zip") ||
        !receipt.name.endsWith(".sha256") ||
        !Number.isSafeInteger(zip.size) || zip.size < 1 || zip.size > 15000000 ||
        receipt.size !== 65) {
      softwareResult.textContent = "HOLD: kies precies één ZIP van 1–15.000.000 bytes en één originele .sha256 van exact 65 bytes.";
      softwareResult.dataset.kind = "error";
      return;
    }
    if (!window.crypto || !window.crypto.subtle ||
        typeof window.crypto.subtle.digest !== "function") {
      softwareResult.textContent = "HOLD: lokale WebCrypto SHA-256 niet beschikbaar. Gebruik de native inspect-archive-opdracht; geen upload of fallback.";
      softwareResult.dataset.kind = "error";
      return;
    }
    const generation = ++softwareGeneration;
    softwareBusy = true;
    softwareCompare.disabled = true;
    softwareResult.dataset.kind = "info";
    softwareResult.textContent = "PRIVATE bestanden uitsluitend lokaal lezen en vergelijken…";
    try {
      const signature = new Uint8Array(await receipt.arrayBuffer());
      if (signature.length !== 65 || signature[64] !== 10 ||
          !Array.from(signature.slice(0, 64)).every(b =>
            b >= 48 && b <= 57 || b >= 97 && b <= 102)) {
        throw Error("receipt-format");
      }
      const expected = String.fromCharCode(...signature.slice(0, 64));
      const bytes = await zip.arrayBuffer();
      if (bytes.byteLength !== zip.size || bytes.byteLength > 15000000) {
        throw Error("zip-changed");
      }
      const hash = Array.from(
        new Uint8Array(await window.crypto.subtle.digest("SHA-256", bytes)),
        b => b.toString(16).padStart(2, "0")).join("");
      if (generation !== softwareGeneration) return;
      if (hash !== expected) {
        softwareResult.textContent = "HOLD: SHA-256 van ontvangen ZIP wijkt af van het afzonderlijke checksum-bestand. Niet installeren of stilzwijgend vervangen.";
        softwareResult.dataset.kind = "error";
      } else {
        softwareResult.textContent = "REVIEW_ONLY: oorspronkelijke ZIP en 65-byte checksum zijn lokaal byte-gelijk volgens SHA-256 (" +
          zip.size + " bytes). Voer de afzonderlijke native bron-/ZIP-controle uit; geen afzender- of toestemmingbewijs.";
        softwareResult.dataset.kind = "info";
      }
    } catch (_) {
      if (generation === softwareGeneration) {
        softwareResult.textContent = "HOLD: lokale SHA-256 of originele checksumindeling ongeldig. Geen gedeeltelijke goedkeuring.";
        softwareResult.dataset.kind = "error";
      }
    } finally {
      softwareBusy = false;
      softwareCompare.disabled = false;
    }
  });

  select(chosen.name);
})();
