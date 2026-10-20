/* LightUp Lab Launchpad: local memory only, no fetch/storage/scanning/dispatch. */
(() => {
  "use strict";
  const list = [];
  const max = 16;
  const input = document.getElementById("entry");
  const feedback = document.getElementById("feedback");
  const targets = document.getElementById("targets");
  const empty = document.getElementById("empty");
  const count = document.getElementById("count");
  const manifest = document.getElementById("manifest");
  const receipt = document.getElementById("receipt");

  function privateNumericAddress(hostname) {
    if (hostname.startsWith("[") && hostname.endsWith("]")) {
      const literal = hostname.slice(1, -1).toLowerCase();
      if (!/^[0-9a-f:]+$/.test(literal)) return false;
      if (literal === "::1") return true;
      const first = literal.split(":")[0];
      if (first === "") return false;
      const number = parseInt(first, 16);
      return (number & 0xfe00) === 0xfc00 || (number & 0xffc0) === 0xfe80;
    }
    if (!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname)) return false;
    const raw = hostname.split(".");
    if (raw.some(part => String(Number(part)) !== part || Number(part) > 255)) return false;
    const a = raw.map(Number);
    return a[0] === 127 || a[0] === 10 ||
      (a[0] === 172 && a[1] >= 16 && a[1] <= 31) ||
      (a[0] === 192 && a[1] === 168);
  }

  function admit(raw) {
    if (typeof raw !== "string" || raw.length < 1 || raw.length > 2048 ||
        raw !== raw.trim() || /[\x00-\x20\x7f]/.test(raw) ||
        !/^https?:\/\//.test(raw) || raw.includes("#")) {
      throw new Error("Use a printable HTTP(S) URL with no fragment or whitespace.");
    }
    let parsed;
    try { parsed = new URL(raw); } catch (_) {
      throw new Error("The URL is malformed.");
    }
    if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
        !parsed.hostname || parsed.username || parsed.password ||
        !privateNumericAddress(parsed.hostname)) {
      throw new Error("Only literal isolated private/loopback numeric lab addresses are accepted.");
    }
    // Reject URL canonicalization tricks (abbreviated, octal or hex IPv4).
    const authority = raw.match(/^https?:\/\/([^/?#]+)/);
    if (!authority || authority[1].includes("@") || authority[1].endsWith(":")) {
      throw new Error("The address or port is malformed.");
    }
    const originalHost = authority[1].startsWith("[")
      ? authority[1].match(/^\[[^\]]+\]/)?.[0]
      : authority[1].split(":")[0];
    if (!originalHost || originalHost.toLowerCase() !== parsed.hostname.toLowerCase()) {
      throw new Error("Use a canonical numeric IP literal.");
    }
    return raw;
  }

  const studioSelect = document.getElementById("studio-select");
  const studioStatus = document.getElementById("studio-status");
  const studioExport = document.getElementById("studio-export");
  const previewCommand = document.getElementById("command");
  let studio = null;

  function selectedStudio() {
    return studio?.rows.find(row => row.scenario_id === studioSelect.value) || null;
  }

  function activeStudioBinding() {
    const selected = selectedStudio();
    if (!selected) return null;
    const endpointIps = [];
    for (const endpoint of list) {
      const sourceAuthority = endpoint.match(/^https?:\/\/([^/?#]+)/)?.[1] || "";
      const port = sourceAuthority.match(/:([0-9]{1,5})$/)?.[1];
      if (!port || Number(port) < 1 || Number(port) > 65535) return null;
      let parsed;
      try { parsed = new URL(endpoint); } catch (_) { return null; }
      endpointIps.push(parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase());
    }
    const declared = selected.targets.map(value => value.toLowerCase());
    if (endpointIps.length !== declared.length ||
        new Set(endpointIps).size !== endpointIps.length ||
        new Set(declared).size !== declared.length ||
        !endpointIps.every(ip => declared.includes(ip))) return null;
    return selected;
  }

  function renderStudio() {
    const selected = selectedStudio();
    const bound = activeStudioBinding();
    if (!studio) {
      studioStatus.textContent = "No original Studio draft imported. Plain lab-batch preparation remains available.";
    } else if (!selected) {
      studioStatus.textContent = "Private Studio draft loaded. Choose one original scenario; this is not source authentication.";
    } else if (!bound) {
      studioStatus.textContent = "HOLD: the chosen Studio scenario requires exactly one explicit URL+port for each original declared lab IP. No Studio export yet.";
    } else {
      const count = bound.expected_findings === null
        ? "UNKNOWN (not zero)"
        : String(bound.expected_findings.length) + " self-declared, unverified expected findings";
      studioStatus.textContent = "Draft match: " + bound.targets.length +
        " original lab IPs, " + count +
        ". Only the original native schema, scope and byte-source checks may accept this draft.";
    }
    document.getElementById("studio-scaffold").disabled = !selected;
    studioExport.disabled = !bound;
    previewCommand.textContent = "lightup lab-assess --targets-file ./targets.txt" +
      (bound ? " --catalog-file ./studio-catalog.json --scenario-id " + bound.scenario_id : "") +
      " --preview-only";
  }

  function status(message, isError = false) {
    feedback.textContent = message;
    feedback.classList.toggle("error", isError);
  }

  function render() {
    targets.replaceChildren();
    list.forEach((url, index) => {
      const li = document.createElement("li");
      const label = document.createElement("div");
      label.className = "target-label";
      const badge = document.createElement("span");
      badge.className = "ordinal";
      badge.textContent = "#" + String(index + 1);
      const value = document.createElement("code");
      value.textContent = url;
      label.append(badge, value);
      const buttons = document.createElement("div");
      buttons.className = "buttons tight";
      for (const [action, title, disabled] of [
        ["up", "Move earlier", index === 0],
        ["down", "Move later", index === list.length - 1],
        ["remove", "Remove", false],
      ]) {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "small quiet";
        b.textContent = title;
        b.disabled = disabled;
        b.setAttribute("aria-label", title + " endpoint " + (index + 1));
        b.addEventListener("click", () => {
          if (action === "remove") list.splice(index, 1);
          if (action === "up") [list[index - 1], list[index]] = [list[index], list[index - 1]];
          if (action === "down") [list[index], list[index + 1]] = [list[index + 1], list[index]];
          render();
          status("Private planning order updated; original CLI validation remains mandatory.");
        });
        buttons.appendChild(b);
      }
      li.append(label, buttons);
      targets.appendChild(li);
    });
    count.textContent = list.length + " / " + max;
    empty.hidden = list.length !== 0;
    manifest.disabled = list.length === 0;
    receipt.disabled = list.length === 0;
    renderStudio();
  }

  function download(filename, payload, mime) {
    const blob = new Blob([payload], {type: mime});
    const address = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = address;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    // Download URL exists only briefly in memory; no browser storage.
    window.setTimeout(() => URL.revokeObjectURL(address), 6000);
  }

  document.getElementById("add").addEventListener("click", () => {
    const rows = input.value.split(/\r?\n/).map(text => text.trim()).filter(Boolean);
    if (!rows.length) { status("Enter at least one lab URL.", true); return; }
    if (rows.length + list.length > max) {
      status("The existing lab-assess CLI admits no more than 16 endpoints.", true);
      return;
    }
    const next = [];
    try {
      for (const row of rows) {
        const url = admit(row);
        if (list.includes(url) || next.includes(url)) {
          throw new Error("Duplicate URL in the proposed batch.");
        }
        next.push(url);
      }
    } catch (e) {
      status("Nothing added. " + e.message + " Review the entire input.", true);
      return;
    }
    list.push(...next);
    input.value = "";
    render();
    status(String(next.length) + " isolated lab URL(s) prepared locally. No connections made.");
  });

  document.getElementById("import").addEventListener("click", async () => {
    const picker = document.getElementById("source-file");
    const file = picker.files && picker.files[0];
    if (!file) { status("Choose a local private .txt file before importing.", true); return; }
    if (!Number.isSafeInteger(file.size) || file.size < 1 || file.size > 16384) {
      status("Nothing changed: input must be an ordinary local file of at most 16 KiB.", true);
      picker.value = "";
      return;
    }
    let proposed;
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      if (bytes.length !== file.size ||
          (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf)) {
        throw new Error("Unstable or non-original UTF-8 source encoding.");
      }
      const raw = new TextDecoder("utf-8", {fatal: true}).decode(bytes);
      if (raw.includes("\u0000")) throw new Error("NUL bytes are unsupported.");
      const rows = raw.split(/\r?\n/).map(row => row.trim())
        .filter(row => row && !row.startsWith("#"));
      if (rows.length < 1 || rows.length > max) {
        throw new Error("Source must have 1–16 non-comment isolated lab URLs.");
      }
      proposed = rows.map(admit);
      if (new Set(proposed).size !== proposed.length) {
        throw new Error("Source repeats an endpoint.");
      }
    } catch (e) {
      status("Nothing changed: entire input held. " + e.message, true);
      picker.value = "";
      return;
    }
    list.splice(0, list.length, ...proposed);
    picker.value = "";
    input.value = "";
    render();
    status(String(list.length) + " private URLs restored as a local proposed batch. No contact or authorization.");
  });

  document.getElementById("studio-import").addEventListener("click", async () => {
    const picker = document.getElementById("studio-file");
    const file = picker.files?.[0];
    if (!file) { status("Choose a private Studio JSON file first.", true); return; }
    if (!Number.isSafeInteger(file.size) || file.size < 1 || file.size > 262144) {
      status("Studio draft held: expected an existing file of at most 256 KiB.", true);
      picker.value = "";
      return;
    }
    let candidate;
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      if (bytes.length !== file.size) throw new Error("Source changed while reading.");
      const decoded = new TextDecoder("utf-8", {fatal: true}).decode(bytes);
      const catalogDoc = JSON.parse(decoded);
      const flags = ["authorized", "consent_verified", "dispatch_allowed", "release_allowed"];
      if (!catalogDoc || Array.isArray(catalogDoc) || typeof catalogDoc !== "object" ||
          catalogDoc.schema !== "lightup.lab_design_catalog.v1" ||
          catalogDoc.status !== "DRAFT_ONLY" ||
          flags.some(key => catalogDoc[key] !== false) ||
          !Array.isArray(catalogDoc.scenarios) ||
          catalogDoc.scenarios.length < 1 || catalogDoc.scenarios.length > 32) {
        throw new Error("Source is not the original Studio v1 DRAFT_ONLY format.");
      }
      const names = new Set();
      for (const row of catalogDoc.scenarios) {
        if (!row || typeof row !== "object" || Array.isArray(row) ||
            typeof row.scenario_id !== "string" ||
            !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(row.scenario_id) ||
            names.has(row.scenario_id) ||
            typeof row.name !== "string" || !Array.isArray(row.targets) ||
            !row.targets.length || row.targets.length > 16 ||
            row.targets.some(ip => typeof ip !== "string" || ip.length > 45) ||
            (row.expected_findings !== null && !Array.isArray(row.expected_findings))) {
          throw new Error("Catalog contains a noncanonical draft scenario.");
        }
        names.add(row.scenario_id);
      }
      // Preserve the *exact original bytes* for subsequent native admission.
      // Browser JSON.parse cannot reject duplicate JSON keys: Python source
      // read_selected_lab_design is mandatory and authoritative, never skipped.
      candidate = {raw: bytes, rows: catalogDoc.scenarios};
    } catch (e) {
      picker.value = "";
      status("Studio HOLD, previous private selection kept. " + e.message, true);
      return;
    }
    studio = candidate;
    studioSelect.replaceChildren();
    const prompt = document.createElement("option");
    prompt.value = "";
    prompt.textContent = "Select one original draft scenario";
    studioSelect.appendChild(prompt);
    for (const row of studio.rows) {
      const option = document.createElement("option");
      option.value = row.scenario_id;
      option.textContent = row.name.slice(0, 100) + " (" + row.scenario_id + ")";
      studioSelect.appendChild(option);
    }
    studioSelect.disabled = false;
    picker.value = "";
    renderStudio();
    status("Original Studio bytes loaded locally for human preparation; authority NOT verified.");
  });

  studioSelect.addEventListener("change", renderStudio);
  document.getElementById("studio-scaffold").addEventListener("click", () => {
    const selected = selectedStudio();
    if (!selected) { status("Choose an original draft Studio scenario first.", true); return; }
    const scheme = document.getElementById("studio-scheme").value;
    const portText = document.getElementById("studio-port").value;
    if (!["http", "https"].includes(scheme) || !/^[1-9][0-9]{0,4}$/.test(portText) ||
        Number(portText) > 65535) {
      status("Choose an explicit HTTP(S) scheme and a valid numeric port (1–65535).", true);
      return;
    }
    let prepared;
    try {
      prepared = selected.targets.map(rawIp => {
        const bracketed = rawIp.includes(":") ? "[" + rawIp + "]" : rawIp;
        return admit(scheme + "://" + bracketed + ":" + portText + "/");
      });
      if (prepared.length !== selected.targets.length ||
          new Set(prepared).size !== prepared.length) {
        throw new Error("Original scenario has duplicate or unusable lab addresses.");
      }
    } catch (e) {
      status("No batch replaced: " + e.message + " Original native validation remains required.", true);
      return;
    }
    if (list.length && !window.confirm(
      "Replace all current local lab URL entries with URLs prepared from the selected Studio draft? No network or assessment will be run."
    )) return;
    list.splice(0, list.length, ...prepared);
    input.value = "";
    render();
    status(prepared.length + " human-proposed lab URLs prepared from the original draft. No command executed, no consent inferred.");
  });



  document.getElementById("studio-clear").addEventListener("click", () => {
    studio = null;
    studioSelect.replaceChildren();
    studioSelect.disabled = true;
    document.getElementById("studio-file").value = "";
    renderStudio();
    status("Private Studio draft discarded from the offline editor memory.");
  });

  studioExport.addEventListener("click", () => {
    if (!studio || !activeStudioBinding()) return;
    download("studio-catalog.json", studio.raw, "application/json");
    status("Original Studio source bytes exported PRIVATE. The native original schema and scope gate must still admit them.");
  });

  document.getElementById("clear").addEventListener("click", () => {
    list.length = 0;
    input.value = "";
    render();
    status("All local prepared inputs cleared; no browser storage used.");
  });

  manifest.addEventListener("click", () => {
    if (!list.length) return;
    download("targets.txt", list.join("\n") + "\n", "text/plain;charset=utf-8");
    status("Private targets.txt prepared. Validate with the original lab policy before any use.");
  });

  receipt.addEventListener("click", () => {
    if (!list.length) return;
    const output = {
      schema: "lightup.lab_launchpad_aggregate.v1",
      status: "DRAFT_HOLD",
      source_count: list.length,
      preview_only: true,
      planning_not_permission: true,
      authorized: false,
      consent_verified: false,
      dispatch_allowed: false,
      release_allowed: false
    };
    download("anonymous-plan.json", JSON.stringify(output, null, 2) + "\n",
      "application/json;charset=utf-8");
    status("Counts-only anonymous planning summary prepared; not an authorization receipt.");
  });

  render();
})();
