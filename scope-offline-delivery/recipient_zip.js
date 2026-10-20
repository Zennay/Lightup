"use strict";
/* Original bytes only: bounded ZIP browser and explicit local saves after independent SHA match.
   This is not source authentication, client consent, scope approval or safe-to-execute inspection. */
(() => {
  const el = id => document.getElementById(id);
  const examine = el("examine-archive"), inventory = el("archive-inventory");
  const panel = el("archive-panel"), saveRow = el("safe-downloads");
  const sourceInfo = el("archive-summary");
  const selections = [
    { path: "workspace/LightUp-Scope-Offline-DRAFT-HOLD.zip", title: "Original offline scope workspace (ZIP)",
      sha: "60f9086490ecb00d725ae00da173ee6eb843de9d346d4c39b5f4a51a359703de",
      name: "LightUp-Scope-Offline-DRAFT-HOLD.zip" },
    { path: "workspace/SOURCE-MANIFEST.json", title: "Original source-bound scope manifest (JSON)",
      sha: "dc1aa82f9d335e07e142466b1e144b31f97239af4339b5b56279ee1a28235f63",
      name: "LightUp-Scope-SOURCE-MANIFEST.json" },
    { path: "workspace/DIST-MANIFEST.json", title: "Original offline delivery manifest (JSON)",
      sha: "c8cb4d972d4822939bc542c6b292f72e5e246d772ed32587d3a9ed4fed1f629d",
      name: "LightUp-Scope-DIST-MANIFEST.json" },
    { path: "workspace/verify.html", title: "Original offline source byte verifier (HTML)",
      sha: "d1d0d2ca5a53599d2dc85589c58a4af6eddf7528cb519498185943a5718723c5",
      name: "LightUp-Scope-Source-Verify.html" },
    { path: "courier/PRIVATE-encrypted-courier.html", title: "Original encrypted HUMAN courier (offline HTML)",
      sha: "55cbef56f7ca0df32ad5fe65ea6868efc4c7ac2f1abf01ecb1e4d97b7e327edf",
      name: "PRIVATE-encrypted-courier.html" },
    { path: "privacy/disclosure-preflight.html", title: "Original manual PRIVATE disclosure desk (offline HTML)",
      sha: "d23b51b73b39c994edbb681e20b7e501bd037be366488870470bfe68ef34bb24",
      name: "PRIVATE-disclosure-preflight.html" },
    { path: "privacy/disclosure-recipient-verify.html", title: "Original recipient redacted-text review (offline HTML)",
      sha: "a3b48236e0b297f1a903f2d02ba8fdedf4ea63b03109089a96f116cab1011483",
      name: "PRIVATE-disclosure-recipient-verify.html" },
  ];
  const roleBase = ["PRIVATE-ROLE-START-HERE.html", "PRIVATE-ROLE-README.txt",
    "PRIVATE-ROLE-RECEIPT.json", "tools/role_pack.py"];
  const profiles = {
    "privacy-recipient": ["courier/PRIVATE-encrypted-courier.html", "privacy/disclosure-recipient-verify.html"],
    "privacy-editor": ["courier/PRIVATE-encrypted-courier.html", "privacy/disclosure-preflight.html", "privacy/disclosure-recipient-verify.html"],
    "scope-reviewer": ["workspace/LightUp-Scope-Offline-DRAFT-HOLD.zip", "workspace/SOURCE-MANIFEST.json", "workspace/DIST-MANIFEST.json", "workspace/verify.html"],
  };
  let accepted = null, acceptedSha = null, generation = 0, extracted = new Map();
  const saveInspection = el("save-inspection-receipt");
  let localInspection = null;

  function clear() {
    generation++;
    accepted = null;
    acceptedSha = null;
    localInspection = null;
    saveInspection.hidden = true;
    extracted.clear();
    inventory.replaceChildren();
    saveRow.replaceChildren();
    sourceInfo.textContent = "";
    panel.hidden = true;
    examine.disabled = true;
  }
  document.addEventListener("lightup:selection-reset", clear);
  document.addEventListener("lightup:byte-match", event => {
    clear();
    const detail = event.detail;
    if (!detail || !(detail.bytes instanceof ArrayBuffer) ||
        detail.bytes.byteLength > 2500000 || !detail.name ||
        !/\.zip$/i.test(detail.name)) return;
    accepted = detail.bytes;
    acceptedSha = detail.sha256;
    panel.hidden = false;
    examine.disabled = false;
    sourceInfo.textContent = "Source bytes matched an independently supplied SHA-256. Inspect the local ZIP directory before saving files; this remains REVIEW ONLY.";
  });

  const view = bytes => new DataView(bytes);
  const text = (bytes, offset, length) => {
    try {
      return new TextDecoder("utf-8", {fatal: true}).decode(new Uint8Array(bytes, offset, length));
    } catch (_) {
      throw Error("Non-canonical ZIP UTF-8 name");
    }
  };
  function checkName(name) {
    if (!name || name.startsWith("/") || name.includes("\\") ||
        name.includes(":") || /[\x00-\x1f\x7f]/.test(name) ||
        name.split("/").some(part => !part || part === "." || part === "..")) {
      throw Error("Unsafe file name in archive");
    }
  }

  function parseStoredZip(bytes) {
    const dv = view(bytes);
    if (dv.byteLength < 22 || dv.byteLength > 2500000) throw Error("Archive size outside supported bounds");
    // Builder uses deterministic comment-free, single-disk and ZIP64-free stored ZIP.
    const eocd = dv.byteLength - 22;
    if (dv.getUint32(eocd, true) !== 0x06054b50 || dv.getUint16(eocd + 20, true) !== 0 ||
        dv.getUint16(eocd + 4, true) !== 0 || dv.getUint16(eocd + 6, true) !== 0) {
      throw Error("Unsupported ZIP central-directory footer");
    }
    const count = dv.getUint16(eocd + 10, true);
    const countDisk = dv.getUint16(eocd + 8, true);
    const dirBytes = dv.getUint32(eocd + 12, true);
    const dirStart = dv.getUint32(eocd + 16, true);
    if (count !== countDisk || count < 1 || count > 64 ||
        dirStart + dirBytes !== eocd || dirStart > eocd) {
      throw Error("Invalid, multi-disk, oversized or incomplete ZIP directory");
    }
    let cursor = dirStart;
    const seen = new Set(), entries = new Map(), regions = [];
    for (let i = 0; i < count; ++i) {
      if (cursor + 46 > eocd || dv.getUint32(cursor, true) !== 0x02014b50) {
        throw Error("Malformed ZIP directory entry");
      }
      const flags = dv.getUint16(cursor + 8, true), method = dv.getUint16(cursor + 10, true);
      const compressed = dv.getUint32(cursor + 20, true), size = dv.getUint32(cursor + 24, true);
      const nameLen = dv.getUint16(cursor + 28, true), extraLen = dv.getUint16(cursor + 30, true);
      const commentLen = dv.getUint16(cursor + 32, true), startDisk = dv.getUint16(cursor + 34, true);
      const outerType = dv.getUint32(cursor + 38, true);
      const local = dv.getUint32(cursor + 42, true);
      const end = cursor + 46 + nameLen + extraLen + commentLen;
      if (end > eocd || !nameLen || nameLen > 180 || compressed !== size ||
          compressed > 2000000 || flags !== 0 || method !== 0 ||
          extraLen || commentLen || startDisk || (outerType >>> 16 & 0xf000) === 0xa000) {
        throw Error("Unsupported ZIP entry encoding, permission or size");
      }
      const name = text(bytes, cursor + 46, nameLen);
      checkName(name);
      if (seen.has(name)) throw Error("Duplicate original member name");
      seen.add(name);
      if (local + 30 > dirStart || dv.getUint32(local, true) !== 0x04034b50 ||
          dv.getUint16(local + 6, true) !== flags || dv.getUint16(local + 8, true) !== method ||
          dv.getUint32(local + 18, true) !== compressed || dv.getUint32(local + 22, true) !== size ||
          dv.getUint16(local + 26, true) !== nameLen || dv.getUint16(local + 28, true) !== 0 ||
          text(bytes, local + 30, nameLen) !== name) {
        throw Error("ZIP local header does not match central-directory identity");
      }
      const dataStart = local + 30 + nameLen;
      const dataEnd = dataStart + size;
      if (dataEnd > dirStart) throw Error("ZIP member overlaps central directory");
      regions.push([local, dataEnd]);
      entries.set(name, {name, size, bytes: new Uint8Array(bytes, dataStart, size)});
      cursor = end;
    }
    if (cursor !== eocd) throw Error("ZIP directory contains unexpected padding");
    regions.sort((a, b) => a[0] - b[0]);
    if (regions[0][0] !== 0 || regions[regions.length - 1][1] !== dirStart ||
        regions.slice(1).some((range, i) => range[0] !== regions[i][1])) {
      throw Error("Unexpected unreferenced or overlapping ZIP payload bytes");
    }
    return entries;
  }


  // Read-only strict original source member inventory for offline version diff.
  // A caller must independently verify the earlier outer ZIP SHA-256.
  document.addEventListener("lightup:strict-zip-read", event => {
    const detail = event.detail;
    if (!detail || !accepted || !acceptedSha ||
        !(detail.bytes instanceof ArrayBuffer) ||
        detail.bytes.byteLength > 2500000) return;
    detail.entries = parseStoredZip(detail.bytes);
  });

  // Match the actual deterministic Python role receipt, rather than assuming
  // that matching ZIP member names and source SHA pins authenticate a handoff.
  // Byte-canonical JSON rejects duplicate fields and alternate encodings.
  const ROLE_SCRIPT_SHA = "43d9b6e915ba991dea63572f01750ef7661261c8b505c5198609029da0894e43";
  const ROLE_HEAD = "0f76f2f90a89f5b64bc8033aa2e2ee6ec2fc49cc";
  const ROLE_AUTHORITY = ["client_consent", "deploy", "grant", "operator_consent", "release", "scan"];
  const exactKeys = (obj, keys) => obj && typeof obj === "object" && !Array.isArray(obj) &&
    Object.keys(obj).sort().join("|") === [...keys].sort().join("|");
  const validDigest = value => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
  function canonicalJSON(value, depth = 0) {
    if (value === null || typeof value !== "object") return JSON.stringify(value);
    const names = Array.isArray(value) ? value.map((_v, i) => i) : Object.keys(value).sort();
    if (!names.length) return Array.isArray(value) ? "[]" : "{}";
    const pad = "  ".repeat(depth + 1);
    const rows = names.map(key => pad + (Array.isArray(value) ? "" : JSON.stringify(key) + ": ") +
      canonicalJSON(value[key], depth + 1));
    return (Array.isArray(value) ? "[" : "{") + "\n" + rows.join(",\n") +
      "\n" + "  ".repeat(depth) + (Array.isArray(value) ? "]" : "}");
  }
  async function validateRoleReceipt(entries, profile) {
    const entry = entries.get("PRIVATE-ROLE-RECEIPT.json");
    if (!entry || entry.size < 100 || entry.size > 12000) throw Error("Role receipt is missing or too large");
    const source = new TextDecoder("utf-8", {fatal: true}).decode(entry.bytes);
    const receipt = JSON.parse(source);
    if (source !== canonicalJSON(receipt) + "\n" ||
        !exactKeys(receipt, ["format", "posture", "profile", "source_head",
          "source_outer_sha256", "authenticated_sender", "release", "authority", "files", "note"]) ||
        receipt.format !== "lightup.scope_private_role_handoff.v1" ||
        receipt.posture !== "INCUBATE_M3_M7_DRAFT_HOLD" ||
        receipt.profile !== profile || receipt.source_head !== ROLE_HEAD ||
        !validDigest(receipt.source_outer_sha256) ||
        receipt.authenticated_sender !== false || receipt.release !== false ||
        !exactKeys(receipt.authority, ROLE_AUTHORITY) ||
        !ROLE_AUTHORITY.every(field => receipt.authority[field] === false) ||
        receipt.note !== "UNSIGNED PRIVATE REVIEW ONLY; no client or operator consent or release.") {
      throw Error("Role receipt is noncanonical or contains authority claims");
    }
    const records = [...entries.values()].filter(item => item.name !== "PRIVATE-ROLE-RECEIPT.json")
      .sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
    if (!Array.isArray(receipt.files) || receipt.files.length !== records.length) {
      throw Error("Role file inventory is incomplete");
    }
    for (let i = 0; i < records.length; i++) {
      const row = receipt.files[i], item = records[i];
      if (!exactKeys(row, ["path", "bytes", "sha256"]) ||
          row.path !== item.name || !Number.isSafeInteger(row.bytes) ||
          row.bytes !== item.size || !validDigest(row.sha256) ||
          row.sha256 !== await sha(item.bytes)) {
        throw Error("Original role file differs from unsigned byte receipt");
      }
      if (item.name === "tools/role_pack.py" && row.sha256 !== ROLE_SCRIPT_SHA) {
        throw Error("Unrecognized role inspector source bytes");
      }
    }
    return {files: receipt.files, sourceOuterSha256: receipt.source_outer_sha256}; // NO identity/consent.
  }

  // Two-way local admission: use the same strict ZIP and role receipt
  // boundary before permitting a freshly browser-created role download.
  document.addEventListener("lightup:role-build-inspection", event => {
    const candidate = event.detail;
    if (!candidate || !accepted || !acceptedSha ||
        !(candidate.bytes instanceof Uint8Array) ||
        candidate.sourceSha256 !== acceptedSha ||
        !Object.hasOwn(profiles,candidate.role) ||
        !/^[0-9a-f]{64}$/.test(candidate.sha256 || "")) return;
    const revision = generation;
    candidate.check = (async () => {
      if (await sha(candidate.bytes) !== candidate.sha256) throw Error("New role SHA mismatch");
      const rows = parseStoredZip(candidate.bytes.buffer);
      const required = [...roleBase, ...profiles[candidate.role]];
      if (rows.size !== required.length || required.some(name => !rows.has(name))) {
        throw Error("New role member set differs from native profile");
      }
      const receipt = await validateRoleReceipt(rows, candidate.role);
      if (receipt.files.length !== required.length - 1) throw Error("New role receipt incomplete");
      for (const desc of selections.filter(x => profiles[candidate.role].includes(x.path))) {
        if (await sha(rows.get(desc.path).bytes) !== desc.sha) {
          throw Error("Locally created role changed a pinned original source");
        }
      }
      if (generation !== revision || !accepted || acceptedSha !== candidate.sourceSha256) {
        throw Error("Original source selection changed");
      }
      return true;
    })();
  });

  const sha = async bytes => Array.from(new Uint8Array(
    await crypto.subtle.digest("SHA-256", bytes))).map(x => x.toString(16).padStart(2,"0")).join("");

  // Explicitly revoke temporary local download URLs on navigation.
  const activeDownloadURLs = new Set();
  window.addEventListener("pagehide", () => {
    for (const url of activeDownloadURLs) URL.revokeObjectURL(url);
    activeDownloadURLs.clear();
  });

  function save(bytes, filename) {
    // Opaque local download: no auto-open or evaluation of HTML, scripts or ZIP contents.
    const url = URL.createObjectURL(new Blob([bytes], {type:"application/octet-stream"}));
    activeDownloadURLs.add(url);
    const link = document.createElement("a");
    link.href = url; link.download = filename; link.rel = "noopener";
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => { URL.revokeObjectURL(url); activeDownloadURLs.delete(url); }, 30000);
  }

  saveInspection.addEventListener("click", () => {
    if (!localInspection || !accepted || !acceptedSha || localInspection.generation !== generation) return;
    // Private byte receipt, never proof of identity, legal consent or disclosure clearance.
    const payload = {
      format: "lightup.scope_private_local_inspection.v1",
      posture: "INCUBATE_M3_M7_DRAFT_HOLD",
      decision: "REVIEW_ONLY",
      authenticated_sender: false,
      consent_granted: false,
      release_approved: false,
      profile: localInspection.profile,
      received_zip_sha256: acceptedSha,
      received_zip_bytes: accepted.byteLength,
      files: localInspection.files,
      note: "UNSIGNED PRIVATE source-byte inspection only; independently verify recipient and channel."
    };
    const bytes = new TextEncoder().encode(JSON.stringify(payload, null, 2) + "\n");
    save(bytes, "LightUp-PRIVATE-role-inspection-REVIEW-ONLY.json");
  });
  examine.addEventListener("click", async () => {
    const current = ++generation;
    inventory.replaceChildren(); saveRow.replaceChildren(); extracted.clear();
    localInspection = null; saveInspection.hidden = true;
    examine.disabled = true;
    sourceInfo.textContent = "Inspecting ZIP member layout and pinned original artifact SHA-256 locally...";
    try {
      if (!accepted) throw Error("No independently matched archive is loaded");
      if (!crypto?.subtle) throw Error("Local WebCrypto is unavailable");
      const entries = parseStoredZip(accepted);
      // The full integrated kit has all seven original sources. Smaller role
      // packets must match one exact allowlisted role inventory, not mere names.
      let role = null;
      let admittedPaths = selections.map(s => s.path);
      if (entries.has("PRIVATE-ROLE-RECEIPT.json")) {
        const found = Object.entries(profiles).filter(([_name, paths]) => {
          const expected = [...roleBase, ...paths];
          return expected.length === entries.size && expected.every(name => entries.has(name));
        });
        if (found.length !== 1) throw Error("Unknown or mixed private recipient role");
        role = found[0][0];
        admittedPaths = found[0][1];
      }
      const admissible = [];
      for (const descriptor of selections.filter(s => admittedPaths.includes(s.path))) {
        const candidate = entries.get(descriptor.path);
        if (!candidate) throw Error("Missing expected source product: " + descriptor.path);
        const hash = await sha(candidate.bytes);
        if (current !== generation) return;
        if (hash !== descriptor.sha) throw Error("Original source-pinned byte mismatch: " + descriptor.path);
        admissible.push({descriptor, candidate});
      }
      const roleFiles = role ? await validateRoleReceipt(entries, role) : null;
      if (current !== generation) return;
      for (const name of Array.from(entries.keys()).sort()) {
        const item = document.createElement("li");
        const row = entries.get(name);
        item.textContent = name + " · " + row.size.toLocaleString() + " bytes";
        inventory.append(item);
      }
      for (const {descriptor, candidate} of admissible) {
        const button = document.createElement("button");
        button.textContent = "Save " + descriptor.title;
        button.type = "button";
        // Retain only immutable Uint8Array referencing matched local copy; never execute it.
        button.addEventListener("click", () => {
          if (current !== generation || !accepted) return;
          save(candidate.bytes, descriptor.name);
        });
        saveRow.append(button);
      }
      // Browser sender may build a smaller source-only package ONLY from the
      // complete known original outer kit, never from an arbitrary role/mixed ZIP.
      const knownOuter = [
        "workspace/LightUp-Scope-Offline-DRAFT-HOLD.zip",
        "workspace/SOURCE-MANIFEST.json", "workspace/DIST-MANIFEST.json",
        "workspace/verify.html", "courier/PRIVATE-encrypted-courier.html",
        "privacy/disclosure-preflight.html", "privacy/disclosure-recipient-verify.html",
        "PRIVATE-receive.html", "tools/recipient.js", "tools/recipient.css",
        "tools/recipient_zip.js", "tools/role_builder.js", "tools/handoff_review.js", "tools/ack_return.js", "tools/version_delta.js", "tools/role_pack.py",
        "tools/recipient.template.html", "tools/package.py", "tools/unpack.py",
        "START-HERE.html", "README.txt", "manifest.json"
      ];
      if (!role && entries.size === knownOuter.length &&
          knownOuter.every(path => entries.has(path)) &&
          await sha(entries.get("tools/role_pack.py").bytes) === ROLE_SCRIPT_SHA) {
        if (current !== generation) return;
        document.dispatchEvent(new CustomEvent("lightup:full-kit-admitted",
          {detail:{entries,sha256:acceptedSha}}));
      }
      if (role && roleFiles && acceptedSha) {
        localInspection = {generation: current, profile: role, files: roleFiles.files};
        saveInspection.hidden = false;
      }
      if (role && roleFiles && acceptedSha) {
        document.dispatchEvent(new CustomEvent("lightup:received-role-admitted", {
          detail: {profile: role, sha256: acceptedSha, size: accepted.byteLength,
            sourceOuterSha256: roleFiles.sourceOuterSha256, files: roleFiles.files}
        }));
      }
      sourceInfo.textContent = "REVIEW ONLY · " + (role ? "private role " + role : "full original scope kit") +
        " · " + entries.size + " canonical members; " + admissible.length +
        " original component file(s) match pinned SHA-256. Role receipts remain unsigned; " +
        "Choose exactly the components you need to save. This does not authenticate the sender or approve any disclosure.";
    } catch (_) {
      if (current !== generation) return;
      inventory.replaceChildren(); saveRow.replaceChildren();
      localInspection = null; saveInspection.hidden = true;
      sourceInfo.textContent = "HOLD — ZIP structure, role membership, size or original source identity not admitted. " +
        "Nothing can be extracted from this browser tool. Use the Python source inspector on an independently authenticated copy.";
    } finally {
      if (current === generation) examine.disabled = false;
    }
  });
})();
