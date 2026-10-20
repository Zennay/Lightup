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
      sha: "55cbef56f7ca0df32ad5fe65ea6868efc4c7ac2f1abf01ebc1e4d97b7e327edf",
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
  let accepted = null, generation = 0, extracted = new Map();

  function clear() {
    generation++;
    accepted = null;
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

  const sha = async bytes => Array.from(new Uint8Array(
    await crypto.subtle.digest("SHA-256", bytes))).map(x => x.toString(16).padStart(2,"0")).join("");

  function save(bytes, filename) {
    // Opaque local download: no auto-open or evaluation of HTML, scripts or ZIP contents.
    const url = URL.createObjectURL(new Blob([bytes], {type:"application/octet-stream"}));
    const link = document.createElement("a");
    link.href = url; link.download = filename; link.rel = "noopener";
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }

  examine.addEventListener("click", async () => {
    const current = ++generation;
    inventory.replaceChildren(); saveRow.replaceChildren(); extracted.clear();
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
      sourceInfo.textContent = "REVIEW ONLY · " + (role ? "private role " + role : "full original scope kit") +
        " · " + entries.size + " canonical members; " + admissible.length +
        " original component file(s) match pinned SHA-256. Role receipts remain unsigned; " +
        "Choose exactly the components you need to save. This does not authenticate the sender or approve any disclosure.";
    } catch (_) {
      if (current !== generation) return;
      inventory.replaceChildren(); saveRow.replaceChildren();
      sourceInfo.textContent = "HOLD — ZIP structure, role membership, size or original source identity not admitted. " +
        "Nothing can be extracted from this browser tool. Use the Python source inspector on an independently authenticated copy.";
    } finally {
      if (current === generation) examine.disabled = false;
    }
  });
})();
