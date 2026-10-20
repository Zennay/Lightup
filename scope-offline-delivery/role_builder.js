"use strict";
/* Build native-compatible, source-only private role ZIPs in local browser memory.
   No network, recipient authentication, real consent, scan, authorization or release. */
(() => {
  const el = id => document.getElementById(id);
  const panel = el("role-builder-panel"), profile = el("role-profile");
  const buildButton = el("build-role"), saveButton = el("save-built-role");
  const status = el("role-build-status"), digestOutput = el("role-build-digest");
  const profiles = Object.freeze({
    "privacy-recipient": ["courier/PRIVATE-encrypted-courier.html", "privacy/disclosure-recipient-verify.html"],
    "privacy-editor": ["courier/PRIVATE-encrypted-courier.html", "privacy/disclosure-preflight.html", "privacy/disclosure-recipient-verify.html"],
    "scope-reviewer": ["workspace/LightUp-Scope-Offline-DRAFT-HOLD.zip", "workspace/SOURCE-MANIFEST.json", "workspace/DIST-MANIFEST.json", "workspace/verify.html"]
  });
  const sourceScript = "tools/role_pack.py", name = "PRIVATE-ROLE-START-HERE.html";
  const doc = "PRIVATE-ROLE-README.txt", receiptName = "PRIVATE-ROLE-RECEIPT.json";
  const sourceHead = "0f76f2f90a89f5b64bc8033aa2e2ee6ec2fc49cc";
  const scriptHash = "43d9b6e915ba991dea63572f01750ef7661261c8b505c5198609029da0894e43";
  const pin = Object.freeze({
    "workspace/LightUp-Scope-Offline-DRAFT-HOLD.zip": "60f9086490ecb00d725ae00da173ee6eb843de9d346d4c39b5f4a51a359703de",
    "workspace/SOURCE-MANIFEST.json": "dc1aa82f9d335e07e142466b1e144b31f97239af4339b5b56279ee1a28235f63",
    "workspace/DIST-MANIFEST.json": "c8cb4d972d4822939bc542c6b292f72e5e246d772ed32587d3a9ed4fed1f629d",
    "workspace/verify.html": "d1d0d2ca5a53599d2dc85589c58a4af6eddf7528cb519498185943a5718723c5",
    "courier/PRIVATE-encrypted-courier.html": "55cbef56f7ca0df32ad5fe65ea6868efc4c7ac2f1abf01ecb1e4d97b7e327edf",
    "privacy/disclosure-preflight.html": "d23b51b73b39c994edbb681e20b7e501bd037be366488870470bfe68ef34bb24",
    "privacy/disclosure-recipient-verify.html": "a3b48236e0b297f1a903f2d02ba8fdedf4ea63b03109089a96f116cab1011483"
  });
  const encode = value => new TextEncoder().encode(value);
  const authority = {client_consent: false, operator_consent: false, grant: false,
    scan: false, deploy: false, release: false};
  const sha = async bytes => Array.from(new Uint8Array(
    await crypto.subtle.digest("SHA-256", bytes))).map(v => v.toString(16).padStart(2, "0")).join("");
  let currentSource = null, revision = 0, built = null;
  const clear = () => {
    revision++; currentSource = null; built = null;
    buildButton.disabled = true; saveButton.hidden = true; panel.hidden = true;
    status.textContent = ""; digestOutput.textContent = "";
  };
  document.addEventListener("lightup:selection-reset", clear);
  document.addEventListener("lightup:full-kit-admitted", event => {
    clear();
    const detail = event.detail;
    if (!detail || !(detail.entries instanceof Map) ||
        typeof detail.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(detail.sha256)) return;
    currentSource = detail;
    panel.hidden = false;
    buildButton.disabled = false;
    status.textContent = "FULL SOURCE MATCH / REVIEW ONLY. Choose a least-disclosure role; no person or permission is authenticated.";
  });
  profile.addEventListener("change", () => {
    revision++; built = null; saveButton.hidden = true; digestOutput.textContent = "";
    status.textContent = "Selection changed. Build a fresh PRIVATE role file.";
  });
  const note = role => [
    "LightUp PRIVATE HUMAN scope handoff — " + role,
    "INCUBATE M3/M7 PLAN/LAB ONLY — DRAFT/HOLD — REVIEW ONLY.",
    "This bundle contains unchanged ORIGINAL source tools for exactly one human role,",
    "not access credentials, a signed receipt, proof of privacy, or permission.",
    "No bundled tool automatically contacts assets, grants work or performs scans.",
    "First verify this ENTIRE original ZIP against a SHA-256 you obtained through an",
    "authenticated, independent channel: python3 tools/role_pack.py inspect",
    "  /path/to/received.zip --expected-sha256 <64-lowercase-hex>",
    "Only then run: python3 tools/role_pack.py unpack RECEIVED.zip",
    "  PRIVATE_PARENT/NEW_DIR --expected-sha256 ROLE-ZIP-SHA256",
    "Use only a user-owned private parent; open the offline start page manually.",
    "The encrypted HUMAN courier needs a strong unique passphrase exchanged separately.",
    "A matching digest and encryption do not authenticate a sender or recipient.",
    "Human review, consent and all LightUp original release/CI/security gates remain.",
    ""
  ].join("\n");
  const landing = role => {
    const items = profiles[role].map(path => "<li><a href='" + path + "'>" + path + "</a></li>").join("");
    return "<!doctype html><html lang='en'><head><meta charset='utf-8'>" +
      "<meta name='viewport' content='width=device-width,initial-scale=1'>" +
      "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';" +
      "style-src 'unsafe-inline';connect-src 'none';object-src 'none';" +
      "frame-src 'none';form-action 'none';base-uri 'none'\">" +
      "<title>LightUp PRIVATE role handoff · DRAFT/HOLD</title>" +
      "<style>body{font:1rem/1.65 system-ui,sans-serif;max-width:760px;" +
      "margin:3rem auto;padding:1rem;background:#101b2a;color:#f2f6ff}" +
      "section{padding:1rem;border:1px solid #75839a;border-radius:10px}" +
      "a{color:#8fdaff}strong{color:#ffd09a}</style></head><body>" +
      "<h1>LightUp PRIVATE HUMAN handoff — " + role + "</h1>" +
      "<p><strong>INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.</strong></p>" +
      "<p>Verify the entire package against a separately authenticated expected " +
      "SHA-256 before extracting anything. This receipt is unsigned and proves " +
      "no sender identity, client/operator approval, recipient access or authority.</p>" +
      "<section><h2>Source-pinned original components</h2><ul>" + items + "</ul>" +
      "<p>The original files are not modified or executed automatically. " +
      "Share each only with its independently authenticated, intended reviewer.</p></section>" +
      "<p>Manual private sharing, independent client/operator consent, original " +
      "security reviews, approved scope and HUMAN GO are required before any real assessment.</p>" +
      "</body></html>";
  };
  const canonical = (value, depth = 0) => {
    if (value === null || typeof value !== "object") return JSON.stringify(value);
    const keys = Array.isArray(value) ? value.map((_v,i) => i) : Object.keys(value).sort();
    if (!keys.length) return Array.isArray(value) ? "[]" : "{}";
    const pad = "  ".repeat(depth + 1);
    const lines = keys.map(k => pad + (Array.isArray(value) ? "" : JSON.stringify(k) + ": ") +
      canonical(value[k], depth + 1));
    return (Array.isArray(value) ? "[" : "{") + "\n" + lines.join(",\n") +
      "\n" + "  ".repeat(depth) + (Array.isArray(value) ? "]" : "}");
  };
  function crc32(bytes) {
    let crc = 0xffffffff;
    for (const byte of bytes) {
      crc ^= byte;
      for (let k=0; k<8; k++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
    return (crc ^ 0xffffffff) >>> 0;
  }
  function storedZip(parts) {
    const items = [...parts].sort((a,b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
    if (!items.length || items.length > 8) throw Error("Invalid role member count");
    const dosDate = ((2026 - 1980) << 9) | (10 << 5) | 20;
    const encoder = new TextEncoder();
    let offset = 0;
    const locals = [], central = [];
    const u16 = (dv,pos,n) => dv.setUint16(pos,n,true);
    const u32 = (dv,pos,n) => dv.setUint32(pos,n>>>0,true);
    for (const [path,bytes] of items) {
      if (!/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/.test(path) ||
          !(bytes instanceof Uint8Array) || bytes.byteLength > 1_000_000) {
        throw Error("Unsafe role ZIP member");
      }
      const filename = encoder.encode(path), checksum = crc32(bytes);
      const local = new Uint8Array(30 + filename.length + bytes.byteLength);
      const lv = new DataView(local.buffer);
      u32(lv,0,0x04034b50); u16(lv,4,20); u16(lv,10,0); u16(lv,12,dosDate);
      u32(lv,14,checksum); u32(lv,18,bytes.byteLength); u32(lv,22,bytes.byteLength);
      u16(lv,26,filename.length);
      local.set(filename,30); local.set(bytes,30+filename.length);
      locals.push(local);
      const dir = new Uint8Array(46 + filename.length), dv = new DataView(dir.buffer);
      u32(dv,0,0x02014b50); u16(dv,4,0x0314); u16(dv,6,20);
      u16(dv,12,0); u16(dv,14,dosDate);
      u32(dv,16,checksum); u32(dv,20,bytes.byteLength); u32(dv,24,bytes.byteLength);
      u16(dv,28,filename.length); u32(dv,38,(0o100600 << 16)>>>0);
      u32(dv,42,offset); dir.set(filename,46); central.push(dir);
      offset += local.length;
    }
    const centralSize = central.reduce((sum,x)=>sum+x.length,0);
    const total = offset + centralSize + 22;
    if (total > 2_000_000) throw Error("Role ZIP exceeds private limit");
    const eocd = new Uint8Array(22), ev = new DataView(eocd.buffer);
    u32(ev,0,0x06054b50); u16(ev,8,items.length); u16(ev,10,items.length);
    u32(ev,12,centralSize); u32(ev,16,offset);
    const zip = new Uint8Array(total);
    let cursor = 0;
    for (const chunk of [...locals,...central,eocd]) {
      zip.set(chunk,cursor); cursor+=chunk.length;
    }
    return zip;
  }
  const save = (bytes, filename) => {
    const url = URL.createObjectURL(new Blob([bytes], {type:"application/octet-stream"}));
    const anchor = document.createElement("a");
    anchor.href = url; anchor.download = filename; anchor.rel = "noopener";
    document.body.append(anchor); anchor.click(); anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  };
  buildButton.addEventListener("click", async () => {
    const current = ++revision;
    built = null; saveButton.hidden = true;
    buildButton.disabled = true; digestOutput.textContent = "";
    try {
      if (!currentSource || !crypto?.subtle) throw Error("No verified local original kit");
      const role = profile.value;
      if (!Object.hasOwn(profiles, role)) throw Error("Unsupported role");
      const entries = currentSource.entries, outerSha = currentSource.sha256;
      const required = Object.keys(pin);
      if (required.some(key => !entries.has(key)) || !entries.has(sourceScript)) {
        throw Error("Original source set incomplete");
      }
      const original = new Map();
      for (const path of profiles[role]) {
        const bytes = entries.get(path).bytes;
        if (await sha(bytes) !== pin[path]) throw Error("Pinned original source drift: " + path);
        if (current !== revision) return;
        original.set(path,bytes);
      }
      const script = entries.get(sourceScript).bytes;
      if (await sha(script) !== scriptHash) throw Error("Unknown original native role inspector");
      if (current !== revision) return;
      const parts = new Map(original);
      parts.set(name,encode(landing(role)));
      parts.set(doc,encode(note(role)));
      parts.set(sourceScript,script);
      const rows = [];
      for (const [path,bytes] of [...parts].sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0)) {
        rows.push({path,bytes:bytes.byteLength,sha256:await sha(bytes)});
        if (current !== revision) return;
      }
      const receipt = {
        format:"lightup.scope_private_role_handoff.v1",
        posture:"INCUBATE_M3_M7_DRAFT_HOLD",
        profile:role,source_head:sourceHead,source_outer_sha256:outerSha,
        authenticated_sender:false,release:false,authority,files:rows,
        note:"UNSIGNED PRIVATE REVIEW ONLY; no client or operator consent or release."
      };
      parts.set(receiptName,encode(canonical(receipt)+"\n"));
      const archive = storedZip(parts);
      const digest = await sha(archive);
      if (current !== revision) return;
      // The SAME browser intake parser must admit every locally created role
      // before the file can be saved. Never advertise unchecked ZIP bytes.
      const handoff = {bytes:archive,role,sha256:digest,sourceSha256:outerSha,check:null};
      document.dispatchEvent(new CustomEvent("lightup:role-build-inspection", {detail:handoff}));
      if (!handoff.check || await handoff.check !== true) {
        throw Error("Locally produced role ZIP did not pass original receiver admission");
      }
      if (current !== revision) return;
      built = {bytes:archive,role,digest};
      digestOutput.textContent = "NEW local " + role + " ZIP · " + archive.length +
        " bytes · SHA-256: " + digest +
        " · source-only / unsigned / REVIEW ONLY. Exchange the digest through a separately authenticated channel.";
      status.textContent = "Private role built in local memory. Save manually; encrypt confidential handoffs in the separate original courier.";
      saveButton.hidden = false;
    } catch (_) {
      if (current === revision) {
        status.textContent = "HOLD — original source identity or browser role packaging unavailable.";
      }
    } finally {
      if (current === revision) buildButton.disabled = false;
    }
  });
  saveButton.addEventListener("click", () => {
    if (!built || !currentSource) return;
    if (!window.confirm("SAVE a SOURCE-ONLY unsigned role ZIP? This does NOT grant consent, prove identity or encrypt confidential material.")) return;
    save(built.bytes,"PRIVATE-" + built.role + "-DRAFT-HOLD.zip");
  });
})();
