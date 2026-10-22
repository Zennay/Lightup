/* Source-free LightUp PRIVATE HUMAN owner reply editor.
 * HUMAN proposals only. Original native strict admission remains mandatory.
 * No remote I/O, persistence, permissions, grants, scanner or dispatch.
 */
(() => {
  "use strict";
  const $ = name => document.getElementById(name);
  const MAX = 1048576;
  const SHA256_K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ]);
  function sha256Fallback(bytes) {
    const length = Math.ceil((bytes.length + 9) / 64) * 64;
    const padded = new Uint8Array(length);
    padded.set(bytes);
    padded[bytes.length] = 0x80;
    const view = new DataView(padded.buffer);
    view.setUint32(length - 8, Math.floor(bytes.length / 0x20000000), false);
    view.setUint32(length - 4, (bytes.length * 8) >>> 0, false);
    const state = new Uint32Array([
      0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
      0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    ]);
    const words = new Uint32Array(64);
    const rotate = (x,n) => (x >>> n) | (x << (32 - n));
    for (let offset = 0; offset < length; offset += 64) {
      for (let i = 0; i < 16; i++) words[i] = view.getUint32(offset + i * 4, false);
      for (let i = 16; i < 64; i++) {
        const x = words[i - 15], y = words[i - 2];
        const s0 = rotate(x,7) ^ rotate(x,18) ^ (x >>> 3);
        const s1 = rotate(y,17) ^ rotate(y,19) ^ (y >>> 10);
        words[i] = (words[i - 16] + s0 + words[i - 7] + s1) >>> 0;
      }
      let a=state[0], b=state[1], c=state[2], d=state[3];
      let e=state[4], f=state[5], g=state[6], h=state[7];
      for (let i = 0; i < 64; i++) {
        const s1 = rotate(e,6) ^ rotate(e,11) ^ rotate(e,25);
        const choose = (e & f) ^ (~e & g);
        const t1 = (h + s1 + choose + SHA256_K[i] + words[i]) >>> 0;
        const s0 = rotate(a,2) ^ rotate(a,13) ^ rotate(a,22);
        const majority = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (s0 + majority) >>> 0;
        h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
      }
      state[0]=(state[0]+a)>>>0; state[1]=(state[1]+b)>>>0;
      state[2]=(state[2]+c)>>>0; state[3]=(state[3]+d)>>>0;
      state[4]=(state[4]+e)>>>0; state[5]=(state[5]+f)>>>0;
      state[6]=(state[6]+g)>>>0; state[7]=(state[7]+h)>>>0;
    }
    return Array.from(state, word => word.toString(16).padStart(8,'0')).join('');
  }
  async function sha256Hex(buffer) {
    if (globalThis.crypto && globalThis.crypto.subtle) {
      try {
        const digest = await globalThis.crypto.subtle.digest('SHA-256', buffer);
        return {hex:Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2,'0')).join(''),
          method:'Web Crypto SHA-256'};
      } catch (_) {}
    }
    return {hex:sha256Fallback(new Uint8Array(buffer)), method:'portable local SHA-256'};
  }
  const KEYS = ["schema", "authority", "historical_only", "sources_reopened",
    "recipient_authenticated", "consent_assumed", "actions_dispatched",
    "appointments_booked", "verified_remediation", "proposed_human_owner_label",
    "original_source_portfolio_sha256", "original_source_meeting_sha256",
    "original_review_return_sha256", "human_rows_only_for_selected_owner"];
  const ROW_KEYS = ["local_case", "historical_transition", "original_kit",
    "original_human_priority", "original_proposed_day", "human_review_stage",
    "original_private_human_next_step", "private_human_meeting_note"];
  const AUTH_KEYS = ["authorization", "consent", "verified_finding",
    "release_approval"];
  const STAGES = ["needs_discussion", "proposed_followup", "hold"];
  const CSV_KEYS = ["local_case", "historical_transition", "original_kit",
    "original_owner_packet_sha256", "human_reply_stage", "private_reply_note"];
  let original = null, sha = "", rows = [], dirty = false;
  const exact = (o, keys) => o && typeof o === "object" &&
    !Array.isArray(o) && Object.keys(o).length === keys.length &&
    keys.every(k => Object.prototype.hasOwnProperty.call(o, k));
  const hash = s => typeof s === "string" && /^[a-f0-9]{64}$/.test(s);
  const status = value => { $("status").textContent = value; };
  const hold = value => status("PRIVATE HOLD: " + value);
  const allowed = s => typeof s === "string" && s.length <= 240 &&
    !/[\x00-\x1f\x7f]/.test(s) && !/^\s*[=+@-]/.test(s);
  function verify(doc) {
    if (!exact(doc, KEYS) ||
      doc.schema !== "lightup.private.workspace-ledger-human-owner-handoff.v1" ||
      !exact(doc.authority, AUTH_KEYS) ||
      !AUTH_KEYS.every(k => doc.authority[k] === false) ||
      doc.historical_only !== true ||
      !["sources_reopened", "recipient_authenticated", "consent_assumed",
        "actions_dispatched", "appointments_booked", "verified_remediation"
      ].every(k => doc[k] === false) ||
      !hash(doc.original_source_portfolio_sha256) ||
      !hash(doc.original_source_meeting_sha256) ||
      !hash(doc.original_review_return_sha256) ||
      typeof doc.proposed_human_owner_label !== "string" ||
      !doc.proposed_human_owner_label || doc.proposed_human_owner_label.length > 80 ||
      !Array.isArray(doc.human_rows_only_for_selected_owner) ||
      !doc.human_rows_only_for_selected_owner.length ||
      doc.human_rows_only_for_selected_owner.length > 2048) {
      throw Error("Unknown HUMAN owner packet authority/schema");
    }
    const identities = new Set();
    for (const row of doc.human_rows_only_for_selected_owner) {
      if (!exact(row, ROW_KEYS)) throw Error("Unknown original owner row");
      const id = [row.local_case, row.historical_transition, row.original_kit];
      if (id.some(v => !Number.isInteger(v)) || id[0] < 1 || id[0] > 8 ||
        id[1] < 1 || id[1] > 11 || id[2] < 1 || id[2] > 12) {
        throw Error("Out-of-range original owner row");
      }
      const literal = id.join(":");
      if (identities.has(literal)) throw Error("Duplicate original owner row");
      identities.add(literal);
      if (!STAGES.includes(row.human_review_stage) ||
        !["human_urgent", "near_term", "routine", "unset"].includes(row.original_human_priority) ||
        typeof row.original_proposed_day !== "string" ||
        row.original_proposed_day.length > 10 ||
        !allowed(row.original_private_human_next_step) ||
        !allowed(row.private_human_meeting_note)) {
        throw Error("Invalid private original HUMAN proposal");
      }
    }
  }
  function clear() {
    original = null; sha = ""; rows = []; dirty = false;
    $("workroom").hidden = true;
    $("cards").replaceChildren();
    $("owner").textContent = ""; $("totals").textContent = "";
    status("Choose original local PRIVATE-HUMAN-owner.json. No network will be used.");
  }
  function make(tag, value, className) {
    const element = document.createElement(tag);
    if (value !== undefined) element.textContent = String(value);
    if (className) element.className = className;
    return element;
  }
  function render() {
    const search = $("search").value.trim().toLocaleLowerCase();
    const filter = $("stageFilter").value;
    const container = $("cards");
    container.replaceChildren();
    let displayed = 0;
    for (const row of rows) {
      const corpus = (row.local_case + " " + row.original_human_priority + " " +
        row.original_private_human_next_step + " " +
        row.private_human_meeting_note).toLocaleLowerCase();
      if ((search && !corpus.includes(search)) ||
        (filter && row.replyStage !== filter)) continue;
      displayed++;
      const card = make("article", undefined, "card");
      card.append(make("h3", "Case " + row.local_case + " / transition " +
        row.historical_transition + " / kit " + row.original_kit));
      const meta = make("div", undefined, "facts");
      for (const [title, value] of [
        ["Original HUMAN priority", row.original_human_priority],
        ["Original HUMAN stage", row.human_review_stage],
        ["Historical proposed date", row.original_proposed_day || "none"],
        ["Original PRIVATE HUMAN next step", row.original_private_human_next_step],
        ["Original PRIVATE review note", row.private_human_meeting_note]
      ]) {
        const block = make("div", undefined, "fact");
        block.append(make("strong", title), make("span", value || "—"));
        meta.append(block);
      }
      const editor = make("div", undefined, "edit");
      const label = make("label", "My HUMAN-only proposed follow-up");
      const select = document.createElement("select");
      for (const name of STAGES) {
        const option = make("option", name.replaceAll("_", " "));
        option.value = name; select.append(option);
      }
      select.value = row.replyStage;
      select.addEventListener("change", () => {
        row.replyStage = select.value; dirty = true;
        if (filter) render(); else update();
      });
      label.append(select);
      const noteLabel = make("label", "PRIVATE HUMAN reply note (240 characters)");
      const note = document.createElement("textarea");
      note.rows = 2; note.maxLength = 240; note.value = row.replyNote;
      note.placeholder = "Discussion proposal only; no passwords, tokens or personal secrets.";
      note.addEventListener("input", () => {
        row.replyNote = note.value; dirty = true; update();
      });
      noteLabel.append(note);
      editor.append(label, noteLabel);
      card.append(meta, editor);
      container.append(card);
    }
    $("visible").textContent = displayed + " visible / " + rows.length +
      " original owner rows. All rows will be retained on export.";
    update();
  }
  function update() {
    const counts = Object.fromEntries(STAGES.map(s => [
      s, rows.filter(row => row.replyStage === s).length
    ]));
    $("totals").textContent = rows.length + " original HUMAN proposals · " +
      counts.needs_discussion + " discussion · " +
      counts.proposed_followup + " proposed follow-up · " +
      counts.hold + " HOLD · " +
      rows.filter(row => row.replyNote.length).length + " notes" +
      (dirty ? " · unsaved edits" : "");
  }
  async function load(file) {
    clear();
    if (!file || !file.size || file.size > MAX) return hold("Original private owner JSON must be 1–1048576 bytes");
    try {
      const raw = await file.arrayBuffer();
      if (raw.byteLength !== file.size) throw Error("source changed");
      const data = JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(raw));
      verify(data);
      const hashed = await sha256Hex(raw);
      sha = hashed.hex;
      original = data;
      rows = data.human_rows_only_for_selected_owner.map(row => ({
        ...row, replyStage: "needs_discussion", replyNote: ""
      }));
      $("owner").textContent = "Original proposed owner label: " +
        data.proposed_human_owner_label + ". This does NOT authenticate identity.";
      $("search").value = ""; $("stageFilter").value = ""; dirty = false;
      $("workroom").hidden = false;
      status("PRIVATE DRAFT ONLY: selected source bytes bound with " + hashed.method +
        " (" + sha.slice(0, 12) + "…). Digest is unsigned; native strict original-source admission remains mandatory.");
      render();
    } catch (_e) {
      clear();
      hold("Original owner packet is not an admissible browser preview");
    }
  }
  function parseCsv(raw) {
    const result = [], fields = [];
    let value = "", quoted = false, closed = false;
    for (let i = 0; i < raw.length; i++) {
      const c = raw[i];
      if (quoted) {
        if (c === '"') {
          if (raw[i + 1] === '"') { value += '"'; i++; }
          else { quoted = false; closed = true; }
        } else { value += c; }
      } else if (c === '"' && !value && !closed) {
        quoted = true;
      } else if (c === '"') {
        throw Error("invalid CSV quote");
      } else if (c === "," || c === "\n" || c === "\r") {
        fields.push(value); value = ""; closed = false;
        if (c !== ",") {
          if (c === "\r") {
            if (raw[i + 1] !== "\n") throw Error("invalid CSV newline");
            i++;
          }
          result.push(fields.splice(0));
        }
      } else if (closed) {
        throw Error("invalid quoted CSV field suffix");
      } else { value += c; }
    }
    if (quoted) throw Error("unclosed CSV quote");
    if (value || fields.length) { fields.push(value); result.push(fields); }
    return result;
  }
  async function restore(file) {
    if (!original || !sha || !rows.length) return hold(
      "Open original source owner packet before restoring HUMAN reply");
    if (!file || !file.size || file.size > MAX) return hold(
      "PRIVATE HUMAN reply CSV must be bounded to 1 MiB");
    try {
      const text = new TextDecoder("utf-8", {fatal:true}).decode(await file.arrayBuffer());
      const data = parseCsv(text);
      if (data.length !== rows.length + 1 ||
        data[0].length !== CSV_KEYS.length ||
        !CSV_KEYS.every((v, i) => data[0][i] === v)) throw Error("schema");
      const proposal = [];
      for (let i = 0; i < rows.length; i++) {
        const original = rows[i], selected = data[i + 1];
        if (selected.length !== CSV_KEYS.length ||
          selected[0] !== String(original.local_case) ||
          selected[1] !== String(original.historical_transition) ||
          selected[2] !== String(original.original_kit) ||
          selected[3] !== sha || !STAGES.includes(selected[4]) ||
          !allowed(selected[5])) throw Error("source mismatch");
        proposal.push({replyStage:selected[4], replyNote:selected[5]});
      }
      if (!confirm("Replace local HUMAN draft with this full exact-source CSV? " +
        "Original native finalization will still be mandatory.")) return;
      proposal.forEach((p, i) => {
        rows[i].replyStage = p.replyStage;
        rows[i].replyNote = p.replyNote;
      });
      dirty = true;
      render();
      status("PRIVATE DRAFT ONLY: original-source-bound CSV restored to local memory. " +
        "Not authenticated, finalized, scheduled or sent.");
    } catch (_e) {
      hold("HUMAN reply CSV restore refused, all existing local choices preserved");
    }
  }
  function quote(value) {
    return '"' + String(value).replaceAll('"', '""') + '"';
  }
  function download() {
    if (!original || !sha || !rows.length) return hold("No original source packet");
    const result = [CSV_KEYS.join(",")];
    for (const row of rows) {
      if (!STAGES.includes(row.replyStage) || !allowed(row.replyNote))
        return hold("Invalid HUMAN stage/note: no unsafe CSV export");
      result.push([
        row.local_case, row.historical_transition, row.original_kit,
        sha, row.replyStage, row.replyNote
      ].map(quote).join(","));
    }
    const csv = new Blob([result.join("\n") + "\n"], {type:"text/csv;charset=utf-8"});
    if (csv.size > MAX) return hold("HUMAN reply exceeds original private limit");
    const url = URL.createObjectURL(csv);
    const a = document.createElement("a");
    a.href = url; a.download = "HUMAN-owner-reply-template.csv";
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    dirty = false; update();
    status("PRIVATE REVIEW_ONLY: local browser download requested. Move CSV to trusted " +
      "0600 storage, then run original portfolio_owner_reply.py native finalizer. " +
      "No consent, grant, identity, sending or actual security finding verified.");
  }
  $("source").addEventListener("change", event => {
    void load(event.target.files && event.target.files[0]);
  });
  $("restore").addEventListener("change", event => {
    void restore(event.target.files && event.target.files[0]);
    event.target.value = "";
  });
  $("search").addEventListener("input", render);
  $("stageFilter").addEventListener("change", render);
  $("download").addEventListener("click", download);
  $("clear").addEventListener("click", () => {
    if (dirty && !confirm("Discard unsaved local HUMAN draft edits?")) return;
    $("source").value = ""; $("restore").value = ""; clear();
  });
  window.addEventListener("beforeunload", e => {
    if (dirty) { e.preventDefault(); e.returnValue = ""; }
  });
  window.addEventListener("pagehide", () => { $("source").value = ""; $("restore").value = ""; clear(); });
  clear();
})();
