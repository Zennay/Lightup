/* PRIVATE, source-free, offline HUMAN inbox discussion interface.
 * Browser previews unsigned original inbox bytes. Only strict native
 * portfolio_owner_inbox_review.py can finalize the source-bound private draft.
 * Never authenticates owner or grants permission to execute anything.
 */
(() => {
  "use strict";
  const $ = id => document.getElementById(id);
    const LIGHTUP_SHA256_K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ]);
  function lightupSha256Fallback(bytes) {
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
        const t1 = (h + s1 + choose + LIGHTUP_SHA256_K[i] + words[i]) >>> 0;
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
  async function lightupSha256Hex(buffer) {
    if (globalThis.crypto && globalThis.crypto.subtle) {
      try {
        const digest = await globalThis.crypto.subtle.digest('SHA-256', buffer);
        return {hex:Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2,'0')).join(''),
          method:'Web Crypto SHA-256'};
      } catch (_) {}
    }
    return {hex:lightupSha256Fallback(new Uint8Array(buffer)), method:'portable local SHA-256'};
  }
const MAX = 1048576;
  const SCHEMA = "lightup.private.workspace-ledger-owner-reply-inbox.v1";
  const KEYS = ["schema","authority","historical_only","sources_reopened",
    "recipient_authenticated","consent_assumed","actions_dispatched",
    "appointments_booked","verified_remediation","original_portfolio_sha256",
    "original_meeting_sha256","original_review_return_sha256",
    "original_owner_reply_packets_in_explicit_human_order"];
  const AUTH = ["authorization","consent","verified_finding","release_approval"];
  const GROUP = ["owner_label","original_owner_packet_sha256",
    "original_owner_reply_sha256","original_reply_csv_sha256","human_rows"];
  const ROW = ["local_case","historical_transition","original_kit",
    "original_proposed_human_owner","original_human_priority",
    "original_human_stage","new_human_reply_stage","private_human_reply_text"];
  const CSV = ["local_case","historical_transition","original_kit",
    "original_inbox_sha256","human_triage_stage","private_human_triage_note"];
  const STAGES = ["needs_discussion","proposed_followup","hold"];
  let source = null, sha = "", allRows = [], dirty = false;

  function exact(x, keys) {
    return x && typeof x === "object" && !Array.isArray(x) &&
      Object.keys(x).length === keys.length &&
      keys.every(k => Object.prototype.hasOwnProperty.call(x, k));
  }
  function hexdigest(x) { return typeof x === "string" && /^[a-f0-9]{64}$/.test(x); }
  function safeNote(x) {
    return typeof x === "string" && x.length <= 240 &&
      !/[\x00-\x1f\x7f]/.test(x) && !/^\s*[=+@-]/.test(x);
  }
  function message(x) { $("status").textContent = x; }
  function hold(x) { message("PRIVATE HOLD: " + x); }
  function validate(doc) {
    if (!exact(doc, KEYS) || doc.schema !== SCHEMA ||
      !exact(doc.authority, AUTH) || !AUTH.every(k => doc.authority[k] === false) ||
      doc.historical_only !== true ||
      !["sources_reopened","recipient_authenticated","consent_assumed",
        "actions_dispatched","appointments_booked","verified_remediation"
      ].every(k => doc[k] === false) ||
      !["original_portfolio_sha256","original_meeting_sha256",
        "original_review_return_sha256"].every(k => hexdigest(doc[k])) ||
      !Array.isArray(doc.original_owner_reply_packets_in_explicit_human_order) ||
      doc.original_owner_reply_packets_in_explicit_human_order.length < 1 ||
      doc.original_owner_reply_packets_in_explicit_human_order.length > 8) {
      throw Error("Not an original private HUMAN inbox");
    }
    const names = new Set(), identities = new Set(), extracted = [];
    for (const p of doc.original_owner_reply_packets_in_explicit_human_order) {
      if (!exact(p, GROUP) ||
        !["original_owner_packet_sha256","original_owner_reply_sha256",
          "original_reply_csv_sha256"].every(k => hexdigest(p[k])) ||
        typeof p.owner_label !== "string" || !p.owner_label ||
        p.owner_label.length > 80 || names.has(p.owner_label) ||
        !Array.isArray(p.human_rows) || !p.human_rows.length) {
        throw Error("Owner response group is ambiguous");
      }
      names.add(p.owner_label);
      for (const row of p.human_rows) {
        if (!exact(row, ROW)) throw Error("Unknown original HUMAN inbox slot");
        const ordinal = [row.local_case, row.historical_transition, row.original_kit];
        const key = ordinal.join(":");
        if (ordinal.some(n => !Number.isInteger(n)) || ordinal[0] < 1 ||
          ordinal[0] > 8 || ordinal[1] < 1 || ordinal[1] > 11 ||
          ordinal[2] < 1 || ordinal[2] > 12 || identities.has(key) ||
          row.original_proposed_human_owner !== p.owner_label ||
          !["human_urgent","near_term","routine","unset"].includes(row.original_human_priority) ||
          !STAGES.includes(row.original_human_stage) ||
          !STAGES.includes(row.new_human_reply_stage) ||
          !safeNote(row.private_human_reply_text)) {
          throw Error("Original source or HUMAN stage invalid");
        }
        identities.add(key);
        extracted.push({...row, triageStage:"needs_discussion", triageNote:""});
      }
    }
    if (extracted.length > 2048) throw Error("Too many original HUMAN inbox rows");
    return extracted;
  }
  function empty() {
    source = null; sha = ""; allRows = []; dirty = false;
    $("workroom").hidden = true;
    $("owner").replaceChildren(); $("cards").replaceChildren();
    $("totals").textContent = ""; $("visible").textContent = "";
    message("Select one original local PRIVATE-HUMAN-owner-inbox.json. No network.");
  }
  function el(tag, value, className) {
    const n = document.createElement(tag);
    if (value !== undefined) n.textContent = String(value);
    if (className) n.className = className;
    return n;
  }
  function update() {
    const counts = Object.fromEntries(STAGES.map(s => [
      s, allRows.filter(r => r.triageStage === s).length
    ]));
    $("totals").textContent = allRows.length + " original slots • " +
      counts.needs_discussion + " HUMAN discussion • " +
      counts.proposed_followup + " HUMAN follow-up proposed • " +
      counts.hold + " HUMAN HOLD • " +
      allRows.filter(r => r.triageNote).length + " notes" +
      (dirty ? " • local draft edited" : "");
  }
  function visibleRow(row) {
    const owner = $("ownerFilter").value;
    const stage = $("stageFilter").value;
    const query = $("query").value.trim().toLocaleLowerCase();
    if ((owner && row.original_proposed_human_owner !== owner) ||
        (stage && row.triageStage !== stage)) return false;
    const corpus = (row.local_case + " " + row.original_proposed_human_owner +
      " " + row.original_human_priority + " " +
      row.private_human_reply_text + " " + row.triageNote).toLocaleLowerCase();
    return !query || corpus.includes(query);
  }
  function render() {
    const cards = $("cards"); cards.replaceChildren();
    let visible = 0;
    for (const row of allRows) {
      if (!visibleRow(row)) continue;
      visible++;
      const card = el("article",undefined,"card");
      card.append(el("h3","Original case " + row.local_case +
        " / transition " + row.historical_transition + " / kit " + row.original_kit));
      const facts = el("div",undefined,"facts");
      for (const [title,value] of [
        ["Original proposed HUMAN owner",row.original_proposed_human_owner],
        ["Historical proposed HUMAN priority",row.original_human_priority],
        ["Original HUMAN stage",row.original_human_stage],
        ["Received HUMAN reply stage",row.new_human_reply_stage],
        ["Original PRIVATE HUMAN reply",row.private_human_reply_text || "—"]
      ]) {
        const fact = el("div",undefined,"fact");
        fact.append(el("strong",title),el("span",value));
        facts.append(fact);
      }
      const edit = el("div",undefined,"edit");
      const stageLabel = el("label","Local HUMAN discussion proposal");
      const select = el("select");
      for (const name of STAGES) {
        const opt = el("option",name.replaceAll("_"," "));
        opt.value = name; select.append(opt);
      }
      select.value = row.triageStage;
      select.addEventListener("change",() => {
        row.triageStage = select.value; dirty = true;
        if (stage) render(); else update();
      });
      stageLabel.append(select);
      const noteLabel = el("label","PRIVATE HUMAN discussion note, <=240 characters");
      const note = el("textarea");
      note.rows = 2; note.maxLength = 240; note.value = row.triageNote;
      note.placeholder = "Discussion only. Do not paste secrets or real authorization.";
      note.addEventListener("input",() => {
        row.triageNote = note.value; dirty = true; update();
      });
      noteLabel.append(note);
      edit.append(stageLabel,noteLabel);
      card.append(facts,edit); cards.append(card);
    }
    $("visible").textContent = visible + " shown / " + allRows.length +
      " original source-bound HUMAN slots. CSV always includes every row.";
    update();
  }
  async function load(file) {
    if (dirty && !confirm("Discard unsaved HUMAN inbox draft changes?")) return;
    empty();
    if (!file || !file.size || file.size > MAX) return hold(
      "Original inbox JSON must be a bounded local file");
    try {
      const raw = await file.arrayBuffer();
      if (raw.byteLength !== file.size) throw Error("Original file size changed");
      const parsed = JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(raw));
      const extracted = validate(parsed);
      sha = (await lightupSha256Hex(raw)).hex;
      source = parsed; allRows = extracted; dirty = false;
      $("ownerFilter").replaceChildren(el("option","All original owners"));
      $("ownerFilter").firstChild.value = "";
      for (const name of new Set(allRows.map(r => r.original_proposed_human_owner))) {
        const option = el("option",name); option.value = name;
        $("ownerFilter").append(option);
      }
      $("query").value = ""; $("stageFilter").value = "";
      $("workroom").hidden = false;
      message("PRIVATE HUMAN DRAFT ONLY: local original inbox SHA-256 " +
        sha.slice(0,14) + "… Native source admission remains mandatory.");
      render();
    } catch (_) {
      empty();
      hold("Selected file is not an acceptable original inbox preview");
    }
  }
  function bulkApply() {
    if (!source || !sha || !allRows.length)
      return hold("Open original HUMAN inbox before local group discussion");
    const owner = $("ownerFilter").value;
    if (!owner) return hold(
      "Select one original proposed HUMAN owner before group-stage editing");
    const stage = $("bulkStage").value;
    if (!STAGES.includes(stage)) return hold("Invalid HUMAN-only proposal stage");
    const subset = allRows.filter(visibleRow);
    if (!subset.length) return hold("No original HUMAN inbox rows match visible filters");
    if (!confirm("Change only the " + subset.length + " visible HUMAN discussion " +
      "draft stages for original owner '" + owner +
      "' to " + stage.replaceAll("_"," ") + "? " +
      "No real task, finding, authorization or grant will be changed.")) return;
    for (const row of subset) row.triageStage = stage;
    dirty = true;
    render();
    message("PRIVATE HUMAN draft: changed " + subset.length +
      " original owner discussion-stage choices. All original source rows " +
      "will still be included in source-bound CSV export. Not approved or sent.");
  }
  function csvEncode(value) {
    return '"' + String(value).replaceAll('"','""') + '"';
  }
  function exportCsv() {
    if (!source || !sha || !allRows.length) return hold("No original source inbox");
    const lines = [CSV.join(",")];
    for (const row of allRows) {
      if (!STAGES.includes(row.triageStage) || !safeNote(row.triageNote))
        return hold("Unsafe HUMAN discussion proposal: no CSV export");
      lines.push([
        row.local_case,row.historical_transition,row.original_kit,
        sha,row.triageStage,row.triageNote
      ].map(csvEncode).join(","));
    }
    const blob = new Blob([lines.join("\n")+"\n"],{type:"text/csv;charset=utf-8"});
    if (blob.size > MAX) return hold("PRIVATE source-bound CSV exceeds original bound");
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url; anchor.download = "HUMAN-inbox-review-template.csv";
    document.body.append(anchor); anchor.click(); anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url),30000);
    dirty = false; update();
    message("PRIVATE HUMAN CSV download requested. Store original bytes in 0600 " +
      "owner-private custody and use portfolio_owner_inbox_review.py. No task, " +
      "consent, permission, scan, finding or remediation was verified.");
  }
  function parseCsv(text) {
    const records = [], row = [];
    let field = "", inside = false, endquote = false;
    for (let i=0;i<text.length;i++) {
      const char = text[i];
      if (inside) {
        if (char === '"') {
          if (text[i+1] === '"') {field += '"'; i++;}
          else {inside = false; endquote = true;}
        } else field += char;
      } else if (char === '"' && !field && !endquote) inside = true;
      else if (char === '"') throw Error("invalid CSV quote");
      else if (char === "," || char === "\n" || char === "\r") {
        row.push(field); field = ""; endquote = false;
        if (char !== ",") {
          if (char === "\r") {
            if (text[i+1] !== "\n") throw Error("invalid CSV newline");
            i++;
          }
          records.push(row.splice(0));
        }
      } else if (endquote) throw Error("bad CSV field suffix");
      else field += char;
    }
    if (inside) throw Error("unterminated CSV field");
    if (field || row.length) {row.push(field); records.push(row);}
    return records;
  }
  async function restore(file) {
    if (!source || !sha || !allRows.length) return hold("Open original inbox first");
    if (!file || !file.size || file.size > MAX) return hold("Invalid bounded HUMAN CSV");
    try {
      const text = new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
      const records = parseCsv(text);
      if (records.length !== allRows.length + 1 ||
        records[0].length !== CSV.length ||
        !CSV.every((key,i) => records[0][i] === key))
        throw Error("Original HUMAN CSV schema/order mismatch");
      const proposals = [];
      for (let i=0;i<allRows.length;i++) {
        const row = allRows[i], record = records[i+1];
        if (record.length !== CSV.length ||
          record[0] !== String(row.local_case) ||
          record[1] !== String(row.historical_transition) ||
          record[2] !== String(row.original_kit) ||
          record[3] !== sha || !STAGES.includes(record[4]) ||
          !safeNote(record[5])) throw Error("Original HUMAN source slot mismatch");
        proposals.push({stage:record[4],note:record[5]});
      }
      if (!confirm("Restore complete exact-source HUMAN discussion draft locally? " +
        "No actual task or authorization will be changed.")) return;
      for (let i=0;i<allRows.length;i++) {
        allRows[i].triageStage = proposals[i].stage;
        allRows[i].triageNote = proposals[i].note;
      }
      dirty = true; render();
      message("PRIVATE HUMAN discussion draft restored to local memory. " +
        "Native finalizer still required; no external action taken.");
    } catch (_) {
      hold("Original HUMAN inbox CSV rejected; current draft choices retained");
    }
  }
  $("source").addEventListener("change",event => {
    void load(event.target.files?.[0]);
  });
  $("restore").addEventListener("change",event => {
    void restore(event.target.files?.[0]);
    event.target.value = "";
  });
  $("query").addEventListener("input",render);
  $("stageFilter").addEventListener("change",render);
  $("ownerFilter").addEventListener("change",render);
  $("bulkApply").addEventListener("click",bulkApply);
  $("download").addEventListener("click",exportCsv);
  $("clear").addEventListener("click",() => {
    if (dirty && !confirm("Discard unsaved HUMAN inbox draft edits?")) return;
    $("source").value = ""; $("restore").value = ""; empty();
  });
  window.addEventListener("beforeunload",event => {
    if (dirty) {event.preventDefault();event.returnValue = "";}
  });
  window.addEventListener("pagehide",() => {
    $("source").value = ""; $("restore").value = ""; empty();
  });
  empty();
})();
