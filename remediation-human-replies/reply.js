"use strict";
/* Local-only PRIVATE human response interface. No requests or persistence. */
(() => {
  const seed = JSON.parse(document.getElementById("seed").textContent);
  const root = document.getElementById("tasks");
  const summary = document.getElementById("summary");
  const query = document.getElementById("filter");
  const message = document.getElementById("message");
  const form = document.getElementById("save-form");
  const pass = document.getElementById("password");
  const confirmation = document.getElementById("confirm");
  const rows = seed.responses.map(x => Object.assign({}, x));
  const encoder = new TextEncoder();
  const disallowed = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}]/u;
  const stages = [
    ["received_human", "Received (HUMAN only)"],
    ["working_human", "HUMAN working"],
    ["need_clarification_human", "Needs HUMAN clarification"],
    ["answered_human_only", "HUMAN answered; NOT fixed"],
    ["declined_human", "HUMAN declined"]
  ];
  let dirty = false;
  let encrypting = false;
  function notice(s) { message.textContent = s; }
  function element(tag, content) {
    const el = document.createElement(tag);
    el.textContent = content;
    return el;
  }
  function field(title, control) {
    const label = document.createElement("label");
    label.appendChild(document.createTextNode(title));
    label.appendChild(control);
    return label;
  }
  function textValid(v) {
    if (typeof v !== "string" || v.length > 240 || encoder.encode(v).length > 960) return false;
    for (const c of v) if (c !== "\n" && disallowed.test(c)) return false;
    return true;
  }
  function updateSummary() {
    summary.textContent = String(rows.length) + " original selected private HUMAN tasks · " +
      stages.map(pair => pair[1] + ": " + rows.filter(r => r.status === pair[0]).length).join(" · ") +
      " · NOT verified fixes or source identity.";
  }
  function render() {
    root.replaceChildren();
    const filter = query.value.toLocaleLowerCase().trim();
    let seen = 0;
    seed.original_items.forEach((item, i) => {
      const row = rows[i];
      const match = [item.reason, item.next_action, item.stage, row.status,
                     row.answer, row.question].join(" ").toLocaleLowerCase();
      if (filter && !match.includes(filter)) return;
      seen++;
      const card = document.createElement("article");
      card.appendChild(element("h2", "Private HUMAN request " + (i + 1)));
      card.appendChild(element("p", "Original source-redacted HUMAN reason: " + item.reason));
      card.appendChild(element("p", "Original HUMAN requested next action: " + (item.next_action || "None declared")));
      card.appendChild(element("small", "Original HUMAN state: " + item.stage +
        " · Due: " + (item.due || "unplanned") + ". No authenticated original case identity."));
      const select = document.createElement("select");
      select.setAttribute("aria-label", "HUMAN reply status " + (i + 1));
      for (const [value, title] of stages) {
        const opt = element("option", title);
        opt.value = value;
        select.appendChild(opt);
      }
      select.value = row.status;
      select.addEventListener("change", () => {
        row.status = select.value;
        dirty = true;
        notice("Private HUMAN edits are in browser memory only.");
        updateSummary();
      });
      card.appendChild(field("Recipient HUMAN-only status", select));
      for (const [key, title] of [
        ["answer", "Private HUMAN answer (NOT fix proof)"],
        ["question", "Next private HUMAN clarification question"]
      ]) {
        const area = document.createElement("textarea");
        area.value = row[key];
        area.maxLength = 240;
        area.setAttribute("aria-label", title + " " + (i + 1));
        area.addEventListener("input", () => {
          if (!textValid(area.value)) {
            notice("HOLD: HUMAN reply must be at most 240 characters/960 UTF-8 bytes without unsafe controls.");
            area.value = row[key];
            return;
          }
          row[key] = area.value;
          dirty = true;
          notice("HUMAN reply changed in memory; no network or autosave.");
        });
        card.appendChild(field(title, area));
      }
      root.appendChild(card);
    });
    if (!seen) root.appendChild(element("p", "No private HUMAN tasks match this filter."));
    updateSummary();
  }
  function b64(bytes) {
    let result = "";
    for (const value of bytes) result += String.fromCharCode(value);
    return btoa(result);
  }
  query.addEventListener("input", render);
  window.addEventListener("beforeunload", event => {
    if (!dirty) return;
    event.preventDefault();
    event.returnValue = "";
  });
  document.getElementById("reset").addEventListener("click", () => {
    if (!window.confirm("Discard all locally edited HUMAN replies? Existing downloaded files are unaffected.")) return;
    seed.responses.forEach((row, i) => Object.assign(rows[i], row));
    dirty = false;
    pass.value = "";
    confirmation.value = "";
    notice("Local HUMAN reply edits discarded.");
    render();
  });
  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (encrypting) return;
    const phrase = pass.value;
    if (phrase !== confirmation.value ||
        phrase.length < 14 || phrase.length > 256 ||
        phrase !== phrase.trim() || phrase.normalize("NFC") !== phrase ||
        disallowed.test(phrase)) {
      notice("HOLD: identical 14–256-character NFC passwords without surrounding whitespace/control characters required.");
      return;
    }
    if (rows.some(row => !stages.some(stage => stage[0] === row.status) ||
        !textValid(row.answer) || !textValid(row.question))) {
      notice("HOLD: invalid recipient HUMAN reply. No file created.");
      return;
    }
    if (rows.some(row => (row.status === "answered_human_only" && !row.answer.trim()) ||
        (row.status === "need_clarification_human" && !row.question.trim()))) {
      notice("HOLD: answered HUMAN status requires an actual answer; clarification status needs an actual question.");
      return;
    }
    if (!window.crypto || !crypto.subtle || !crypto.getRandomValues) {
      notice("HOLD: local secure Web Crypto is unavailable. There is no plaintext fallback.");
      return;
    }
    if (!window.confirm("Selected HUMAN text can still be PRIVATE. Passwords do NOT prove sender, consent, authorized disclosure or remediation. Continue only with separate actual permission?")) return;
    encrypting = true;
    try {
      notice("Encrypting locally. No server request.");
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const input = await crypto.subtle.importKey("raw", encoder.encode(phrase), "PBKDF2", false, ["deriveKey"]);
      const key = await crypto.subtle.deriveKey(
        {name: "PBKDF2", salt: salt, iterations: 600000, hash: "SHA-256"},
        input, {name: "AES-GCM", length: 256}, false, ["encrypt"]
      );
      const response = Object.assign({}, seed, {
        responses: rows.map(r => Object.assign({}, r))
      });
      delete response.original_items; // Never echo original selected private actions/notes in returned .luhr.
      const clear = encoder.encode(JSON.stringify(response));
      if (clear.length > 262144) throw new Error("PRIVATE HUMAN reply payload exceeds bound");
      const cipher = new Uint8Array(await crypto.subtle.encrypt({
        name: "AES-GCM", iv: nonce,
        additionalData: encoder.encode("LIGHTUP_PRIVATE_SOURCE_REDACTED_HUMAN_REPLY_V1")
      }, key, clear));
      const envelope = {
        kind: "lightup.private_source_redacted_human_reply_encrypted.v1",
        version: 1, disposition: "PRIVATE_HUMAN_RESPONSE_DRAFT_HOLD",
        authority_granted: false, consent_verified: false,
        source_authenticated: false, remediation_verified: false,
        warning: seed.warning, kdf: "PBKDF2-HMAC-SHA256", iterations: 600000,
        algorithm: "AES-256-GCM", salt_b64: b64(salt),
        nonce_b64: b64(nonce), ciphertext_b64: b64(cipher)
      };
      const data = encoder.encode(JSON.stringify(envelope));
      if (data.length > 400000) throw new Error("PRIVATE HUMAN encrypted reply exceeds bound");
      const url = URL.createObjectURL(new Blob([data], {type: "application/octet-stream"}));
      try {
        const link = document.createElement("a");
        link.href = url;
        link.download = "lightup-private-human-reply.luhr";
        document.body.appendChild(link);
        link.click();
        link.remove();
      } finally {
        setTimeout(() => URL.revokeObjectURL(url), 30000);
      }
      pass.value = "";
      confirmation.value = "";
      notice("Encrypted PRIVATE .luhr download requested. Verify the file before closing. No verified finding or consent is implied.");
    } catch (error) {
      notice("HOLD: failed to encrypt HUMAN reply: " + String(error.message || error));
    } finally {
      encrypting = false;
    }
  });
  render();
})();