"use strict";
/*
 * LightUp original Casebook observation companion.
 * READ-ONLY · PRIVATE · all imported statements are source-declared, not independently verified.
 * Separate from the proposed-intake source and original DomainStore/scanner/permission code.
 */
(() => {
  const SCHEMA = "lightup.auth_casebook.v1";
  const LIMIT = 512 * 1024;
  const ROW_LIMIT = 200;
  const FALSE_AUTHORITY = Object.freeze([
    "source_authenticated", "client_consent_verified", "operator_consent_verified",
    "authorization_granted", "execution_allowed", "release_approved"
  ]);
  const TOP_KEYS = Object.freeze([
    "schema", "status", "source", "as_of", "client_id", "requests", "engagements",
    "grants", "risk_approvals", "case_overview", "declared_counts", ...FALSE_AUTHORITY
  ]);
  const COUNTS = Object.freeze([
    "requests", "engagements", "grants", "risk_approvals", "grant_link_hold",
    "risk_tenant_hold", "case_attention_hold", "foreign_tenant_row_count",
    "recorded_window_review", "risk_provenance_hold", "pending_risk_review"
  ]);
  const CASE_FIELDS = Object.freeze([
    "engagement_id", "status", "grant_count", "risk_record_count", "attention", "next_review_action"
  ]);
  const VALID_HUMAN = Object.freeze({
    unreviewed: "Unreviewed (local HUMAN)",
    investigating: "Investigating (local HUMAN)",
    escalated: "Escalated (local HUMAN)",
    documented: "Documented (local HUMAN; NOT resolved)"
  });
  const $ = id => document.getElementById(id);
  let source = null;
  let human = new Map();
  let privateNotes = new Map();
  let requestHuman = new Map();
  let requestQueueUndo = null;
  let digestHex = null;
  let rawPrivateSource = null;

  // Fully recursive bounded parser: unlike a JSON.parse + stringify roundtrip,
  // each object's duplicate-key check is independent of key order and original
  // Unicode escaping. Numeric and string grammar is delegated to JSON.parse.
  function parseDuplicateSafeJson(raw) {
    let offset = 0;
    let nodes = 0;
    const whitespace = () => {
      while (offset < raw.length && /[\u0020\t\n\r]/.test(raw[offset])) offset++;
    };
    function quoted() {
      const rest = raw.slice(offset);
      const match = /^"(?:\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4})|[^"\\\u0000-\u001f])*"/u.exec(rest);
      if (!match) throw Error("Invalid JSON string or escape.");
      offset += match[0].length;
      return JSON.parse(match[0]);
    }
    function value(depth = 0) {
      if (depth > 24 || ++nodes > 18000) throw Error("Original Casebook nesting or node budget exceeded.");
      whitespace();
      const c = raw[offset];
      if (c === '"') return quoted();
      if (c === "{") {
        offset++; whitespace();
        const obj = Object.create(null);
        if (raw[offset] === "}") { offset++; return obj; }
        let count = 0;
        while (true) {
          if (++count > 2000) throw Error("Source object key budget exceeded.");
          whitespace();
          if (raw[offset] !== '"') throw Error("Invalid source object key.");
          const key = quoted();
          if (Object.hasOwn(obj, key)) throw Error("Duplicate source JSON key: ambiguous packet.");
          whitespace();
          if (raw[offset++] !== ":") throw Error("Invalid source object separator.");
          obj[key] = value(depth + 1);
          whitespace();
          if (raw[offset] === "}") { offset++; break; }
          if (raw[offset++] !== ",") throw Error("Invalid source object delimiter.");
        }
        return obj;
      }
      if (c === "[") {
        offset++; whitespace();
        const items = [];
        if (raw[offset] === "]") { offset++; return items; }
        while (true) {
          if (items.length >= 2000) throw Error("Source array exceeds parser item budget.");
          items.push(value(depth + 1)); whitespace();
          if (raw[offset] === "]") { offset++; break; }
          if (raw[offset++] !== ",") throw Error("Invalid source array delimiter.");
        }
        return items;
      }
      if (raw.startsWith("true", offset)) { offset += 4; return true; }
      if (raw.startsWith("false", offset)) { offset += 5; return false; }
      if (raw.startsWith("null", offset)) { offset += 4; return null; }
      const number = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(raw.slice(offset));
      if (!number) throw Error("Invalid source JSON literal.");
      const parsed = JSON.parse(number[0]);
      if (!Number.isFinite(parsed)) throw Error("Nonfinite numeric source input.");
      offset += number[0].length;
      return parsed;
    }
    const obj = value();
    whitespace();
    if (offset !== raw.length) throw Error("Unexpected bytes after original source JSON.");
    return obj;
  }

  const sameKeys = (value, keys) => value && typeof value === "object" &&
    !Array.isArray(value) && Object.keys(value).length === keys.length &&
    keys.every(k => Object.hasOwn(value, k));
  const textField = (v, max = 180) => typeof v === "string" &&
    v.length > 0 && v.length <= max && v === v.trim() &&
    !/[\u0000-\u001f\u007f]|\p{Cf}|\p{Cs}/u.test(v);
  const countField = (v, max = ROW_LIMIT) =>
    Number.isSafeInteger(v) && v >= 0 && v <= max;
  const riskField = v => Number.isSafeInteger(v) && v >= 0 && v <= 5;
  const linkedId = v => v === null || textField(v);
  const sourceText = (v,max = 80) => typeof v === "string" && v.length <= max &&
    !/[\u0000-\u001f\u007f]/u.test(v);
  const storedTimestamp = v => typeof v === "string" && v.length <= 80 &&
    !/[\u0000-\u001f\u007f]/u.test(v);
  const safeArray = v => Array.isArray(v) && v.length <= ROW_LIMIT;

  function inspectOriginal(doc) {
    if (!sameKeys(doc, TOP_KEYS) || doc.schema !== SCHEMA ||
        doc.status !== "REVIEW_ONLY" ||
        doc.source !== "original_persisted_domain_unverified" ||
        !textField(doc.client_id) || !textField(doc.as_of, 80) ||
        FALSE_AUTHORITY.some(k => doc[k] !== false)) {
      throw Error("HOLD: unsupported original Casebook or source asserted authority.");
    }
    if (!safeArray(doc.requests) || !safeArray(doc.engagements) ||
        !safeArray(doc.grants) || !safeArray(doc.risk_approvals) ||
        !safeArray(doc.case_overview) || !sameKeys(doc.declared_counts, COUNTS)) {
      throw Error("HOLD: original Casebook collections or counts invalid.");
    }
    if (COUNTS.some(k => !countField(doc.declared_counts[k], 2000))) {
      throw Error("HOLD: original source counts invalid.");
    }
    const ids = new Map([
      ["requests", new Set()], ["engagements", new Set()],
      ["grants", new Set()], ["risk_approvals", new Set()]
    ]);
    const accept = (category, id) => {
      if (!textField(id) || ids.get(category).has(id)) {
        throw Error("HOLD: duplicated or invalid original source identity.");
      }
      ids.get(category).add(id);
    };
    for (const r of doc.requests) {
      if (!sameKeys(r, ["request_id", "status", "requested_mode", "requested_risk", "created_at", "decision_recorded"]) ||
          !["submitted", "under_review", "approved", "rejected"].includes(r.status) ||
          !(typeof r.requested_mode === "string" && r.requested_mode.length <= 80) || !textField(r.created_at, 80) ||
          !riskField(r.requested_risk) || typeof r.decision_recorded !== "boolean") {
        throw Error("HOLD: invalid original request fields.");
      }
      accept("requests", r.request_id);
    }
    for (const r of doc.engagements) {
      if (!sameKeys(r, ["engagement_id", "status", "created_at"]) ||
          !sourceText(r.status, 80) || !textField(r.created_at, 80)) {
        throw Error("HOLD: invalid original engagement fields.");
      }
      accept("engagements", r.engagement_id);
    }
    const allowedLinks = new Set([
      "HOLD_TENANT_OR_ENGAGEMENT_MISMATCH", "HOLD_NO_REQUEST_BINDING",
      "HOLD_REQUEST_SOURCE_MISSING", "HOLD_REQUEST_NOT_APPROVED",
      "HOLD_REQUEST_SCOPE_OR_PROVENANCE_MISMATCH", "REQUEST_SCOPE_COMPATIBLE_UNVERIFIED"
    ]);
    const windows = new Set([
      "HOLD_INVALID_RECORDED_WINDOW", "EXPIRED_RECORDED_WINDOW",
      "FUTURE_RECORDED_WINDOW", "WITHIN_RECORDED_WINDOW_NOT_AUTHORITY"
    ]);
    for (const r of doc.grants) {
      if (!sameKeys(r, ["grant_id", "engagement_id", "approved_request_id",
        "request_link_observation", "max_risk", "valid_from", "valid_until", "validity_observation"]) ||
          !linkedId(r.engagement_id) || !linkedId(r.approved_request_id) ||
          !allowedLinks.has(r.request_link_observation) || !windows.has(r.validity_observation) ||
          !riskField(r.max_risk) || !storedTimestamp(r.valid_from) || !storedTimestamp(r.valid_until)) {
        throw Error("HOLD: malformed original grant source row.");
      }
      accept("grants", r.grant_id);
      if (r.engagement_id !== null && !ids.get("engagements").has(r.engagement_id)) {
        throw Error("HOLD: unresolved grant engagement reference.");
      }
    }
    const allowedRiskObservations = new Set([
      "HOLD_RISK_SOURCE_IDENTITY_OR_STATUS", "HOLD_RISK_PENDING_WITH_DECISION",
      "HOLD_RISK_DECIDER_PROVENANCE", "RISK_DECISION_PENDING_REVIEW",
      "RISK_DECISION_RECORDED_UNVERIFIED"
    ]);
    for (const r of doc.risk_approvals) {
      if (!sameKeys(r, ["approval_id", "engagement_id", "status", "requested_risk",
        "source_tenant_matches", "decision_recorded", "decision_provenance_observation"]) ||
          !linkedId(r.engagement_id) || !sourceText(r.status, 80) ||
          !riskField(r.requested_risk) ||
          typeof r.source_tenant_matches !== "boolean" ||
          typeof r.decision_recorded !== "boolean" ||
          !allowedRiskObservations.has(r.decision_provenance_observation)) {
        throw Error("HOLD: malformed original risk review row.");
      }
      if (!["pending", "approved", "denied"].includes(r.status) &&
          r.decision_provenance_observation !== "HOLD_RISK_SOURCE_IDENTITY_OR_STATUS") {
        throw Error("HOLD: unknown risk status without original provenance HOLD.");
      }
      accept("risk_approvals", r.approval_id);
      if (r.engagement_id !== null && !ids.get("engagements").has(r.engagement_id)) {
        throw Error("HOLD: unresolved risk engagement reference.");
      }
    }
    const seenCases = new Set();
    for (const c of doc.case_overview) {
      if (!sameKeys(c, CASE_FIELDS) || !ids.get("engagements").has(c.engagement_id) ||
          seenCases.has(c.engagement_id) || !sourceText(c.status, 80) ||
          !textField(c.attention, 120) || !textField(c.next_review_action, 160) ||
          !countField(c.grant_count) || !countField(c.risk_record_count)) {
        throw Error("HOLD: malformed or duplicated original case overview.");
      }
      seenCases.add(c.engagement_id);
      const eng = doc.engagements.find(x => x.engagement_id === c.engagement_id);
      if (c.status !== eng.status ||
          c.grant_count !== doc.grants.filter(x => x.engagement_id === c.engagement_id).length ||
          c.risk_record_count !== doc.risk_approvals.filter(x => x.engagement_id === c.engagement_id).length) {
        throw Error("HOLD: case overview contradicts original source relations.");
      }
    }
    if (seenCases.size !== doc.engagements.length) {
      throw Error("HOLD: missing engagement overview in original snapshot.");
    }
    const d = doc.declared_counts;
    const computed = {
      requests: doc.requests.length,
      engagements: doc.engagements.length,
      grants: doc.grants.length,
      risk_approvals: doc.risk_approvals.length,
      grant_link_hold: doc.grants.filter(g => g.request_link_observation.startsWith("HOLD_")).length,
      risk_tenant_hold: doc.risk_approvals.filter(r => !r.source_tenant_matches).length,
      case_attention_hold: doc.case_overview.filter(c => c.attention.startsWith("HOLD_")).length,
      recorded_window_review: doc.grants.filter(g =>
        g.validity_observation !== "WITHIN_RECORDED_WINDOW_NOT_AUTHORITY").length,
      risk_provenance_hold: doc.risk_approvals.filter(r =>
        r.decision_provenance_observation.startsWith("HOLD_")).length,
      pending_risk_review: doc.risk_approvals.filter(r =>
        r.decision_provenance_observation === "RISK_DECISION_PENDING_REVIEW").length
    };
    if (Object.keys(computed).some(k => d[k] !== computed[k])) {
      throw Error("HOLD: original declared counts contradict source records.");
    }
    // foreign_tenant_row_count is an original-SQL aggregate, not reconstructable
    // from privacy-reduced JSON; preserve the unverified declared aggregate only.
    return doc;
  }

  function show(text, error = false) {
    $("casebook-import-status").textContent = text;
    $("casebook-import-status").classList.toggle("danger-text", error);
  }
  function clearOriginal(confirmHuman = false) {
    if (confirmHuman && source && !confirm("Discard the PRIVATE original Casebook source and local HUMAN labels from browser memory? Your proposed scope draft will remain untouched.")) return;
    source = null;
    digestHex = null;
    rawPrivateSource = null;
    human.clear();
    privateNotes.clear();
    requestHuman.clear();
    requestQueueUndo = null;
    $("casebook-selected").hidden = true;
    $("casebook-selected").textContent = "";
    renderCases();
    show("No Casebook original source in memory. No original authorization exists in this workroom.");
  }

  function priority(c) {
    if (c.attention.startsWith("HOLD_")) return 0;
    if (c.attention.includes("RISK_")) return 1;
    if (c.attention.includes("EXPIRED") || c.attention.includes("FUTURE")) return 2;
    return 3;
  }

  function renderCases() {
    const cases = source?.case_overview || [];
    $("casebook-engagement-count").textContent = cases.length;
    $("casebook-grant-hold-count").textContent = source?.declared_counts.grant_link_hold ?? 0;
    $("casebook-risk-review-count").textContent = source ?
      source.declared_counts.risk_provenance_hold + source.declared_counts.pending_risk_review : 0;
    $("casebook-case-attention-count").textContent = source?.declared_counts.case_attention_hold ?? 0;
    renderRequestInbox();
    const query = $("casebook-filter").value.trim().toLowerCase();
    const category = $("casebook-category").value;
    const tbody = $("casebook-cases"); tbody.replaceChildren();
    for (const c of [...cases].sort((a, b) => priority(a) - priority(b))) {
      if (query && !(c.engagement_id + " " + c.attention + " " + c.next_review_action)
        .toLowerCase().includes(query)) continue;
      if (category === "hold" && !c.attention.startsWith("HOLD_")) continue;
      if (category === "risk" && !c.attention.includes("RISK_")) continue;
      if (category === "other" && (c.attention.startsWith("HOLD_") ||
          c.attention.includes("RISK_"))) continue;
      const tr = document.createElement("tr");
      for (const value of [
        c.engagement_id, c.status || "(empty stored state · HUMAN HOLD)",
        c.grant_count + " stored / " + c.risk_record_count + " risk",
        c.attention, c.next_review_action
      ]) {
        const td = document.createElement("td");
        td.textContent = String(value); tr.append(td);
      }
      const tools = document.createElement("td");
      const button = document.createElement("button"); button.type = "button";
      button.textContent = "Inspect PRIVATE original";
      button.addEventListener("click", () => inspectCase(c.engagement_id));
      tools.append(button);
      const stage = document.createElement("select");
      stage.setAttribute("aria-label", "Local HUMAN review stage for " + c.engagement_id);
      for (const [key, label] of Object.entries(VALID_HUMAN)) {
        const opt = document.createElement("option"); opt.value = key; opt.textContent = label; stage.append(opt);
      }
      stage.value = human.get(c.engagement_id) || "unreviewed";
      stage.addEventListener("change", event => {
        human.set(c.engagement_id, event.target.value);
        show("PRIVATE human stage stored only in this browser tab; no original source records changed.");
      });
      tools.append(stage);
      tr.append(tools);
      tbody.append(tr);
    }
  }

  function sourceRequests() {
    if (!source) return [];
    return source.requests.map(req => {
      const linked = source.grants.filter(g => g.approved_request_id === req.request_id);
      let attention;
      if (req.status === "approved" && !req.decision_recorded) {
        attention = "HOLD_APPROVED_BUT_DECISION_ABSENT";
      } else if (linked.some(g => g.request_link_observation.startsWith("HOLD_"))) {
        attention = "HOLD_ORIGINAL_GRANT_LINK";
      } else if (req.status === "approved" && !linked.length) {
        attention = "HUMAN_APPROVED_REQUEST_NO_GRANT_RECORD";
      } else if (req.status === "approved") {
        attention = "ORIGINAL_LINKS_RECORDED_UNVERIFIED";
      } else if (req.status === "under_review" || req.status === "submitted") {
        attention = "ORIGINAL_REQUEST_NOT_REVIEWED_TO_APPROVAL";
      } else {
        attention = "ORIGINAL_REQUEST_REJECTED_UNVERIFIED";
      }
      return {req, linked, attention};
    });
  }

  function inspectOriginalRequest(id) {
    if (!source) return;
    const item = sourceRequests().find(x => x.req.request_id === id);
    if (!item) return;
    const box = $("casebook-request-detail");
    box.replaceChildren();
    const heading = document.createElement("h3");
    heading.textContent = "PRIVATE original request " + id + " · HUMAN retrospective only";
    box.append(heading);
    const info = text => {
      const p = document.createElement("p"); p.textContent = text; box.append(p);
    };
    const {req,linked,attention} = item;
    info("Original persisted state " + req.status + "; decision recorded flag: " +
      req.decision_recorded + "; original requested mode: " + req.requested_mode +
      "; recorded risk " + req.requested_risk + ". SOURCE observation, not live consent.");
    info("Human attention: " + attention + ". The Casebook deliberately does not expose approved asset lists, so this request CANNOT be joined to your proposed target inputs.");
    for (const grant of linked) {
      info("Recorded reference grant " + grant.grant_id + " / original engagement " +
        (grant.engagement_id || "(source missing)") + ": " +
        grant.request_link_observation + ", " + grant.validity_observation +
        ", recorded max-risk " + grant.max_risk +
        ". Nothing here independently verifies permission, request asset coverage or at-use revocation.");
    }
    if (!linked.length) {
      info("No stored grant references this request in the selected source. This does NOT prove a grant does not exist at the current original database snapshot or at action time.");
    }
    box.hidden = false;
  }

  function clearRequestQueueUndo() {
    requestQueueUndo = null;
    $("undo-unbound-requests").disabled = true;
  }

  function queueUnboundRequests() {
    if (!source) {show("Load a real original PRIVATE Casebook first.",true); return;}
    const patches = sourceRequests().filter(item =>
      (item.req.status === "approved" && !item.linked.length) ||
      item.attention.startsWith("HOLD_")
    ).filter(item => !requestHuman.has(item.req.request_id) ||
      requestHuman.get(item.req.request_id) === "unreviewed"
    ).map(item => ({id:item.req.request_id,before:requestHuman.get(item.req.request_id) || null}));
    if (!patches.length) {show("No currently unreviewed original request source gaps to queue."); return;}
    if (!confirm("Mark " + patches.length +
      " ORIGINAL request source gap(s) as HUMAN investigating?\n\nThis does not validate the original client/operator, create a grant, or approve target scope.")) return;
    for (const patch of patches) requestHuman.set(patch.id,"investigating");
    requestQueueUndo = patches;
    $("undo-unbound-requests").disabled = false;
    renderRequestInbox();
    show(patches.length + " original request SOURCE gaps marked for HUMAN investigation only.");
  }

  function undoUnboundRequests() {
    if (!requestQueueUndo?.length || !source) return;
    if (requestQueueUndo.some(patch => requestHuman.get(patch.id) !== "investigating")) {
      clearRequestQueueUndo();
      show("HOLD: HUMAN request stages changed since bulk action. No stale undo applied.",true);
      return;
    }
    for (const patch of requestQueueUndo) {
      if (patch.before === null) requestHuman.delete(patch.id);
      else requestHuman.set(patch.id,patch.before);
    }
    clearRequestQueueUndo();
    renderRequestInbox();
    show("HUMAN-only request queue action reverted. Original source unchanged.");
  }

  function renderRequestInbox() {
    const tbody = $("casebook-requests"); tbody.replaceChildren();
    const query = $("request-filter").value.trim().toLowerCase();
    const category = $("request-category").value;
    const lines = sourceRequests();
    let shown = 0;
    for (const line of lines) {
      const {req,linked,attention} = line;
      if (query && !(req.request_id + " " + req.status + " " + attention).toLowerCase().includes(query)) continue;
      if (category === "unbound" && !(req.status === "approved" && !linked.length)) continue;
      if (category === "hold" && !attention.startsWith("HOLD_")) continue;
      if (category === "pending" && !["under_review","submitted","rejected"].includes(req.status)) continue;
      const tr = document.createElement("tr");
      for (const value of [
        req.request_id,
        (req.status || "(empty source status)") + (req.decision_recorded ? " / decision recorded (UNVERIFIED)" : " / no stored decision"),
        req.requested_mode + " / " + req.requested_risk,
        String(linked.length) + " stored links (NOT AUTHORITY)",
        attention
      ]) {
        const td = document.createElement("td");td.textContent=value;tr.append(td);
      }
      const td = document.createElement("td");
      const sel = document.createElement("select");
      sel.setAttribute("aria-label","Local HUMAN stage for original request " + req.request_id);
      for (const [value,label] of Object.entries(VALID_HUMAN)) {
        const opt = document.createElement("option"); opt.value=value; opt.textContent=label; sel.append(opt);
      }
      sel.value = requestHuman.get(req.request_id) || "unreviewed";
      sel.addEventListener("change",event => {
        clearRequestQueueUndo();
        requestHuman.set(req.request_id,event.target.value);
        show("Original request HUMAN stage updated only in browser memory — no approval or source mutation.");
      });
      td.append(sel);
      const inspect = document.createElement("button");inspect.type="button";
      inspect.textContent="Inspect PRIVATE request";
      inspect.addEventListener("click",() => inspectOriginalRequest(req.request_id));
      td.append(inspect);
      tr.append(td);tbody.append(tr);shown++;
    }
    $("casebook-request-status").textContent = source ?
      shown + " original request rows shown. " + lines.filter(x =>
        x.req.status === "approved" && !x.linked.length).length +
      " approved-looking original request(s) have no stored grant binding in this source; this is NOT permission or proof of absent grants." :
      "No original request source is loaded. This is NOT an authorization.";
  }

  function inspectCase(id) {
    if (!source) return;
    const item = source.case_overview.find(c => c.engagement_id === id);
    if (!item) return;
    const grants = source.grants.filter(g => g.engagement_id === id);
    const risks = source.risk_approvals.filter(r => r.engagement_id === id);
    const box = $("casebook-selected"); box.replaceChildren();
    const head = document.createElement("h3");
    head.textContent = "PRIVATE ORIGINAL source case " + id + " — not authorization";
    box.append(head);
    const line = (value) => {
      const p = document.createElement("p");
      p.textContent = value; box.append(p);
    };
    line("Source attention: " + item.attention + " · Suggested human follow-up: " +
      item.next_review_action + ". Neither is independently authenticated.");
    for (const g of grants) {
      const request = source.requests.find(r => r.request_id === g.approved_request_id);
      line("Recorded grant ID " + g.grant_id + " — binding ID " +
        (g.approved_request_id || "(missing)") + ", original request status " +
        (request?.status || "(source not available)") +
        "; source linkage " + g.request_link_observation + "; source window " +
        g.validity_observation + "; recorded max-risk " + g.max_risk +
        " (NO live permission).");
    }
    for (const risk of risks) {
      line("Recorded risk ID " + risk.approval_id + ": " + risk.status +
        "; provenance " + risk.decision_provenance_observation +
        "; declared tenant match " + risk.source_tenant_matches +
        " (NOT fresh operator/client consent).");
    }
    if (!grants.length && !risks.length) {
      line("No source-linked grants or risks in this case. This does NOT prove absent authorizations or permission.");
    }
    const label = document.createElement("label");
    label.textContent = "PRIVATE HUMAN follow-up note (up to 500 characters; never authority):";
    const input = document.createElement("textarea");
    input.maxLength = 500;
    input.setAttribute("aria-label", "PRIVATE HUMAN follow-up note for selected original case");
    input.autocomplete = "off";
    input.value = privateNotes.get(id) || "";
    input.addEventListener("input", event => {
      const value = event.target.value;
      if (value.length > 500 || /[\u0000-\u0008\u000b-\u001f\u007f]|\p{Cf}|\p{Cs}/u.test(value)) {
        show("HOLD: control or invisible formatting in PRIVATE note.", true);
        return;
      }
      if (value.trim()) privateNotes.set(id, value);
      else privateNotes.delete(id);
      show("HUMAN note held only in this private browser tab until an optional encrypted handoff.");
    });
    label.append(input);
    box.append(label);
    box.hidden = false;
  }

  async function openPrivateFile(file) {
    if (!file || file.size === 0 || file.size > LIMIT) throw Error("PRIVATE Casebook source must be 1–512 KiB.");
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (bytes.length > LIMIT) throw Error("PRIVATE Casebook source exceeded bound.");
    let raw;
    try { raw = new TextDecoder("utf-8", {fatal: true, ignoreBOM: true}).decode(bytes); }
    catch (_) { throw Error("PRIVATE source has invalid UTF-8 bytes."); }
    if (new TextEncoder().encode(raw).length !== bytes.length) {
      throw Error("Original PRIVATE source UTF-8 bytes noncanonical.");
    }
    const parsed = inspectOriginal(parseDuplicateSafeJson(raw));
    // Byte fingerprint ties only this local input to subsequent HUMAN review;
    // it is NOT a signed origin/source/timestamp proof.
    const hash = globalThis.crypto?.subtle ?
      await globalThis.crypto.subtle.digest("SHA-256", bytes) : null;
    const fingerprint = hash ? Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, "0")).join("") : null;
    return {parsed, fingerprint, raw};
  }

  function download(name, payload) {
    const blob = new Blob([payload], {type: "application/json;charset=utf-8"});
    const url = URL.createObjectURL(blob), a = document.createElement("a");
    a.href = url; a.download = name; document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }

  const HANDOFF_SCHEMA = "lightup.scope_intake.casebook_private_handoff.v1";
  const HANDOFF_BYTES = 1150000;
  const HANDOFF_ROUNDS = 600000;
  const HANDOFF_PURPOSE = "lightup.scope_intake.casebook_private_handoff.v1;REVIEW_ONLY";
  const HANDOFF_KEYS = ["schema", "posture", "cipher", "kdf", "iterations", "salt_b64",
    "nonce_b64", "ciphertext_b64"];
  const CONTENT_KEYS = ["schema", "posture", "source_raw", "source_sha256", "human_stages",
    "request_stages", ...FALSE_AUTHORITY];
  const LEGACY_CONTENT_KEYS = ["schema", "posture", "source_raw", "source_sha256", "human_stages",
    ...FALSE_AUTHORITY];

  function mustHavePrivateCrypto() {
    if (!globalThis.isSecureContext || !globalThis.crypto?.subtle ||
        typeof globalThis.crypto.getRandomValues !== "function") {
      throw Error("Secure offline WebCrypto unavailable; plaintext fallback is forbidden.");
    }
  }
  function userPassword(isNew) {
    const value = prompt(isNew ?
      "Enter NEW private Casebook handoff password (14–256 UTF-8 bytes). Never send it with the file." :
      "Enter PRIVATE Casebook handoff password:");
    if (value === null) return null;
    const bytes = new TextEncoder().encode(value);
    if (bytes.length < 14 || bytes.length > 256 ||
        /[\u0000-\u001f\u007f]/u.test(value) || !value.trim()) {
      bytes.fill(0);
      throw Error("Casebook password must be 14–256 noncontrol UTF-8 bytes.");
    }
    bytes.fill(0);
    if (isNew) {
      const again = prompt("Confirm NEW PRIVATE Casebook handoff password:");
      if (again === null) return null;
      if (again !== value) throw Error("Passwords do not match.");
    }
    return value;
  }

  async function privateKey(password, salt) {
    const raw = new TextEncoder().encode(password);
    try {
      const imported = await globalThis.crypto.subtle.importKey(
        "raw", raw, "PBKDF2", false, ["deriveKey"]);
      return await globalThis.crypto.subtle.deriveKey(
        {name:"PBKDF2", salt, iterations:HANDOFF_ROUNDS, hash:"SHA-256"},
        imported, {name:"AES-GCM", length:256}, false, ["encrypt", "decrypt"]);
    } finally { raw.fill(0); }
  }

  function encode64(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i += 4096) {
      binary += String.fromCharCode(...bytes.subarray(i, i + 4096));
    }
    return btoa(binary);
  }
  function decode64(value, length = null) {
    if (typeof value !== "string" || value.length > HANDOFF_BYTES ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
      throw Error("HOLD: invalid original Casebook transfer encoding.");
    }
    let result;
    try { result = Uint8Array.from(atob(value), c => c.charCodeAt(0)); }
    catch (_) { throw Error("HOLD: invalid original Casebook transfer encoding."); }
    if (encode64(result) !== value || (length !== null && result.length !== length)) {
      result.fill(0); throw Error("HOLD: noncanonical original Casebook transfer bytes.");
    }
    return result;
  }
  async function digestOfRaw(raw) {
    const bytes = new TextEncoder().encode(raw);
    try {
      const sha = await globalThis.crypto.subtle.digest("SHA-256", bytes);
      return Array.from(new Uint8Array(sha), b => b.toString(16).padStart(2, "0")).join("");
    } finally { bytes.fill(0); }
  }

  async function saveEncryptedHandoff() {
    try {
      mustHavePrivateCrypto();
      if (!source || !rawPrivateSource) throw Error("Import an original PRIVATE Casebook first.");
      const pwd = userPassword(true);
      if (pwd === null) return;
      if (!confirm("Encrypt original PRIVATE source plus your own HUMAN follow-up labels locally? This file is confidential and does not authenticate the producer, client/operator consent or authority. Keep its password separately.")) return;
      const humanStages = source.case_overview.map(c => ({
        engagement_id: c.engagement_id, stage: human.get(c.engagement_id) || "unreviewed",
        note: privateNotes.get(c.engagement_id) || ""
      }));
      const payload = {
        schema: HANDOFF_SCHEMA, posture:"REVIEW_ONLY",
        source_raw: rawPrivateSource,
        source_sha256: await digestOfRaw(rawPrivateSource),
        human_stages: humanStages,
        request_stages: source.requests.map(req => ({
          request_id: req.request_id, stage: requestHuman.get(req.request_id) || "unreviewed"
        })),
        ...Object.fromEntries(FALSE_AUTHORITY.map(x => [x,false]))
      };
      const plain = new TextEncoder().encode(JSON.stringify(payload, null, 2) + "\n");
      if (plain.length > LIMIT + 100000) {
        plain.fill(0); throw Error("Bounded Casebook private handoff data too large.");
      }
      const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
      const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
      let sealed;
      try {
        const key = await privateKey(pwd, salt);
        const ciphertext = await globalThis.crypto.subtle.encrypt(
          {name:"AES-GCM", iv, additionalData:new TextEncoder().encode(HANDOFF_PURPOSE), tagLength:128},
          key, plain);
        sealed = new Uint8Array(ciphertext);
        const packet = {
          schema: HANDOFF_SCHEMA, posture:"REVIEW_ONLY", cipher:"AES-256-GCM",
          kdf:"PBKDF2-SHA256", iterations:HANDOFF_ROUNDS,
          salt_b64:encode64(salt), nonce_b64:encode64(iv), ciphertext_b64:encode64(sealed)
        };
        const text = JSON.stringify(packet, null, 2) + "\n";
        if (new TextEncoder().encode(text).length > HANDOFF_BYTES) {
          throw Error("Encrypted original Casebook packet exceeds private size limit.");
        }
        download("lightup-original-casebook-PRIVATE-encrypted.lucb", text);
        show("Encrypted PRIVATE Casebook source + HUMAN follow-up downloaded. No original authority or consent granted.");
      } finally { plain.fill(0); salt.fill(0); iv.fill(0); sealed?.fill(0); }
    } catch (e) {
      show("PRIVATE encrypted handoff refused: " + e.message + " Existing original source retained.", true);
    }
  }

  async function openEncryptedHandoff(file) {
    mustHavePrivateCrypto();
    if (!file || !file.size || file.size > HANDOFF_BYTES) throw Error("Encrypted source handoff too large.");
    const encryptedBytes = new Uint8Array(await file.arrayBuffer());
    if (encryptedBytes.length > HANDOFF_BYTES) throw Error("Encrypted original source exceeded limit.");
    let envelopeText;
    try { envelopeText = new TextDecoder("utf-8", {fatal:true,ignoreBOM:true}).decode(encryptedBytes); }
    catch (_) { throw Error("Original encrypted handoff has invalid UTF-8."); }
    if (new TextEncoder().encode(envelopeText).length !== encryptedBytes.length) {
      throw Error("Noncanonical encrypted source UTF-8.");
    }
    const packet = parseDuplicateSafeJson(envelopeText);
    if (!sameKeys(packet, HANDOFF_KEYS) ||
        envelopeText !== JSON.stringify(packet,null,2) + "\n" ||
        packet.schema !== HANDOFF_SCHEMA || packet.posture !== "REVIEW_ONLY" ||
        packet.cipher !== "AES-256-GCM" || packet.kdf !== "PBKDF2-SHA256" ||
        packet.iterations !== HANDOFF_ROUNDS) {
      throw Error("HOLD: unsupported or noncanonical original Casebook encryption packet.");
    }
    const salt = decode64(packet.salt_b64,16);
    const iv = decode64(packet.nonce_b64,12);
    const ciphertext = decode64(packet.ciphertext_b64);
    let opened;
    try {
      const pwd = userPassword(false);
      if (pwd === null) throw Error("Password entry canceled.");
      const key = await privateKey(pwd,salt);
      try {
        opened = new Uint8Array(await globalThis.crypto.subtle.decrypt(
          {name:"AES-GCM",iv,additionalData:new TextEncoder().encode(HANDOFF_PURPOSE),tagLength:128},
          key,ciphertext));
      } catch (_) {
        throw Error("Wrong password, changed bytes or PRIVATE source authentication failed.");
      }
      if (opened.length > LIMIT + 100000) throw Error("Decrypted source exceeds human packet limit.");
      let payloadText;
      try { payloadText = new TextDecoder("utf-8",{fatal:true,ignoreBOM:true}).decode(opened); }
      catch (_) { throw Error("Decrypted source is not UTF-8."); }
      if (new TextEncoder().encode(payloadText).length !== opened.length) {
        throw Error("Decrypted original Casebook handoff is not canonical UTF-8.");
      }
      const payload = parseDuplicateSafeJson(payloadText);
      if (!(sameKeys(payload,CONTENT_KEYS) || sameKeys(payload,LEGACY_CONTENT_KEYS)) ||
          payloadText !== JSON.stringify(payload,null,2) + "\n" ||
          payload.schema !== HANDOFF_SCHEMA || payload.posture !== "REVIEW_ONLY" ||
          FALSE_AUTHORITY.some(k => payload[k] !== false) ||
          typeof payload.source_raw !== "string" ||
          new TextEncoder().encode(payload.source_raw).length > LIMIT ||
          !/^[0-9a-f]{64}$/.test(payload.source_sha256) ||
          !Array.isArray(payload.human_stages)) {
        throw Error("HOLD: source or HUMAN metadata structure violates original private contract.");
      }
      if (await digestOfRaw(payload.source_raw) !== payload.source_sha256) {
        throw Error("HOLD: original source byte fingerprint mismatch.");
      }
      const original = inspectOriginal(parseDuplicateSafeJson(payload.source_raw));
      if (payload.human_stages.length !== original.case_overview.length) {
        throw Error("HOLD: incomplete HUMAN source-bound cases.");
      }
      const restored = new Map();
      const restoredNotes = new Map();
      for (let i = 0; i < payload.human_stages.length; i++) {
        const record = payload.human_stages[i];
        if (!(sameKeys(record,["engagement_id","stage","note"]) ||
              sameKeys(record,["engagement_id","stage"])) ||
            (record.note !== undefined && (typeof record.note !== "string" ||
              record.note.length > 500 ||
              /[\u0000-\u0008\u000b-\u001f\u007f]|\p{Cf}|\p{Cs}/u.test(record.note))) ||
            record.engagement_id !== original.case_overview[i].engagement_id ||
            !Object.hasOwn(VALID_HUMAN,record.stage) ||
            restored.has(record.engagement_id)) {
          throw Error("HOLD: HUMAN labels do not belong to the exact original source cases.");
        }
        restored.set(record.engagement_id,record.stage);
        if (record.note?.trim()) restoredNotes.set(record.engagement_id,record.note);
      }
      const restoredRequests = new Map();
      if (payload.request_stages !== undefined) {
        if (!Array.isArray(payload.request_stages) ||
            payload.request_stages.length !== original.requests.length) {
          throw Error("HOLD: original request HUMAN follow-up is incomplete.");
        }
        for (let i = 0; i < payload.request_stages.length; i++) {
          const record = payload.request_stages[i];
          if (!sameKeys(record, ["request_id","stage"]) ||
              record.request_id !== original.requests[i].request_id ||
              !Object.hasOwn(VALID_HUMAN,record.stage) ||
              restoredRequests.has(record.request_id)) {
            throw Error("HOLD: original request HUMAN stage identity/order mismatch.");
          }
          restoredRequests.set(record.request_id,record.stage);
        }
      }
      return {parsed:original,fingerprint:payload.source_sha256,raw:payload.source_raw,
        stages:restored,notes:restoredNotes,requestStages:restoredRequests};
    } finally {
      salt.fill(0); iv.fill(0); ciphertext.fill(0); opened?.fill(0); encryptedBytes.fill(0);
    }
  }

  function exportAggregate() {
    if (!source) { show("Open original PRIVATE Casebook source first.", true); return; }
    if (!confirm("Export only source-free aggregate counts and local HUMAN stage totals? Small-cohort totals remain sensitive. No original client/record IDs, assets or timestamp included. This is never authorization.")) return;
    const stages = Object.fromEntries(Object.keys(VALID_HUMAN).map(k => [k, 0]));
    for (const c of source.case_overview) stages[human.get(c.engagement_id) || "unreviewed"]++;
    const requestStages = Object.fromEntries(Object.keys(VALID_HUMAN).map(k => [k, 0]));
    for (const r of source.requests) requestStages[requestHuman.get(r.request_id) || "unreviewed"]++;
    const unlinkedApproved = sourceRequests().filter(v =>
      v.req.status === "approved" && !v.linked.length).length;
    const data = {
      schema: "lightup.scope_intake.casebook_human_counts.v1",
      posture: "REVIEW_ONLY",
      authority: Object.fromEntries(FALSE_AUTHORITY.map(x => [x, false])),
      original_source_counts: {...source.declared_counts},
      local_human_stages: stages,
      local_original_request_stages: requestStages,
      approved_requests_without_stored_link_count: unlinkedApproved,
      original_source_authenticated_by_this_browser: false,
      consent_or_permission_granted_by_this_browser: false
    };
    download("lightup-casebook-human-counts-NO-SOURCE.json", JSON.stringify(data, null, 2) + "\n");
    show("Aggregate-only source-free HUMAN counts prepared; still no original source authenticity or permission.");
  }

  function initialize() {
    $("choose-casebook").addEventListener("click", () => $("casebook-file").click());
    $("clear-casebook").addEventListener("click", () => clearOriginal(true));
    $("casebook-filter").addEventListener("input", renderCases);
    $("casebook-category").addEventListener("change", renderCases);
    $("request-filter").addEventListener("input", renderRequestInbox);
    $("request-category").addEventListener("change", renderRequestInbox);
    $("casebook-aggregate").addEventListener("click", exportAggregate);
    $("queue-unbound-requests").addEventListener("click", queueUnboundRequests);
    $("undo-unbound-requests").addEventListener("click", undoUnboundRequests);
    $("save-casebook-secure").addEventListener("click", saveEncryptedHandoff);
    $("open-casebook-secure").addEventListener("click", () => $("casebook-secure-file").click());
    $("casebook-secure-file").addEventListener("change", async event => {
      const file = event.target.files[0]; event.target.value = "";
      if (!file) return;
      try {
        const result = await openEncryptedHandoff(file);
        if (!confirm("Replace original PRIVATE Casebook and local HUMAN labels with this decrypted, byte-bound package? This does NOT grant authorization or change your separate proposed scope.")) return;
        source = result.parsed;
        digestHex = result.fingerprint;
        rawPrivateSource = result.raw;
        human = result.stages;
        privateNotes = result.notes;
        requestHuman = result.requestStages;
        requestQueueUndo = null;
        $("casebook-filter").value = "";
        $("casebook-category").value = "all";
        $("request-filter").value = "";
        $("request-category").value = "all";
        $("casebook-selected").hidden = true;
        $("casebook-selected").textContent = "";
        $("casebook-request-detail").hidden = true;
        $("casebook-request-detail").textContent = "";
        $("undo-unbound-requests").disabled = true;
        renderCases();
        show("Encrypted ORIGINAL Casebook + local HUMAN stages restored. SHA-256 " + digestHex +
          ". No present-tense origin/consent/grant reauthenticated.");
      } catch (e) {
        show("PRIVATE ENCRYPTED SOURCE HOLD: " + e.message +
          " Existing Casebook and human stages retained.", true);
      }
    });
    $("casebook-file").addEventListener("change", async (event) => {
      const file = event.target.files[0]; event.target.value = "";
      if (!file) return;
      try {
        const result = await openPrivateFile(file);
        if (!confirm("Replace the previous PRIVATE original Casebook tab state with this schema-checked, UNAUTHENTICATED local file? This does not import any approval or authorization into the proposed scope.")) {
          show("PRIVATE source replacement canceled; previous Casebook remains intact."); return;
        }
        source = result.parsed;
        digestHex = result.fingerprint;
        rawPrivateSource = result.raw;
        human.clear();
        privateNotes.clear();
        requestHuman.clear();
        requestQueueUndo = null;
        $("casebook-selected").hidden = true;
        $("casebook-selected").textContent = "";
        $("casebook-filter").value = "";
        $("casebook-category").value = "all";
        renderCases();
        show("PRIVATE Casebook-shaped source loaded locally. Declared tenant ID: " + source.client_id +
          ". Local unsigned source SHA-256: " + (digestHex || "unavailable") +
          ". No original account, client consent, operator consent or grant reauthenticated.");
      } catch (e) {
        show("SOURCE HOLD: " + e.message + " Existing workroom/source retained.", true);
      }
    });
    clearOriginal(false);
  }
  document.addEventListener("DOMContentLoaded", initialize, {once: true});
})();
