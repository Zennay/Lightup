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
  let digestHex = null;

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
          !textField(r.requested_mode, 80) || !textField(r.created_at, 80) ||
          !riskField(r.requested_risk) || typeof r.decision_recorded !== "boolean") {
        throw Error("HOLD: invalid original request fields.");
      }
      accept("requests", r.request_id);
    }
    for (const r of doc.engagements) {
      if (!sameKeys(r, ["engagement_id", "status", "created_at"]) ||
          !textField(r.status, 80) || !textField(r.created_at, 80)) {
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
          !riskField(r.max_risk) || !textField(r.valid_from, 80) || !textField(r.valid_until, 80)) {
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
          !linkedId(r.engagement_id) || !["pending", "approved", "denied"].includes(r.status) ||
          !riskField(r.requested_risk) ||
          typeof r.source_tenant_matches !== "boolean" ||
          typeof r.decision_recorded !== "boolean" ||
          !allowedRiskObservations.has(r.decision_provenance_observation)) {
        throw Error("HOLD: malformed original risk review row.");
      }
      accept("risk_approvals", r.approval_id);
      if (r.engagement_id !== null && !ids.get("engagements").has(r.engagement_id)) {
        throw Error("HOLD: unresolved risk engagement reference.");
      }
    }
    const seenCases = new Set();
    for (const c of doc.case_overview) {
      if (!sameKeys(c, CASE_FIELDS) || !ids.get("engagements").has(c.engagement_id) ||
          seenCases.has(c.engagement_id) || !textField(c.status, 80) ||
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
    human.clear();
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
        c.engagement_id, c.status,
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
    return {parsed, fingerprint};
  }

  function download(name, payload) {
    const blob = new Blob([payload], {type: "application/json;charset=utf-8"});
    const url = URL.createObjectURL(blob), a = document.createElement("a");
    a.href = url; a.download = name; document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }

  function exportAggregate() {
    if (!source) { show("Open original PRIVATE Casebook source first.", true); return; }
    if (!confirm("Export only source-free aggregate counts and local HUMAN stage totals? Small-cohort totals remain sensitive. No original client/record IDs, assets or timestamp included. This is never authorization.")) return;
    const stages = Object.fromEntries(Object.keys(VALID_HUMAN).map(k => [k, 0]));
    for (const c of source.case_overview) stages[human.get(c.engagement_id) || "unreviewed"]++;
    const data = {
      schema: "lightup.scope_intake.casebook_human_counts.v1",
      posture: "REVIEW_ONLY",
      authority: Object.fromEntries(FALSE_AUTHORITY.map(x => [x, false])),
      original_source_counts: {...source.declared_counts},
      local_human_stages: stages,
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
    $("casebook-aggregate").addEventListener("click", exportAggregate);
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
        human.clear();
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
