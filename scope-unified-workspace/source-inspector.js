"use strict";
/*
 * PRIVATE source-format inspector (offline, read-only, non-authorizing).
 * Structural admission for routing only; never authenticates producers, tenants,
 * source values, current consent, revocation, or source owner code correctness.
 * No network, persistent storage, grants, scans, execution or HTML rendering.
 */
const LightUpPrivateSourceInspector = (() => {
  const MAX_JSON_BYTES = 2 * 1024 * 1024;
  const OPAQUE = Object.freeze({
    ".lucb": { kind: "ENCRYPTED_CASEBOOK", route: "intake", label: "Versleutelde Casebook: inhoud niet gecontroleerd" },
    ".luie": { kind: "ENCRYPTED_INTAKE", route: "intake", label: "Versleutelde intake: inhoud niet gecontroleerd" },
    ".lupt": { kind: "ENCRYPTED_TRANSFER", route: "casebook", label: "Versleutelde overdracht: inhoud niet gecontroleerd" }
  });
  const CASEBOOK_AUTH = Object.freeze([
    "source_authenticated", "client_consent_verified", "operator_consent_verified",
    "authorization_granted", "execution_allowed", "release_approved"
  ]);
  const FALSE_SCOPE = Object.freeze([
    "authorization", "client_consent", "operator_consent", "grant", "execution", "revocation_checked"
  ]);
  const FALSE_READINESS = Object.freeze([
    "authorization_granted", "client_consent_verified", "execution_allowed",
    "operator_consent_verified", "release_approved"
  ]);
  const asObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  const onlyFalse = (v, keys) => asObject(v) && keys.every((k) => Object.hasOwn(v, k) && v[k] === false);
  const bounded = (v, max = 200) => typeof v === "string" && v.length <= max &&
    !/[\u0000-\u001f\u007f]/u.test(v);
  const count = (v, max = 10000) => Number.isSafeInteger(v) && v >= 0 && v <= max;
  const sha = (v) => typeof v === "string" && /^[0-9a-f]{64}$/u.test(v);
  const exact = (value, expected) => asObject(value) && Object.keys(value).length === expected.length &&
    expected.every((key) => Object.hasOwn(value, key));

  // Bounded recursive parser that refuses nested, escaped and unescaped
  // duplicate JSON keys. A regular JSON.parse silently collapses duplicates.
  function parse(text) {
    if (typeof text !== "string" || text.length > MAX_JSON_BYTES) throw Error("oversized JSON");
    let i = 0, nodes = 0;
    const ws = () => { while (i < text.length && /[\x20\t\n\r]/u.test(text[i])) i++; };
    const stringMatcher = /"(?:\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4})|[^"\\\u0000-\u001f])*"/uy;
    const numberMatcher = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/uy;
    const quoted = () => {
      stringMatcher.lastIndex = i;
      const m = stringMatcher.exec(text);
      if (!m) throw Error("invalid JSON string");
      i = stringMatcher.lastIndex;
      return JSON.parse(m[0]);
    };
    const visit = (depth) => {
      if (depth > 30 || ++nodes > 150000) throw Error("unbounded JSON structure");
      ws(); const ch = text[i];
      if (ch === '"') return quoted();
      if (ch === "{") {
        const obj = Object.create(null); const seen = new Set(); i++; ws();
        if (text[i] === "}") { i++; return obj; }
        for (;;) {
          ws(); if (text[i] !== '"') throw Error("invalid object key");
          const key = quoted();
          if (seen.has(key)) throw Error("duplicate JSON property");
          seen.add(key); if (seen.size > 3000) throw Error("too many properties");
          ws(); if (text[i++] !== ":") throw Error("invalid separator");
          obj[key] = visit(depth + 1); ws();
          if (text[i] === "}") { i++; return obj; }
          if (text[i++] !== ",") throw Error("invalid object delimiter");
        }
      }
      if (ch === "[") {
        const arr = []; i++; ws();
        if (text[i] === "]") { i++; return arr; }
        for (;;) {
          if (arr.length >= 3000) throw Error("too many array elements");
          arr.push(visit(depth + 1)); ws();
          if (text[i] === "]") { i++; return arr; }
          if (text[i++] !== ",") throw Error("invalid array delimiter");
        }
      }
      numberMatcher.lastIndex = i;
      const n = numberMatcher.exec(text);
      if (n) { i = numberMatcher.lastIndex; const v = Number(n[0]); if (!Number.isFinite(v)) throw Error("invalid number"); return v; }
      for (const [literal, value] of [["true", true], ["false", false], ["null", null]]) {
        if (text.startsWith(literal, i)) { i += literal.length; return value; }
      }
      throw Error("invalid JSON value");
    };
    const data = visit(0); ws();
    if (i !== text.length) throw Error("trailing JSON content");
    return data;
  }

  function classifyJSON(data, size) {
    if (!asObject(data)) return { kind: "UNKNOWN_JSON", route: "none", label: "Onbekende JSON: handmatige review vereist" };

    if (data.kind === "lightup.scope_proposal_draft") {
      if (size > 65536) throw Error("oversized original Studio draft");
      const valid = data.schema_version === 1 && data.state === "DRAFT_ONLY" &&
        FALSE_SCOPE.every((key) => data[key] === false) &&
        Array.isArray(data.requested_assets) && data.requested_assets.length <= 80 &&
        data.requested_assets.every((a) => bounded(a, 253)) &&
        Array.isArray(data.excluded_assets) && data.excluded_assets.length <= 80 &&
        data.excluded_assets.every((a) => bounded(a, 253)) &&
        count(data.requested_risk, 4) && data.requested_risk >= 1 &&
        ["analysis_only", "authorized_assessment"].includes(data.requested_mode) &&
        bounded(data.proposal_name, 120) && bounded(data.client_label, 100) &&
        asObject(data.proposed_window_local) && asObject(data.proposed_window_utc) &&
        asObject(data.proposed_activities);
      if (!valid) throw Error("declared Studio source malformed or authority flag");
      return { kind: "STUDIO_DRAFT", route: "studio",
        label: "Studio DRAFT_ONLY · " + data.requested_assets.length +
          " voorgestelde assets · risico " + data.requested_risk + " · NIET GEAUTORISEERD" };
    }

    if (data.schema === "lightup.auth_casebook.v1") {
      if (size > 512 * 1024) throw Error("oversized original Casebook source");
      const counts = data.declared_counts;
      const top = ["schema", "status", "source", "as_of", "client_id", "requests", "engagements",
        "grants", "risk_approvals", "case_overview", "declared_counts", ...CASEBOOK_AUTH];
      const counterKeys = ["requests", "engagements", "grants", "risk_approvals", "grant_link_hold",
        "risk_tenant_hold", "case_attention_hold", "foreign_tenant_row_count",
        "recorded_window_review", "risk_provenance_hold", "pending_risk_review"];
      if (!exact(data, top) || data.status !== "REVIEW_ONLY" ||
          data.source !== "original_persisted_domain_unverified" ||
          !CASEBOOK_AUTH.every((key) => data[key] === false) ||
          !bounded(data.client_id, 180) || !exact(counts, counterKeys) ||
          !counterKeys.every((key) => count(counts[key], 2000)) ||
          !["requests", "engagements", "grants", "risk_approvals"].every((key) => count(counts[key])) ||
          !["requests", "engagements", "grants", "risk_approvals", "case_overview"].every((key) =>
            Array.isArray(data[key]) && data[key].length <= 200)) {
        throw Error("declared original Casebook source malformed or authority flag");
      }
      return { kind: "CASEBOOK_SOURCE", route: "intake",
        label: "Origineel Casebook-formaat · " + data.engagements.length +
          " bronengagements · alleen retrospectief" };
    }

    if (data.format === "lightup.authorization_readiness_operator_v1") {
      if (size > 2000000) throw Error("oversized original operator-readiness report");
      const keys = ["format", "disposition", "request_binding_schema_present",
        "scope_fingerprint", "scope_description", "authority", "limitations",
        "summary", "engagements", "review_queue", "request_history"];
      const valid = exact(data, keys) && data.disposition === "REVIEW_ONLY" &&
        (data.request_binding_schema_present === true || data.request_binding_schema_present === false) &&
        sha(data.scope_fingerprint) && ["all_clients", "single_client", "single_engagement"].includes(data.scope_description) &&
        exact(data.authority, FALSE_READINESS) &&
        FALSE_READINESS.every((key) => data.authority[key] === false) &&
        asObject(data.summary) && Array.isArray(data.engagements) && Array.isArray(data.review_queue) &&
        Array.isArray(data.request_history) && data.engagements.length <= 3000 &&
        data.review_queue.length <= 3000 && data.request_history.length <= 3000;
      if (!valid) throw Error("declared operator readiness malformed or authority flag");
      return { kind: "OPERATOR_READINESS", route: "risk",
        label: "Operator-readinessformaat · " + data.engagements.length + " bronengagements · geen consent" };
    }

    if (data.format === "lightup.scope_handoff_PRIVATE_inventory.v1" ||
        data.format === "lightup.scope_handoff_PRIVATE_inventory.v2" ||
        data.format === "lightup.scope_handoff_anonymous_counts.v1" ||
        data.format === "lightup.scope_PRIVATE_human_proposal_draft.v1") {
      return { kind: "SELF_REPORTED_INVENTORY", route: "none",
        label: "HUMAN inventaris; geen oorspronkelijke bron" };
    }
    return { kind: "UNKNOWN_JSON", route: "none",
      label: "Onbekende JSON: geen automatische bronroutering" };
  }
  async function inspect(file) {
    if (!file || typeof file.name !== "string") throw Error("invalid file");
    const ext = file.name.toLowerCase().match(/\.[a-z]{2,8}$/u)?.[0] || "";
    if (Object.hasOwn(OPAQUE, ext)) return OPAQUE[ext];
    if (ext !== ".json") return { kind: "OPAQUE_FILE", route: "none", label: "Niet-herkend bestand · inhoud niet gecontroleerd" };
    if (file.size < 2 || file.size > MAX_JSON_BYTES) throw Error("unbounded JSON");
    const bytes = await file.arrayBuffer();
    const content = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const data = parse(content);
    if (asObject(data)) {
      const declarations = ["authorization", "client_consent", "operator_consent", "grant",
        "execution", "revocation_checked", "source_authenticated", "client_consent_verified",
        "operator_consent_verified", "authorization_granted", "execution_allowed", "release_approved"];
      if (declarations.some((key) => Object.hasOwn(data, key) && data[key] !== false)) {
        throw Error("untrusted source asserts authorization");
      }
    }
    return classifyJSON(data, file.size);
  }
  async function readHumanInventory(file) {
    if (!file || file.size < 10 || file.size > 96 * 1024) {
      throw Error("PRIVATE source inventory outside bounded size");
    }
    const raw = new TextDecoder("utf-8", { fatal: true }).decode(await file.arrayBuffer());
    const doc = parse(raw);
    if (!exact(doc, ["format", "status", "authority", "entries", "warning"]) ||
        !["lightup.scope_handoff_PRIVATE_inventory.v1", "lightup.scope_handoff_PRIVATE_inventory.v2"].includes(doc.format) ||
        doc.status !== "REVIEW_ONLY" ||
        !exact(doc.authority, ["client_consent", "operator_consent", "grant", "scan", "deploy", "release"]) ||
        !Object.values(doc.authority).every((v) => v === false) ||
        !Array.isArray(doc.entries) || doc.entries.length < 1 || doc.entries.length > 16 ||
        typeof doc.warning !== "string" || doc.warning.length > 300) {
      throw Error("Untrusted PRIVATE inventory format or authority flags");
    }
    const fields = ["original_name", "byte_length", "unsigned_sha256", "structural_kind_unverified",
      "human_route", "human_stage", "human_team", "private_human_note"];
    const v2 = doc.format === "lightup.scope_handoff_PRIVATE_inventory.v2";
    const rowFields = v2 ? [...fields, "private_note_included"] : fields;
    const names = new Set(), hashes = new Set();
    const routes = ["none", "studio", "intake", "casebook", "reconcile", "risk", "stop", "vault"];
    const stages = ["unreviewed", "preparing", "escalated", "documented"];
    const teams = ["unassigned", "security", "privacy", "client_ops", "platform"];
    for (const row of doc.entries) {
      if (!exact(row, rowFields) || (v2 && (typeof row.private_note_included !== "boolean" ||
          (!row.private_note_included && row.private_human_note !== ""))) ||
          !bounded(row.original_name, 220) || !row.original_name ||
          !count(row.byte_length, 8 * 1024 * 1024) || row.byte_length < 1 ||
          !sha(row.unsigned_sha256) || !bounded(row.structural_kind_unverified, 80) ||
          !routes.includes(row.human_route) || !stages.includes(row.human_stage) ||
          !teams.includes(row.human_team) ||
          typeof row.private_human_note !== "string" || row.private_human_note.length > 280) {
        throw Error("PRIVATE inventory contains invalid source binding or HUMAN values");
      }
      const key = row.original_name.normalize("NFC").toLowerCase();
      if (names.has(key) || hashes.has(row.unsigned_sha256)) {
        throw Error("Ambiguous PRIVATE inventory source identity");
      }
      names.add(key); hashes.add(row.unsigned_sha256);
    }
    // V1 always carries the note. V2 explicitly distinguishes redaction from an empty note.
    return doc.entries.map(row => ({...row, private_note_included: v2 ? row.private_note_included : true}));
  }
  // Private HUMAN draft choices are not an authorization schema. Validate
  // with the existing bounded duplicate-key-refusing JSON reader.
  async function readHumanProposalDraft(file) {
    if (!file || file.size < 10 || file.size > 64 * 1024) {
      throw Error("PRIVATE HUMAN draft outside bounded size");
    }
    const text = new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
    const doc = parse(text);
    if (!exact(doc, ["format","status","authority","packets","sources","warning"]) ||
        doc.format !== "lightup.scope_PRIVATE_human_proposal_draft.v1" ||
        doc.status !== "REVIEW_ONLY" ||
        !exact(doc.authority, ["client_consent","operator_consent","grant","scan","deploy","release"]) ||
        !Object.values(doc.authority).every(v => v === false) ||
        !Array.isArray(doc.packets) || doc.packets.length < 2 || doc.packets.length > 8 ||
        !Array.isArray(doc.sources) || doc.sources.length < 1 || doc.sources.length > 16 ||
        !bounded(doc.warning,300)) {
      throw Error("Untrusted PRIVATE HUMAN proposal draft structure");
    }
    const packetHashes = new Set();
    for (let i=0;i<doc.packets.length;i++) {
      const packet = doc.packets[i];
      if (!exact(packet, ["local_packet_number","original_packet_byte_length",
                          "unsigned_original_packet_sha256"]) ||
          packet.local_packet_number !== i + 1 ||
          !count(packet.original_packet_byte_length,96*1024) ||
          packet.original_packet_byte_length < 10 ||
          !sha(packet.unsigned_original_packet_sha256) ||
          packetHashes.has(packet.unsigned_original_packet_sha256)) {
        throw Error("Untrusted duplicate or invalid HUMAN reviewer packet binding");
      }
      packetHashes.add(packet.unsigned_original_packet_sha256);
    }
    const names = new Set(), hashes = new Set();
    for (const row of doc.sources) {
      if (!exact(row, ["original_name","byte_length","unsigned_sha256",
                       "structural_kind_unverified","packet_choice"]) ||
          !bounded(row.original_name,220) || !row.original_name ||
          !count(row.byte_length,8*1024*1024) || row.byte_length < 1 ||
          !sha(row.unsigned_sha256) ||
          !bounded(row.structural_kind_unverified,80) ||
          !Number.isInteger(row.packet_choice) ||
          !(row.packet_choice === -1 || row.packet_choice >= 1 &&
            row.packet_choice <= doc.packets.length)) {
        throw Error("Invalid source binding or nonexplicit HUMAN packet choice");
      }
      const key=row.original_name.normalize("NFC").toLowerCase();
      if(names.has(key) || hashes.has(row.unsigned_sha256))
        throw Error("Ambiguous original HUMAN draft source");
      names.add(key);hashes.add(row.unsigned_sha256);
    }
    return doc;
  }
  return Object.freeze({ inspect, readHumanInventory, readHumanProposalDraft });
})();