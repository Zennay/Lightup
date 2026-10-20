"use strict";
/* HUMAN-only literal source snapshot comparison. No tenant / chronology / fix claims. */
(function () {
  const SCHEMA = "lightup.offline_private_csv_revision.v1";
  const DIGEST = /^[0-9a-f]{64}$/;
  const MAX_HISTORY = 3;
  const MAX_HISTORY_BYTES = 512 * 1024;
  const ENCODER = new TextEncoder();
  const TYPES = new Set(["changed", "absent"]);
  const POLICY = new Set(["reset", "retain"]);

  function exact(obj, keys) {
    return obj && typeof obj === "object" && !Array.isArray(obj) &&
      Object.keys(obj).length === keys.length &&
      keys.every(key => Object.prototype.hasOwnProperty.call(obj, key));
  }
  function fail() { throw new Error("PRIVATE source revision history is invalid or too large"); }
  function sameSource(a,b) {
    return a.id === b.id && a.title === b.title && a.severity === b.severity &&
      a.retest === b.retest && a.remediation === b.remediation;
  }
  function build(oldRows, incomingRows, oldJournal, fromDigest, toDigest) {
    if (!Array.isArray(oldRows) || !Array.isArray(incomingRows) ||
        !Array.isArray(oldJournal) || oldRows.length !== oldJournal.length ||
        !DIGEST.test(fromDigest) || !DIGEST.test(toDigest) ||
        fromDigest === toDigest) fail();
    const previous = new Map(oldRows.map((row, i) => [row.id, {row, human: oldJournal[i]}]));
    const incoming = new Set(incomingRows.map(row => row.id));
    const stats = {unchanged: 0, changed: 0, added: 0, absent: 0};
    const kinds = [];
    const affected = [];
    for (const row of incomingRows) {
      const past = previous.get(row.id);
      if (!past) {
        kinds.push("added"); stats.added++;
      } else if (sameSource(past.row, row)) {
        kinds.push("unchanged"); stats.unchanged++;
      } else {
        kinds.push("changed"); stats.changed++;
        affected.push({id: row.id, type: "changed", source_title: past.row.title,
          source_severity: past.row.severity, source_retest: past.row.retest,
          human: {...past.human}});
      }
    }
    for (const old of oldRows) {
      if (!incoming.has(old.id)) {
        const item = previous.get(old.id);
        stats.absent++;
        affected.push({id: old.id, type: "absent", source_title: old.title,
          source_severity: old.severity, source_retest: old.retest,
          human: {...item.human}});
      }
    }
    return {oldRows, incomingRows, oldJournal, fromDigest, toDigest, kinds, stats, affected};
  }
  function migrate(plan, choice, blankEntry, existingHistory) {
    if (!POLICY.has(choice) || typeof blankEntry !== "function" ||
        !Array.isArray(existingHistory)) fail();
    const old = new Map(plan.oldRows.map((row,i) => [row.id, plan.oldJournal[i]]));
    const journal = plan.incomingRows.map((row, i) => {
      const kind = plan.kinds[i];
      if (kind === "added" || (kind === "changed" && choice === "reset")) return blankEntry(row.id);
      const from = old.get(row.id);
      if (!from) fail();
      if (kind === "changed") {
        return {...from, stage: "needs_evidence"};
      }
      return {...from};
    });
    const entry = {
      schema: SCHEMA, from_sha256: plan.fromDigest, to_sha256: plan.toDigest,
      counts: {...plan.stats}, changed_policy: choice,
      affected: plan.affected.map(item => ({
        id: item.id, type: item.type, source_title: item.source_title,
        source_severity: item.source_severity, source_retest: item.source_retest,
        human: {...item.human}
      }))
    };
    const history = [...existingHistory, entry];
    if (history.length > MAX_HISTORY ||
        ENCODER.encode(JSON.stringify(history)).length > MAX_HISTORY_BYTES) {
      throw new Error("PRIVATE revision archive would exceed its limit (3 revisions / 512 KiB). " +
        "Save the current encrypted complete workroom before starting another revision; " +
        "never silently discard previously missing HUMAN records.");
    }
    return {journal, history};
  }
  function admitHistory(history, currentDigest, admitHuman, safeDisplay) {
    if (!Array.isArray(history) || history.length > MAX_HISTORY ||
        !DIGEST.test(currentDigest) || !admitHuman || !safeDisplay ||
        ENCODER.encode(JSON.stringify(history)).length > MAX_HISTORY_BYTES) fail();
    let prior;
    const canonical = [];
    for (const item of history) {
      if (!exact(item, ["schema", "from_sha256", "to_sha256", "counts", "changed_policy", "affected"]) ||
          item.schema !== SCHEMA || !DIGEST.test(item.from_sha256) ||
          !DIGEST.test(item.to_sha256) || item.from_sha256 === item.to_sha256 ||
          !POLICY.has(item.changed_policy) ||
          (prior && prior !== item.from_sha256) ||
          !exact(item.counts, ["unchanged","changed","added","absent"]) ||
          !Object.values(item.counts).every(n => Number.isSafeInteger(n) && n >= 0 && n <= 128) ||
          !Array.isArray(item.affected) || item.affected.length > 128 ||
          item.affected.length !== item.counts.changed + item.counts.absent) fail();
      if (item.counts.unchanged + item.counts.changed + item.counts.absent > 128 ||
          item.counts.unchanged + item.counts.changed + item.counts.added > 128) fail();
      const seen = new Set();
      const affected = item.affected.map(row => {
        if (!exact(row, ["id","type","source_title","source_severity","source_retest","human"]) ||
            !TYPES.has(row.type) || typeof row.id !== "string" ||
            seen.has(row.id) || !safeDisplay(row.id, 32768, false) ||
            !safeDisplay(row.source_title, 32768, false) ||
            !["critical","high","medium","low","info"].includes(row.source_severity) ||
            !["not_tested","fix_pending","fixed","regression"].includes(row.source_retest)) fail();
        seen.add(row.id);
        return {...row, human: admitHuman(row.human, row.id)};
      });
      if (affected.filter(x => x.type === "changed").length !== item.counts.changed ||
          affected.filter(x => x.type === "absent").length !== item.counts.absent) fail();
      canonical.push({...item, counts: {...item.counts}, affected});
      prior = item.to_sha256;
    }
    if (prior && prior !== currentDigest) fail();
    return canonical;
  }
  globalThis.LightUpCsvRevision = Object.freeze({build, migrate, admitHistory});
})();
