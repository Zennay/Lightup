"use strict";
/* Original-file byte lineage comparison for a PRIVATE HUMAN desk only.
 * The comparison never updates stored originals, merges review decisions,
 * claims source authorship, validates consent or performs revocation.
 */
const LightUpPrivateDrift = (() => {
  const key = (name) => name.normalize("NFC").toLowerCase();
  const format = Object.freeze({
    UNCHANGED: "Ongewijzigde lokale bronbytes · HUMAN-keuzes blijven apart",
    CHANGED_REVIEW_REQUIRED: "Bronnaam-/byte-/formaatverschil · nieuwe HUMAN-review vereist",
    NEW_REVIEW_REQUIRED: "Nieuw in lokale selectie · HUMAN-review vereist",
    ABSENT_FROM_LOCAL_SELECTION: "Niet opnieuw geselecteerd · GEEN bewijs van intrekking/fix"
  });
  function compare(previous, current) {
    if (!Array.isArray(previous) || !Array.isArray(current) ||
        previous.length < 1 || previous.length > 16 || current.length < 1 || current.length > 16) {
      throw Error("source set outside bounded comparison");
    }
    const seen = new Set();
    const now = new Map();
    for (const item of current) {
      const id = key(item.file.name);
      if (now.has(id)) throw Error("ambiguous active source identity");
      now.set(id, item);
    }
    const rows = [];
    for (const old of previous) {
      const id = key(old.original_name);
      if (seen.has(id)) throw Error("ambiguous earlier source identity");
      seen.add(id);
      const present = now.get(id);
      const unchanged = Boolean(present) && old.original_name === present.file.name &&
        old.byte_length === present.file.size &&
        old.unsigned_sha256 === present.hash &&
        old.structural_kind_unverified === present.inspection.kind;
      const status = !present ? "ABSENT_FROM_LOCAL_SELECTION" :
        unchanged ? "UNCHANGED" : "CHANGED_REVIEW_REQUIRED";
      rows.push(Object.freeze({
        original_name: present ? present.file.name : old.original_name,
        previous_unsigned_sha256: old.unsigned_sha256,
        selected_unsigned_sha256: present ? present.hash : null,
        status, human_action: format[status]
      }));
    }
    for (const item of current) {
      const id = key(item.file.name);
      if (seen.has(id)) continue;
      rows.push(Object.freeze({
        original_name: item.file.name,
        previous_unsigned_sha256: null,
        selected_unsigned_sha256: item.hash,
        status: "NEW_REVIEW_REQUIRED",
        human_action: format.NEW_REVIEW_REQUIRED
      }));
    }
    const totals = Object.fromEntries(Object.keys(format).map(k => [k, 0]));
    for (const row of rows) totals[row.status]++;
    if (rows.length > 32) throw Error("source drift exceeds maximum inventory");
    return Object.freeze({ rows, totals });
  }
  return Object.freeze({ compare });
})();