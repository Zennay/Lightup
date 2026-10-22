/* Offline-only resume of a strictly source-bound HUMAN role return CSV.
   This executes inside the CSP-hashed in-memory role editor IIFE. */
const resumeInput = document.getElementById("resume");
const progress = document.getElementById("progress");
const editors = [];
function statusSummary() {
  const changed = rows.reduce((n, row) =>
    n + Number(row.prior !== row.proposed || row.note.length > 0), 0);
  progress.textContent = rows.length + " selected HUMAN slots · " +
    changed + " local proposed changes · unsaved until PRIVATE CSV export";
}
function restrictedNote(value) {
  const forbidden = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2060-\u2069]/u;
  const normalized = value.normalize("NFKC").trimStart();
  return value.length > 400 || forbidden.test(value) ||
    (value !== "-" && /^[=+@-]/u.test(normalized));
}
function decodeStrictCsv(input) {
  if (typeof input !== "string" || input.length < 1 ||
      input.length > 32768 || input.startsWith("\uFEFF") ||
      /\r(?!\n)/u.test(input)) {
    throw new Error("Invalid bounded CSV data");
  }
  const text = input.replaceAll("\r\n", "\n");
  if (!text.endsWith("\n")) throw new Error("CSV is not newline terminated");
  const result = [];
  let record = [];
  let cell = "";
  let quoted = false;
  let afterQuote = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"') {
        if (text[i + 1] === '"') { cell += '"'; i++; }
        else { quoted = false; afterQuote = true; }
      } else { cell += ch; }
    } else if (ch === ",") {
      record.push(cell); cell = ""; afterQuote = false;
    } else if (ch === "\n") {
      record.push(cell);
      result.push(record);
      record = []; cell = ""; afterQuote = false;
      if (result.length > 17) throw new Error("Too many role rows");
    } else if (ch === '"') {
      if (cell || afterQuote) throw new Error("Invalid CSV quote");
      quoted = true;
    } else {
      if (afterQuote) throw new Error("Trailing CSV cell content");
      cell += ch;
    }
    if (cell.length > 2048) throw new Error("Oversized CSV cell");
  }
  if (quoted || record.length || cell) throw new Error("Incomplete CSV row");
  return result;
}
resumeInput.addEventListener("change", async () => {
  const file = resumeInput.files && resumeInput.files[0];
  resumeInput.value = "";
  if (!file) return;
  if (file.size < 1 || file.size > 32768) {
    message.textContent = "PRIVATE reply rejected: file size exceeds native CSV bound.";
    return;
  }
  try {
    const records = decodeStrictCsv(await file.text());
    if (records.length !== rows.length + 1 ||
        records[0].length !== decoded.header.length ||
        records[0].some((value, i) => value !== decoded.header[i])) {
      throw new Error("Unexpected role return schema or row count");
    }
    const proposed = [];
    for (let i = 0; i < rows.length; i++) {
      const item = records[i + 1];
      const original = rows[i];
      if (item.length !== 6 || item[0] !== decoded.fingerprint ||
          item[1] !== String(original.slot) || item[2] !== decoded.role ||
          item[3] !== original.prior || !stages.includes(item[4]) ||
          restrictedNote(item[5])) {
        throw new Error("Role-return source, stage or note mismatch");
      }
      proposed.push({stage:item[4], note:item[5]});
    }
    // Apply only after every original row is admitted. Invalid files never
    // partially overwrite in-memory edits.
    for (let i = 0; i < rows.length; i++) {
      rows[i].proposed = proposed[i].stage;
      rows[i].note = proposed[i].note;
      editors[i].stage.value = proposed[i].stage;
      editors[i].note.value = proposed[i].note;
    }
    statusSummary();
    message.textContent = "Source-matched PRIVATE draft loaded in memory. " +
      "Re-export and submit to the native owner-only role_return.py importer.";
  } catch (error) {
    message.textContent = "HOLD: PRIVATE draft was not admitted. " +
      "Original in-memory edits were preserved.";
  }
});
