/* No-storage, all-or-nothing PRIVATE HUMAN choice CSV resume. */
const resume = document.getElementById("resume");
const TEMPLATE_COLUMNS = [
 "source_set_sha256","original_slot","eligible_packet_numbers","chosen_packet_number"
];
resume.addEventListener("change", async () => {
  const file = resume.files && resume.files[0];
  resume.value = "";
  if (!file) return;
  if (file.size < 1 || file.size > 32768) {
    message.textContent = "HOLD: HUMAN conflict choice file exceeds the bounded PRIVATE size.";
    return;
  }
  try {
    const contents = await file.text();
    if (contents.startsWith("\uFEFF") || contents.includes("\u0000") ||
        !contents.endsWith("\n") || contents.length > 32768) {
      throw Error("noncanonical PRIVATE CSV input");
    }
    // The browser's own CSV output is deliberately fixed plain ASCII and
    // never contains user-controlled commas, quotes or embedded newlines.
    const lines = contents.replaceAll("\r\n", "\n").slice(0, -1).split("\n");
    if (lines.length !== rows.length + 1 ||
        lines[0] !== TEMPLATE_COLUMNS.join(",")) {
      throw Error("unknown HUMAN conflict choice schema or row count");
    }
    const proposed = [];
    for (let i = 0; i < rows.length; i++) {
      const cells = lines[i + 1].split(",");
      const source = rows[i];
      const eligible = source.options.map(option => String(option.packet));
      if (cells.length !== 4 || cells[0] !== state.fingerprint ||
          cells[1] !== String(source.slot) || cells[2] !== eligible.join("|") ||
          !eligible.includes(cells[3])) {
        throw Error("source, slot, packet set or HUMAN decision changed");
      }
      proposed.push(Number(cells[3]));
    }
    // Invalid or mixed-source drafts cannot partially replace prior choices.
    for (let i = 0; i < rows.length; i++) {
      const slot = rows[i].slot;
      chosen.set(slot, proposed[i]);
      selectors.get(slot).value = String(proposed[i]);
    }
    updateProgress();
    message.textContent = "PRIVATE source-matched manual choices restored in memory. " +
      "Export again and submit to the native owner-private decision-file gate.";
  } catch (_) {
    message.textContent = "HOLD: draft source or manual choices are not admitted. " +
      "The current in-memory decisions were preserved.";
  }
});
