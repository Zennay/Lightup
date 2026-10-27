'use strict';
// Offline PRIVATE one-Cockpit HUMAN coordination. No fetch, external I/O,
// browser persistence, grants, evidence mutation, scanning or native Apply.
(() => {
  const seed = JSON.parse(document.getElementById('seed').textContent);
  const root = document.getElementById('reasons');
  const status = document.getElementById('status');
  const query = document.getElementById('query');
  const stageFilter = document.getElementById('stage-filter');
  const overview = document.getElementById('overview');
  const choices = ['open_human', 'ask_source_owner', 'in_discussion_human', 'answered_human_only'];
  const names = {
    open_human: 'Open for HUMAN review',
    ask_source_owner: 'Ask original source owner',
    in_discussion_human: 'Discuss locally (unverified)',
    answered_human_only: 'HUMAN response received (NOT fixed)'
  };
  const entries = seed.items.map(item => ({...item}));
  const cards = [];
  let dirty = false;
  function element(tag, value, className) {
    const node = document.createElement(tag);
    if (value !== undefined) node.textContent = value;
    if (className) node.className = className;
    return node;
  }
  function changed() {
    dirty = true;
    status.textContent = 'Unsaved PRIVATE HUMAN choices on this page.';
    refresh();
  }
  function refresh() {
    const needle = query.value.toLocaleLowerCase();
    const byStage = stageFilter.value;
    let shown = 0;
    let humanAnswered = 0;
    let needsOriginalOwner = 0;
    for (const [idx, item] of entries.entries()) {
      if (item.stage === 'answered_human_only') humanAnswered++;
      if (item.stage === 'ask_source_owner') needsOriginalOwner++;
      const searchable = ('slot ' + item.slot + ' ' + item.reason.replaceAll('_', ' ')).toLocaleLowerCase();
      const visible = (!needle || searchable.includes(needle)) &&
                      (byStage === 'all' || item.stage === byStage);
      cards[idx].hidden = !visible;
      if (visible) shown++;
    }
    overview.textContent = shown + ' / ' + entries.length +
      ' HUMAN reason groups shown. ' + (entries.length - humanAnswered) +
      ' need HUMAN follow-up; ' + needsOriginalOwner +
      ' ask original source owner; ' + humanAnswered +
      ' locally answered (NOT verified fixes). Counts are groups, not unique findings.';
  }
  const controls = [];
  for (const [idx, item] of entries.entries()) {
    const card = element('article');
    card.appendChild(element('h3', 'Slot ' + item.slot + ' · ' + item.reason.replaceAll('_', ' ')));
    card.appendChild(element('p', item.count + ' declared HUMAN reason occurrence(s); not unique cases.'));
    card.appendChild(element('p', item.advice));
    const label = element('label', 'HUMAN follow-up state');
    const select = element('select');
    select.setAttribute('aria-label', 'HUMAN follow-up for slot ' + item.slot + ' ' + item.reason);
    for (const stage of choices) {
      const option = element('option', names[stage]);
      option.value = stage;
      select.appendChild(option);
    }
    select.value = item.stage;
    select.addEventListener('change', () => { entries[idx].stage = select.value; changed(); });
    label.appendChild(select);
    card.appendChild(label);
    const noteLabel = element('label', 'PRIVATE HUMAN note — no client names, secrets or credentials');
    const area = element('textarea');
    area.maxLength = 240;
    area.rows = 2;
    area.value = item.note;
    area.setAttribute('aria-label', 'Private note for slot ' + item.slot + ' ' + item.reason);
    area.addEventListener('input', () => { entries[idx].note = area.value; changed(); });
    noteLabel.appendChild(area);
    card.appendChild(noteLabel);
    root.appendChild(card);
    cards.push(card);
    controls.push({select, area});
  }
  query.addEventListener('input', refresh);
  stageFilter.addEventListener('change', refresh);
  function nativeAdmissible(row) {
    // Mirror native single_review.py::valid_note: max 240 Unicode units in
    // Python's scalar count, max 960 UTF-8 bytes; newline alone is allowed
    // among Unicode category C code points.
    const scalars = [...row.note];
    return choices.includes(row.stage) &&
           scalars.length <= 240 &&
           new TextEncoder().encode(row.note).length <= 960 &&
           !/\p{C}/u.test(row.note.replaceAll('\n', ''));
  }
  document.getElementById('save').addEventListener('click', () => {
    const badIndex = entries.findIndex(item => !nativeAdmissible(item));
    if (badIndex !== -1) {
      status.textContent = 'HOLD: invalid PRIVATE note or HUMAN stage in slot ' +
        entries[badIndex].slot + '. Remove tabs, hidden/control characters or excessive text before saving.';
      cards[badIndex].hidden = false;
      controls[badIndex].area.focus();
      return;
    }
    const output = {
      kind: seed.kind, version: seed.version, disposition: seed.disposition,
      authority_granted: false, consent_verified: false,
      remediation_verified: false,
      source_free_packet_sha256: seed.source_free_packet_sha256,
      warning: seed.warning,
      items: entries.map(row => ({
        slot: row.slot, reason: row.reason, count: row.count,
        stage: row.stage, note: row.note
      }))
    };
    const content = JSON.stringify(output, null, 2) + '\n';
    const blob = new Blob([content], {type: 'application/json'});
    const url = URL.createObjectURL(blob);
    const link = element('a');
    link.href = url;
    link.download = 'lightup-human-single-review-private.json';
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
    dirty = false;
    status.textContent = 'PRIVATE HUMAN journal downloaded locally. No case writeback, consent, verified repair or approval.';
  });
  document.getElementById('clear').addEventListener('click', () => {
    if (!confirm('Clear only HUMAN edits in this page? Previously downloaded PRIVATE files are NOT erased.')) return;
    for (const [i, item] of entries.entries()) {
      item.stage = 'open_human';
      item.note = '';
      controls[i].select.value = item.stage;
      controls[i].area.value = '';
    }
    changed();
    status.textContent = 'In-memory HUMAN edits reset. Download a new PRIVATE journal to preserve this choice.';
  });
  root.addEventListener('lightup-private-encrypted-journal-saved', () => {
    dirty = false;
    status.textContent = 'Encrypted PRIVATE source-bound HUMAN journal downloaded. ' +
      'No plaintext download made by this action; keep the passphrase separately.';
  });
  // Only the locally CSP-hash-pinned vault reader dispatches this in-page
  // event after authenticating the encrypted bytes and the source-bound
  // original HUMAN reason inventory. There is no browser storage or network.
  root.addEventListener('lightup-private-sourcebound-restore', event => {
    const restored = event.detail;
    if (!Array.isArray(restored) || restored.length !== entries.length) {
      status.textContent = 'HOLD: encrypted HUMAN source inventory not admissible.';
      return;
    }
    for (let i = 0; i < restored.length; i++) {
      const next = restored[i];
      const old = entries[i];
      if (next.slot !== old.slot || next.reason !== old.reason ||
          next.count !== old.count || !choices.includes(next.stage) ||
          !nativeAdmissible({...next})) {
        status.textContent = 'HOLD: source-bound encrypted HUMAN reasons changed.';
        return;
      }
    }
    for (let i = 0; i < restored.length; i++) {
      entries[i].stage = restored[i].stage;
      entries[i].note = restored[i].note;
      controls[i].select.value = entries[i].stage;
      controls[i].area.value = entries[i].note;
    }
    changed();
    status.textContent = 'Encrypted private HUMAN journal opened only in browser memory. ' +
      'Save a new encrypted .luhj before closing. No authenticated consent or fixes.';
  });
  window.addEventListener('beforeunload', event => {
    if (!dirty) return;
    event.preventDefault();
    event.returnValue = '';
  });
  refresh();
})();