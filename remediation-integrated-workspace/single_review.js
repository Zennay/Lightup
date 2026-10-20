'use strict';
// LightUp: offline, source-free, HUMAN-only single-packet reviewer.
// No fetch, storage, cookie, network, grants, native apply, or live targets.
(() => {
  const seed = JSON.parse(document.getElementById('seed').textContent);
  const root = document.getElementById('reasons');
  const status = document.getElementById('status');
  const choices = ['open_human', 'ask_source_owner', 'in_discussion_human', 'answered_human_only'];
  const names = {
    open_human: 'Open for HUMAN review',
    ask_source_owner: 'Ask original source owner',
    in_discussion_human: 'Discuss locally (unverified)',
    answered_human_only: 'HUMAN response received (NOT fixed)'
  };
  const entries = seed.items.map(item => ({ ...item }));
  function element(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  }
  for (const [idx, row] of entries.entries()) {
    const card = element('article');
    card.appendChild(element('h3', 'Slot ' + row.slot + ' · ' + row.reason.replaceAll('_', ' ')));
    card.appendChild(element('p', row.count + ' declared HUMAN reason occurrence(s); not unique cases.'));
    card.appendChild(element('p', row.advice));
    const label = element('label', 'HUMAN follow-up state');
    const select = element('select');
    select.setAttribute('aria-label', 'HUMAN follow-up for slot ' + row.slot + ' ' + row.reason);
    for (const choice of choices) {
      const option = element('option', names[choice]);
      option.value = choice;
      select.appendChild(option);
    }
    select.value = row.stage;
    select.addEventListener('change', () => { entries[idx].stage = select.value; status.textContent = 'Unsaved local HUMAN changes.'; });
    label.appendChild(select);
    card.appendChild(label);
    const noteLabel = element('label', 'PRIVATE HUMAN note — no customer names, secrets or credentials');
    const area = element('textarea');
    area.maxLength = 240;
    area.rows = 2;
    area.value = row.note;
    area.setAttribute('aria-label', 'PRIVATE note for slot ' + row.slot + ' ' + row.reason);
    area.addEventListener('input', () => { entries[idx].note = area.value; status.textContent = 'Unsaved local HUMAN changes.'; });
    noteLabel.appendChild(area);
    card.appendChild(noteLabel);
    root.appendChild(card);
  }
  document.getElementById('save').addEventListener('click', () => {
    const output = {
      kind: seed.kind,
      version: seed.version,
      disposition: seed.disposition,
      authority_granted: false,
      consent_verified: false,
      remediation_verified: false,
      source_free_packet_sha256: seed.source_free_packet_sha256,
      warning: seed.warning,
      items: entries.map(row => ({
        slot: row.slot, reason: row.reason, count: row.count,
        stage: row.stage, note: row.note
      }))
    };
    const json = JSON.stringify(output, null, 2) + '\n';
    const blob = new Blob([json], {type: 'application/json'});
    const url = URL.createObjectURL(blob);
    const link = element('a');
    link.href = url;
    link.download = 'lightup-human-single-review-private.json';
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
    status.textContent = 'PRIVATE HUMAN-only journal downloaded locally. No source changes or approvals.';
  });
  document.getElementById('clear').addEventListener('click', () => {
    if (!confirm('Clear only the HUMAN edits on this current page? Original PRIVATE source and previously downloaded files remain unchanged.')) return;
    for (const item of entries) {
      item.stage = 'open_human';
      item.note = '';
    }
    for (const card of root.querySelectorAll('article')) {
      card.querySelector('select').value = 'open_human';
      card.querySelector('textarea').value = '';
    }
    status.textContent = 'Current in-memory edits cleared. Previously downloaded journals are NOT erased.';
  });
})();
