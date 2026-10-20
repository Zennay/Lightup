#!/usr/bin/env python3
"""Build a portable source-free HUMAN editor for PRIVATE ledger.json.

The HTML is local-only software; it has no sample/source/customer data embedded.
The Python ledger CLI remains the authoritative fail-closed importer.
"""
from __future__ import annotations
import base64
import hashlib
import html

SCRIPT = r"""
(() => {
  'use strict';
  const input = document.getElementById('source');
  const status = document.getElementById('status');
  const rows = document.getElementById('rows');
  const exportButton = document.getElementById('export');
  const carryInput = document.getElementById('carry');
  const csvInput = document.getElementById('resume');
  const humanInput = document.getElementById('human-final');
  const queryInput = document.getElementById('query');
  const stageFilter = document.getElementById('stage-filter');
  const summary = document.getElementById('summary');
  let dirty = false;
  let current = [];
  let currentDigest = null;
  const STAGES = ['needs_review', 'owner_followup', 'hold', 'reference_only'];
  const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  const escCsv = value => '"' + String(value).replace(/"/g, '""') + '"';
  function confirmOverwrite() {
    return !dirty || window.confirm(
      'Your PRIVATE HUMAN edits have not been exported. Discard these local changes?'
    );
  }
  function validHuman(row) {
    return STAGES.includes(row.stage) && typeof row.owner === 'string' &&
      typeof row.question === 'string' && row.owner.length <= 80 &&
      row.question.length <= 500 && !/[\x00-\x1f]/.test(row.owner + row.question) &&
      !/^\s*[=+\-@]/.test(row.owner) && !/^\s*[=+\-@]/.test(row.question);
  }
  function updateView() {
    const q = queryInput.value.trim().toLocaleLowerCase();
    const chosen = stageFilter.value;
    let shown = 0;
    const counts = Object.fromEntries(STAGES.map(x => [x, 0]));
    for (const row of current) {
      const stage = row.stage.value;
      counts[stage] = (counts[stage] || 0) + 1;
      const matches = (!q || (row.label + ' ' + row.ordinal + ' ' +
        row.owner.value + ' ' + row.question.value).toLocaleLowerCase().includes(q)) &&
        (chosen === 'all' || chosen === stage);
      row.article.hidden = !matches;
      if (matches) shown++;
    }
    summary.textContent = current.length
      ? shown + ' of ' + current.length + ' PRIVATE kits visible. ' +
        STAGES.map(x => x.replaceAll('_',' ') + ': ' + counts[x]).join(' · ') +
        (dirty ? ' · UNSAVED HUMAN EDITS' : '')
      : 'No PRIVATE ledger loaded.';
  }
  function markDirty() { dirty = true; updateView(); }
  rows.addEventListener('input', markDirty);
  rows.addEventListener('change', markDirty);
  queryInput.addEventListener('input', updateView);
  stageFilter.addEventListener('change', updateView);

  // Strict finite single-pass CSV parser for native ledger.py HUMAN-review.csv.
  // No formula evaluation, multiline cells, partial import, or implicit row repair.
  function parseHumanCsv(text) {
    if (text.length > 65536 || text.includes('\r') || text.includes('\0'))
      throw new Error('Oversized or control-containing CSV');
    const table = [];
    let row = [], field = '', quoted = false, closed = false, started = false;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (quoted) {
        if (ch === '"') {
          if (text[i+1] === '"') { field += '"'; i++; }
          else { quoted = false; closed = true; }
        } else {
          if (ch === '\n') throw new Error('Multiline HUMAN value');
          field += ch;
        }
      } else if (ch === ',') {
        row.push(field); field = ''; closed = false; started = false;
      } else if (ch === '\n') {
        row.push(field);
        table.push(row);
        row = []; field = ''; closed = false; started = false;
      } else if (ch === '"' && !started && !closed && field === '') {
        quoted = true; started = true;
      } else if (ch === '"' || closed) {
        throw new Error('Malformed quoting in HUMAN CSV');
      } else {
        field += ch; started = true;
      }
      if (table.length > 13 || field.length > 700) throw new Error('HUMAN CSV limits');
    }
    if (quoted) throw new Error('Unterminated HUMAN CSV');
    if (started || closed || field !== '' || row.length) {
      row.push(field); table.push(row);
    }
    const head = table[0] && table[0].join(',');
    const modern = head === 'ordinal,ledger_sha256,kit_digest,stage,owner,question';
    const legacy = head === 'ordinal,kit_digest,stage,owner,question';
    if (!modern && !legacy) throw new Error('Unexpected HUMAN CSV header');
    if (modern && !currentDigest) throw new Error('Exact original ledger digest unavailable');
    if (table.length !== current.length + 1)
      throw new Error('Wrong number of HUMAN rows');
    const result = table.slice(1).map((r, i) => {
      if (r.length !== (modern ? 6 : 5) || r[0] !== String(current[i].ordinal) ||
          (modern && r[1] !== currentDigest) || r[modern ? 2 : 1] !== current[i].digest)
        throw new Error('HUMAN CSV original ledger/kit identity mismatch');
      const offset = modern ? 1 : 0;
      const obj = {stage:r[2+offset],owner:r[3+offset],question:r[4+offset]};
      if (!validHuman(obj)) throw new Error('Invalid HUMAN status or text');
      return obj;
    });
    return {rows:result, legacy};
  }

  function refuse(msg) {
    current = [];
    currentDigest = null;
    carryInput.disabled = true;
    csvInput.disabled = true;
    humanInput.disabled = true;
    dirty = false;
    rows.replaceChildren();
    updateView();
    exportButton.disabled = true;
    status.textContent = 'HOLD — ' + msg + '. Existing edits discarded; no export.';
  }
  function node(tag, text) {
    const el = document.createElement(tag);
    el.textContent = text;
    return el;
  }
  function control(tag, opts = {}) {
    const el = document.createElement(tag);
    for (const [key, value] of Object.entries(opts)) el.setAttribute(key, value);
    return el;
  }
  function isPrivateDraft(data) {
    if (!data || typeof data !== 'object' || Array.isArray(data) ||
        data.schema !== 'lightup.private.workspace-ledger.v1' ||
        !data.authority || typeof data.authority !== 'object' ||
        Array.isArray(data.authority) ||
        Object.keys(data.authority).sort().join(',') !== [
          'authorization','consent','release_approval','source_authentication',
          'verified_finding','verified_remediation'].sort().join(',') ||
        Object.values(data.authority).some(v => v !== false) ||
        !Array.isArray(data.kits) || data.kits.length < 1 || data.kits.length > 12) return false;
    return data.kits.every((kit, i) => kit && typeof kit === 'object' &&
      kit.ordinal === i + 1 && hex(kit.digest) &&
      typeof kit.label === 'string' && kit.label.length > 0 &&
      kit.label.length <= 96 && Array.isArray(kit.files) &&
      kit.files.length >= 1 && kit.files.length <= 256 &&
      Number.isSafeInteger(kit.bytes) && kit.bytes >= 0);
  }
  input.addEventListener('change', async () => {
    const file = input.files && input.files[0];
    if (!file) return;
    if (!confirmOverwrite()) { input.value = ''; return; }
    if (file.size < 8 || file.size > 1048576 || file.name !== 'ledger.json') {
      status.textContent = 'HOLD — invalid source filename/size; current decisions kept.';
      return;
    }
    let data, hexDigest = null;
    try {
      const buffer = await file.arrayBuffer();
      data = JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(buffer));
      if (globalThis.crypto && crypto.subtle) {
        const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', buffer));
        hexDigest = Array.from(bytes, b => b.toString(16).padStart(2,'0')).join('');
      }
    } catch (_) {
      status.textContent = 'HOLD — unreadable PRIVATE ledger; current edits preserved.'; return;
    }
    if (!isPrivateDraft(data)) {
      status.textContent = 'HOLD — invalid or authority-claiming ledger; current edits preserved.'; return;
    }
    const fragment = document.createDocumentFragment();
    const entries = [];
    for (const kit of data.kits) {
      const article = node('article', '');
      const heading = node('h2', 'Kit ' + kit.ordinal + ': ' + kit.label);
      const subtitle = node('p', kit.files.length + ' local files · ' + kit.bytes +
        ' bytes · source-reported, unsigned SHA prefix: ' + kit.digest.slice(0, 12));
      const stageLabel = node('label', 'HUMAN status');
      const stage = control('select');
      for (const name of STAGES) {
        const opt = control('option', {value: name});
        opt.textContent = name.replaceAll('_', ' ');
        stage.appendChild(opt);
      }
      const ownerLabel = node('label', 'Proposed owner (optional, max 80)');
      const owner = control('input', {type:'text', maxlength:'80', autocomplete:'off'});
      const questionLabel = node('label', 'Next HUMAN question (optional, max 500)');
      const question = control('textarea', {maxlength:'500', rows:'3'});
      stageLabel.append(stage);
      ownerLabel.append(owner);
      questionLabel.append(question);
      article.append(heading, subtitle, stageLabel, ownerLabel, questionLabel);
      fragment.appendChild(article);
      entries.push({ordinal:kit.ordinal, digest:kit.digest, label:kit.label,
                    article, stage, owner, question});
    }
    current = entries;
    currentDigest = hexDigest;
    carryInput.disabled = !hexDigest;
    csvInput.disabled = false;
    humanInput.disabled = !hexDigest;
    dirty = false;
    rows.replaceChildren(fragment);
    updateView();
    status.textContent = 'PRIVATE HUMAN draft loaded. No client identity, original verification or consent established.';
    exportButton.disabled = !hexDigest;
    if (!hexDigest) status.textContent = 'HOLD — browser cannot compute exact original ledger SHA-256 in this context.';
  });
  carryInput.addEventListener('change', async () => {
    if (!current.length || !currentDigest) {
      status.textContent = 'HOLD — first load exact original ledger.json using a secure offline browser.';
      return;
    }
    const file = carryInput.files && carryInput.files[0];
    if (!file || file.name !== 'HUMAN-carry.json' || file.size < 8 || file.size > 1048576) {
      status.textContent = 'HOLD — choose native source-bound HUMAN-carry.json (<= 1 MiB).';
      return;
    }
    let packet;
    try {
      packet = JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(await file.arrayBuffer()));
    } catch (_) {
      status.textContent = 'HOLD — malformed HUMAN-carry.json; current edits kept.';
      return;
    }
    const authority = packet && packet.authority;
    const expectedKeys = ['authorization','consent','release_approval',
      'source_authentication','verified_finding','verified_remediation'];
    const allowedAuthority = authority && typeof authority === 'object' &&
      !Array.isArray(authority) &&
      Object.keys(authority).sort().join(',') === expectedKeys.sort().join(',') &&
      Object.values(authority).every(v => v === false);
    const validRows = packet && Array.isArray(packet.rows) &&
      packet.rows.length === current.length &&
      packet.rows.every((row,i) => {
        if (!row || typeof row !== 'object' || Array.isArray(row) ||
            Object.keys(row).sort().join(',') !==
            ['ordinal','kit_digest','stage','owner','question','carried'].sort().join(','))
          return false;
        const oldSource = current[i];
        if (row.ordinal !== oldSource.ordinal || row.kit_digest !== oldSource.digest ||
            !STAGES.includes(row.stage) || typeof row.owner !== 'string' ||
            typeof row.question !== 'string' || typeof row.carried !== 'boolean' ||
            row.owner.length > 80 || row.question.length > 500 ||
            /[\x00-\x1f]/.test(row.owner+row.question) ||
            /^[\s]*[=+\-@]/.test(row.owner) || /^[\s]*[=+\-@]/.test(row.question))
          return false;
        return row.carried || (row.stage === 'needs_review' &&
                                row.owner === '' && row.question === '');
      });
    if (!allowedAuthority || packet.schema !== 'lightup.private.workspace-ledger-carry.v1' ||
        packet.current_ledger_sha256 !== currentDigest ||
        !hex(packet.previous_ledger_sha256) || !hex(packet.previous_human_sha256) ||
        packet.requires_human_reconfirmation !== true || !validRows) {
      status.textContent = 'HOLD — carried HUMAN data does not match source bytes/ordinals. Existing edits kept.';
      return;
    }
    if (!confirmOverwrite()) {
      status.textContent = 'PRIVATE prior edits retained; continuation not applied.';
      return;
    }
    for (const [i,row] of packet.rows.entries()) {
      const target = current[i];
      target.stage.value = row.stage;
      target.owner.value = row.owner;
      target.question.value = row.question;
    }
    dirty = true;
    updateView();
    status.textContent = 'PRIVATE HUMAN proposals restored against EXACT ledger bytes; ' +
      'reconfirm every stage and export a NEW decision CSV. No permission or approval inherited.';
  });

  csvInput.addEventListener('change', async () => {
    if (!current.length) {
      status.textContent = 'HOLD — load original ledger.json before CSV restore.';
      return;
    }
    const file = csvInput.files && csvInput.files[0];
    if (!file || file.name !== 'HUMAN-review.csv' || file.size < 16 ||
        file.size > 65536) {
      status.textContent = 'HOLD — choose original PRIVATE HUMAN-review.csv <= 64KiB.';
      return;
    }
    let imported;
    try {
      imported = parseHumanCsv(
        new TextDecoder('utf-8', {fatal:true}).decode(await file.arrayBuffer())
      );
    } catch (_) {
      status.textContent = 'HOLD — HUMAN CSV invalid, incomplete or bound to different kit bytes. Edits retained.';
      return;
    }
    if (imported.legacy && !window.confirm(
      'LEGACY CSV has NO full ledger binding. Kit bytes match, but original case context may differ. ' +
      'Load only as UNTRUSTED HUMAN DRAFT, manually review all fields, then export new exact-ledger v2?'
    )) {
      status.textContent = 'Unbound legacy HUMAN CSV was not imported.';
      return;
    }
    if (!confirmOverwrite()) {
      status.textContent = 'Previous unsaved HUMAN decisions retained.';
      return;
    }
    for (const [i,row] of imported.rows.entries()) {
      current[i].stage.value = row.stage;
      current[i].owner.value = row.owner;
      current[i].question.value = row.question;
    }
    dirty = true;
    updateView();
    status.textContent = imported.legacy
      ? 'LEGACY UNBOUND HUMAN DRAFT restored for manual review only; export a fresh v2. Native finalizer refuses old unbound CSV.'
      : 'PRIVATE HUMAN CSV restored for exact original ledger SHA and kit digests. Native finalizer rechecks all originals.';
  });

  humanInput.addEventListener('change', async () => {
    if (!current.length || !currentDigest) {
      status.textContent = 'HOLD — load original PRIVATE ledger.json first.';
      return;
    }
    const file = humanInput.files && humanInput.files[0];
    if (!file || file.name !== 'HUMAN-only.json' || file.size < 8 ||
        file.size > 1048576) {
      status.textContent = 'HOLD — choose native PRIVATE HUMAN-only.json <= 1MiB.';
      return;
    }
    let packet;
    try {
      packet = JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(await file.arrayBuffer()));
    } catch (_) {
      status.textContent = 'HOLD — malformed HUMAN-only.json; existing edits kept.';
      return;
    }
    const allowedKeys = ['schema','authority','ledger_sha256','plan_sha256','rows'];
    const flags = ['authorization','consent','release_approval','source_authentication',
      'verified_finding','verified_remediation'];
    const authority = packet && packet.authority;
    if (!packet || Array.isArray(packet) || typeof packet !== 'object' ||
        Object.keys(packet).sort().join(',') !== allowedKeys.sort().join(',') ||
        packet.schema !== 'lightup.private.workspace-ledger-human.v1' ||
        !authority || typeof authority !== 'object' || Array.isArray(authority) ||
        Object.keys(authority).sort().join(',') !== flags.sort().join(',') ||
        !Object.values(authority).every(v => v === false) ||
        packet.ledger_sha256 !== currentDigest || !hex(packet.plan_sha256) ||
        !Array.isArray(packet.rows) || packet.rows.length !== current.length ||
        !packet.rows.every((row, i) =>
          row && typeof row === 'object' && !Array.isArray(row) &&
          Object.keys(row).sort().join(',') ===
            ['ordinal','stage','owner','question','kit_digest'].sort().join(',') &&
          row.ordinal === current[i].ordinal && row.kit_digest === current[i].digest &&
          validHuman(row))) {
      status.textContent = 'HOLD — original HUMAN packet schema or source digest differs. Edits kept.';
      return;
    }
    if (!confirmOverwrite()) {
      status.textContent = 'Original unsaved edits retained; packet not imported.';
      return;
    }
    for (const [i, row] of packet.rows.entries()) {
      current[i].stage.value = row.stage;
      current[i].owner.value = row.owner;
      current[i].question.value = row.question;
    }
    dirty = true;
    updateView();
    status.textContent = 'PRIVATE HUMAN-only packet reloaded against EXACT ledger bytes. ' +
      'These are human proposals only. Reconfirm and export NEW CSV; native finalize rechecks originals.';
  });

  window.addEventListener('beforeunload', event => {
    if (dirty) { event.preventDefault(); event.returnValue = ''; }
  });

  exportButton.addEventListener('click', () => {
    if (!current.length || !currentDigest) {
      status.textContent = 'HOLD — no exact ledger SHA-256 available; no export.';
      return;
    }
    const lines = ['ordinal,ledger_sha256,kit_digest,stage,owner,question'];
    for (const row of current) {
      const owner = row.owner.value, question = row.question.value;
      if (!STAGES.includes(row.stage.value) || owner.length > 80 || question.length > 500 ||
          /[\x00-\x1f]/.test(owner + question) ||
          /^[\s]*[=+\-@]/.test(owner) || /^[\s]*[=+\-@]/.test(question)) {
        status.textContent = 'HOLD — invalid HUMAN text or spreadsheet formula. Correct before export.';
        return;
      }
      lines.push([row.ordinal, currentDigest, row.digest, row.stage.value, owner, question].map(escCsv).join(','));
    }
    const blob = new Blob([lines.join('\n') + '\n'], {type:'text/csv;charset=utf-8'});
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url; link.download = 'HUMAN-review.csv';
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    dirty = false;
    updateView();
    status.textContent = 'PRIVATE CSV download requested locally. Run native ledger.py finalize with unchanged source ledger; browser edits NEVER confer authority.';
  });
})();
"""
STYLE = """
body{font:16px/1.55 system-ui,sans-serif;margin:0;background:#f2f5f9;color:#17324c}
main{max-width:960px;margin:auto;padding:24px}
section,article{background:white;border:1px solid #c2ccdc;border-radius:12px;padding:20px;margin:16px 0}
h1{font-size:1.8rem}h2{font-size:1.2rem}
label{display:block;font-weight:600;margin:1em 0}
input,select,textarea{display:block;width:100%;box-sizing:border-box;padding:10px;
border:1px solid #7185a1;border-radius:6px;font:inherit;margin-top:4px}
button{font:inherit;padding:12px 20px;border-radius:8px}
button:disabled{opacity:.45}strong{color:#81320c}
:focus-visible{outline:3px solid #1358ac;outline-offset:3px}
"""

def render_studio():
    digest = base64.b64encode(hashlib.sha256(SCRIPT.encode("utf-8")).digest()).decode("ascii")
    policy = ("default-src 'none'; script-src 'sha256-" + digest +
              "'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; "
              "object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'")
    return ("<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<meta http-equiv='Content-Security-Policy' content=\"" + html.escape(policy, quote=True) + "\">"
            "<title>PRIVATE LightUp HUMAN Ledger Studio</title><style>" + STYLE + "</style>"
            "<main><h1>LightUp · PRIVATE HUMAN ledger Studio</h1>"
            "<section><p><strong>HOLD / PLAN-LAB ONLY.</strong> This offline browser does not authenticate "
            "the source producer, identify a tenant, certify findings, prove fixes, grant access, "
            "verify consent, release or execute an assessment. All artifacts are PRIVATE.</p>"
            "<label>Choose your native ledger.json <input type='file' id='source' accept='.json,application/json'></label>"
            "<label>Optionally restore previously proposed HUMAN stages from source-bound "
            "HUMAN-carry.json <input type='file' id='carry' accept='.json,application/json' disabled></label>"
            "<label>Or resume an exact-source locally saved HUMAN-review.csv "
            "<input type='file' id='resume' accept='.csv,text/csv' disabled></label>"
            "<label>Or reopen source-bound original finalized HUMAN-only.json "
            "<input type='file' id='human-final' accept='.json,application/json' disabled></label>"
            "<p>Resume/import never verifies current source bytes. All decisions remain HUMAN-only.</p>"
            "<p id='status' role='status' aria-live='polite'>Choose only an original locally generated "
            "PRIVATE ledger.json. Nothing is uploaded or persisted by this browser.</p></section>"
            "<section><label>Find kits by label, ordinal, proposed owner or question"
            "<input id='query' type='search' placeholder='Search locally, never uploaded'></label>"
            "<label>Filter current HUMAN stage<select id='stage-filter'><option value='all'>All statuses</option>"
            "<option value='needs_review'>Needs review</option><option value='owner_followup'>Owner follow-up</option>"
            "<option value='hold'>HOLD</option><option value='reference_only'>Reference only</option>"
            "</select></label><p id='summary' role='status'>No PRIVATE ledger loaded.</p></section>"
            "<section id='rows' aria-label='Kit HUMAN stages'></section>"
            "<section><button id='export' disabled>Save PRIVATE HUMAN-review.csv</button>"
            "<p>Export contains local unsigned kit byte fingerprints and HUMAN proposals. "
            "Native ledger.py finalize re-checks complete original source files, strict schema, "
            "the HUMAN row order and fingerprints before creating any PRIVATE packet. "
            "Source differences require HOLD, never auto-approved.</p></section>"
            "<script>" + SCRIPT + "</script></main></html>")


def main():
    """Produce a standalone source-free single-file browser studio, never overwrite."""
    import argparse
    import os
    from pathlib import Path
    parser = argparse.ArgumentParser(description="Build source-free offline HUMAN review browser (no original kits needed)")
    parser.add_argument("--output", required=True, help="Absolute filename for NEW browser-only HTML")
    args = parser.parse_args()
    path = Path(args.output)
    if not path.is_absolute() or path.suffix.lower() != ".html":
        parser.error("--output must be an absolute .html file path")
    # No source/customer/assessment bytes in the software itself.
    payload = render_studio().encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        position = 0
        while position < len(payload):
            position += os.write(fd, payload[position:])
        os.fsync(fd)
    finally:
        os.close(fd)
    print("OFFLINE software-only HTML created; human and source review still HOLD")
    print(path)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
