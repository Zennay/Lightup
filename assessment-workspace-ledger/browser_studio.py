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
  let current = [];
  const STAGES = ['needs_review', 'owner_followup', 'hold', 'reference_only'];
  const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  const escCsv = value => '"' + String(value).replace(/"/g, '""') + '"';
  function refuse(msg) {
    current = [];
    rows.replaceChildren();
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
    refuse('Choose an original PRIVATE ledger.json');
    const file = input.files && input.files[0];
    if (!file || file.size < 8 || file.size > 1048576 || file.name !== 'ledger.json') return;
    let data;
    try { data = JSON.parse(await file.text()); }
    catch (_) { refuse('Malformed JSON'); return; }
    if (!isPrivateDraft(data)) { refuse('Invalid or authority-claiming ledger'); return; }
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
      entries.push({ordinal:kit.ordinal, digest:kit.digest, stage, owner, question});
    }
    current = entries;
    rows.replaceChildren(fragment);
    status.textContent = 'PRIVATE HUMAN draft loaded. No client identity, original verification or consent established.';
    exportButton.disabled = false;
  });
  exportButton.addEventListener('click', () => {
    if (!current.length) return refuse('No ledger loaded');
    const lines = ['ordinal,kit_digest,stage,owner,question'];
    for (const row of current) {
      const owner = row.owner.value, question = row.question.value;
      if (!STAGES.includes(row.stage.value) || owner.length > 80 || question.length > 500 ||
          /[\x00-\x1f]/.test(owner + question) ||
          /^[\s]*[=+\-@]/.test(owner) || /^[\s]*[=+\-@]/.test(question)) {
        status.textContent = 'HOLD — invalid HUMAN text or spreadsheet formula. Correct before export.';
        return;
      }
      lines.push([row.ordinal, row.digest, row.stage.value, owner, question].map(escCsv).join(','));
    }
    const blob = new Blob([lines.join('\n') + '\n'], {type:'text/csv;charset=utf-8'});
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url; link.download = 'HUMAN-review.csv';
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    status.textContent = 'PRIVATE CSV downloaded locally. Run native ledger.py finalize with unchanged source ledger; browser edits NEVER confer authority.';
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
            "<p id='status' role='status' aria-live='polite'>Choose only an original locally generated "
            "PRIVATE ledger.json. Nothing is uploaded or persisted by this browser.</p></section>"
            "<section id='rows' aria-label='Kit HUMAN stages'></section>"
            "<section><button id='export' disabled>Save PRIVATE HUMAN-review.csv</button>"
            "<p>Export contains local unsigned kit byte fingerprints and HUMAN proposals. "
            "Native ledger.py finalize re-checks complete original source files, strict schema, "
            "the HUMAN row order and fingerprints before creating any PRIVATE packet. "
            "Source differences require HOLD, never auto-approved.</p></section>"
            "<script>" + SCRIPT + "</script></main></html>")


if __name__ == "__main__":
    print("This is a software module. Run ledger.py capture to generate its PRIVATE HTML.")
