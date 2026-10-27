'use strict';
// Separate offline-only PRIVATE HUMAN journal encryption controller.
// Browser Web Crypto seals the original native journal DIRECTLY into .luhj.
// No fetch, persistent browser storage, network, API, grant or scanner.
(() => {
  const seed = JSON.parse(document.getElementById('seed').textContent);
  const button = document.getElementById('encrypt-journal');
  const status = document.getElementById('status');
  const secret = document.getElementById('journal-password');
  const confirm = document.getElementById('journal-confirm');
  const AAD = 'LIGHTUP_PRIVATE_SOURCEBOUND_HUMAN_JOURNAL_AES_GCM_V1';
  const states = new Set(['open_human', 'ask_source_owner',
                          'in_discussion_human', 'answered_human_only']);
  const enc = new TextEncoder();
  let busy = false;

  function validNote(note) {
    return typeof note === 'string' && [...note].length <= 240 &&
      enc.encode(note).length <= 960 &&
      !/\p{C}/u.test(note.replaceAll('\n', ''));
  }
  function gather() {
    const cards = [...document.querySelectorAll('#reasons article')];
    if (cards.length !== seed.items.length) throw Error('Original reason rows differ');
    const items = seed.items.map((entry, index) => {
      const state = cards[index].querySelector('select')?.value;
      const note = cards[index].querySelector('textarea')?.value;
      if (!states.has(state) || !validNote(note)) {
        throw Error('Original HUMAN reason row ' + (index + 1) +
                    ' has a non-admissible status or note');
      }
      return {slot: entry.slot, reason: entry.reason, count: entry.count,
              stage: state, note};
    });
    return {
      kind: seed.kind, version: seed.version, disposition: seed.disposition,
      authority_granted: false, consent_verified: false,
      remediation_verified: false,
      source_free_packet_sha256: seed.source_free_packet_sha256,
      warning: seed.warning, items
    };
  }
  function admissiblePassword(p) {
    return typeof p === 'string' && [...p].length >= 14 &&
      [...p].length <= 256 && p.trim() === p && p.normalize('NFC') === p &&
      !/\p{C}/u.test(p);
  }
  function b64(bytes) {
    let out = '';
    for (let i = 0; i < bytes.length; i += 8192) {
      out += String.fromCharCode(...bytes.subarray(i, i + 8192));
    }
    return btoa(out);
  }
  function canonicalAscii(doc) {
    const keys = Object.keys(doc).sort();
    const result = {};
    for (const key of keys) result[key] = doc[key];
    // Python json.dumps(sort_keys=True, separators=(',',':'), ensure_ascii=True)
    // serializes non-ASCII UTF-16 code units as lowercase escaped hex.
    return JSON.stringify(result)
      .replace(/[\u007f-\uffff]/g, c => '\\u' +
        c.charCodeAt(0).toString(16).padStart(4, '0')) + '\n';
  }
  function download(ciphertext) {
    const blob = new Blob([ciphertext], {type: 'application/json'});
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'lightup-human-sourcebound-private.luhj';
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
  }
  button.addEventListener('click', async () => {
    if (busy) return;
    busy = true;
    button.disabled = true;
    try {
      if (!globalThis.crypto?.subtle || !crypto.getRandomValues) {
        throw Error('Web Crypto unavailable in this trusted local browser');
      }
      const journal = gather();
      const plaintext = enc.encode(JSON.stringify(journal, null, 2) + '\n');
      if (plaintext.length === 0 || plaintext.length > 262144) {
        throw Error('Original source-bound HUMAN journal exceeds native size bound');
      }
      const pass = secret.value;
      if (!admissiblePassword(pass) || pass !== confirm.value) {
        throw Error('Passphrases differ or must be NFC, 14–256 characters, no outer spaces/control marks');
      }
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const rawKey = await crypto.subtle.importKey(
        'raw', enc.encode(pass), {name: 'PBKDF2'}, false, ['deriveKey']);
      const key = await crypto.subtle.deriveKey(
        {name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256'},
        rawKey, {name: 'AES-GCM', length: 256}, false, ['encrypt']);
      const encrypted = new Uint8Array(await crypto.subtle.encrypt(
        {name: 'AES-GCM', iv: nonce, additionalData: enc.encode(AAD), tagLength: 128},
        key, plaintext));
      const envelope = {
        kind: 'lightup.private_sourcebound_human_journal_vault',
        schema_version: 1, disposition: 'ENCRYPTED_HUMAN_JOURNAL_NOT_ACTION_AUTHORITY',
        kdf: 'PBKDF2-HMAC-SHA256', iterations: 600000,
        salt_b64: b64(salt), nonce_b64: b64(nonce), ciphertext_b64: b64(encrypted),
        authority_granted: false, consent_verified: false,
        remediation_verified: false, warning: seed.vault_warning
      };
      const serialized = canonicalAscii(envelope);
      if (enc.encode(serialized).length > 360000) {
        throw Error('Encrypted HUMAN source-bound journal envelope too large');
      }
      download(serialized);
      document.getElementById('reasons').dispatchEvent(
        new CustomEvent('lightup-private-encrypted-journal-saved'));
      status.textContent = 'PRIVATE source-bound journal encrypted locally (.luhj). ' +
        'No plaintext download made by this action. Passphrase loss is permanent.';
    } catch (e) {
      status.textContent = 'HOLD: encrypted PRIVATE journal not created: ' +
        (e instanceof Error ? e.message : 'browser cryptography unavailable');
    } finally {
      secret.value = '';
      confirm.value = '';
      busy = false;
      button.disabled = false;
    }
  });
})();
