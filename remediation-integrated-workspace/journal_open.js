'use strict';
// Memory-only, source-bound encrypted HUMAN journal reopening for an
// independently admitted SINGLE native Cockpit. No network or storage.
(() => {
  const seed = JSON.parse(document.getElementById('seed').textContent);
  const input = document.getElementById('vault-file');
  const password = document.getElementById('vault-password');
  const button = document.getElementById('open-vault');
  const status = document.getElementById('status');
  const target = document.getElementById('reasons');
  const enc = new TextEncoder();
  const dec = new TextDecoder('utf-8', {fatal: true});
  const AAD = 'LIGHTUP_PRIVATE_SOURCEBOUND_HUMAN_JOURNAL_AES_GCM_V1';
  const stages = new Set(['open_human', 'ask_source_owner',
                          'in_discussion_human', 'answered_human_only']);
  const columns = ['slot', 'reason', 'count', 'stage', 'note'];
  const envelopeNames = [
    'kind', 'schema_version', 'disposition', 'kdf', 'iterations',
    'salt_b64', 'nonce_b64', 'ciphertext_b64',
    'authority_granted', 'consent_verified', 'remediation_verified', 'warning'
  ].sort();
  let busy = false;

  function require(value, why) {
    if (!value) throw Error(why);
  }
  function objectShape(item, names) {
    return item !== null && typeof item === 'object' && !Array.isArray(item) &&
      JSON.stringify(Object.keys(item).sort()) === JSON.stringify([...names].sort());
  }
  function asciiCanonical(obj) {
    const sorted = {};
    for (const name of Object.keys(obj).sort()) sorted[name] = obj[name];
    return JSON.stringify(sorted)
      .replace(/[\u007f-\uffff]/g,
        ch => '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0')) + '\n';
  }
  function decodeBase64(text, min, max) {
    require(typeof text === 'string' && text.length < 360000 &&
            /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text),
            'Encrypted HUMAN field is not canonical base64');
    const binary = atob(text);
    require(binary.length >= min && binary.length <= max &&
            btoa(binary) === text, 'Encrypted HUMAN field outside original bound');
    return Uint8Array.from(binary, c => c.charCodeAt(0));
  }
  function validNote(note) {
    return typeof note === 'string' && [...note].length <= 240 &&
      enc.encode(note).length <= 960 &&
      !/\p{C}/u.test(note.replaceAll('\n', ''));
  }
  function originalBoundJournal(journal) {
    const schema = ['kind', 'version', 'disposition', 'authority_granted',
      'consent_verified', 'remediation_verified', 'warning',
      'source_free_packet_sha256', 'items'];
    require(objectShape(journal, schema) && journal.kind === seed.kind &&
            Number.isInteger(journal.version) && journal.version === 1 &&
            journal.disposition === seed.disposition &&
            journal.authority_granted === false &&
            journal.consent_verified === false &&
            journal.remediation_verified === false &&
            journal.warning === seed.warning &&
            journal.source_free_packet_sha256 === seed.source_free_packet_sha256 &&
            Array.isArray(journal.items) &&
            journal.items.length === seed.items.length,
            'Encrypted HUMAN journal does not match this original source-free Cockpit');
    for (const [index, item] of journal.items.entries()) {
      const previous = seed.items[index];
      require(objectShape(item, columns) &&
              Number.isInteger(item.slot) && item.slot === previous.slot &&
              Number.isInteger(item.count) && item.count === previous.count &&
              item.reason === previous.reason &&
              stages.has(item.stage) && validNote(item.note),
              'Encrypted HUMAN source-bound reason ' + (index + 1) + ' was changed');
    }
    return journal.items;
  }
  button.addEventListener('click', async () => {
    if (busy) return;
    busy = true;
    button.disabled = true;
    try {
      require(globalThis.crypto?.subtle,
              'Browser Web Crypto unavailable for PRIVATE in-memory journal reopening');
      const file = input.files?.[0];
      require(file && file.size >= 1 && file.size <= 360000,
              'Choose exactly one bounded source-bound .luhj private file');
      const pass = password.value;
      require([...pass].length >= 14 && [...pass].length <= 256 &&
              pass === pass.trim() && pass.normalize('NFC') === pass &&
              !/\p{C}/u.test(pass), 'Private passphrase format invalid');
      const rawBytes = new Uint8Array(await file.arrayBuffer());
      const originalText = dec.decode(rawBytes);
      const envelope = JSON.parse(originalText);
      require(objectShape(envelope, envelopeNames) &&
              asciiCanonical(envelope) === originalText &&
              envelope.kind === 'lightup.private_sourcebound_human_journal_vault' &&
              envelope.schema_version === 1 &&
              envelope.disposition === 'ENCRYPTED_HUMAN_JOURNAL_NOT_ACTION_AUTHORITY' &&
              envelope.kdf === 'PBKDF2-HMAC-SHA256' &&
              envelope.iterations === 600000 &&
              envelope.authority_granted === false &&
              envelope.consent_verified === false &&
              envelope.remediation_verified === false &&
              envelope.warning === seed.vault_warning,
              'Noncanonical or unauthorized encrypted HUMAN journal envelope');
      const salt = decodeBase64(envelope.salt_b64, 16, 16);
      const nonce = decodeBase64(envelope.nonce_b64, 12, 12);
      const ciphertext = decodeBase64(envelope.ciphertext_b64, 17, 262160);
      const master = await crypto.subtle.importKey(
        'raw', enc.encode(pass), {name: 'PBKDF2'}, false, ['deriveKey']);
      const key = await crypto.subtle.deriveKey(
        {name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256'},
        master, {name: 'AES-GCM', length: 256}, false, ['decrypt']);
      let clearBytes;
      try {
        clearBytes = new Uint8Array(await crypto.subtle.decrypt(
          {name: 'AES-GCM', iv: nonce, additionalData: enc.encode(AAD), tagLength: 128},
          key, ciphertext));
      } catch {
        throw Error('Wrong passphrase or modified encrypted PRIVATE HUMAN journal');
      }
      require(clearBytes.length > 0 && clearBytes.length <= 262144,
              'Decrypted private HUMAN journal exceeds native size limit');
      const decoded = dec.decode(clearBytes);
      const items = originalBoundJournal(JSON.parse(decoded));
      // The other CSP-hash-pinned local script holds editable original
      // journal state. Transfer only native-bound row values in memory.
      target.dispatchEvent(new CustomEvent('lightup-private-sourcebound-restore',
                                           {detail: items}));
    } catch (e) {
      status.textContent = 'HOLD: PRIVATE encrypted HUMAN journal not opened: ' +
        (e instanceof Error ? e.message : 'invalid encrypted source data');
    } finally {
      password.value = '';
      input.value = '';
      busy = false;
      button.disabled = false;
    }
  });
})();
