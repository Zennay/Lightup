# LightUp · Private Remediation Handoff Vault

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is a browser-only, independently isolated human coordination companion; it does not authenticate or authorize clients, engagements, grants, retests, scans, verified fixes or targets.

## Delivered workflow

1. Download and open [standalone.html](./standalone.html) in a WebCrypto-capable browser that treats local files as a secure context. There is no app server, model, external CSS/JS/font, API endpoint, persistent browser storage or network request. The strict CSP forbids connections, embedded frames and remote resources.
2. Use **Pack** to choose up to eight separately authorised existing LightUp *private human coordination exports* in .json, .csv, .md or .txt format. Max 2 MiB per file, 6 MiB total. Their bytes and filenames are carried exactly; the app never interprets statuses as verified security outcomes. Files must be valid UTF-8.
3. Independently confirm the actual client, exact engagement, recipient and approved private transfer channel. Enter a passphrase (at least 12 characters; pass it through a different approved channel). Click **Encrypt & download**. A single .vault.json is saved manually.
4. Use **Unlock** with that file and passphrase. Authenticated decrypt and independent SHA-256 fingerprint validation run locally, with all-or-nothing file admission; original names and private label are recovered only *inside* the decrypted payload. Download only the individual files you need after independently checking recipient authority. The clipboard feature copies only an anonymous count.
5. **Clear private session** when finished. Closing the tab also clears ordinary in-memory state, but browser/OS download histories and memory are outside this app's control.

## Technical format and safety

- Encrypted envelope format: lightup.remediation_vault.v1. PBKDF2-HMAC-SHA256 with 310,000 iterations, random 16-byte salt, 256-bit AES-GCM, unique random 12-byte IV and fixed format string as authenticated additional data.
- Original filenames, private label and source bytes live **only inside authenticated ciphertext**. Per-file SHA-256 and source byte sizes are separately enforced after decrypt; duplicate entries, illegal paths, unknown structures and oversized packets fail atomically. No password or key is saved to disk by this app.
- A version 1 serialized envelope is canonical pretty-printed JSON; other representations, unknown keys or duplicates are rejected before decrypt. GCM rejects wrong passphrases or tampered ciphertext.
- File selection and re-open are bounded. No auto-sharing, scanning, introspection of source authority, browser/local storage, remote request or backend. The ciphertext length and presence of a file remain visible. Manual decrypted downloads are sensitive plaintext.
- Encrypting does **not** establish genuine ownership, identity, original record integrity, scope, independent client/operator consent or permission. No remediation action is performed or recommended by this tool.
- Security review, source-owner approval, existing exact-head hosted and permanent named VPS CI, separately authenticated client/operator consent with at-use revocation, #177/#182/#829 and explicit HUMAN GO must still be satisfied before main merge or production use.

## Build

Run python3 remediation-vault/package.py to create the portable, CSP-hash-pinned HTML file. For direct non-QA source inspection: node --check remediation-vault/app.js and python3 -m py_compile remediation-vault/package.py. No QA/regression/test suites are included or invoked.

## Isolation

All changes are exclusively new paths under remediation-vault/. Original Casework #1568, Evidence Review #1623, unified Cockpit #1627, Calendar #1635 and Dependency Board #1638 remain unmodified. This standalone companion is suitable for independently approved, existing, human-only offline exports from those products. Never ship actual client files, passphrases or decrypted copies in source control.
