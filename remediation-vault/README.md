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

## Re-encrypt an existing private packet

After unlocking a vault, the recipient can select **Re-encrypt unlocked files**, reconfirm the real recipient and exact engagement, and enter a new 12+ character passphrase. The application immediately creates a second ciphertext envelope using fresh random salt/nonce and its own SHA-256-checked original file bytes, without first saving decrypted files. The previous encrypted packet and its passphrase are **not revoked**; remove old copies separately according to the private retention policy. No original authority or finding status is changed.

## Privacy-minimal selective onward transfer

After unlocking, each recovered original file is shown with a checked **include in next private encrypted handoff** control and a separate manual plaintext-download button. Uncheck files the next authorised recipient must not receive, independently reconfirm that exact recipient/client/engagement and private channel, and re-encrypt only the selected in-memory files with a new passphrase. At least one file must remain selected. This is not consent or authority to share; do not assume every original record is permitted for a new recipient.

## Portable offline operator kit

For a single ready-to-open package, download LightUp-Private-Handoff-Vault.zip and open START-HERE.html locally, then standalone.html. Kit includes a reproducible SHA-256 MANIFEST.json, README.md and the offline app. It includes no customer source, recovered contents, keys or credentials. Build with python3 remediation-vault/package_kit.py after updating the standalone bundler.

## Five-app offline remediation composition (new)

The current deterministic portable ZIP adds unchanged SHA-pinned original Evidence Review #1623, Casework Calendar plus Owner Reply Desk #1635, and Dependency Board #1638 as separate local app entrypoints. Open START-HERE.html to navigate. Exact immutable original owner SHA-256 and source commits are in the kit MANIFEST.json. WORKFLOWS.md provides a complete private operator-to-owner-to-operator workflow. This composition does not merge, modify, supersede or publish the original source-owner PRs; no client data, grant, consent, actual retest, scanner or execution are included.

## Optional exact-ciphertext transfer receipt

After encrypting or re-encrypting a vault, download a separate small unsigned .receipt.json containing ONLY the encrypted file byte length, its SHA-256 fingerprint, an explicit false authority marker and version. It contains no original filenames, client data, labels, source hashes, recipient identity or plaintext. The receiver can select this optional receipt before unlocking; any byte mismatch fails *before* decryption. A match means only that the recipient's encrypted bytes match the separately provided anonymous fingerprint. Anybody could generate a different receipt; source authenticity, independent sender identity, actual consent and scope must still be verified outside the app. Do not treat receipt matches as authorization.

## Offline two-vault revision comparison

Unlock an existing private baseline vault, then privately select and decrypt a **second** independently received vault (a different passphrase is supported). Independently confirm the two packages are for the exact same actual client/engagement. The browser compares original file names and independently SHA-256-bound original contents: **unchanged, changed, added or absent**. An absent file is never an assertion that any finding was repaired or closed. Original baseline remains untouched, comparison is in-memory only and no source contents are uploaded or persisted. A separate anonymous JSON export contains only category counts, with all authority and verification fields literally false; private filenames, hashes, source rows and client details are not exported.

## Confidential file-level revision report

Following two source-bound local private vault unlocks, deliberately confirm the real recipient, client, exact engagement and approved private channel. Export a PRIVATE JSON report listing original filenames, original file SHA-256/size before and after, changed/unchanged/added/absent classification, anonymous counts and encrypted vault SHA-256 fingerprints binding which two ciphertext packets were compared. No raw original file content is exported. Filenames and hashes can be sensitive and must be re-encrypted before transmission if the original approved channel requires it. All identity, consent, source and remediation/retest authority flags are false. An absent file NEVER means a resolved finding; no source is changed.

## Private session and minimum disclosure

The single **Clear private session** control reliably clears private browser selections. The original anonymous-count clipboard handler is initialized on the full standalone. Following unlock, onward-handoff checkboxes start **unselected**, requiring a deliberate per-file minimum disclosure decision; changing this choice clears the previous human recipient acknowledgement. The private decrypted payload parser also refuses noncanonical or duplicate-key JSON inside the authenticated envelope instead of accepting ambiguous source structures. This does not establish client identity or permission.

## Seven-app complete offline remediation edition

The current ZIP adds unchanged source-owner Capacity Studio #1583 and Funding Studio #1586 to the original five-app preview. Both are SHA-256-pinned to immutable original commits. Capacity consumes separately authorized original finding/Casework human data; Funding consumes only the original aggregate Capacity draft. No actual staffing, funding commitment, verified remediation, consent, grant, scan or release is created. The separately owned latest Client Brief #1582 is NOT included: its 152 KiB upstream standalone exceeded the connected zSSH scoped maximum file size and that restriction was respected without alternate bypass. Obtain Client Brief independently from its own held source-owner PR if separately permitted; it is not part of this offline package.
