# Private Scope Packet Vault — offline encrypted handoff (DRAFT/HOLD)

**Status:** LightUp INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. This is human-preparation tooling, **not** client identity, signed evidence, verified approval, authorization, a scanner, a permit, or release readiness.

## Use it

Open [scope-vault/index.html](../scope-vault/index.html) in a modern browser that supports secure-context Web Crypto. The page has **no dependencies, backend, network requests or persistent browser storage**. Save the three files `index.html`, `style.css` and `vault.js` side by side, then open `index.html`. A browser that denies Web Crypto to file URLs will refuse encryption; use a browser that permits Web Crypto in a local secure context. Do not host on a public site or disable CSP to work around it.

1. Choose one or more *non-secret*, UTF-8 draft files (.json, .md, .txt, .ics or .csv; up to 12 files, 512 KiB each, 2 MiB total). Studio v1 proposals, private coordination drafts and anonymous schedule handoffs can be preserved **as opaque files**. The vault never validates their authorization semantics and never replaces the canonical source-side validation.
2. Enter the same passphrase of at least 14 characters twice. Click **Download encrypted** to obtain `lightup-private-scope-packet.lightup-vault.json`. Store the passphrase separately. There is no backend and no recovery service.
3. To restore, choose the saved encrypted JSON and enter the passphrase. The entire payload must pass authenticated decryption, exact schema checks, digest verification, UTF-8 validation, filename and byte limits **before** any prior in-memory workspace is replaced.
4. Original decrypted files are downloaded only by an explicit secondary click and confirmation. Anyone with access to that plaintext download can see the contents. Click **Lock immediately** to clear retained in-tab buffers. Hiding the tab automatically locks unless an operation is in progress; inactivity also locks after five minutes. The browser and OS may retain transient copies outside JavaScript's control.

## File format

Outer JSON exposes only the cryptographic parameters and encrypted bytes: exact version, PBKDF2-SHA256, 600,000 iterations, 16-byte random salt, AES-256-GCM, 12-byte random IV, and ciphertext including an authenticated 128-bit tag. Each export uses fresh cryptographic randomness. The AES-GCM additional authenticated data is the constant `LIGHTUP-SCOPE-PACKET-V1`. **Filenames, file count, timestamps, content and per-file SHA-256 digests are encrypted.**

The authenticated inner payload has a version, UTC time, an explicit set of literally false action/consent/release flags, and a bounded collection of UTF-8 files with original name, byte size, SHA-256 and encoded bytes. The SHA-256 values are integrity fingerprints, **not signatures, client identity or evidence that consent was granted**. Restoration is atomic with respect to application-level state.

The format is intentionally **not interoperable with actual LightUp execution grants, live tokens, authorization DB records, web request endpoints or scope evaluator claims**.

## Boundaries and caveats

- Untrusted input is only interpreted as a bounded local file or encrypted packet; no HTML preview, script execution, network access, localStorage or server sync.
- Human reviewers must independently authenticate both the actual client and operator, verify exact asset scope and risk, check the current revocation state at action time, and complete the original mandatory CI/security/privacy/release gates. Encrypted export and restore are never approval.
- Avoid importing credentials or customer production secrets. A weak or reused passphrase can be guessed offline; PBKDF2 is a slowing mechanism, not a substitute for a strong passphrase. There is no account recovery or rotation feature.
- In-memory wiping is best-effort; ordinary JavaScript strings, browser downloads, snapshots, caches and OS swap cannot be provably zeroized. A downloaded plaintext file is outside this app's control. This is a convenience confidentiality tool, **not a regulated secrets vault**.
- Do **not** merge or deploy this isolated new-path feature without the repository's original exact-head hosted and permanently registered VPS CI, independent security/privacy review, source-owner integration and explicit human GO. No tests/QA suites were added or run under the 17 October execution policy.

## Isolation

This branch adds only `scope-vault/index.html`, `scope-vault/style.css`, `scope-vault/vault.js` and this documentation. It does not modify the active owners' PRs #1566, #1567, #1569, #1570, #1571, #1572 or #1573; production `src/lightup` code, policies, consent/grant stores, CI/workflows, VPS runners, network adapters and deployment are untouched.
