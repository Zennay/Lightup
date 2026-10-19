# LightUp · PRIVATE Casebook Transfer

**INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** Human-private offline transport only. This feature is an add-only companion to [the original Casebook](../docs/authorization-casebook-20261018.md) and the [held original-source Casebook history PR #1668](https://github.com/Zennay/Lightup/pull/1668), pinned at `2e10197061fe7876dcd6458ae4fc70d9674af9d3`. No source-owner code, network, grants, scanner, authentication, CI, tests or QA paths are modified.

## Operator workflow

Open [standalone.html](standalone.html) **locally in a current secure-context browser**, or open `transfer.html` with both adjacent `transfer.js` and `transfer.css` files (when local browser CSP permits local relative assets). The portable standalone version has SHA-256 CSP-pinned inline CSS and JavaScript, zero external dependencies or fetch.

1. Use the **original** authenticated Casebook producer to capture `casebook-01.json` through `casebook-NN.json`, contiguous from 01, up to 12. Those originals come from the original held branch, not from this new transport. Optionally include the exact generated current-HUMAN-only `workroom-current-template.csv` (not the historical multi-moment `private-human-review-template.csv`). Do not use client data on a shared/untrusted device.
2. In the local transfer page, select those files (each max 4 MiB; all files max 12 MiB; max 13 entries). Supply a strong distinct password of at least 12 Unicode characters. Acknowledge this is **not authorization**. Click **Maak versleutelde PRIVATE overdracht**. It immediately downloads `lightup-casebook-private-transfer.lupt` as an opaque octet-stream.
3. Move the encrypted file over your approved secure human handoff channel. Communicate the password **separately** using an approved route. The password is not saved by this application, so losing it loses access to the handoff. Do not treat encryption as evidence of who produced the original snapshots.
4. On the receiving trusted offline device, open the same standalone page, select the exact `.lupt` filename and enter the password. The entire ciphertext is authenticated and the complete canonical v1 payload re-admitted before the page asks for confirmation. Wrong passwords, changed bytes, unexpected names, repeated names, changed SHA-256, missing chronology ordinals, unknown extra fields and over-size payloads are refused **without replacing the previously loaded local workset**.
5. Only after manual confirmation, use the per-record **Exporteer exacte bytes** buttons to recover the original selected bytes as downloads. Reopen those files using the **original trusted Casebook/history validators**. This tool never issues a grant or modifies the LightUp database. Its digest is an internal transport continuity check, **not source authentication**.
6. For a second approved HUMAN recipient, enter a different local password under **Beveiligde dooroverdracht** after loading or restoring a workset. The app performs a fresh AES-GCM encryption **directly from the in-memory original bytes**, with a new salt and nonce, downloading a new encrypted file **without producing extra plaintext exports**. The previous encrypted file and the original source files are not overwritten. Human review of the new recipient and channel remains necessary.

## Design boundary

- Offline WebCrypto `PBKDF2-SHA256` with 310,000 iterations, cryptographically random 16-byte salt, `AES-256-GCM` with a fresh 12-byte nonce for every export. Nonces and salt are chosen by the browser CSPRNG; original files are encrypted **without any lossy text decoding**.
- The encrypted v1 envelope is strict canonical JSON, carries an authenticated encrypted v1 body with exact original byte lengths/digests, and is bounded to 26 MiB. Unknown/duplicate keys or extra properties fail canonical re-serialization, before passwords are used. Expected file names/contiguous ordinals, no duplicate entries, exact SHA-256 byte rechecks, byte limits and a single all-or-nothing in-memory handoff are required.
- No analytics, HTTP(S), network, sessions, browser storage, service worker, authentication, grants, target use, model calls, clipboard reads or automatic plain file persistence. The portable HTML embeds local JS/CSS with **hash-pinned CSP**; all displayed filenames are pre-admitted fixed patterns and inserted as text nodes. Downloads are explicit and use `application/octet-stream`, not HTML execution.
- Clear releases references and overwrites in-memory typed byte buffers on a best-effort basis, but JavaScript engines/browser caches cannot guarantee physical memory erasure. On shared machines or after dealing with private inputs, close the browser and follow normal endpoint security/retention policy.
- This app **does not parse or validate original Casebook client/source claims**. Sources can be old, altered, inconsistent or belong to different clients. A successful decrypt/digest does **not** prove original producer identity, tenant membership, approved request, current grant, trusted timestamps, independent operator/client consent, action-time revocation or a verified security finding. The original independent authorization paths remain mandatory.
- The local transfer password and endpoint security are critical. AES-GCM ciphertext can protect at-rest data against someone without the password; it cannot make a compromised browser or endpoint trustworthy. Exported plaintext downloads remain sensitive. Small data sets may be re-identifiable.

## Source / build

Edit `transfer.html`, `transfer.css` and `transfer.js` in this directory only. To regenerate the deterministic one-file artifact with CSS/JS CSP hashes (production packaging, **not QA or tests**):

```bash
python3 scope-casebook-transfer/build_standalone.py
```

The built `standalone.html` should be committed alongside its source. Never loosen original scope, risk, cookie, network or scanner gates to ship this companion.

## Release hold

No production/main merge or deployment absent the original exact-head hosted CI **and** permanently registered named VPS CI, original source-owner acceptance, independent security/privacy/browser review, resolution of original **#177/#182/#829**, separate genuinely current authenticated client **and** operator consent with revocation at action time, and explicit HUMAN GO. This add-only offline feature supplies none of those approvals. It should remain an isolated **DRAFT/HOLD** PR.
