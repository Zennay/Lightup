# LightUp · offline PRIVATE Casebook HUMAN reconciliation

**INCUBATE M3/M7 — PLAN/LAB ONLY — DRAFT/HOLD. Not an authorization or release.**

This standalone add-only companion uses original held [Casebook PRIVATE transfer PR #1671](https://github.com/Zennay/Lightup/pull/1671) pinned commit `f40b0d2cf626e49bbd8f764968df132ba9d4365a`, in turn based on authentic original Casebook owner PR #1668. Neither source-owner file is modified.

## Complete operator workflow

1. Save [standalone.html](standalone.html) locally, open it in a browser where local files are a trusted secure WebCrypto context, and keep sensitive documents off web services.
2. Select two original individually encrypted `.lupt` version-one transfers with their distinct passwords. Each must already contain original 1–12 Casebook snapshots and an explicitly saved current original source-bound HUMAN CSV.
3. The desk admits each complete input and compares the original source sequence. Only the **same original source bytes** and same source-declared client are accepted across both receipts. If either original source differs, reconciliation is refused; ask the original source owner to resolve chronology.
4. For each current case, equal HUMAN fields carry forward. Every conflicting **stage, route, or blocker** stays on HOLD until the operator explicitly chooses A, B, or resets that field to its original 'unreviewed / unassigned / none' value. Source IDs and original actions remain unmodified and private.
5. Choose a new secret of at least twelve characters, acknowledge limitations, then explicitly download a fresh AES-256-GCM encrypted `.lupt` source+HUMAN package. This retains exact original historical Casebook bytes and changes only the current HUMAN CSV. The normal original Casebook validator and separate real, current consent checks remain necessary.

After every HUMAN field is resolved, an optional **source-free, count-only HUMAN reconciliation JSON** can also be exported with identical/changed case and field counts, A/B/reset selection totals and all six authority flags literally false. It contains no original source IDs, paths, hashes or individual choices. **Small group counts may still be sensitive** and require explicit human distribution review.

Private original case IDs, action text and HUMAN choices remain entirely in browser memory, never in exported aggregate logs or servers. New ciphertext has a fresh random salt and nonce, PBKDF2-SHA256 310,000 iterations and AES-256-GCM. No account, localStorage, remote network, grant, API, scan or active-target support is present. Incorrect input does not replace the previous workset. A compromised browser can reveal locally displayed PRIVATE information; choose a trusted computer and exchange the new secret separately.

## Admission, bounded execution and source relationship

- Exact canonical original envelope, encrypted payload and base64; v1 schema, GCM authentication, strict source file manifest size and SHA-256, consecutive original filenames and final single HUMAN CSV; fixed 26 MiB encrypted, 20 MiB plaintext and 12 MiB source bounds.
- Strict UTF-8 original Casebook v1 shape, all six source authority flags literal false, nested duplicate JSON keys rejected, one identical source-declared client. This source ID is not a signature.
- Unmodified original `scope-casebook-transfer/human-board.js` source is imported at **build time** with an exact hardcoded SHA-256 pin; its original ordering, HUMAN CSV admission and serializer are reused. Build fails closed if this pinned original changes. This does **not** itself authenticate an original source producer.
- User-visible standalone HTML has all CSS/JS inline with CSP SHA-256 hashes, no external assets and `connect-src 'none'`. No QA suites or fixtures are added.

Build without running QA/regression suites:

```sh
python3 scope-casebook-reconcile/build_standalone.py
node --check scope-casebook-reconcile/app.js
```

## Release fence

**DRAFT/HOLD only**: independently accepted original hosted and permanently named VPS runner CI exact release head, authentic original source-owner acceptance, security/privacy/browser review, unresolved original #177/#182/#829, separately authenticated currently valid client and operator consent plus action-time revocation, and explicit HUMAN GO. Not merged to main, deployed, permitted to grant authority or allowed to run any target scan.
