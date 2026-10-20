# LightUp · offline PRIVATE Casebook HUMAN reconciliation

**INCUBATE M3/M7 — PLAN/LAB ONLY — DRAFT/HOLD. Not an authorization or release.**

This standalone add-only companion uses original held [Casebook PRIVATE transfer PR #1671](https://github.com/Zennay/Lightup/pull/1671) pinned commit `f40b0d2cf626e49bbd8f764968df132ba9d4365a`, in turn based on authentic original Casebook owner PR #1668. Neither source-owner file is modified.

## Complete operator workflow

1. Save [standalone.html](standalone.html) locally, open it in a browser where local files are a trusted secure WebCrypto context, and keep sensitive documents off web services.
2. Select two original individually encrypted `.lupt` version-one transfers with their distinct passwords. Each must already contain original 1–12 Casebook snapshots and an explicitly saved current original source-bound HUMAN CSV.
3. The desk admits each complete input and compares the original source sequence. Only the **same original source bytes** and same source-declared client are accepted across both receipts. If either original source differs, reconciliation is refused; ask the original source owner to resolve chronology.
4. On a large workroom, search by private dossier/action, select only changed cases or only unresolved HUMAN fields, and jump directly to the first pending case. Unresolved-only cases disappear when all their field choices are made, without losing underlying selections.
5. For each current case, equal HUMAN fields carry forward. Every conflicting **stage, route, or blocker** stays on HOLD until the operator explicitly chooses A, B, reset to the canonical unreviewed / unassigned / none value, **or explicitly chooses another field-specific original HUMAN enum value**. Manual choices can never add a grant, authorization, real approval or new unrecognized status. Source IDs and original actions remain unmodified and private.
6. Choose a new secret of at least twelve characters, acknowledge limitations, then explicitly download a fresh AES-256-GCM encrypted `.lupt` source+HUMAN package. This retains exact original historical Casebook bytes and changes only the current HUMAN CSV. The normal original Casebook validator and separate real, current consent checks remain necessary.

After every HUMAN field is resolved, an optional **source-free, count-only HUMAN reconciliation JSON** can also be exported with identical/changed case and field counts, A/B/reset/manual-enum selection totals and all six authority flags literally false. It contains no original source IDs, paths, hashes or individual choices. **Small group counts may still be sensitive** and require explicit human distribution review.

Private original case IDs, action text and HUMAN choices remain entirely in browser memory, never in exported aggregate logs or servers. New ciphertext has a fresh random salt and nonce, PBKDF2-SHA256 310,000 iterations and AES-256-GCM. No account, localStorage, remote network, grant, API, scan or active-target support is present. Incorrect input does not replace the previous workset. A compromised browser can reveal locally displayed PRIVATE information; choose a trusted computer and exchange the new secret separately.

## PRIVATE HUMAN decision rationale

Each original Casebook case that has conflicting HUMAN fields now has an **optional PRIVATE human review-reason and freeform note** (maximum 800 UTF-16 characters and 1,200 UTF-8 bytes, explicitly bounded). Notes are shown locally only and **never inserted into the original immutable Casebook JSON, the current original HUMAN CSV, or the source-free aggregate**. They are not evidence of genuine client, source, consent, grant, or verified security outcome. Values are DOM text, never HTML. Reasons are a fixed human-only follow-up taxonomy, not automated approvals.

The encrypted local `.lurd` draft format has been versioned to v2 so the new notepad and choices restore together, **only** after exact original source and both original current HUMAN CSV SHA bindings match. Original v1 encrypted drafts remain readable; they only restore their own choices, without replacing later private notes. A malformed or source-mismatched import refuses atomic replacement. No automatic network, consent, grant or storage is added.

## Encrypted source-bound human review memorandum

After a new original source+HUMAN `.lupt` bundle has been offered, an optional **separately password-encrypted PRIVATE human-review memorandum** (`.lurm`) can be created. It includes the exact self-declared original source file names, byte lengths and source SHA-256 values, the original A/B HUMAN CSV SHA-256 values, the **actual offered encrypted output** byte SHA-256, new resulting HUMAN CSV SHA-256, all PRIVATE original case identifiers/actions, original A/B choices, explicit human decisions and the optional PRIVATE HUMAN reasons/notes. It carries literal `REVIEW_ONLY`, all six authority flags `false`, and **no** original source JSON, active target, scan grant, credentials or original casebook bytes. It is private even though encrypted: handle as sensitive material.

An independent recipient can open `.lurm` locally in this same offline app using its own password, inspect the human-only memorandum and select an **actual received encrypted `.lupt` file** to compare the byte SHA-256 exactly. A match proves only that the chosen encrypted bytes match the memo's locally declared hash; it does not authenticate the original exporter, client/operator consent, current revocation, any security finding, or real permission to act. The application does not automatically import the memo as authority or mutate a source record.

Memo admission is bounded (1 MiB envelope, 512 KiB plaintext, up to 200 declared case rows), canonical JSON+base64, authenticated AES-GCM / PBKDF2-SHA256 310000, finite original field enums, source SHA shape/ordinal and case uniqueness. The only public source is the source-pinned ORIGINAL adapter at the same `f40b0d2` parent; no target-capable code is changed. Both file output formats `.lurd` and `.lurm` are **optional** and do not extend the original `.lupt` schema.

## Encrypted HUMAN draft continuity (optional)

For long workrooms, **Save PRIVATE HUMAN draft** produces a separate `.lurd` AES-256-GCM / PBKDF2-SHA256 310000 file under a fresh operator-chosen password. It contains **only encrypted** original file name/size/SHA-256 references, the two distinct original current HUMAN CSV SHA-256 references and current per-field A/B/reset/manual-canonical-enum/unresolved selections — **no original Casebook source JSON or current source HUMAN CSV bodies**. It is still PRIVATE because it can reveal operator decisions after decryption.

After reopening the exact same two original `.lupt` files in the same A/B order, **Restore PRIVATE HUMAN draft** verifies complete canonical encrypted schema, crypto authenticity, literal six false source authority flags, all current original file digest/size/name references, both original current HUMAN CSV digests, current case count and every allowed choice. A different source, changed HUMAN revision, swapped A/B input or invalid decision means full HOLD without overwriting current selections. Human confirmation precedes atomic replacement in browser memory. The draft does not convey current client consent or any authority and does not authenticate the claimed original producer.

## Admission, bounded execution and source relationship

- Exact canonical original envelope, encrypted payload and base64; v1 schema, GCM authentication, strict source file manifest size and SHA-256, consecutive original filenames and final single HUMAN CSV; fixed 26 MiB encrypted, 20 MiB plaintext and 12 MiB source bounds.
- Strict UTF-8 original Casebook v1 shape, all six source authority flags literal false, nested duplicate JSON keys rejected, one identical source-declared client. This source ID is not a signature.
- Unmodified original `scope-casebook-transfer/human-board.js` source is imported at **build time** with an exact hardcoded SHA-256 pin; its original ordering, HUMAN CSV admission and serializer are reused. Build fails closed if this pinned original changes. This does **not** itself authenticate an original source producer.
- User-visible standalone HTML has all CSS/JS inline with CSP SHA-256 hashes, no external assets and `connect-src 'none'`. No QA suites or fixtures are added.

Build without running QA/regression suites (the builder includes the source-pinned original adapter plus both new production JavaScript files):

```sh
python3 scope-casebook-reconcile/build_standalone.py
node --check scope-casebook-reconcile/app.js
node --check scope-casebook-reconcile/draft.js
```

## Release fence

**DRAFT/HOLD only**: independently accepted original hosted and permanently named VPS runner CI exact release head, authentic original source-owner acceptance, security/privacy/browser review, unresolved original #177/#182/#829, separately authenticated currently valid client and operator consent plus action-time revocation, and explicit HUMAN GO. Not merged to main, deployed, permitted to grant authority or allowed to run any target scan.
