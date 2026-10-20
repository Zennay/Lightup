# LightUp PRIVATE Assessment Retention Desk

**INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** Add-only, fully offline HUMAN operations companion. This is *not* part of an approved active assessment, release, authorization grant, consent workflow, delete automation or evidence verification.

## What the operator can actually do

1. Open `index.html` on a trusted device and keep `desk.js`, `vault.js` and `desk.css` alongside it. No backend, browser extension, network permission, model calls or service workers.
2. Select 1–12 **already-produced** PRIVATE assessment artifacts, each 1 byte–8 MiB and maximum 64 MiB combined. WebCrypto SHA-256 is calculated on the actual selected file bytes, never from its name or a sender assertion. Source bytes and filenames never enter the plan export.
3. Give each source a HUMAN-only alias, proposal (review / retain / quarantine / propose delete), review date and next action. Triage tentative overdue / due-next-seven-days / undated / action-less HUMAN work, using live filters and sorting. These dates are not legally verified deadlines.
4. Apply HUMAN phase, date and optional action to the currently filtered subset only after explicit confirmation. One guarded, source-bound undo remains available until another item is changed. A delete proposal is **never deletion** and always requires an explicit HUMAN follow-up action.
5. **Preferred confidential handoff:** choose a separate 12–128-character password, export `.lurt` and store it privately. AES-256-GCM, 310,000 PBKDF2-SHA256 rounds, fresh random 16-byte salt + 12-byte nonce and purpose-bound AAD protect PRIVATE HUMAN aliases, hashes and actions. The browser never saves this password or plaintext intermediate. A lost password cannot be recovered.
6. Re-select the **exact same actual original file bytes** and open the `.lurt` with its password. Wrong password, unrecognized fields, false-authority deviations, changed/extra/missing/duplicated source SHA or size HOLD atomically. Operator must explicitly confirm before replacing any HUMAN decision; encryption does not authenticate the source, client or approval.
7. **Compare older encrypted plan** to current locally held HUMAN choices using the same password and exact original byte admission. This shows changes to alias/status/date/action without importing earlier choices or creating an unencrypted file. After reopening an encrypted plan you can explicitly choose a new password and re-encrypt in browser memory.
8. If native offline scripts require a source-bound HUMAN plan, use the **separately confirmed, intentionally unencrypted** PRIVATE `.json` export. This exposes source SHA-256 identities and human actions; store it only in a trusted private directory. The original receipt schema contains six literal false-authority flags.
9. The separate **Compare other private plan** (plaintext) tool shows source arrivals and disappearances without carrying any approval or implying remediation/deletion. Export anonymous-looking but still PRIVATE counts-only stage CSV or print a PRIVATE review agenda on a trusted device.
10. Use `history.py` for 2–12 plaintext exact-same-original-source HUMAN plans and `drift.py` for two changed source sets. They write *new* private scriptless 0600 HUMAN reports in an already existing private 0700 directory. No evidence, target, original source content, deletion or authorization is interpreted or executed.

### Read-only native source comparison

```sh
python3 assessment-retention-desk/history.py --output /private/operator/history.html /private/operator/plan-01.json /private/operator/plan-02.json
python3 assessment-retention-desk/drift.py --output /private/operator/source-diff.html /private/operator/plan-01.json /private/operator/plan-02.json
```

## Boundaries and tradeoffs

- All input files may contain client secrets. Only use assets that you may lawfully possess and review. This tool performs **no scanning, model calls, network requests, subprocess dispatch, source modification, deletion or remote sync**. Browser CSP prohibits network connections and externally hosted scripts; no tracking, localStorage, IndexedDB or service workers.
- SHA-256 checks only equality of the *selected bytes*. Hashes/JSON/HUMAN labels **do not authenticate an original creator**, grant, current tenant, engagement, finding, remediation, legal hold or genuine authorized deletion. Source-file names are never serialized, nor are source bodies.
- "Proposed delete" never removes anything or grants permission to do so. Real client retention, legal-hold, consent/revocation and independent approvals must occur outside this application.
- Date fields are tentative user-entered plain dates, not independently verified timestamps. File picking and browser memory are NOT secure erase; old downloaded exports and print spool data remain outside its control.
- Encrypted `.lurt` imports are intentionally supported **in the browser only**. Native `history.py` and `drift.py` accept original plaintext `.json` source-set-bound HUMAN receipts. Export plaintext only when necessary, on a trusted device and after the separate sensitive-export confirmation; never email decrypted source data or treat SHA identity as producer attestation. The vault has **no recovery key**; a lost password makes the encrypted plan unrecoverable.
- Browser file origins may handle WebCrypto differently. If unavailable, the workspace fails closed rather than weakening SHA validation. Use a browser with `crypto.subtle` enabled; do not upload private files to another service to get around this.
- A receipt is valid only for the exact **complete** selected file set; an operator must intentionally create a new plan after any source revision. No automatic claim that absence means fixed/deleted.
- `history.py` is a read-only view of HUMAN plans. An input sequence is operator-declared, not trusted chronology or source provenance. It never edits receipts. The HTML output contains potentially sensitive aliases, statuses and source hash prefixes.
- No QA/testsuites created or executed by this module. Only permitted syntax / direct product inspection is within scope of this work.

## Browser files

`index.html`, `desk.css`, `desk.js`, `vault.js` are the complete browser UI. Portable as a four-file local folder; all resources are local and fetched from that same folder. There are no external dependencies.

## Self-contained one-file private workroom

Create a new, private 0600 browser artifact with separate CSP SHA-256 hashes pinned to BOTH local production JavaScript modules and to the style sheet:

```sh
mkdir -m 700 -p /private/operator
python3 assessment-retention-desk/package.py --output /private/operator/retention-offline.html
```

The native packager requires a pre-existing 0700 directory. It refuses overwrite, unsafe inline element terminators or product-template drift. Do not move its output to a public web host or use a browser that blocks WebCrypto without acknowledging the limitation.

## Offline native multi-plan history

```sh
python3 assessment-retention-desk/history.py --output /private/operator/retention-history.html /private/operator/plan-01.json /private/operator/plan-02.json
```

Output must be a **new**, non-existing file in an existing private directory. It is written privately (0600) using an exclusive create; no silent overwrite. Input plans must have identical original SHA-256 + sizes and the exact tool schema. Fails closed on source drift, duplicates, malformed/oversized/linked files or authority flag changes. It never opens original assessment source files or authorizes a retention action.

## Release boundary

Per Notion: LightUp **INCUBATE/M3-M7 PLAN/LAB ONLY**, all new work **DRAFT/HOLD**. Existing original hosted CI plus permanent named VPS CI, independent security/privacy/browser review, original source-owner acceptance, #177/#182/#829, genuine separately authenticated current client/operator consent with action-time revocation and explicit HUMAN GO remain mandatory. No merge to main, deploy, scan, grant or live target work from this artifact.