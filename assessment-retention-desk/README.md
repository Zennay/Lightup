# LightUp PRIVATE Assessment Retention Desk

**INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** Add-only, fully offline HUMAN operations companion. This is *not* part of an approved active assessment, release, authorization grant, consent workflow, delete automation or evidence verification.

## Direct usable offline application

**[Save the complete standalone HTML file](standalone.html)** from the branch to
a trusted local computer and then **open the saved file locally** in a browser
with WebCrypto support. GitHub's normal file preview is source code, not a
running application; do not upload client source materials to a web viewer.
The standalone app bundles all browser JS and CSS with SHA-256-pinned CSP,
with no other browser assets required. No live site or production deployment.

Original PRIVATE assessment files are admitted only from the local file chooser
after a separate operator selection. Existing real authorization and consent
requirements are **not** satisfied by opening the app or by encrypted receipt
passwords. Build yourself with `package.py` only if you need to change the
source; the committed standalone HTML is already produced.

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

## Source-bound HUMAN custody and retention-hold decisions (schema v2)

The browser workroom now includes **HUMAN-declared custodian or team**, a
**HUMAN sensitivity classification** (unknown, internal, confidential,
restricted) and an explicit **HUMAN-only hold indicator** (unknown, human
declared active, human declared no known restriction). None is authenticated,
a real legal-hold determination, owner permission or verified source metadata.

Every newly created PRIVATE plan and encrypted `.lurt` carries the exact
original-byte-bound **version 2** HUMAN row shape. The offline `history.py`,
`drift.py`, `vault_history.py` and `vault_drift.py` read and display this
custodian/classification/hold metadata and compare it between revision moments.
**Older version-1 browser plans and encrypted vaults remain readable**.
They are upgraded **in memory** with `custodian=""`,
`classification="unknown"`, `hold_flag="unknown"`. Older missing
metadata must NEVER be interpreted as cleared or approved. Exporting
subsequent private plans uses v2 and preserves all explicit HUMAN fields.

For multiple sources, the **filtered bulk editor** also supports shared HUMAN
custodian, sensitivity and hold updates without overwriting the existing
status, review date or other fields (each dimension has an explicit
"keep unchanged" option). It prepares the complete proposed state
before asking for confirmation; any incomplete HUMAN delete proposal fails
the **entire batch** without partial changes. The one-step undo now
restores all v2 HUMAN metadata together. Neither operation changes files.

Proposed deletion remains only a PRIVATE unverified HUMAN request and is
**never an executable delete**. In v2 a publishable proposal also requires a
nonempty HUMAN custodian, explicit human next action and the operator-selected
"no known restriction" *claim*. If any are missing, export and native v2
admission HOLD; selecting this UI value **never proves actual absence of legal
hold or authentic consent**. In v1, a previous human delete proposal can still
be read, but the missing custodian and hold metadata become UNKNOWN, so it
cannot silently be re-exported as a complete new v2 proposal.

The UI includes filters for undeclared holder, declared active/unknown hold
and incomplete delete proposals, alongside due-date workload summaries.
Counts-only CSV includes these HUMAN-only categories (not individual source
identifiers). This may still be sensitive for small cohorts. New metadata is
PRIVATE even when encrypted; avoid placing personal information in aliases,
owner fields or free-text descriptions unless there is a need and permission.

## Scriptless PRIVATE HUMAN custody review dossier

The browser provides an additional **explicit, privacy-confirmed HTML review dossier**. It orders the current exact-SHA/size-bound assessment assets by operator-declared HUMAN hold uncertainty, includes a **short SHA-prefix** for local source disambiguation, shows HUMAN owner, sensitivity, tentative date and follow-up action, and flags incomplete delete proposals as **HOLD**. The HTML is built from inert DOM `textContent`, has its own no-network/no-script CSP, and contains **no original source bytes, filenames, complete SHA-256 or verified grant/consent**.

**It is still PRIVATE and unencrypted** because HUMAN owner/notes, even without original source bytes, may contain sensitive personal and security information. The operator must separately confirm this export and keep it only in a trusted private location. Never attach it to a public issue or infer that a claimed clearance is an actual legal determination. No automatic deletion or external delivery is ever triggered.
## Native encrypted HUMAN history with original-byte revalidation

The existing browser `.lurt` AES-256-GCM HUMAN vaults can now be compared without exporting decrypted JSON to disk. `vault_history.py` opens each vault in memory via an independently entered non-echoed password, validates the original unchanged browser HUMAN receipt, and **re-hashes every separately selected genuine source file**. Missing/changed/duplicate original bytes HOLD before publishing any report. The operator-declared vault order never proves a real chronology or authenticated source provenance.

This optional native product uses the established Python **cryptography** library for AES-256-GCM. It fails closed if that package is unavailable; no weakened crypto or remote-decryption fallback is used. Install the dependency separately in a trusted prepared environment, not from a browser or through the assessment tool itself.

```sh
python3 assessment-retention-desk/vault_history.py \
  --output /private/operator/private-encrypted-history.html \
  --source-file /private/original-lab-1.json \
  --source-file /private/original-lab-2.json \
  /private/operator/first-review.lurt \
  /private/operator/next-review.lurt
```

All outputs are new, source-bound 0600 scriptless PRIVATE HUMAN history inside a pre-existing private 0700 directory. No decrypted receipt, source body, entire SHA, password, grant or verified finding is published. A crypto envelope authenticates only its own bytes, never their real source/client.

## Native encrypted source-drift briefing (including changed original bytes)

The companion `vault_drift.py` compares two original browser `.lurt` HUMAN vaults against **two separately reselected sets of original actual bytes**. It re-hashes the earlier and current source files independently before reporting added/absent/unchanged SHA identities and HUMAN-only differences. A missing source is **never** interpreted as deleted, fixed or authorized. As with encrypted history, no plaintext receipt is saved and the operator enters each vault password interactively.

```sh
python3 assessment-retention-desk/vault_drift.py \
  --output /private/operator/private-encrypted-source-drift.html \
  --old-source-file /private/original-previous.json \
  --new-source-file /private/original-current.json \
  /private/operator/review-before.lurt \
  /private/operator/review-after.lurt
```

Native AES-GCM support is an **optional, separate dependency** declared in `assessment-retention-desk/requirements-native.txt`; no changes to the original LightUp production dependency graph or CI. The portable browser workroom has no Python dependency. Install a trusted packaged version of `cryptography` deliberately in a private/offline environment before using native vault history/drift.
## Opt-in private tentative review calendar

The browser can export an all-day `.ics` calendar grouped by operator-entered HUMAN review date and count. It contains **no aliases, original SHA, source path, notes, targets, evidence or HUMAN actions**. Every event is PRIVATE, TENTATIVE and nonblocking; calendar applications may still sync imported calendars to the cloud. Review-date/count combinations can identify small groups; export requires separate explicit privacy confirmation. No calendar API, automatic import, recipient dispatch or authorization is performed.

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