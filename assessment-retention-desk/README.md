# LightUp PRIVATE Assessment Retention Desk

**INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** Add-only, fully offline HUMAN operations companion. This is *not* part of an approved active assessment, release, authorization grant, consent workflow, delete automation or evidence verification.

## Strict import encoding

Plaintext HUMAN plan imports, source-free plan comparisons, and encrypted-vault envelopes are decoded from the original bytes with fatal UTF-8 handling. Malformed byte sequences and UTF-8 BOMs fail closed before JSON parsing or any restore/compare action. This prevents silent U+FFFD replacement from changing imported HUMAN fields while leaving the existing exact source SHA/size binding and all-or-nothing restore rules intact.

## Encrypted-envelope self-check before download

Before an encrypted `.lurt` export or password-rotation file is offered for download,
the browser now reopens the newly generated envelope in memory using the same password,
runs the existing strict envelope/decryption checks, and requires the recovered UTF-8
plan text to equal the original string exactly. A decryption, contract, or byte-content
mismatch raises HOLD before download. No temporary file, browser storage, or network
request is used for this self-check. It confirms only that this local browser can reopen
its own new envelope; it does not authenticate the source, producer, client, consent,
retention decision or authorization.

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
8. **Rotate the password of an existing encrypted .lurt plan without restoring it.** Re-select the exact original source files, choose the old plan/password, enter and confirm a distinct new password, and confirm the rotation. The app validates the old encrypted plan against the exact currently selected source set, then re-encrypts the original plan with fresh salt/nonce and the new password. It downloads a separate rekeyed file; the current HUMAN workroom and old file are unchanged. Re-open/compare the new file with the new password before retiring the old one. Password buffers are cleared after use. Rotation does not prove producer identity, consent or authority.
9. If native offline scripts require a source-bound HUMAN plan, use the **separately confirmed, intentionally unencrypted** PRIVATE `.json` export. This exposes source SHA-256 identities and human actions; store it only in a trusted private directory. The original receipt schema contains six literal false-authority flags.
10. The separate **Compare other private plan** (plaintext) tool shows source arrivals and disappearances without carrying any approval or implying remediation/deletion. Export anonymous-looking but still PRIVATE counts-only stage CSV or print a PRIVATE review agenda on a trusted device.
11. Use `history.py` for 2–12 plaintext exact-same-original-source HUMAN plans and `drift.py` for two changed source sets. They write *new* private scriptless 0600 HUMAN reports in an already existing private 0700 directory. No evidence, target, original source content, deletion or authorization is interpreted or executed.

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

The browser can export an all-day `.ics` calendar grouped by operator-entered HUMAN review date and count. It contains **no aliases, original SHA, source path, notes, targets, evidence or HUMAN actions**. Every event is PRIVATE, TENTATIVE and nonblocking; calendar applications may still sync imported calendars to the cloud. Review-date/count combinations can identify small groups; export requires separate explicit privacy confirmation. No calendar API, automatic import, recipient dispatch or authorization is performed. A separate **visible rows only** calendar export applies the current table filters first and includes only dates/counts represented by those visible rows; it never exports aliases, source identities, filenames, hashes or notes.

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

Current standalone artifact: **69,157 bytes**, SHA-256 `da436e0bff28c01174b9eae7126ecf9da064950ae12b396fa33e0b22a571c2c0`. Exact desk.js, vault.js and CSS bytes are pinned by the standalone CSP.

Create a new, private 0600 browser artifact with separate CSP SHA-256 hashes pinned to BOTH local production JavaScript modules and to the style sheet:

```sh
mkdir -m 700 -p /private/operator
python3 assessment-retention-desk/package.py --output /private/operator/retention-offline.html
```

The native packager requires a pre-existing 0700 directory. It refuses overwrite, unsafe inline element terminators or product-template drift. Do not move its output to a public web host or use a browser that blocks WebCrypto without acknowledging the limitation.

To re-open an existing artifact read-only against the current source bundle, use:

    python3 assessment-retention-desk/package.py --reopen /private/operator/retention-offline.html

The reopen mode requires the existing file to be a regular owner-only 0600 file in an owner-only 0700 directory, rejects links and metadata changes during reading, and compares the complete bytes against a freshly assembled current-source bundle. It never overwrites the artifact. Source drift returns HOLD; this is a local package-integrity check, not source authenticity, consent, authorization or release approval.

## Offline native multi-plan history

```sh
python3 assessment-retention-desk/history.py --output /private/operator/retention-history.html /private/operator/plan-01.json /private/operator/plan-02.json
```

Output must be a **new**, non-existing file in an existing private directory. It is written privately (0600) using an exclusive create; no silent overwrite. Input plans must have identical original SHA-256 + sizes and the exact tool schema. Fails closed on source drift, duplicates, malformed/oversized/linked files or authority flag changes. It never opens original assessment source files or authorizes a retention action.

## Release boundary

Per Notion: LightUp **INCUBATE/M3-M7 PLAN/LAB ONLY**, all new work **DRAFT/HOLD**. Existing original hosted CI plus permanent named VPS CI, independent security/privacy/browser review, original source-owner acceptance, #177/#182/#829, genuine separately authenticated current client/operator consent with action-time revocation and explicit HUMAN GO remain mandatory. No merge to main, deploy, scan, grant or live target work from this artifact.

## Multi-snapshot source-set lineage (2–12 HUMAN plans)

The native `source_history.py` extends the existing same-source `history.py`
and two-plan `drift.py` workflows to **2–12 intentionally ordered plan
snapshots whose source membership may differ**. It records when each source
digest prefix is present, absent from a selected snapshot, or reappears after
a gap; it also counts changes to HUMAN fields only when the source is present
in both adjacent plans. A digest with conflicting declared byte lengths
refuses the entire report.

~~~sh
mkdir -m 700 /private/operator
python3 assessment-retention-desk/source_history.py \
  --output /private/operator/source-set-history.html \
  /private/operator/plan-01.json \
  /private/operator/plan-02.json \
  /private/operator/plan-03.json
~~~

Inputs must be bounded owner-private unlinked regular plan files; the original
strict duplicate-key/schema/false-authority receipt parser remains authoritative.
The new script does not open assessment assets or restore a previous plan. The
scriptless report shows per-plan membership and stage counts plus one row per
source/plan, retaining only a private digest prefix and byte size, HUMAN stage,
proposed date, whether a custodian was declared, classification, hold category
and changed field names. Aliases and free-text actions are never included.
Missing membership does **not** mean deletion, remediation, revocation or
clearance; manual ordering does not prove chronology. Output is exclusive
0600 in an existing owner-owned 0700 directory and remains sensitive, unsigned
and non-authorizing. No scan, delete, grant, client contact or release occurs.


## Encrypted multi-snapshot source-set lineage (no plaintext export)

For teams that keep each HUMAN plan in its original encrypted `.lurt` vault,
`vault_source_history.py` extends the same 2–12-snapshot lineage to changing
source sets. Each vault and original source must be an owner-owned, unlinked
regular file with owner-only permissions. Each plan is decrypted only in
process memory and matched to its own separately selected original source
bytes. All vault and source bytes are re-admitted immediately before report
publication; any drift refuses the complete report. The report is produced
only if every snapshot's complete SHA-256/size membership matches exactly.

~~~sh
python3 assessment-retention-desk/vault_source_history.py \
  --output /private/operator/encrypted-source-history.html \
  --source-file 1=/private/older/source-a.json \
  --source-file 1=/private/older/source-b.json \
  --source-file 2=/private/newer/source-a.json \
  /private/operator/plan-before.lurt \
  /private/operator/plan-after.lurt
~~~

Repeat `--source-file SNAPSHOT=PATH` for every original file in every
snapshot; snapshot numbers follow the manually selected vault order. The
native tool prompts separately for each vault password (never as a command-line
argument), rejects missing/extra/changed source membership, and writes only a
scriptless 0600 HTML report in an existing owner-owned 0700 directory. It does
not write decrypted JSON or HUMAN notes to disk. Manual order is not verified
chronology; source absence is not deletion, remediation, revocation or
clearance. Digest prefixes and HUMAN stage/hold categories remain sensitive.


## Portable private lineage bundle (HTML + CSV + JSON)

Both lineage commands accept `--bundle-output` **instead of** `--output`.
This publishes one new, owner-only 0600 ZIP atomically through the same native
private publisher, rather than publishing several separate files that could
leave a partial export.

Plaintext receipt declarations:

~~~sh
python3 assessment-retention-desk/source_history.py \
  --bundle-output /private/operator/source-set-history.zip \
  /private/operator/plan-01.json \
  /private/operator/plan-02.json \
  /private/operator/plan-03.json
~~~

Encrypted plans, without writing decrypted plan JSON to disk:

~~~sh
python3 assessment-retention-desk/vault_source_history.py \
  --bundle-output /private/operator/encrypted-source-history.zip \
  --source-file 1=/private/older/source-a.json \
  --source-file 1=/private/older/source-b.json \
  --source-file 2=/private/newer/source-a.json \
  /private/operator/plan-before.lurt \
  /private/operator/plan-after.lurt
~~~

The bounded ZIP contains the scriptless HTML, a complete flat CSV, a
machine-readable JSON projection, privacy/evidence-boundary notes and an
unsigned manifest with hashes of the report artifacts. To inspect a received
bundle before opening or forwarding it, place it in an existing owner-only
0700 directory with file mode 0600 and run:

~~~sh
python3 assessment-retention-desk/source_history.py \
  --inspect-bundle /private/operator/source-set-history.zip
~~~

Inspection is read-only and does not extract files or open original assessment
sources. It rejects links, non-private permissions, duplicate/reordered ZIP
members, unsafe archive entries, manifest/hash mismatches, non-canonical JSON,
inconsistent membership/summary counts and HTML/CSV/README that do not match
the admitted JSON projection. A successful result establishes only that the
unsigned local bundle is internally consistent; it does not authenticate the
publisher, original source bytes, reviewer, chronology, consent or permission.
 The manifest protects
against accidental local byte changes only; it is not a signature or source
provenance. The exports deliberately omit original source paths, aliases,
free-text actions, full source digests and source contents. Digest prefixes,
plan dates, stages and hold/classification categories can still identify a
small cohort, so the archive remains sensitive. Plan order is manual, and
neither export mode authorizes retention changes, assessment, client contact,
scanning, grants or release. The ZIP's entry modes are 0600; extract and store
it only in owner-private storage.


## Clear guard during asynchronous local admission

The Clear action now refuses to run while a source-byte ingest, HUMAN receipt import/comparison, or encrypted-vault operation is active. Those operations read files asynchronously; clearing midway could otherwise be followed by a late ingest completion that appends the just-cleared source identities back into the workroom, or a stale comparison error/status replacing the clear state. The operator receives an explicit HOLD and can clear after the local operation completes. No partial clear occurs, no files are uploaded, and downloaded private files are never deleted by the workroom.
