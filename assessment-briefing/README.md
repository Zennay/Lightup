# LightUp · PRIVATE Assessment Briefing & Source Drift

**INCUBATE · M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Independent new-only source in `assessment-briefing/` built for original, **already-produced**, strictly isolated lab-assessment JSON from original held assessment-runtime [#1608 / PR #1610](https://github.com/Zennay/Lightup/pull/1610). Companion to original offline review issue [#1637](https://github.com/Zennay/Lightup/issues/1637) without changing that actively owned original desk [PR #1639](https://github.com/Zennay/Lightup/pull/1639), original lab tool, authorization or scan surfaces.

## Usable offline product

From a trusted local checkout containing a PRIVATE original source JSON produced elsewhere:

```bash
python3 assessment-briefing/briefing.py --source ./original-private-lab.json --output-dir ./NEW-PRIVATE-BRIEFING
```

This **does not run a scan**. Creates the new directory exclusively as 0700 and the following files as 0600, refuses to overwrite existing output, and rejects symlinks, duplicate JSON keys and unsupported/oversize source before publishing:

- **`private-briefing.html`:** Print-friendly scriptless, CSP-hash-pinned offline report with original severity distribution, finding descriptions, check/capability, exact declared endpoint ordinal when literally equal, private source evidence reference counts, impact/fix/retest/evidence summary in opt-in expandable details, and blank HUMAN-only follow-up worksheets. Records appear in source order. Empty original results still produce a report.
- **`human-followup.csv`:** Blank HUMAN ownership / action / blocker worksheet indexed only by original row ordinal, source severity and evidence-reference count. No source target URLs, findings text, names, hashes or evidence content in this CSV; still treat aggregates as PRIVATE. Blank cells cannot inject spreadsheet formulas.
- **`manifest.json`:** Original source byte SHA-256 (unsigned), output file SHA-256, source-reported totals and literal `false` authentication/authorization/release declarations. Not a signed receipt.

To review literal source drift between **two separately, already-produced** original lab results:

```bash
python3 assessment-briefing/compare.py --before ./source-A.json --after ./source-B.json --output-dir ./NEW-PRIVATE-DRIFT
```

The comparator requires a different source-byte SHA, different run ID, identical original scenario literal and same exact declared target **set**. It groups only by exact source target + original capability ID + original check ID. Duplicate keys on either side remain **AMBIGUOUS** (no silent pairing). Other source-declaration categories are `reported_only_before`, `reported_only_after`, `source_description_changed` and `source_description_equal`. This is a textual source-reconciliation heuristic only — **neither absence nor change proves a fixed, new, active, vulnerable or retested target**.

The second packet contains:

- **`private-drift.html`:** Fully offline scriptless printable category dashboard and PRIVATE before/after original source descriptions, plus blank human evidence and follow-up worksheets. Original identifiers and declared target strings are shown only in this PRIVATE HTML.
- **`human-drift-followup.csv`:** Group ordinal, category, original declaration counts and blank HUMAN fields, without target/ID/finding literals.
- **`manifest.json`:** Unsigned original source fingerprints, category counts, PRIVATE output digests and literal-false permission flags.

### Explicit safety model

Both CLIs read only explicit ordinary local files (at most 8 MiB), cap original findings at 2048, endpoints at 16, validate exact frozen original field shapes, basic metric consistency and original lab context if `benchmark_case` exists, reject ambiguous JSON object keys and fail closed with content-free error messages. These are **conservative presentation checks, not original-source authentication or full independent correctness proof**. The original source is unchanged.

Both output directories are **new only**; on failure, newly published files are removed and no old output is overwritten. Successful preparation intentionally exits with code **2 (REVIEW_ONLY)**; HOLD returns **3**. Nothing contacts a target, resolves DNS, loads a browser resource, writes a credential, runs a model, grants permission, claims a vulnerability verdict or changes existing original results. Source signatures, source trust, assessments, actual client/operator identity, grant/revocation and security verification are **not** established by a hash or this report.

The printable HTML and any exported files are **PRIVATE** even if the CSV omits original identifiers. Never upload original reports or private HTML/manifest publicly. Device, browser and human review-channel controls remain the operator's responsibility.

## Delivery isolation and release gates

This branch adds only `assessment-briefing/`. No existing source-owner, parallel PR, default webapp, original DomainStore, CLI entrypoint, execution policy, scan worker, security gate, CI, tests or deployment file is modified. No new QA or regression suites were authored or run.

The source stays **DRAFT/HOLD**. No merge to `main`, deployment or live target use without the original exact-head hosted and permanent named VPS CI gates, source-owner sign-off, independent privacy/security review, original #177/#182/#829 closure, actual separately authenticated client/operator consent including at-use revocation, and explicit HUMAN GO. This module cannot satisfy any of those requirements.

## New: privacy-minimal human briefing (without original source identifiers)

For a separate private human conversation that should **not** include original target URLs, finding names, scenario/run IDs, evidence or original file hashes, use:

```bash
python3 assessment-briefing/aggregate.py --source ./original-private-lab.json --output-dir ./NEW-PRIVATE-AGGREGATE
```

This prepares a scriptless printable `private-human-aggregate.html` and the corresponding `private-human-aggregate.json`, using only original **source-declared totals**: endpoint/finding counts, severity distribution, records with an evidence-reference list and records with an evidence-summary. Neither file carries original finding names, IDs, targets, run labels, scenario labels, evidence text or source hashes. All permission and validity flags are explicitly false, and actionable human questions are supplied without inferring fixes or execution. Success exit code is 2 (REVIEW_ONLY). **Aggregate counts can still reveal sensitive information**, so use only a separately approved private channel. Not a release, not a source authenticity signature, and not a public safe-to-share certification.

## NEW: completed human worksheet → PRIVATE follow-up return

The original `human-followup.csv` is now genuinely reusable. After a human fills the **four original human columns** (`human_stage`, `human_owner_group`, `human_next_action`, `human_blocker`) in a PRIVATE local spreadsheet, close the file and export it as UTF-8 CSV with the original seven headers and original row ordering. Human stage may be blank or `needs_review`, `discussing`, `blocked`, `documented`; the program never infers approval from any value.

```bash
python3 assessment-briefing/human_return.py \
  --source ./original-private-lab.json \
  --manifest ./NEW-PRIVATE-BRIEFING/manifest.json \
  --worksheet ./human-filled-followup.csv \
  --output-dir ./NEW-PRIVATE-HUMAN-RETURN
```

This strictly reopens the same independently obtained original lab file and verifies its **exact unsigned source-byte digest** against the original briefing manifest, original endpoint/finding totals, the complete seven-column worksheet header, EVERY original ordinal, EVERY original severity and its evidence-reference count before touching output. CSV size is limited to 1 MiB, human owner to 120 characters, each action/blocker to 600, and unknown status values or altered membership HOLD the whole import. There is no silent row matching or partial application. Both supplied original lab and worksheet are still untrusted local files; the unsigned manifest does not authenticate the producer or human identity.

Creates an entirely NEW 0700 private directory containing `private-human-return.html` (printable scriptless private per-finding human plan plus original unchanged evidence in optional detail panels) and `private-human-summary.json` (self-reported status counts and no human names/notes). Each file is 0600, and any previous outputs or original source remain unchanged. Human edits are labels/proposals only, not verified remediation, approval, source authenticity, real-time consent, accepted scope or authorization. Exit 2 is REVIEW_ONLY and exit 3 is HOLD.

## NEW: compare two source-bound HUMAN revisions (same original source)

No code or model infers that a review-status movement proves an improved exposure. Compare two separately saved editable human worksheets against the **exact same original original lab source and original briefing manifest**:

```bash
python3 assessment-briefing/human_revision.py \
  --source ./original-private-lab.json \
  --manifest ./NEW-PRIVATE-BRIEFING/manifest.json \
  --before-worksheet ./human-before.csv \
  --after-worksheet ./human-after.csv \
  --output-dir ./NEW-PRIVATE-HUMAN-REVISIONS
```

Both human CSVs are independently admitted in full using the same strict original-ordinal/severity/evidence-count contract; all changes are then explicitly compared by HUMAN stage, group, proposed action and blocker. The new private scriptless `private-human-revisions.html` shows only changed human fields with PRIVATE original finding titles; `human-revision-counts.json` contains only numeric change / HUMAN stage-transition totals and unsigned fingerprints (still PRIVATE). Ambiguous membership or unmatched source HOLD the entire operation, leaving all prior source and review files untouched. Original finding text, actual evidence, target state, client consent, reviewer identity or source authenticity are never modified or verified.

## One-menu private operations console

For people who prefer not to assemble five different long commands, the companion offers a complete **foreground local menu**:

```bash
python3 assessment-briefing/console.py
```

Choose the detailed original briefing, two-source drift, privacy-minimal aggregate, original HUMAN return or original HUMAN revision comparison; enter only explicit local existing input paths and one NEW output directory. The console displays exactly the private disclosure profile of the chosen workflow and requires an explicit `REVIEW ONLY` confirmation. Invalid options, cancelled input, CTRL-C or declined disclosure do not run a source operation. Original execution/scan/grant/production routes are never touched and no existing output is overwritten. It intentionally returns 2 for a prepared private review packet, and 3 for cancellation/HOLD.


## Portable HUMAN Worksheet Studio (browser; no Python or server required)

**[One-file offline Studio](worksheet-studio-standalone.html)** · [Original HTML](worksheet-studio.html) · [JS](worksheet-studio.js) · [CSS](worksheet-studio.css) · [offline builder](build_worksheet_studio.py).

This new PRIVATE HUMAN ordinal CSV editor is independent of the original lab-result owner. Download and open `worksheet-studio-standalone.html` as a local file on a trusted, preferably disconnected device. The built HTML includes all JS and CSS, SHA-256 pinned inline CSP, `connect-src 'none'`, no remote assets or browser persistence. Rebuild from the exact three source files with `python3 assessment-briefing/build_worksheet_studio.py --replace`.

**Local HUMAN follow-up:** import the seven-column `human-followup.csv` generated by original `briefing.py`, capped at 1 MiB and 2048 rows. Strict UTF-8, CSV quoting, unique ascending original ordinal, identical seven-column header, severity, evidence-reference count, human stage and per-field bounds are required. The browser also rejects spreadsheet formula-looking HUMAN input. Failures preserve existing work. Only anonymous original ordinals, source-reported severities/evidence counts and HUMAN notes are in the browser, **not** original target URLs, run IDs, finding titles, evidence or source hashes.

Filter locally by original severity or HUMAN stage/group/notes, edit each HUMAN stage, group, action or blocker, and see progress and blockers explicitly as self-reported work—not security outcomes. Explicitly confirm bulk stage/group changes on filtered rows, Undo the last bulk change, and download the complete original-format PRIVATE CSV with all unchanged original ordinal/severity/evidence-reference-count cells. A separate optional source-free counts JSON omits target/finding/note/hash text, but remains PRIVATE.

**Incoming HUMAN proposal inbox:** open a second original-format PRIVATE human CSV from a separately contacted person. Admission requires all original ordinal, severity and evidence-reference-count values to match the loaded worksheet exactly. Compare every changed HUMAN stage/group/action/blocker field side by side. Nothing is auto-selected. Check specific proposed fields, optionally select visible page proposals after confirmation, then explicitly accept only those selected values. Any intervening local edit invalidates pending proposal admission; reopen the incoming CSV to compare again. Peer identity, original producer identity, consent and genuine remediation are not authenticated.

**Handoff:** Save the new PRIVATE edited CSV and run `human_return.py` with the unchanged original source and original unsigned manifest to generate the source-byte-bound private HUMAN return report. Browser-level CSV matching alone cannot authenticate source bytes. A malicious device/browser can read all HUMAN note content, and downloaded files survive closing the tab. The standalone has not undergone independent browser/privacy/security acceptance and is **DRAFT/HOLD, PLAN/LAB ONLY**.


## Optional encrypted PRIVATE HUMAN CSV transport (one-file Studio)

The same fully offline `worksheet-studio-standalone.html` additionally supports an opt-in **encrypted, password-bound HUMAN CSV handoff**. This is NOT the existing original encrypted source-workroom owner and does not store original lab result bytes, target URLs, evidence or consent.

1. Import or manually edit an original ordinal worksheet as before. Expand **Optional ENCRYPTED PRIVATE worksheet** at the bottom; type the same locally chosen 12–256-character passphrase twice and explicitly confirm the export. The browser encodes the original-format complete HUMAN CSV, chooses fresh cryptographically random 16-byte salt and 12-byte AES-GCM nonce, derives an AES-256 key with PBKDF2-HMAC-SHA256 **310,000 iterations**, and encrypts with a dedicated fixed application additional-authenticated-data string and 128-bit GCM tag.
2. Only the new `lightup-private-human-worksheet.luhw` local JSON is downloaded. Its outer envelope has a strict v1 schema and explicit literal false fields for source/auth/client consent/dispatch/release authority. The plaintext CSV fields are inside ciphertext. Its file size and the original CSV size are bounded; no password is stored in file or browser storage.
3. On a trusted offline browser, open this same standalone file, expand **Open optional encrypted PRIVATE HUMAN worksheet**, choose the `.luhw` and enter the actual passphrase. The browser checks exact canonical outer JSON, rejects unexpected/duplicate or inconsistent metadata by refusing any noncanonical representation, checks base64 fields, authenticates/decrypts with AES-256-GCM and independently re-admits the decrypted CSV using the unchanged strict original-ordinal/evidence/severity/HUMAN parser. Only on full successful admission **and separate human approval of overwriting unsaved local edits** is the active workspace replaced. A wrong password, altered file or unavailable WebCrypto leaves the prior in-memory work unchanged.
4. After editing, download a new PRIVATE CSV or another new encrypted PRIVATE file. The old downloaded ciphertext, original source and other saved files are never changed. There is **no key escrow or password recovery**.

**This encryption is a confidentiality convenience only**, not verified identity, trustworthy provenance, source authenticity, client/operator authorization, current consent/revocation, or an approved way to distribute client data. WebCrypto support, device/browser security, passphrase strength, human access controls and separately authorized private transport remain required. No independent cryptographic/browser security assessment has been performed. The entire original feature remains DRAFT/HOLD; no production security claim or real-client deployment follows from it.


## Large original findings: PRIVATE paged report library (up to 2,048)

A large original finding source may not fit into one comfortable print/browser document. **Now use this entirely new read-only offline pipeline instead of truncating any original record**:

```bash
python3 assessment-briefing/paged_review.py \
  --source ./original-private-lab.json \
  --output-dir ./NEW-PRIVATE-PAGED-REPORT
```

Or choose **Build paged PRIVATE original finding library** from the same `console.py` foreground menu. This source-reader accepts the same already-produced strict original lab JSON (no new work/scan), renders at most 40 original findings per scriptless PRIVATE local HTML page and keeps each **original source ordinal unchanged**. For the maximum 2,048 original findings, the output has at most 52 linked pages; zero original findings produce an explicit empty page rather than a fabricated finding.

All files are written exclusively inside one new 0700 directory as 0600 regular files, with no overwrites: `index.html` (PRIVATE severity distribution, original ordinal ranges and local links), `page-0001.html` and later pages (original private source details, literal targets, evidence summary, mitigations, human-only blank review worksheets), `human-followup.csv` (the SAME seven-column original rows/ordinals suitable for the browser HUMAN Studio) and `manifest.json` (unsigned exact original source hash, each PRIVATE page digest, row ranges, aggregate counts and literal false authority flags).

The original `human_return.py` and `human_revision.py` now admit up to 64 KiB of **PRIVATE paged manifest** while maintaining the original exact source-byte SHA, finding/endpoint counts and HUMAN-row membership boundaries. The extra manifest size only accommodates the paged file inventory; it does not establish source authenticity or independent client consent. The HTML remains scriptless, Content Security Policy pinned, locally linked only and with original PRIVATE text HTML-escaped.

**PRIVATE file hygiene:** these pages intentionally contain potentially confidential original target URLs, finding titles, evidence and source descriptions, unlike the source-free browser ordinal Studio. Keep the *entire* directory private and within separately approved human controls; none of the pages contacts a target or resolves DNS. No production rollout is justified, and all original M3/M7 DRAFT/HOLD gates remain in force.


## Original-source-bound PRIVATE HUMAN attention matrix (seventh offline menu workflow)

An independently obtained original lab result and its original SHA-manifest can now be joined with a completed HUMAN review CSV **without modifying original evidence or assuming review-stage truth**.

```bash
python3 assessment-briefing/human_matrix.py \
  --source ./original-private-lab.json \
  --manifest ./NEW-PRIVATE-BRIEFING/manifest.json \
  --worksheet ./human-filled-followup.csv \
  --output-dir ./NEW-PRIVATE-HUMAN-MATRIX
```

Or select **Produce PRIVATE severity × HUMAN attention matrix and ordinal queue** in the shared `console.py` menu. The existing original source-byte fingerprint, exact original source endpoint/finding totals and all original CSV row/ordinal/severity/evidence-reference membership are checked before publishing any output.

The NEW 0700 directory contains the following 0600 PRIVATE artifacts:

- `private-human-matrix.html`: a scriptless offline and printable source-declared **severity × HUMAN stage** table with HUMAN missing owner/action, blocker and source-evidence-reference counts by source severity. Original target, ID, finding title, evidence and HUMAN comments are not in this matrix view. Original source SHA stays PRIVATE in the report.
- `private-human-matrix.json`: corresponding count-only machine-readable matrix and literal-false identity/consent/auth/release flags; no original names, target details, evidence or human comments.
- `private-ordinal-followup.csv`: original source ordinal, declared severity and evidence-ref count plus booleans for missing HUMAN group, action, blocker and the current self-reported stage. Rows are ordered by source-reported severity and HUMAN blockers for a **human convenience queue**, not a derived verified risk priority. Original ordinals remain immutable, but the output is not a replacement for the original seven-column HUMAN CSV.
- `manifest.json`: unsigned original source hash and output digest references, NEVER producer authentication.

Even counts-only results are PRIVATE and may re-identify a small cohort. This is a HUMAN coordination report only: stage `documented` cannot prove a fix, source severity is not independently verified, and an explicit HUMAN blocker does not establish permission or incident status. **No active scanning, source mutation, verified verdict, consent or grant is performed.**


## Portable PRIVATE paged ZIP handoff (two-way local workflow)

**Product gap closed:** a paged 1–52 file original report is awkward to transfer between two trusted offline devices. You can now bundle an **already-produced** paged PRIVATE report and restore it to a NEW protected folder, without running a scan, invoking models, opening a target, widening scopes, creating any permission or changing its original source.

**Sender, from an already-produced `paged_review.py` directory:**

```bash
python3 assessment-briefing/private_paged_zip.py \
  --private-paged-dir ./NEW-PRIVATE-PAGED-REPORT \
  --output-dir ./NEW-PRIVATE-ZIP-HANDOFF
```

The sender strictly requires the *exact original* paged manifest v1: original source declaration byte SHA, literal false authority flags, 1–16 original declared endpoint count, ≤2048 original rows, expected 40-row page ordinal ranges and **the unsigned original private HTML/CSV SHA-256 digests of every page**. It reads only fixed expected private local filenames relative to a no-follow directory descriptor, rejects symlinks/other group/world-readable source artifacts and unexpected extra files, and refuses any mismatch before making a new 0700 directory. The output contains a 0600 **`LightUp-PRIVATE-Paged-Review.zip`** and 0600 `PRIVATE-archive-receipt.json` with unsigned byte digest and explicit `archive_is_encrypted:false`. ZIP contents include source target literals, findings, summaries and evidence references. The ZIP is **NOT ENCRYPTED**: keep it offline or transfer only using a separately approved confidential encrypted channel. The source total and ZIP size are bounded (≤64 MiB original files / ≤23 MiB zip) and larger packs HOLD without truncation.

**Recipient, on a trusted offline device:**

```bash
python3 assessment-briefing/private_paged_restore.py \
  --private-zip ./LightUp-PRIVATE-Paged-Review.zip \
  --output-dir ./NEW-PRIVATE-RESTORED-REVIEW
```

The receiver first admits the bounded ZIP and its exact manifest and original page inventory. It rejects duplicate/ambiguous ZIP member names, arbitrary paths/traversal, directories, symlinks, altered content/checksums, encrypted ZIP entries, unexpected compression, appended files and modified operator instructions. **Only after every original member is admitted and complete** are known relative artifacts extracted into one entirely NEW 0700 protected directory as 0600 files, with an explicit private local restore-receipt and retained original manifest. The recipient opens the resulting `index.html` LOCALLY; links reach the original source-ordinal pages. The original `human-followup.csv` can enter the existing browser HUMAN Studio or `human_return.py`. A source digest remains an **UNSIGNED identifier**; matching it is not source producer, client/operator identity, consent, authorization, verified findings, remediation or release.

Both tools are also in the foreground `console.py` menu. Neither performs a background operation. **Do not publish the ZIP or restored directory to a public host.** No production deployment or active target activity is allowed under the current M3/M7 DRAFT/HOLD phase.


## Safe HUMAN follow-up continuity across TWO original lab runs

A new product flow now drafts HUMAN review continuity when an operator has *already* obtained a newer original PRIVATE lab result. **Nothing runs or contacts a target**, and a changed or missing source declaration NEVER becomes a verified fix or a newly proven vulnerability. All new HUMAN stages are deliberately reset to `needs_review` even for identical original source descriptions.

```bash
python3 assessment-briefing/human_source_continuity.py \
  --before ./earlier-original-lab.json \
  --before-manifest ./EARLIER-PRIVATE-BRIEFING/manifest.json \
  --before-worksheet ./human-earlier.csv \
  --after ./newer-original-lab.json \
  --output-dir ./NEW-PRIVATE-HUMAN-CONTINUITY
```

The program first strictly admits the earlier original lab JSON, exact SHA-bound earlier manifest and complete original seven-column HUMAN worksheet. It independently admits the **newer already-produced** lab JSON. The two original results must have **different original run IDs**, identical scenario literal and identical set of declared original target strings. They remain unverified source declarations. It uses the original literal target + capability ID + check ID strictly as a heuristic candidate-key, not verified identity or finding truth; duplicate keys on either side remain ambiguous and get no carryover.

Per newest original finding ordinal, the resulting PRIVATE human **PROPOSAL** CSV is a complete original seven-column format with the new source-reported severity and evidence-reference count. Every HUMAN stage is always reset to `needs_review`. Only an exact one-to-one original literal key can suggest copying the former generic HUMAN group; old HUMAN next action and blocker suggestions are copied **only if all original described source fields, original evidence references and original finding ID are byte-exact-equal**. If the finding ID, evidence references or other description changed, the old action and blocker are cleared instead of implying present validity. No old remediation, approval, source authenticity, finding validity, client/operator consent, actual recency or current permissions can be carried. Potential spreadsheet-formula-leading HUMAN fields are rejected, not silently exported.

The new protected PRIVATE output folder contains:

- `PRIVATE-next-human-review-PROPOSAL.csv` — proposed HUMAN-only values using **the newest original source ordinals**. No original target URLs, check/asset IDs or finding descriptions in CSV. It is deliberately **not automatically adopted or applied**.
- `PRIVATE-human-source-continuity.html` — scriptless, CSP-pinned PRIVATE per-source-row explanation of which previous ordinal (if uniquely matched) informed a proposed HUMAN group/action, with original newest titles, descriptions and target text behind a PRIVATE detail disclosure. Reported absence is NEVER "fixed".
- `PRIVATE-proposal-manifest.json` — old/new UNSIGNED original source SHA-256, source-declaration category counts, private output hashes and literal false security/permission/release flags.

A HUMAN should inspect and edit this proposed CSV in the [PRIVATE browser Studio](worksheet-studio-standalone.html), then run the **original** `briefing.py` or `paged_review.py` for the NEW original lab JSON and use its NEW manifest together with the reviewed CSV in `human_return.py`. This ensures the true new source byte-binding gate remains separate and compulsory. Source similarity never pre-approves any human action. This operator workflow is also available in the shared foreground console. Like all other LightUp modules, it remains DRAFT/HOLD pending original full release gates.


### Portable ZIP round-trip after restore

The same local ZIP packager now also accepts a directory produced by the safe `private_paged_restore.py` receiver. It permits exactly two extra private files from a legitimate original restore: `START-HERE-PRIVATE.txt` with the identical predefined no-authority instructions and `PRIVATE-restore-receipt.json` with the exact restored original source fingerprint, expected member count and all identity/authority/consent/release flags false. It refuses any altered or additional file. The old receipt is **not** included in the new ZIP; a new unsigned archive receipt is generated. This permits a private operator to pass an unmodified report onward without manual deletion or recreating source packages. It still authenticates neither the original producer nor receiving person, and the archive is still plain unencrypted ZIP.
