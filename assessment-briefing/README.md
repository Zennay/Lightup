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
